package site.aicc.demo;

import com.sun.net.httpserver.HttpExchange;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Shared HTTP handling for the demo: bounded request bodies, a strict JSON reader and error replies
 * that reveal nothing about the failure's internals.
 */
final class DemoHttp {
  /** Far above any request of this protocol; larger bodies are refused without being stored. */
  static final int MAX_BODY_BYTES = 64 * 1024;

  private static final int READ_CHUNK_BYTES = 4096;

  private DemoHttp() {}

  /** A request that must be answered with this status and message, which are safe to send. */
  static final class RequestException extends Exception {
    private static final long serialVersionUID = 1L;
    final int status;

    RequestException(int status, String message) {
      super(message);
      this.status = status;
    }
  }

  /** Reads the whole body up to the limit; {@code available()} cannot tell where a body ends. */
  static String readBody(HttpExchange exchange) throws IOException, RequestException {
    if (declaresOversizedBody(exchange)) {
      throw new RequestException(413, "Request body too large");
    }
    ByteArrayOutputStream body = new ByteArrayOutputStream();
    byte[] chunk = new byte[READ_CHUNK_BYTES];
    try (InputStream is = exchange.getRequestBody()) {
      int n;
      while ((n = is.read(chunk)) != -1) {
        if (body.size() + n > MAX_BODY_BYTES) {
          throw new RequestException(413, "Request body too large");
        }
        body.write(chunk, 0, n);
      }
    }
    try {
      return StandardCharsets.UTF_8
          .newDecoder()
          .onMalformedInput(CodingErrorAction.REPORT)
          .onUnmappableCharacter(CodingErrorAction.REPORT)
          .decode(ByteBuffer.wrap(body.toByteArray()))
          .toString();
    } catch (CharacterCodingException e) {
      throw new RequestException(400, "Malformed request");
    }
  }

  /** Refuses a too-large declared body before waiting for any of it to arrive. */
  private static boolean declaresOversizedBody(HttpExchange exchange) {
    String declared = exchange.getRequestHeaders().getFirst("Content-Length");
    if (declared == null) {
      return false;
    }
    try {
      return Long.parseLong(declared.trim()) > MAX_BODY_BYTES;
    } catch (NumberFormatException e) {
      return true;
    }
  }

  static void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
    exchange.getResponseHeaders().add("Content-Type", "application/json");
    byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
    exchange.sendResponseHeaders(code, bytes.length);
    try (OutputStream os = exchange.getResponseBody()) {
      os.write(bytes);
    }
  }

  static void sendError(HttpExchange exchange, int code, String message) throws IOException {
    sendResponse(exchange, code, "{\"error\":\"" + escapeJson(message) + "\"}");
  }

  /** Reports an unexpected failure by type only: messages and traces could quote request data. */
  static void sendInternalError(HttpExchange exchange, Exception e) throws IOException {
    System.out.println("Request failed: " + e.getClass().getSimpleName());
    sendError(exchange, 500, "Internal error");
  }

  static String escapeJson(String s) {
    StringBuilder out = new StringBuilder(s.length() + 8);
    for (int i = 0; i < s.length(); i++) {
      char c = s.charAt(i);
      switch (c) {
        case '"':
          out.append("\\\"");
          break;
        case '\\':
          out.append("\\\\");
          break;
        case '\n':
          out.append("\\n");
          break;
        case '\r':
          out.append("\\r");
          break;
        case '\t':
          out.append("\\t");
          break;
        default:
          if (c < 0x20) {
            out.append(String.format("\\u%04x", (int) c));
          } else {
            out.append(c);
          }
      }
    }
    return out.toString();
  }

  /** Parses one JSON object of scalar members. */
  static Body parseObject(String json) throws RequestException {
    return new JsonReader(json).readObject();
  }

  /** A parsed request: members keep their JSON type, so a number is not accepted as a string. */
  static final class Body {
    private final Map<String, String> strings = new HashMap<>();
    private final Map<String, String> numbers = new HashMap<>();
    private final Set<String> keys = new HashSet<>();

    /** Returns a required string member. */
    String string(String key) throws RequestException {
      return required(strings, key);
    }

    /** Returns the literal text of a required number member. */
    String number(String key) throws RequestException {
      return required(numbers, key);
    }

    private static String required(Map<String, String> members, String key)
        throws RequestException {
      String value = members.get(key);
      if (value == null) {
        throw new RequestException(400, "Malformed request");
      }
      return value;
    }
  }

  private static final class JsonReader {
    private final String text;
    private int pos;

    JsonReader(String text) {
      this.text = text;
    }

    Body readObject() throws RequestException {
      Body out = new Body();
      skipSpace();
      expect('{');
      skipSpace();
      if (peek() == '}') {
        pos++;
      } else {
        while (true) {
          skipSpace();
          String key = readString();
          skipSpace();
          expect(':');
          skipSpace();
          if (!out.keys.add(key)) {
            throw malformed();
          }
          readScalar(out, key);
          skipSpace();
          char next = peek();
          pos++;
          if (next == '}') {
            break;
          }
          if (next != ',') {
            throw malformed();
          }
        }
      }
      skipSpace();
      if (pos != text.length()) {
        throw malformed();
      }
      return out;
    }

    private void readScalar(Body out, String key) throws RequestException {
      char c = peek();
      if (c == '"') {
        out.strings.put(key, readString());
        return;
      }
      if (c == '-' || (c >= '0' && c <= '9')) {
        int start = pos;
        while (pos < text.length() && "+-.eE0123456789".indexOf(text.charAt(pos)) >= 0) {
          pos++;
        }
        out.numbers.put(key, text.substring(start, pos));
        return;
      }
      for (String literal : new String[] {"true", "false", "null"}) {
        if (text.startsWith(literal, pos)) {
          pos += literal.length();
          return;
        }
      }
      throw malformed();
    }

    private String readString() throws RequestException {
      expect('"');
      StringBuilder out = new StringBuilder();
      while (true) {
        char c = peek();
        pos++;
        if (c == '"') {
          return out.toString();
        }
        if (c < 0x20) {
          throw malformed();
        }
        if (c != '\\') {
          out.append(c);
          continue;
        }
        char escape = peek();
        pos++;
        switch (escape) {
          case '"':
          case '\\':
          case '/':
            out.append(escape);
            break;
          case 'b':
            out.append('\b');
            break;
          case 'f':
            out.append('\f');
            break;
          case 'n':
            out.append('\n');
            break;
          case 'r':
            out.append('\r');
            break;
          case 't':
            out.append('\t');
            break;
          case 'u':
            out.append(readUnicodeEscape());
            break;
          default:
            throw malformed();
        }
      }
    }

    private char readUnicodeEscape() throws RequestException {
      if (pos + 4 > text.length()) {
        throw malformed();
      }
      int value = 0;
      for (int i = 0; i < 4; i++) {
        int digit = Character.digit(text.charAt(pos++), 16);
        if (digit < 0 || text.charAt(pos - 1) > 0x7F) {
          throw malformed();
        }
        value = value << 4 | digit;
      }
      return (char) value;
    }

    private void skipSpace() {
      while (pos < text.length() && " \t\r\n".indexOf(text.charAt(pos)) >= 0) {
        pos++;
      }
    }

    private void expect(char c) throws RequestException {
      if (peek() != c) {
        throw malformed();
      }
      pos++;
    }

    private char peek() throws RequestException {
      if (pos >= text.length()) {
        throw malformed();
      }
      return text.charAt(pos);
    }

    private static RequestException malformed() {
      return new RequestException(400, "Malformed request");
    }
  }
}
