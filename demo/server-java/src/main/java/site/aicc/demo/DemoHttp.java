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
import java.util.Map;

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

  /** Parses one JSON object of scalar members; numbers keep their text, null reads as absent. */
  static Map<String, String> parseObject(String json) throws RequestException {
    return new JsonReader(json).readObject();
  }

  /** Returns a required member. */
  static String require(Map<String, String> body, String key) throws RequestException {
    String value = body.get(key);
    if (value == null) {
      throw new RequestException(400, "Malformed request");
    }
    return value;
  }

  private static final class JsonReader {
    private final String text;
    private int pos;

    JsonReader(String text) {
      this.text = text;
    }

    Map<String, String> readObject() throws RequestException {
      Map<String, String> out = new HashMap<>();
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
          String value = readScalar();
          if (out.containsKey(key)) {
            throw malformed();
          }
          out.put(key, value);
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

    private String readScalar() throws RequestException {
      char c = peek();
      if (c == '"') {
        return readString();
      }
      if (c == '-' || (c >= '0' && c <= '9')) {
        int start = pos;
        while (pos < text.length() && "+-.eE0123456789".indexOf(text.charAt(pos)) >= 0) {
          pos++;
        }
        return text.substring(start, pos);
      }
      for (String literal : new String[] {"true", "false", "null"}) {
        if (text.startsWith(literal, pos)) {
          pos += literal.length();
          return literal.equals("null") ? null : literal;
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
