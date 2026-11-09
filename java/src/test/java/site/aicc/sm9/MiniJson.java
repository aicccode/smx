package site.aicc.sm9;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON reader for the shared test vectors (the library has no dependencies, so neither do
 * its tests beyond JUnit). Objects become maps, arrays lists, numbers longs.
 */
final class MiniJson {
  private final String s;
  private int i;

  private MiniJson(String s) {
    this.s = s;
  }

  static Object parse(String text) {
    MiniJson p = new MiniJson(text);
    Object v = p.value();
    p.ws();
    if (p.i != text.length()) {
      throw new IllegalArgumentException("trailing data at " + p.i);
    }
    return v;
  }

  private void ws() {
    while (i < s.length() && Character.isWhitespace(s.charAt(i))) {
      i++;
    }
  }

  private Object value() {
    ws();
    char c = s.charAt(i);
    switch (c) {
      case '{':
        return object();
      case '[':
        return array();
      case '"':
        return string();
      case 't':
        return literal("true", Boolean.TRUE);
      case 'f':
        return literal("false", Boolean.FALSE);
      case 'n':
        return literal("null", null);
      default:
        return number();
    }
  }

  private Object literal(String word, Object v) {
    if (!s.startsWith(word, i)) {
      throw new IllegalArgumentException("bad literal at " + i);
    }
    i += word.length();
    return v;
  }

  private Map<String, Object> object() {
    Map<String, Object> m = new LinkedHashMap<>();
    i++;
    ws();
    if (s.charAt(i) == '}') {
      i++;
      return m;
    }
    while (true) {
      ws();
      String k = string();
      ws();
      expect(':');
      m.put(k, value());
      ws();
      if (s.charAt(i) == ',') {
        i++;
        continue;
      }
      expect('}');
      return m;
    }
  }

  private List<Object> array() {
    List<Object> l = new ArrayList<>();
    i++;
    ws();
    if (s.charAt(i) == ']') {
      i++;
      return l;
    }
    while (true) {
      l.add(value());
      ws();
      if (s.charAt(i) == ',') {
        i++;
        continue;
      }
      expect(']');
      return l;
    }
  }

  private void expect(char c) {
    if (s.charAt(i) != c) {
      throw new IllegalArgumentException("expected " + c + " at " + i);
    }
    i++;
  }

  private String string() {
    expect('"');
    StringBuilder b = new StringBuilder();
    while (true) {
      char c = s.charAt(i++);
      if (c == '"') {
        return b.toString();
      }
      if (c != '\\') {
        b.append(c);
        continue;
      }
      char e = s.charAt(i++);
      switch (e) {
        case 'n':
          b.append('\n');
          break;
        case 't':
          b.append('\t');
          break;
        case 'r':
          b.append('\r');
          break;
        case 'b':
          b.append('\b');
          break;
        case 'f':
          b.append('\f');
          break;
        case 'u':
          b.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
          i += 4;
          break;
        default:
          b.append(e);
      }
    }
  }

  private Long number() {
    int start = i;
    while (i < s.length() && "+-0123456789".indexOf(s.charAt(i)) >= 0) {
      i++;
    }
    return Long.parseLong(s.substring(start, i));
  }
}
