package io.hunterpy.burp;

import java.io.IOException;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Tiny dependency-free JSON parser.
 *
 * <p>Identical in shape to {@code io.hunterpy.gui.util.Json} from the
 * desktop GUI. Duplicated intentionally — we don't want the Burp
 * extension JAR to depend on any other HunterPy artifact, and pulling
 * in Jackson would force users to merge classpaths inside Burp.</p>
 */
final class MiniJson {

    private MiniJson() { }

    static Object parse(String text) {
        return new Parser(text).parseValue();
    }

    static Object parseFile(Path path) throws IOException {
        try (Reader r = Files.newBufferedReader(path, StandardCharsets.UTF_8)) {
            StringBuilder sb = new StringBuilder();
            char[] buf = new char[8192];
            int n;
            while ((n = r.read(buf)) != -1) sb.append(buf, 0, n);
            return parse(sb.toString());
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> asMap(Object v) {
        return v instanceof Map ? (Map<String, Object>) v : new LinkedHashMap<>();
    }

    @SuppressWarnings("unchecked")
    static List<Object> asList(Object v) {
        return v instanceof List ? (List<Object>) v : new ArrayList<>();
    }

    static String asString(Object v, String def) {
        return v == null ? def : String.valueOf(v);
    }

    static int asInt(Object v, int def) {
        if (v instanceof Number) return ((Number) v).intValue();
        try { return v == null ? def : Integer.parseInt(v.toString()); }
        catch (NumberFormatException e) { return def; }
    }

    private static final class Parser {
        private final String s;
        private int i = 0;
        Parser(String s) { this.s = s; }

        Object parseValue() {
            skipWs();
            if (i >= s.length()) throw err("eof");
            char c = s.charAt(i);
            if (c == '{') return parseObject();
            if (c == '[') return parseArray();
            if (c == '"') return parseString();
            if (c == 't' || c == 'f') return parseBool();
            if (c == 'n') return parseNull();
            return parseNumber();
        }

        private Map<String, Object> parseObject() {
            expect('{');
            Map<String, Object> m = new LinkedHashMap<>();
            skipWs();
            if (peek() == '}') { i++; return m; }
            while (true) {
                skipWs();
                String key = parseString();
                skipWs(); expect(':');
                m.put(key, parseValue());
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == '}') { i++; return m; }
                throw err("expected , or } got " + c);
            }
        }

        private List<Object> parseArray() {
            expect('[');
            List<Object> a = new ArrayList<>();
            skipWs();
            if (peek() == ']') { i++; return a; }
            while (true) {
                a.add(parseValue());
                skipWs();
                char c = peek();
                if (c == ',') { i++; continue; }
                if (c == ']') { i++; return a; }
                throw err("expected , or ] got " + c);
            }
        }

        private String parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (i < s.length()) {
                char c = s.charAt(i++);
                if (c == '"') return sb.toString();
                if (c == '\\') {
                    char esc = s.charAt(i++);
                    switch (esc) {
                        case '"':  sb.append('"');  break;
                        case '\\': sb.append('\\'); break;
                        case '/':  sb.append('/');  break;
                        case 'b':  sb.append('\b'); break;
                        case 'f':  sb.append('\f'); break;
                        case 'n':  sb.append('\n'); break;
                        case 'r':  sb.append('\r'); break;
                        case 't':  sb.append('\t'); break;
                        case 'u':
                            sb.append((char) Integer.parseInt(s.substring(i, i + 4), 16));
                            i += 4;
                            break;
                        default: throw err("bad escape " + esc);
                    }
                } else sb.append(c);
            }
            throw err("unterminated string");
        }

        private Boolean parseBool() {
            if (s.startsWith("true",  i)) { i += 4; return Boolean.TRUE;  }
            if (s.startsWith("false", i)) { i += 5; return Boolean.FALSE; }
            throw err("expected bool");
        }

        private Object parseNull() {
            if (s.startsWith("null", i)) { i += 4; return null; }
            throw err("expected null");
        }

        private Double parseNumber() {
            int start = i;
            if (peek() == '-') i++;
            while (i < s.length() && "0123456789.eE+-".indexOf(s.charAt(i)) >= 0) i++;
            return Double.parseDouble(s.substring(start, i));
        }

        private void skipWs() {
            while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        }

        private void expect(char c) {
            if (i >= s.length() || s.charAt(i) != c) {
                String got = (i < s.length()) ? String.valueOf(s.charAt(i)) : "EOF";
                throw err("expected '" + c + "' got '" + got + "'");
            }
            i++;
        }

        private char peek() {
            if (i >= s.length()) throw err("eof");
            return s.charAt(i);
        }

        private RuntimeException err(String msg) {
            return new IllegalArgumentException("json: " + msg + " at " + i);
        }
    }
}
