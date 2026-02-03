package site.aicc.demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import site.aicc.sm4.SM4;

/**
 * 加密解密API处理 - 双向加解密验证
 */
public class CryptoHandler implements HttpHandler {

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String method = exchange.getRequestMethod();

        // 设置CORS
        exchange.getResponseHeaders().add("Access-Control-Allow-Origin", "*");
        exchange.getResponseHeaders().add("Access-Control-Allow-Methods", "POST, OPTIONS");
        exchange.getResponseHeaders().add("Access-Control-Allow-Headers", "Content-Type");

        if ("OPTIONS".equals(method)) {
            exchange.sendResponseHeaders(204, -1);
            return;
        }

        if (!"POST".equals(method)) {
            sendResponse(exchange, 405, "{\"error\":\"Method not allowed\"}");
            return;
        }

        try {
            String body = readBody(exchange);
            String response = handleTest(body);
            sendResponse(exchange, 200, response);
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    /**
     * 处理加密通信测试请求
     *
     * 请求格式:
     * {
     *   "sessionId": "uuid",
     *   "clientCiphertext": "hex",      // 客户端加密的数据
     *   "clientPlaintext": "string"     // 客户端原文（用于服务端验证解密结果）
     * }
     *
     * 响应格式:
     * {
     *   "clientDecrypted": "string",    // 服务端解密客户端密文的结果
     *   "clientDecryptMatch": true,     // 是否与原文匹配
     *   "serverPlaintext": "string",    // 服务端发送的原文
     *   "serverCiphertext": "hex"       // 服务端加密的数据
     * }
     */
    private String handleTest(String body) throws Exception {
        String sessionId = extractJsonValue(body, "sessionId");
        String clientCiphertext = extractJsonValue(body, "clientCiphertext");
        String clientPlaintext = extractJsonValue(body, "clientPlaintext");

        System.out.println("\n=== Crypto Test (Bidirectional) ===");
        System.out.println("sessionId: " + sessionId);
        System.out.println("clientPlaintext: " + clientPlaintext);
        System.out.println("clientCiphertext: " + clientCiphertext);

        SessionStore.Session session = SessionStore.get(sessionId);
        if (session == null) {
            throw new Exception("Session not found");
        }

        if (!session.confirmed) {
            throw new Exception("Key exchange not confirmed");
        }

        // 使用协商密钥 (SM4-CBC模式，IV使用全零)
        String iv = "00000000000000000000000000000000";
        SM4 sm4 = new SM4();
        sm4.setKey(session.Kb, iv, true);

        // 1. 服务端解密客户端的密文
        String clientDecrypted = sm4.decrypt(clientCiphertext);
        boolean clientDecryptMatch = clientPlaintext.equals(clientDecrypted);

        System.out.println("clientDecrypted: " + clientDecrypted);
        System.out.println("clientDecryptMatch: " + clientDecryptMatch);

        // 2. 服务端加密一段响应消息
        String serverPlaintext = "Response from Java Server: " + System.currentTimeMillis();
        String serverCiphertext = sm4.encrypt(serverPlaintext);

        System.out.println("serverPlaintext: " + serverPlaintext);
        System.out.println("serverCiphertext: " + serverCiphertext);

        // 返回结果（对特殊字符进行转义）
        return String.format(
            "{\"clientDecrypted\":\"%s\",\"clientDecryptMatch\":%s,\"serverPlaintext\":\"%s\",\"serverCiphertext\":\"%s\"}",
            escapeJson(clientDecrypted), clientDecryptMatch, escapeJson(serverPlaintext), serverCiphertext
        );
    }

    private String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private String readBody(HttpExchange exchange) throws IOException {
        InputStream is = exchange.getRequestBody();
        byte[] bytes = new byte[is.available()];
        is.read(bytes);
        return new String(bytes, StandardCharsets.UTF_8);
    }

    private void sendResponse(HttpExchange exchange, int code, String response) throws IOException {
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(code, bytes.length);
        OutputStream os = exchange.getResponseBody();
        os.write(bytes);
        os.close();
    }

    private String extractJsonValue(String json, String key) {
        String pattern = "\"" + key + "\"";
        int keyIndex = json.indexOf(pattern);
        if (keyIndex == -1) return null;

        int colonIndex = json.indexOf(":", keyIndex);
        if (colonIndex == -1) return null;

        int start = colonIndex + 1;
        while (start < json.length() && Character.isWhitespace(json.charAt(start))) {
            start++;
        }

        if (json.charAt(start) == '"') {
            start++;
            int end = json.indexOf('"', start);
            return json.substring(start, end);
        } else {
            int end = start;
            while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.')) {
                end++;
            }
            return json.substring(start, end);
        }
    }
}
