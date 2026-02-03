package site.aicc.demo;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.UUID;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;

import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;

/**
 * 密钥交换API处理
 */
public class KeySwapHandler implements HttpHandler {

    // 服务端B的固定密钥对（实际使用应该从配置加载）
    private final ECKeyPair serverKeyPair;
    private final String serverId = "server@demo.aicc";

    public KeySwapHandler() {
        this.serverKeyPair = SM2.genSM2KeyPair();
        System.out.println("Server keypair generated");
        AbstractECPoint q = ((ECPublicKey) serverKeyPair.getPublic()).getQ();
        System.out.println("Server public key: 04" +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(q.getXCoord().toBigInteger())) +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(q.getYCoord().toBigInteger())));
    }

    @Override
    public void handle(HttpExchange exchange) throws IOException {
        String path = exchange.getRequestURI().getPath();
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
            String response;

            if (path.endsWith("/init")) {
                response = handleInit(body);
            } else if (path.endsWith("/confirm")) {
                response = handleConfirm(body);
            } else {
                sendResponse(exchange, 404, "{\"error\":\"Not found\"}");
                return;
            }

            sendResponse(exchange, 200, response);
        } catch (Exception e) {
            e.printStackTrace();
            sendResponse(exchange, 500, "{\"error\":\"" + e.getMessage() + "\"}");
        }
    }

    /**
     * 处理密钥交换初始化请求
     */
    private String handleInit(String body) throws Exception {
        // 简单JSON解析
        String IDa = extractJsonValue(body, "IDa");
        String pAHex = extractJsonValue(body, "pA");
        String RaHex = extractJsonValue(body, "Ra");
        int keyLen = Integer.parseInt(extractJsonValue(body, "keyLen"));

        System.out.println("\n=== KeySwap Init ===");
        System.out.println("IDa: " + IDa);
        System.out.println("pA: " + pAHex);
        System.out.println("Ra: " + RaHex);
        System.out.println("keyLen: " + keyLen);

        // 解析A的公钥和随机公钥
        AbstractECPoint pA = SM2.decodePoint(pAHex);
        AbstractECPoint Ra = SM2.decodePoint(RaHex);

        // 获取B的密钥
        AbstractECPoint pB = ((ECPublicKey) serverKeyPair.getPublic()).getQ();
        BigInteger dB = ((ECPrivateKey) serverKeyPair.getPrivate()).getD();

        // 生成B的随机密钥对
        ECKeyPair rbPair = SM2.genSM2KeyPair();
        AbstractECPoint Rb = ((ECPublicKey) rbPair.getPublic()).getQ();
        BigInteger rb = ((ECPrivateKey) rbPair.getPrivate()).getD();

        // 调用getSb
        SM2KeySwapParams result = SM2.getSb(keyLen, pA, Ra, pB, dB, Rb, rb, IDa, serverId);

        if (!result.isSuccess()) {
            throw new Exception("getSb failed: " + result.getMessage());
        }

        System.out.println("Sb: " + result.getSb());
        System.out.println("Kb: " + result.getKb());

        // 创建会话
        String sessionId = UUID.randomUUID().toString();
        SessionStore.Session session = new SessionStore.Session();
        session.sessionId = sessionId;
        session.IDa = IDa;
        session.IDb = serverId;
        session.pA = pA;
        session.Ra = Ra;
        session.pB = pB;
        session.dB = dB;
        session.Rb = Rb;
        session.rb = rb;
        session.Kb = result.getKb();
        session.V = result.getV();
        session.Za = result.getZa();
        session.Zb = result.getZb();
        session.confirmed = false;
        SessionStore.put(sessionId, session);

        // 构建响应
        String pBHex = "04" +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(pB.getXCoord().toBigInteger())) +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(pB.getYCoord().toBigInteger()));
        String RbHex = "04" +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(Rb.getXCoord().toBigInteger())) +
            ConvertUtil.byteToHex(ConvertUtil.bigIntegerTo32Bytes(Rb.getYCoord().toBigInteger()));

        return String.format(
            "{\"sessionId\":\"%s\",\"IDb\":\"%s\",\"pB\":\"%s\",\"Rb\":\"%s\",\"Sb\":\"%s\"}",
            sessionId, serverId, pBHex, RbHex, result.getSb()
        );
    }

    /**
     * 处理密钥交换确认请求
     */
    private String handleConfirm(String body) throws Exception {
        String sessionId = extractJsonValue(body, "sessionId");
        String Sa = extractJsonValue(body, "Sa");

        System.out.println("\n=== KeySwap Confirm ===");
        System.out.println("sessionId: " + sessionId);
        System.out.println("Sa: " + Sa);

        SessionStore.Session session = SessionStore.get(sessionId);
        if (session == null) {
            throw new Exception("Session not found");
        }

        // 验证Sa
        boolean valid = SM2.checkSa(session.V, session.Za, session.Zb, session.Ra, session.Rb, ConvertUtil.hexToByte(Sa));

        System.out.println("checkSa result: " + valid);

        if (!valid) {
            throw new Exception("Sa verification failed");
        }

        session.confirmed = true;
        return "{\"success\":true}";
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
            // 字符串值
            start++;
            int end = json.indexOf('"', start);
            return json.substring(start, end);
        } else {
            // 数字值
            int end = start;
            while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '.')) {
                end++;
            }
            return json.substring(start, end);
        }
    }
}
