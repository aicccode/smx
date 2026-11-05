package site.aicc.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import site.aicc.sm4.SM4;

/** 加密解密API处理 - 双向加解密验证 */
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
      DemoHttp.sendError(exchange, 405, "Method not allowed");
      return;
    }

    try {
      String response = handleTest(DemoHttp.parseObject(DemoHttp.readBody(exchange)));
      DemoHttp.sendResponse(exchange, 200, response);
    } catch (DemoHttp.RequestException e) {
      DemoHttp.sendError(exchange, e.status, e.getMessage());
    } catch (Exception e) {
      DemoHttp.sendInternalError(exchange, e);
    }
  }

  /**
   * 处理加密通信测试请求
   *
   * <p>请求格式: { "sessionId": "uuid", "clientCiphertext": "hex", // 客户端加密的数据 "clientPlaintext":
   * "string" // 客户端原文（用于服务端验证解密结果） }
   *
   * <p>响应格式: { "clientDecrypted": "string", // 服务端解密客户端密文的结果 "clientDecryptMatch": true, // 是否与原文匹配
   * "serverPlaintext": "string", // 服务端发送的原文 "serverCiphertext": "hex" // 服务端加密的数据 }
   *
   * <p>Echoing the decrypted text, and answering differently when decryption fails, are what this
   * self-test exists to do, and in real traffic they would be a padding oracle.
   */
  private String handleTest(DemoHttp.Body body) throws Exception {
    String sessionId = body.string("sessionId");
    String clientCiphertext = body.string("clientCiphertext");
    String clientPlaintext = body.string("clientPlaintext");

    System.out.println("Crypto test request received");

    SessionStore.Session session = SessionStore.get(sessionId);
    if (session == null) {
      throw new DemoHttp.RequestException(500, "Session not found");
    }

    if (!session.isConfirmed()) {
      throw new DemoHttp.RequestException(500, "Key exchange not confirmed");
    }

    // 使用协商密钥 (SM4-CBC模式，IV使用全零)
    // The all-zero IV is part of this demo's protocol; never reuse an IV like this in real traffic.
    String iv = "00000000000000000000000000000000";
    SM4 sm4 = new SM4();
    sm4.setKey(session.kB, iv, true);

    // 1. 服务端解密客户端的密文
    String clientDecrypted;
    try {
      clientDecrypted = sm4.decrypt(clientCiphertext);
    } catch (IllegalArgumentException e) {
      throw new DemoHttp.RequestException(400, "Decryption failed");
    }
    boolean clientDecryptMatch = clientPlaintext.equals(clientDecrypted);

    // 2. 服务端加密一段响应消息
    String serverPlaintext = "Response from Java Server: " + System.currentTimeMillis();
    String serverCiphertext = sm4.encrypt(serverPlaintext);

    System.out.println("Crypto test completed, match: " + clientDecryptMatch);

    // 返回结果（对特殊字符进行转义）
    return String.format(
        "{\"clientDecrypted\":\"%s\",\"clientDecryptMatch\":%s,\"serverPlaintext\":\"%s\",\"serverCiphertext\":\"%s\"}",
        DemoHttp.escapeJson(clientDecrypted),
        clientDecryptMatch,
        DemoHttp.escapeJson(serverPlaintext),
        serverCiphertext);
  }
}
