package site.aicc.demo;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.math.BigInteger;
import java.util.UUID;
import site.aicc.sm2.SM2;
import site.aicc.sm2.SM2KeySwapParams;
import site.aicc.sm2.ec.AbstractECPoint;
import site.aicc.sm2.keygen.ECKeyPair;
import site.aicc.sm2.keygen.ECPrivateKey;
import site.aicc.sm2.keygen.ECPublicKey;
import site.aicc.sm2.util.ConvertUtil;

/** 密钥交换API处理 */
public class KeySwapHandler implements HttpHandler {

  /** The SM4 key the crypto test uses; any other length could not be used afterwards. */
  private static final String SESSION_KEY_BYTES = "16";

  private static final int PRIVATE_KEY_HEX_LENGTH = 64;

  // 服务端B的固定密钥对（实际使用应该从配置加载）
  private final ECKeyPair serverKeyPair;
  private final String serverId = "server@demo.aicc";

  public KeySwapHandler() {
    this.serverKeyPair = loadOrGenerateKeyPair();
    AbstractECPoint q = ((ECPublicKey) serverKeyPair.getPublic()).getQ();
    // Clients pin this value through SM2_DEMO_SERVER_PUBKEY.
    System.out.println("Server public key: " + ConvertUtil.byteToHex(q.getEncoded()));
  }

  /**
   * Uses the key in SM2_DEMO_SERVER_PRIVATE_KEY (64 hex digits), so that clients can pin a public
   * key across restarts, or else a new key per process. A real service would load it from a secret
   * store.
   */
  private static ECKeyPair loadOrGenerateKeyPair() {
    String hex = System.getenv("SM2_DEMO_SERVER_PRIVATE_KEY");
    if (hex == null || hex.isEmpty()) {
      System.out.println("Server keypair generated");
      return SM2.genSM2KeyPair();
    }
    if (hex.length() != PRIVATE_KEY_HEX_LENGTH) {
      throw new IllegalArgumentException("Invalid private key");
    }
    BigInteger d = new BigInteger(1, ConvertUtil.hexToByte(hex));
    AbstractECPoint q = SM2.getPublicKey(d);
    System.out.println("Server keypair loaded");
    return new ECKeyPair(new ECPublicKey(q), new ECPrivateKey(d));
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
      DemoHttp.sendError(exchange, 405, "Method not allowed");
      return;
    }

    try {
      DemoHttp.Body body = DemoHttp.parseObject(DemoHttp.readBody(exchange));
      String response;

      if (path.endsWith("/init")) {
        response = handleInit(body);
      } else if (path.endsWith("/confirm")) {
        response = handleConfirm(body);
      } else {
        DemoHttp.sendError(exchange, 404, "Not found");
        return;
      }

      DemoHttp.sendResponse(exchange, 200, response);
    } catch (DemoHttp.RequestException e) {
      DemoHttp.sendError(exchange, e.status, e.getMessage());
    } catch (Exception e) {
      DemoHttp.sendInternalError(exchange, e);
    }
  }

  private static AbstractECPoint decodePeerPoint(String hex) throws DemoHttp.RequestException {
    try {
      return SM2.decodePoint(hex);
    } catch (IllegalArgumentException e) {
      throw new DemoHttp.RequestException(400, "Invalid public key");
    }
  }

  /** 处理密钥交换初始化请求 */
  private String handleInit(DemoHttp.Body body) throws Exception {
    String idA = body.string("IDa");
    // The exact JSON number, so spellings such as 016 or non-ASCII digits are refused.
    if (!SESSION_KEY_BYTES.equals(body.number("keyLen"))) {
      throw new DemoHttp.RequestException(400, "Invalid key length");
    }
    int keyLen = Integer.parseInt(SESSION_KEY_BYTES);

    System.out.println("Key exchange init received");

    // 解析A的公钥和随机公钥
    AbstractECPoint pA = decodePeerPoint(body.string("pA"));
    AbstractECPoint rA = decodePeerPoint(body.string("Ra"));

    // 获取B的密钥
    AbstractECPoint pB = ((ECPublicKey) serverKeyPair.getPublic()).getQ();
    BigInteger dB = ((ECPrivateKey) serverKeyPair.getPrivate()).getD();

    // 生成B的随机密钥对
    ECKeyPair rbPair = SM2.genSM2KeyPair();
    AbstractECPoint rB = ((ECPublicKey) rbPair.getPublic()).getQ();
    BigInteger rb = ((ECPrivateKey) rbPair.getPrivate()).getD();

    // 调用getSb
    SM2KeySwapParams result = SM2.getSb(keyLen, pA, rA, pB, dB, rB, rb, idA, serverId);

    if (!result.isSuccess()) {
      throw new DemoHttp.RequestException(400, "Key exchange failed");
    }

    // 创建会话
    String sessionId = UUID.randomUUID().toString();
    SessionStore.Session session =
        new SessionStore.Session(
            result.getKb(),
            result.getV().getEncoded(),
            rA.getEncoded(),
            rB.getEncoded(),
            result.getZa(),
            result.getZb());
    if (!SessionStore.addPending(sessionId, session)) {
      throw new DemoHttp.RequestException(503, "Server busy");
    }

    // 构建响应
    return String.format(
        "{\"sessionId\":\"%s\",\"IDb\":\"%s\",\"pB\":\"%s\",\"Rb\":\"%s\",\"Sb\":\"%s\"}",
        sessionId,
        serverId,
        ConvertUtil.byteToHex(pB.getEncoded()),
        ConvertUtil.byteToHex(rB.getEncoded()),
        result.getSb());
  }

  /** 处理密钥交换确认请求 */
  private String handleConfirm(DemoHttp.Body body) throws Exception {
    String sessionId = body.string("sessionId");
    String sA = body.string("Sa");

    SessionStore.Session session = SessionStore.get(sessionId);
    if (session == null) {
      throw new DemoHttp.RequestException(500, "Session not found");
    }

    // 验证Sa
    byte[] saBytes;
    try {
      saBytes = ConvertUtil.hexToByte(sA);
    } catch (IllegalArgumentException e) {
      throw new DemoHttp.RequestException(400, "Sa verification failed");
    }
    boolean valid =
        SM2.checkSa(
            SM2.decodePoint(ConvertUtil.byteToHex(session.v)),
            session.zA,
            session.zB,
            SM2.decodePoint(ConvertUtil.byteToHex(session.rA)),
            SM2.decodePoint(ConvertUtil.byteToHex(session.rB)),
            saBytes);

    System.out.println("Key exchange confirm received, valid: " + valid);

    if (!valid) {
      throw new DemoHttp.RequestException(500, "Sa verification failed");
    }

    if (!SessionStore.confirm(sessionId)) {
      throw new DemoHttp.RequestException(503, "Server busy");
    }
    return "{\"success\":true}";
  }
}
