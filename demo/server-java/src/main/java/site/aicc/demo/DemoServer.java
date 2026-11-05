package site.aicc.demo;

import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.concurrent.Executors;

/**
 * SM2密钥交换Demo服务端
 *
 * <p><b>Demo only.</b> It speaks plain HTTP and authenticates no client; both public keys are taken
 * from the request, so a network attacker can sit in the middle. Its CBC traffic has no integrity
 * and the protocol fixes the IV to zero, as its clients expect. A real service needs TLS, pinned
 * identity keys, a fresh IV per message and an authenticated mode.
 */
public class DemoServer {

  private static final int DEFAULT_PORT = 8080;
  private static final int WORKER_THREADS = 8;
  private static final String MAX_REQUEST_SECONDS = "30";

  public static void main(String[] args) throws IOException {
    int port = port();
    // A client that stalls mid-request is disconnected rather than holding a worker for good.
    System.setProperty("sun.net.httpserver.maxReqTime", MAX_REQUEST_SECONDS);
    System.setProperty("sun.net.httpserver.maxRspTime", MAX_REQUEST_SECONDS);
    HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

    // 密钥交换API
    KeySwapHandler keySwapHandler = new KeySwapHandler();
    server.createContext("/api/keyswap/init", keySwapHandler);
    server.createContext("/api/keyswap/confirm", keySwapHandler);

    // 加密通信API
    CryptoHandler cryptoHandler = new CryptoHandler();
    server.createContext("/api/crypto/test", cryptoHandler);

    server.setExecutor(Executors.newFixedThreadPool(WORKER_THREADS));
    server.start();

    System.out.println("SM2 Demo Server started on port " + port);
    System.out.println("API endpoints:");
    System.out.println("  POST /api/keyswap/init    - Initialize key exchange");
    System.out.println("  POST /api/keyswap/confirm - Confirm key exchange");
    System.out.println("  POST /api/crypto/test     - Test encryption/decryption");
  }

  /** The port from the SM2_DEMO_PORT environment variable, or the default the clients use. */
  private static int port() {
    String value = System.getenv("SM2_DEMO_PORT");
    if (value == null || value.isEmpty()) {
      return DEFAULT_PORT;
    }
    try {
      int port = Integer.parseInt(value);
      if (port >= 1 && port <= 65535) {
        return port;
      }
    } catch (NumberFormatException e) {
      // Reported below.
    }
    throw new IllegalArgumentException("SM2_DEMO_PORT must be a port number");
  }
}
