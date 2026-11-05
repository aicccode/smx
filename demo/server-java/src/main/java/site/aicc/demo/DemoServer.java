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

  /**
   * The JDK's HttpServer reads each request with a blocking call on a worker thread and offers no
   * per-read timeout, only a whole-request deadline checked by a timer. So a stalled
   * unauthenticated socket holds a worker until that deadline. What is done: many workers
   * (bounded), which cost little while blocked, and a short deadline, which together give about
   * WORKER_THREADS / MAX_REQUEST_SECONDS stalled sockets per second before others wait. That is
   * what remains: anyone opening sockets faster than that starves legitimate requests for as long
   * as they keep it up. No per-address limit is possible here, since a connection reaches
   * application code only after its request has been read. A real service belongs behind a reverse
   * proxy that buffers requests.
   */
  private static final int WORKER_THREADS = 64;

  private static final String MAX_REQUEST_SECONDS = "3";
  private static final String MAX_RESPONSE_SECONDS = "5";
  private static final String IDLE_SECONDS = "5";
  private static final String MAX_IDLE_CONNECTIONS = "16";
  private static final String MAX_DRAIN_BYTES = "131072";

  public static void main(String[] args) throws IOException {
    int port = port();
    configureLimit("sun.net.httpserver.maxReqTime", MAX_REQUEST_SECONDS);
    configureLimit("sun.net.httpserver.maxRspTime", MAX_RESPONSE_SECONDS);
    configureLimit("sun.net.httpserver.idleInterval", IDLE_SECONDS);
    configureLimit("sun.net.httpserver.maxIdleConnections", MAX_IDLE_CONNECTIONS);
    configureLimit("sun.net.httpserver.drainAmount", MAX_DRAIN_BYTES);
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

  /** Sets a limit of the JDK's server, which reads these once, unless the operator already did. */
  private static void configureLimit(String property, String value) {
    if (System.getProperty(property) == null) {
      System.setProperty(property, value);
    }
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
