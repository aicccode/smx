package site.aicc.demo;

import java.io.IOException;
import java.net.InetSocketAddress;

import com.sun.net.httpserver.HttpServer;

/**
 * SM2密钥交换Demo服务端
 */
public class DemoServer {

    private static final int PORT = 8080;

    public static void main(String[] args) throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);

        // 密钥交换API
        KeySwapHandler keySwapHandler = new KeySwapHandler();
        server.createContext("/api/keyswap/init", keySwapHandler);
        server.createContext("/api/keyswap/confirm", keySwapHandler);

        // 加密通信API
        CryptoHandler cryptoHandler = new CryptoHandler();
        server.createContext("/api/crypto/test", cryptoHandler);

        server.setExecutor(null);
        server.start();

        System.out.println("SM2 Demo Server started on port " + PORT);
        System.out.println("API endpoints:");
        System.out.println("  POST /api/keyswap/init    - Initialize key exchange");
        System.out.println("  POST /api/keyswap/confirm - Confirm key exchange");
        System.out.println("  POST /api/crypto/test     - Test encryption/decryption");
    }
}
