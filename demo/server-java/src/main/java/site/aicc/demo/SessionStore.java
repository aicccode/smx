package site.aicc.demo;

import java.math.BigInteger;
import java.util.concurrent.ConcurrentHashMap;

import site.aicc.sm2.ec.AbstractECPoint;

/**
 * 会话状态存储
 */
public class SessionStore {
    private static final ConcurrentHashMap<String, Session> sessions = new ConcurrentHashMap<>();

    public static class Session {
        public String sessionId;
        public String IDa;
        public String IDb;
        public AbstractECPoint pA;
        public AbstractECPoint Ra;
        public AbstractECPoint pB;
        public BigInteger dB;
        public AbstractECPoint Rb;
        public BigInteger rb;
        public String Kb; // 协商密钥
        public AbstractECPoint V;
        public byte[] Za;
        public byte[] Zb;
        public boolean confirmed;
    }

    public static void put(String sessionId, Session session) {
        sessions.put(sessionId, session);
    }

    public static Session get(String sessionId) {
        return sessions.get(sessionId);
    }

    public static void remove(String sessionId) {
        sessions.remove(sessionId);
    }
}
