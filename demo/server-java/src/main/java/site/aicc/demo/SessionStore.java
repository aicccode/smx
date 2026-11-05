package site.aicc.demo;

import java.util.LinkedHashMap;
import java.util.Map;
import site.aicc.sm2.ec.AbstractECPoint;

/**
 * Session state. Bounded and expiring, since any client can create sessions. It holds only what
 * later requests need: never the server's private key or the ephemeral private key.
 */
public class SessionStore {
  private static final int MAX_SESSIONS = 10_000;
  private static final long SESSION_LIFETIME_MILLIS = 10 * 60 * 1000L;

  private static final Map<String, Session> SESSIONS =
      new LinkedHashMap<String, Session>(16, 0.75f, false) {
        private static final long serialVersionUID = 1L;

        @Override
        protected boolean removeEldestEntry(Map.Entry<String, Session> eldest) {
          return size() > MAX_SESSIONS;
        }
      };

  public static class Session {
    final long createdMillis = System.currentTimeMillis();
    public String sessionId;
    public String idA;
    public String idB;
    public AbstractECPoint pA;
    public AbstractECPoint rA;
    public AbstractECPoint pB;
    public AbstractECPoint rB;
    public String kB; // 协商密钥
    public AbstractECPoint v;
    public byte[] zA;
    public byte[] zB;
    public volatile boolean confirmed;
  }

  public static synchronized void put(String sessionId, Session session) {
    SESSIONS.put(sessionId, session);
  }

  /** Returns the session, or null when it is unknown or has expired. */
  public static synchronized Session get(String sessionId) {
    Session session = SESSIONS.get(sessionId);
    if (session != null
        && System.currentTimeMillis() - session.createdMillis > SESSION_LIFETIME_MILLIS) {
      SESSIONS.remove(sessionId);
      return null;
    }
    return session;
  }

  public static synchronized void remove(String sessionId) {
    SESSIONS.remove(sessionId);
  }
}
