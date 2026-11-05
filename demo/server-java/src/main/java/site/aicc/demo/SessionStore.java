package site.aicc.demo;

import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Session state, bounded in bytes because any client can create sessions. Each entry holds only the
 * fixed-size values that later requests read, and not the private keys or the client's ID, so the
 * limits below cap the store at a few megabytes.
 *
 * <p>Nothing is ever displaced to make room: a flood cannot evict someone else's session, and when
 * a tier is full, new requests are refused until entries expire. Unconfirmed sessions, which cost
 * an attacker almost nothing, get a short lifetime and their own tier, so that they cannot crowd
 * out confirmed ones. The limit that remains: a sustained flood can still refuse new sessions, and
 * a client that completes the exchange can fill the confirmed tier, since nothing authenticates it.
 */
public class SessionStore {
  private static final int MAX_PENDING_SESSIONS = 4096;
  private static final int MAX_CONFIRMED_SESSIONS = 8192;
  private static final long PENDING_LIFETIME_MILLIS = 60 * 1000L;
  private static final long CONFIRMED_LIFETIME_MILLIS = 10 * 60 * 1000L;

  private static final Map<String, Session> PENDING = new LinkedHashMap<>();
  private static final Map<String, Session> CONFIRMED = new LinkedHashMap<>();

  /** A session's fixed-size state. Points are kept encoded, the most compact form available. */
  public static final class Session {
    /** Set when the session enters a tier; insertion order is therefore expiry order. */
    private long expiresAtMillis;

    public final String kB; // 协商密钥
    public final byte[] v;
    public final byte[] rA;
    public final byte[] rB;
    public final byte[] zA;
    public final byte[] zB;
    private boolean confirmed;

    public Session(String kB, byte[] v, byte[] rA, byte[] rB, byte[] zA, byte[] zB) {
      this.kB = kB;
      this.v = v;
      this.rA = rA;
      this.rB = rB;
      this.zA = zA;
      this.zB = zB;
    }

    public synchronized boolean isConfirmed() {
      return confirmed;
    }

    private synchronized void markConfirmed() {
      confirmed = true;
    }
  }

  private SessionStore() {}

  private static void dropExpired(Map<String, Session> tier, long now) {
    Iterator<Session> sessions = tier.values().iterator();
    while (sessions.hasNext() && sessions.next().expiresAtMillis <= now) {
      sessions.remove();
    }
  }

  /** Adds an unconfirmed session; returns false when that tier is full. */
  public static synchronized boolean addPending(String sessionId, Session session) {
    long now = System.currentTimeMillis();
    dropExpired(PENDING, now);
    if (PENDING.size() >= MAX_PENDING_SESSIONS) {
      return false;
    }
    session.expiresAtMillis = now + PENDING_LIFETIME_MILLIS;
    PENDING.put(sessionId, session);
    return true;
  }

  /**
   * Moves a session to the confirmed tier; a session already there stays as it is.
   *
   * @return false when the confirmed tier is full, in which case the session stays unconfirmed
   */
  public static synchronized boolean confirm(String sessionId) {
    long now = System.currentTimeMillis();
    dropExpired(PENDING, now);
    dropExpired(CONFIRMED, now);
    Session session = PENDING.get(sessionId);
    if (session == null) {
      return CONFIRMED.containsKey(sessionId);
    }
    if (CONFIRMED.size() >= MAX_CONFIRMED_SESSIONS) {
      return false;
    }
    PENDING.remove(sessionId);
    session.expiresAtMillis = now + CONFIRMED_LIFETIME_MILLIS;
    session.markConfirmed();
    CONFIRMED.put(sessionId, session);
    return true;
  }

  /** Returns the session, or null when it is unknown or has expired. */
  public static synchronized Session get(String sessionId) {
    long now = System.currentTimeMillis();
    dropExpired(PENDING, now);
    dropExpired(CONFIRMED, now);
    Session session = CONFIRMED.get(sessionId);
    return session != null ? session : PENDING.get(sessionId);
  }
}
