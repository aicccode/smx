package site.aicc.sm9;

/**
 * One side's result of the SM9 key exchange. On failure only {@link #isSuccess} and {@link
 * #getMessage} are set. Values are lower-case hex.
 */
public final class SM9ExchangeResult {
  private final boolean success;
  private final String message;
  private final String sharedKey;
  private final String sb;
  private final String s2;
  private final String sa;

  private SM9ExchangeResult(
      boolean success, String message, String sharedKey, String sb, String s2, String sa) {
    this.success = success;
    this.message = message;
    this.sharedKey = sharedKey;
    this.sb = sb;
    this.s2 = s2;
    this.sa = sa;
  }

  static SM9ExchangeResult failed(String message) {
    return new SM9ExchangeResult(false, message, null, null, null, null);
  }

  static SM9ExchangeResult responder(String sharedKey, String sb, String s2) {
    return new SM9ExchangeResult(true, null, sharedKey, sb, s2, null);
  }

  static SM9ExchangeResult initiator(String sharedKey, String sa) {
    return new SM9ExchangeResult(true, null, sharedKey, null, null, sa);
  }

  public boolean isSuccess() {
    return success;
  }

  /** Why the exchange failed, or null. */
  public String getMessage() {
    return message;
  }

  /** The secret shared key SK. */
  public String getSharedKey() {
    return sharedKey;
  }

  /** B's confirmation S_B, sent to A (responder only). */
  public String getSb() {
    return sb;
  }

  /** The value B expects from A, S_2, kept by B for {@link SM9#exchangeCheck} (responder only). */
  public String getS2() {
    return s2;
  }

  /** A's confirmation S_A, sent to B (initiator only). */
  public String getSa() {
    return sa;
  }
}
