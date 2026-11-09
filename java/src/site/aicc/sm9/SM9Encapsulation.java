package site.aicc.sm9;

/** The result of SM9 key encapsulation: the shared key and the ciphertext C, as lower-case hex. */
public final class SM9Encapsulation {
  private final String key;
  private final String ciphertext;

  SM9Encapsulation(String key, String ciphertext) {
    this.key = key;
    this.ciphertext = ciphertext;
  }

  /** The secret key K, 2 * keyLen hex digits. */
  public String getKey() {
    return key;
  }

  /** The encapsulation C, a G1 point (130 hex digits), sent to the recipient. */
  public String getCiphertext() {
    return ciphertext;
  }
}
