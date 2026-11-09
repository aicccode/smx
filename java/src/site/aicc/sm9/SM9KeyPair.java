package site.aicc.sm9;

/**
 * A private value and its public counterpart, as lower-case hex: a master key pair (scalar and
 * Ppub), or a key exchange ephemeral (r and R). The private part is secret.
 */
public final class SM9KeyPair {
  private final String privateKey;
  private final String publicKey;

  SM9KeyPair(String privateKey, String publicKey) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
  }

  /** The secret scalar, 64 hex digits. */
  public String getPrivateKey() {
    return privateKey;
  }

  /** The public point: G2 (258 hex digits) for signing, G1 (130 hex digits) otherwise. */
  public String getPublicKey() {
    return publicKey;
  }
}
