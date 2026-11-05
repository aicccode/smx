package site.aicc.sm2.util;

import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * The library's single source of randomness: the operating system's CSPRNG through {@link
 * SecureRandom}. A failure surfaces as {@link IllegalStateException}; there is no fallback.
 */
public final class SystemRandom {
  private static final String[] OS_ALGORITHMS = {"NativePRNGNonBlocking", "Windows-PRNG"};

  private SystemRandom() {}

  private static final class Holder {
    static final SecureRandom SHARED = create();

    private static SecureRandom create() {
      for (String algorithm : OS_ALGORITHMS) {
        try {
          return SecureRandom.getInstance(algorithm);
        } catch (GeneralSecurityException e) {
          // Not this platform: try the next OS source.
          continue;
        }
      }
      // The platform default, which the JDK seeds from the operating system.
      return new SecureRandom();
    }
  }

  /** Returns the shared, thread-safe generator. */
  public static SecureRandom get() {
    return Holder.SHARED;
  }

  /** Fills out with random bytes from source, turning any failure into a clean error. */
  public static void fill(SecureRandom source, byte[] out) {
    if (source == null || out == null) {
      throw new IllegalArgumentException("Random source and buffer are required");
    }
    try {
      source.nextBytes(out);
    } catch (RuntimeException e) {
      throw new IllegalStateException("Secure random source failed");
    }
  }
}
