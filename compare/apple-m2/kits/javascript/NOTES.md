# JavaScript kit

- `base/`: `javascript/` at 3397c6d. `new/`: `javascript/` at HEAD (a327a78 when built).
- Runtime: `$NODE` (Node.js 22). No build step and no flags; `build.sh` only checks that
  Node and both trees are present. No dependencies, no network.
- One program, `bench.mjs`, runs either side through the public API with the same
  sizes and inputs. Each run uses fresh random keys, IV and messages.

## API differences that affect the comparison
- **SM4** is string based on both sides: `setKey(hex, hex, true)`, `encrypt(text)` returns
  hex, `decrypt(hex)` returns text. So every encrypt includes UTF-8 encoding and hex
  output, and every decrypt includes hex parsing and UTF-8 decoding. The plaintext is
  ASCII, so 16B, 1KB and 1MB are exact byte counts. `key_schedule` is `setKey` on an
  existing instance.
- **SM2** is hex and string based on both sides. sign and verify use a 32-character ASCII
  message with the default ID; both sides compute Z, and both sign calls also derive the
  public key from the private key, as the API does internally. decrypt returns a string.
- **sm2/key_exchange**: the baseline library has only the B side (`getSb`, `checkSa`). Its
  A side is the baseline demo client's own code, copied verbatim into `base-exchange.mjs`;
  the new side uses its `getSa`. Both runs include two ephemeral key generations, B's
  `getSb`, A's verification of Sb with computation of Sa and Ka, and B's `checkSa`.
- **Baseline behaviour inside the timing**: the baseline `sm2Sign` retries nonces whose r,
  s or point coordinates have a leading zero hex digit, about 22% extra work on average.
  Its `checkSa` wrongly rejects about 6% of correct exchanges because V is not padded.
  The timing counts these calls as they are; the correctness check before timing allows the
  baseline up to 10 tries for the exchange.
- The new side validates all input and uses constant-flow code for secrets; the
  baseline does neither. That is part of what is being compared.

## Running
- `NODE=<node 22> ./build.sh`, then `./run.sh base` and `./run.sh new`. Each run takes
  about one minute (measured on Linux), mostly warm-up. Nothing needs network access.
