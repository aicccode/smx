/**
 * SM2/SM3/SM4 benchmark for one side of the kit: node bench.mjs <base|new>
 *
 * Both sides run the same operations through the public API, with the same sizes.
 * Per operation: at least 2 s of warm-up, then 7 samples of at least 200 ms each.
 * Prints "<name>\t<median_us>\t<min_us>" per operation. Correctness checks run once
 * before timing; a failure is reported on stderr and the run exits with status 1.
 */
import { performance } from "node:perf_hooks";
import { randomBytes } from "node:crypto";

const side = process.argv[2];
if (side !== "base" && side !== "new") {
  console.error("usage: node bench.mjs <base|new>");
  process.exit(2);
}
const root = new URL(`./${side}/javascript/`, import.meta.url);
const load = (p) => import(new URL(p, root).href);
const { SM3 } = await load("sm3/sm3.js");
const { SM4 } = await load("sm4/sm4.js");
const { getSM2 } = await load("sm2/sm2.js");
const util = await load("sm2/utils.js");
const baseExchange =
  side === "base" ? await import("./base-exchange.mjs") : null;

const WARMUP_MS = 2000;
const SAMPLES = 7;
const SAMPLE_MS = 200;
const USER_ID = "1234567812345678";
const KEY_HEX = randomBytes(16).toString("hex");
const IV_HEX = randomBytes(16).toString("hex");

let sink = 0;
const consume = (v) => {
  sink = (sink + (typeof v === "string" ? v.length : v ? 1 : 0)) | 0;
};

function fail(message) {
  console.error(`[${side}] check failed: ${message}`);
  process.exit(1);
}

/** Runs fn in batches until at least ms have passed; returns microseconds per call. */
function timeFor(fn, ms) {
  let batch = 1;
  let calls = 0;
  const start = performance.now();
  let now = start;
  while (now - start < ms) {
    for (let i = 0; i < batch; i++) consume(fn());
    calls += batch;
    now = performance.now();
    if (now - start < ms / 8) batch *= 2;
  }
  return ((now - start) * 1000) / calls;
}

function bench(name, fn) {
  timeFor(fn, WARMUP_MS);
  const samples = [];
  for (let i = 0; i < SAMPLES; i++) samples.push(timeFor(fn, SAMPLE_MS));
  samples.sort((a, b) => a - b);
  const median = samples[SAMPLES >> 1];
  console.log(`${name}\t${median.toFixed(3)}\t${samples[0].toFixed(3)}`);
}

// ---- inputs ----
const asciiText = (n) => {
  const b = randomBytes(n);
  let s = "";
  for (let i = 0; i < n; i++) s += String.fromCharCode(97 + (b[i] % 26));
  return s;
};
const SM3_INPUTS = { "64B": 64, "1KB": 1024, "1MB": 1 << 20 };
const SM4_SIZES = { "16B": 16, "1KB": 1024, "1MB": 1 << 20 };

// ---- checks, outside timing ----
const sm2 = getSM2();
const keys = util.generateKeyPairHex();
const message32 = asciiText(32);
const bKeys = util.generateKeyPairHex();
const A_ID = "alice@example.com";
const B_ID = "bob@example.com";

{
  if (new SM3().update(new Uint8Array([97, 98, 99])).digest()[0] !== 0x66) {
    fail('SM3("abc")');
  }
  const s = new SM4().setKey(KEY_HEX, IV_HEX, true);
  for (const n of Object.values(SM4_SIZES)) {
    const t = asciiText(n);
    const c = s.encrypt(t);
    if (c.length !== 2 * (n + 16 - (n % 16)))
      fail(`SM4 ciphertext length ${n}`);
    if (s.decrypt(c) !== t) fail(`SM4 round trip ${n}`);
  }
  const sig = sm2.sm2Sign(USER_ID, keys.privateKey, message32);
  if (!sm2.sm2VerifySign(USER_ID, sig, message32, keys.publicKey))
    fail("verify");
  if (sm2.sm2VerifySign(USER_ID, sig, message32 + "x", keys.publicKey)) {
    fail("verify accepted a wrong message");
  }
  const c = sm2.sm2Encrypt(message32, keys.publicKey);
  if (sm2.sm2Decrypt(c, keys.privateKey) !== message32) fail("SM2 round trip");
  // The baseline's checkSa rejects a correct Sa about 6% of the time (its V is
  // not padded), so it gets a few tries; the new side must succeed at once.
  let agreed = false;
  for (let i = 0; i < (side === "base" ? 10 : 1) && !agreed; i++) {
    agreed = exchange().ok;
  }
  if (!agreed) fail("key exchange");
}

/** One complete exchange with fresh ephemeral keys: B computes Sb and Kb, A checks Sb and computes Sa and Ka, B checks Sa. */
function exchange() {
  const ra = util.generateKeyPairHex();
  const rb = util.generateKeyPairHex();
  const B = sm2.getSb(
    16,
    keys.publicKey,
    ra.publicKey,
    A_ID,
    B_ID,
    bKeys.privateKey,
    bKeys.publicKey,
    rb.privateKey,
    rb.publicKey,
  );
  let Sa;
  let Ka;
  if (side === "base") {
    const A = baseExchange.getSa(
      16,
      bKeys.publicKey,
      rb.publicKey,
      keys.publicKey,
      keys.privateKey,
      ra.publicKey,
      ra.privateKey,
      A_ID,
      B_ID,
      B.Sb,
    );
    if (!A.success) return { ok: false };
    Sa = A.Sa;
    Ka = A.Ka;
  } else {
    ({ Sa, Ka } = sm2.getSa(
      16,
      bKeys.publicKey,
      rb.publicKey,
      keys.publicKey,
      ra.publicKey,
      A_ID,
      B_ID,
      keys.privateKey,
      ra.privateKey,
      B.Sb,
    ));
  }
  const confirmed = sm2.checkSa(B.V, B.Za, B.Zb, ra.publicKey, B.Rb, Sa);
  return { ok: confirmed && Ka === B.Kb, Ka };
}

// ---- timing ----
for (const [label, size] of Object.entries(SM3_INPUTS)) {
  const data = randomBytes(size);
  const bytes = new Uint8Array(data.buffer, data.byteOffset, size);
  bench(`sm3/${label}`, () => new SM3().update(bytes).digest()[0]);
}

const sm4 = new SM4().setKey(KEY_HEX, IV_HEX, true);
const schedule = new SM4();
bench("sm4/key_schedule", () => schedule.setKey(KEY_HEX, IV_HEX, true));
const plaintexts = {};
const ciphertexts = {};
for (const [label, size] of Object.entries(SM4_SIZES)) {
  plaintexts[label] = asciiText(size);
  ciphertexts[label] = sm4.encrypt(plaintexts[label]);
}
for (const label of Object.keys(SM4_SIZES)) {
  bench(`sm4/cbc_encrypt/${label}`, () => sm4.encrypt(plaintexts[label]));
}
for (const label of Object.keys(SM4_SIZES)) {
  bench(`sm4/cbc_decrypt/${label}`, () => sm4.decrypt(ciphertexts[label]));
}

bench("sm2/keygen", () => util.generateKeyPairHex().publicKey);
const signature = sm2.sm2Sign(USER_ID, keys.privateKey, message32);
bench("sm2/sign", () => sm2.sm2Sign(USER_ID, keys.privateKey, message32));
bench("sm2/verify", () =>
  sm2.sm2VerifySign(USER_ID, signature, message32, keys.publicKey),
);
const cipher = sm2.sm2Encrypt(message32, keys.publicKey);
bench("sm2/encrypt/32B", () => sm2.sm2Encrypt(message32, keys.publicKey));
bench("sm2/decrypt/32B", () => sm2.sm2Decrypt(cipher, keys.privateKey));
bench("sm2/key_exchange", () => exchange().ok);

if (sink === 0.5) console.log(sink);
