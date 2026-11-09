/**
 * SM9 identity-based cryptography (GB/T 38635): key generation, signatures, key
 * encapsulation, encryption and key exchange. testvectors/SM9-SPEC.md is the
 * specification shared by every language of this repository.
 *
 * Conventions, as in the SM2 API of this package: keys and points travel as hex
 * strings; keys and public points are case-insensitive with an exact length, while
 * signatures, ciphertexts and confirmation values must be lowercase (one string
 * form per value). Output hex is lowercase. Identities and messages are strings
 * (UTF-8) or byte arrays. Failures throw an Error whose message holds no secret;
 * sm9Verify and sm9ExchangeCheck return false instead, and the key exchange steps
 * return {success: false, message}.
 *
 * Security notes (JavaScript limits, as for SM2): field arithmetic uses fixed-width
 * Montgomery limbs in doubles with no data-dependent branches or indices, and
 * secret scalars drive G1, G2 and GT exponentiation through fixed 4-bit windows
 * with full masked table scans. JavaScript cannot promise constant time: the JIT,
 * the GC and the CPU are outside our control, so treat this as hardening. H1/H2
 * use native BigInt on public values only. SM4 in the SM4 encryption mode is this
 * branch's table-based SM4 (see sm4/sm4.js). Secret buffers are wiped on a
 * best-effort basis; strings holding keys cannot be wiped.
 */
import {
  SM9_HID_ENCRYPT,
  SM9_HID_EXCHANGE,
  SM9_HID_SIGN,
  SM9_MODE_SM4,
  SM9_MODE_STREAM,
  decryptBytes,
  encapsulateOnce,
  encryptOnce,
  encryptionPoint,
  equalConfirmation,
  exchangeConfirm,
  exchangeInit,
  exchangeRespond,
  failure,
  generateMaster,
  idBytes,
  masterKey,
  masterPublic,
  messageBytes,
  parseG1,
  parseScalar,
  requireHid,
  requireKeyLength,
  requireMode,
  signOnce,
  userKey,
  verifySignature,
  wipeScratch,
  withRandomScalar,
  decapsulate,
} from './core.js'
import * as util from '../common/utils.js'

export {
  SM9_HID_SIGN,
  SM9_HID_EXCHANGE,
  SM9_HID_ENCRYPT,
  SM9_MODE_STREAM,
  SM9_MODE_SM4,
}

// ---- internal variants with an explicit r, for known-answer tests only ----

/** Not part of the public API. Throws when l = 0 for this r. */
export function sm9SignWithRandom(message, userKeyHex, masterHex, rHex) {
  const r = parseScalar(rHex, 'random r')
  const ds = parseG1(userKeyHex, 'user private key')
  try {
    const sig = signOnce(
      messageBytes(message),
      ds,
      masterKey(masterHex, true),
      r,
    )
    if (sig === null) throw new Error('SM9 signing failed for this r')
    return sig
  } finally {
    r.fill(0)
    wipeScratch()
  }
}

/** Not part of the public API. Throws when K1 is all zero for this r. */
export function sm9EncryptWithRandom(
  plaintext,
  id,
  masterHex,
  hid,
  mode,
  rHex,
) {
  const data = messageBytes(plaintext)
  if (data.length === 0) throw new Error('SM9 cannot encrypt an empty message')
  requireMode(mode)
  const idb = idBytes(id)
  const master = masterKey(masterHex, false)
  const Q = encryptionPoint(idb, requireHid(hid), master.point)
  const r = parseScalar(rHex, 'random r')
  try {
    const out = encryptOnce(data, idb, master, Q, r, mode)
    if (out === null) throw new Error('SM9 encryption failed for this r')
    return out
  } finally {
    r.fill(0)
    data.fill(0)
    wipeScratch()
  }
}

/** Not part of the public API. */
export function sm9EncapsulateWithRandom(id, masterHex, keyLength, hid, rHex) {
  requireKeyLength(keyLength)
  const idb = idBytes(id)
  const master = masterKey(masterHex, false)
  const Q = encryptionPoint(idb, requireHid(hid), master.point)
  const r = parseScalar(rHex, 'random r')
  try {
    const out = encapsulateOnce(idb, master, Q, keyLength, r)
    if (out === null) throw new Error('SM9 encapsulation failed for this r')
    return out
  } finally {
    r.fill(0)
    wipeScratch()
  }
}

/** Not part of the public API. */
export function sm9ExchangeInitWithRandom(peerId, masterHex, hid, rHex) {
  const r = parseScalar(rHex, 'random r')
  try {
    return exchangeInit(peerId, masterHex, hid, r)
  } finally {
    r.fill(0)
  }
}

/**
 * SM9 标识密码算法（GB/T 38635）
 *
 * 提供：主密钥与用户密钥生成、签名、验签、密钥封装、加密、解密、密钥交换。
 * 主私钥和临时随机数是 64 位十六进制、取值在 [1, N-1] 的字符串；签名主公钥是
 * G2 点（258 位十六进制），加密主公钥是 G1 点（130 位十六进制）。
 */
class SM9 {
  // ---- 主密钥 / 用户密钥 ----

  /** @returns {{privateKey: string, publicKey: string}} ks 与 Ppub-s（G2） */
  sm9GenSignMasterKey() {
    return generateMaster(true)
  }

  /** @returns {string} Ppub-s = [ks]P2 */
  sm9SignMasterPublicKey(masterPrivateKey) {
    const ks = parseScalar(masterPrivateKey, 'master private key')
    try {
      return masterPublic(ks, true)
    } finally {
      ks.fill(0)
    }
  }

  /** @returns {string} 签名用户私钥 ds（G1，130 位十六进制） */
  sm9GenSignUserKey(masterPrivateKey, userId, hid = SM9_HID_SIGN) {
    return userKey(masterPrivateKey, userId, hid, true)
  }

  /** @returns {{privateKey: string, publicKey: string}} ke 与 Ppub-e（G1） */
  sm9GenEncMasterKey() {
    return generateMaster(false)
  }

  /** @returns {string} Ppub-e = [ke]P1 */
  sm9EncMasterPublicKey(masterPrivateKey) {
    const ke = parseScalar(masterPrivateKey, 'master private key')
    try {
      return masterPublic(ke, false)
    } finally {
      ke.fill(0)
    }
  }

  /**
   * 加密（也用于密钥封装和密钥交换）用户私钥 de（G2，258 位十六进制）。
   * 密钥交换的用户私钥用 hid = SM9_HID_EXCHANGE 生成
   */
  sm9GenEncUserKey(masterPrivateKey, userId, hid = SM9_HID_ENCRYPT) {
    return userKey(masterPrivateKey, userId, hid, false)
  }

  // ---- 签名 / 验签 ----

  /**
   * @param {string|Uint8Array|number[]} message
   * @param {string} userPrivateKey - ds
   * @param {string} masterPublicKey - Ppub-s
   * @returns {string} 签名 h || S，194 位小写十六进制
   */
  sm9Sign(message, userPrivateKey, masterPublicKey) {
    const msg = messageBytes(message)
    const ds = parseG1(userPrivateKey, 'user private key')
    const master = masterKey(masterPublicKey, true)
    try {
      return withRandomScalar(
        (r) => signOnce(msg, ds, master, r),
        'SM9 signing failed',
      )
    } finally {
      ds.x.fill(0)
      ds.y.fill(0)
      wipeScratch()
    }
  }

  /** @returns {boolean} 任何不合法的输入都返回 false，不会抛出 */
  sm9Verify(message, signature, userId, masterPublicKey, hid = SM9_HID_SIGN) {
    try {
      return verifySignature(message, signature, userId, masterPublicKey, hid)
    } catch {
      return false
    }
  }

  // ---- 加密 / 解密 ----

  /**
   * @param {string|Uint8Array|number[]} plaintext - 不能为空
   * @param {string} mode - SM9_MODE_STREAM（默认）或 SM9_MODE_SM4（SM4-ECB，PKCS#7）
   * @returns {string} 密文 C1 || C3 || C2，小写十六进制
   */
  sm9Encrypt(
    plaintext,
    userId,
    masterPublicKey,
    hid = SM9_HID_ENCRYPT,
    mode = SM9_MODE_STREAM,
  ) {
    const data = messageBytes(plaintext)
    if (data.length === 0)
      throw new Error('SM9 cannot encrypt an empty message')
    requireMode(mode)
    const idb = idBytes(userId)
    const master = masterKey(masterPublicKey, false)
    const Q = encryptionPoint(idb, requireHid(hid), master.point)
    try {
      return withRandomScalar(
        (r) => encryptOnce(data, idb, master, Q, r, mode),
        'SM9 encryption failed',
      )
    } finally {
      data.fill(0)
      wipeScratch()
    }
  }

  /**
   * 解密，返回字节。格式、C1、C3、填充错误都抛出同一个错误；C3 在解密前比较
   * @param {string} mode - 必须与加密时相同
   * @returns {Uint8Array}
   */
  sm9Decrypt(ciphertext, userId, userPrivateKey, mode = SM9_MODE_STREAM) {
    return decryptBytes(ciphertext, userId, userPrivateKey, mode)
  }

  /** 解密并按 UTF-8 解码。非法序列替换为 U+FFFD：二进制明文请用 sm9Decrypt */
  sm9DecryptString(ciphertext, userId, userPrivateKey, mode = SM9_MODE_STREAM) {
    const data = decryptBytes(ciphertext, userId, userPrivateKey, mode)
    const text = util.bytesToString(data)
    data.fill(0)
    return text
  }

  // ---- 密钥封装 ----

  /**
   * @param {number} keyLength - 1 到 1048576 字节
   * @returns {{key: string, ciphertext: string}} key 是秘密，ciphertext 是 G1 点
   */
  sm9Encapsulate(userId, masterPublicKey, keyLength, hid = SM9_HID_ENCRYPT) {
    requireKeyLength(keyLength)
    const idb = idBytes(userId)
    const master = masterKey(masterPublicKey, false)
    const Q = encryptionPoint(idb, requireHid(hid), master.point)
    try {
      return withRandomScalar(
        (r) => encapsulateOnce(idb, master, Q, keyLength, r),
        'SM9 encapsulation failed',
      )
    } finally {
      wipeScratch()
    }
  }

  /** @returns {string} 封装的密钥，十六进制 */
  sm9Decapsulate(ciphertext, userId, userPrivateKey, keyLength) {
    return decapsulate(ciphertext, userId, userPrivateKey, keyLength)
  }

  // ---- 密钥交换 ----

  /**
   * 任一方生成临时密钥：R = [r]Q_peer
   * @param {string} peerId - 对方的标识
   * @returns {{r: string, R: string}} r 是秘密
   */
  sm9ExchangeInit(peerId, masterPublicKey, hid = SM9_HID_EXCHANGE) {
    return withRandomScalar(
      (r) => exchangeInit(peerId, masterPublicKey, hid, r),
      'SM9 key exchange failed',
    )
  }

  /**
   * 响应方 B：计算共享密钥、发给 A 的 S_B，以及期望 A 发回的 S_2
   * @returns {{success: boolean, message: string, sharedKey: string|null,
   *   sB: string|null, s2: string|null}} sharedKey 和 s2 是秘密
   */
  sm9ExchangeRespond(
    keyLength,
    idA,
    idB,
    masterPublicKey,
    userPrivateKeyB,
    rB,
    RB,
    RA,
  ) {
    try {
      return exchangeRespond(
        keyLength,
        idA,
        idB,
        masterPublicKey,
        userPrivateKeyB,
        rB,
        RB,
        RA,
      )
    } catch (e) {
      return failure(e, { sB: null, s2: null })
    }
  }

  /**
   * 发起方 A：验证 S_B（常数时间），然后给出共享密钥和 S_A
   * @returns {{success: boolean, message: string, sharedKey: string|null,
   *   sA: string|null}}
   */
  sm9ExchangeConfirm(
    keyLength,
    idA,
    idB,
    masterPublicKey,
    userPrivateKeyA,
    rA,
    RA,
    RB,
    sB,
  ) {
    try {
      return exchangeConfirm(
        keyLength,
        idA,
        idB,
        masterPublicKey,
        userPrivateKeyA,
        rA,
        RA,
        RB,
        sB,
      )
    } catch (e) {
      return failure(e, { sA: null })
    }
  }

  /**
   * 响应方 B 最后检查 S_A == S_2，常数时间
   * @returns {boolean} 任何不合法的输入都返回 false，不会抛出
   */
  sm9ExchangeCheck(s2, sA) {
    try {
      return equalConfirmation(s2, sA)
    } catch {
      return false
    }
  }
}

export const getSM9 = () => new SM9()
