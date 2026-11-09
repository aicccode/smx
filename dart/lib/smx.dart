/// SM2, SM3, SM4 and SM9 (GB/T 32918, 32905, 32907, 38635) in pure Dart.
///
/// Runs on the Dart VM (JIT and AOT); compiling to JavaScript is not
/// supported, as the arithmetic relies on 64-bit integers.
///
/// Timing: Dart integers give no constant-time guarantee. Secret scalars go
/// through fixed schedules with masked table lookups, which is as far as Dart
/// source can go. SM4 on this branch evaluates its S-box as a Boolean circuit,
/// with no secret-indexed table lookups. SM4-CBC has no integrity protection.
library;

export 'src/errors.dart' show SmxException;
export 'src/hex.dart' show bytesToHex, hexToBytes, hexToBigInt;
export 'src/key_cache.dart'
    show clearKeyCaches, keyCacheEnabled, setKeyCacheEnabled;
export 'src/sm2/exchange.dart'
    show SM2KeySwapParams, sm2CheckSa, sm2GetSa, sm2GetSb;
export 'src/sm2/point.dart' show ECPoint;
export 'src/sm2/sm2.dart'
    show
        SM2KeyPair,
        sm2A,
        sm2B,
        sm2Decrypt,
        sm2DecryptBytes,
        sm2DecodePoint,
        sm2Encrypt,
        sm2EncryptBytes,
        sm2GenKeyPair,
        sm2GetPublicKey,
        sm2Gx,
        sm2Gy,
        sm2N,
        sm2P,
        sm2Sign,
        sm2Verify,
        userSm3Z;
export 'src/sm3.dart' show SM3;
export 'src/sm4.dart' show SM4;
export 'src/sm9/common.dart' show sm9HidEncrypt, sm9HidExchange, sm9HidSign;
export 'src/sm9/encrypt.dart'
    show
        SM9EncryptMode,
        SM9Encapsulation,
        sm9Decapsulate,
        sm9Decrypt,
        sm9DecryptString,
        sm9Encapsulate,
        sm9Encrypt;
export 'src/sm9/exchange.dart'
    show
        SM9ExchangeInit,
        SM9ExchangeResult,
        sm9ExchangeCheck,
        sm9ExchangeConfirm,
        sm9ExchangeInit,
        sm9ExchangeRespond;
export 'src/sm9/sign.dart'
    show
        SM9MasterKeyPair,
        sm9EncMasterPublicKey,
        sm9GenEncMasterKey,
        sm9GenEncUserKey,
        sm9GenSignMasterKey,
        sm9GenSignUserKey,
        sm9Sign,
        sm9SignMasterPublicKey,
        sm9Verify;
