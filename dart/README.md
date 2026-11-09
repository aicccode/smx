# SMX Dart 实现

纯 Dart 实现的 SM2、SM3、SM4、SM9 国密算法，**零第三方依赖**（只有开发依赖 `test`），要求 Dart SDK 3.x。接口语义、输出格式、输入校验和报错行为与仓库中其他语言（以 Python、JavaScript 为蓝本）一致，可以与它们直接互通。

- 只支持 **Dart VM**（`dart run` 的 JIT 与 `dart compile exe` 的 AOT，包括 Flutter 的原生平台）。**不支持编译成 JavaScript**（Flutter Web / `dart compile js`）：域运算依赖 64 位整数。
- 本分支（`main`）的 SM4 使用查表实现，速度快，但**不抵抗缓存计时攻击**，适用场景见仓库根目录 README 的“版本选择”。

## 安装

在 `pubspec.yaml` 中以路径或 Git 依赖引入：

```yaml
dependencies:
  smx:
    path: ../dart
```

```dart
import 'package:smx/smx.dart';
```

## 用法

### SM3

```dart
final digest = SM3().update(utf8.encode('abc')).finish();
print(digest.hashHex());       // 66c7f0f4...（小写）
print(digest.hashHexUpper());  // 与其他语言一致的大写形式
```

`finish()` 之后对象自动复位，可以继续计算下一条消息。

### SM4（CBC / PKCS#7）

```dart
final sm4 = SM4()..setKey(hexToBytes('0123456789abcdeffedcba9876543210'),
                          hexToBytes('000102030405060708090a0b0c0d0e0f'));
final cipher = sm4.encrypt('hello world');   // 小写十六进制
final plain = sm4.decrypt(cipher);           // 返回字符串
final bytes = sm4.decryptBytes(cipher);      // 返回字节，没有 UTF-8 步骤
final block = sm4.encryptBlock(Uint8List(16)); // 单个分组（ECB）
```

### SM2

```dart
final pair = sm2GenKeyPair();  // privateKey：64 位大写十六进制；publicKey：04||x||y
final c = sm2Encrypt('明文', pair.publicKey);   // C1||C3||C2，小写十六进制
final m = sm2Decrypt(c, pair.privateKey);
final sig = sm2Sign('1234567812345678', '消息', pair.privateKey); // r + "h" + s
final ok = sm2Verify('1234567812345678', sig, '消息', pair.publicKey);
```

另有 `sm2EncryptBytes` / `sm2DecryptBytes` 处理二进制明文，`sm2DecodePoint`、`sm2GetPublicKey`、`ECPoint` 处理点。

密钥交换与 Python 版相同（`sm2GetSb`、`sm2GetSa`、`sm2CheckSa`，结果为 `SM2KeySwapParams`）：

```dart
final b = sm2GetSb(16, pA, rA, pB, dB, rB, rb, 'idA', 'idB');      // B 侧
final a = sm2GetSa(16, pB, rB, pA, dA, rA, ra, 'idA', 'idB',
                   hexToBytes(b.sb));                               // A 侧
final confirmed = sm2CheckSa(b.v!, b.za, b.zb, rA, rB, hexToBytes(a.sa));
```

### SM9（GB/T 38635）

```dart
// 签名
final signMaster = sm9GenSignMasterKey();
final userKey = sm9GenSignUserKey(signMaster.privateKey, 'Alice');
final sig = sm9Sign(utf8.encode('消息'), userKey, signMaster.publicKey);
final ok = sm9Verify(utf8.encode('消息'), sig, 'Alice', signMaster.publicKey);

// 加密（默认序列密码方式，也可选 SM4-ECB 方式）
final encMaster = sm9GenEncMasterKey();
final bobKey = sm9GenEncUserKey(encMaster.privateKey, 'Bob');
final c = sm9Encrypt(utf8.encode('明文'), 'Bob', encMaster.publicKey,
                     mode: SM9EncryptMode.sm4);
final m = sm9Decrypt(c, 'Bob', bobKey, mode: SM9EncryptMode.sm4);

// 密钥封装
final kem = sm9Encapsulate('Bob', encMaster.publicKey, 32);
final key = sm9Decapsulate(kem.ciphertext, 'Bob', bobKey, 32);

// 密钥交换：用户密钥使用 hid = 0x02
final keyA = sm9GenEncUserKey(encMaster.privateKey, 'A', hid: sm9HidExchange);
final keyB = sm9GenEncUserKey(encMaster.privateKey, 'B', hid: sm9HidExchange);
final initA = sm9ExchangeInit('B', encMaster.publicKey);  // A 发送 initA.bigR
final initB = sm9ExchangeInit('A', encMaster.publicKey);  // B 发送 initB.bigR
final rb = sm9ExchangeRespond(16, 'A', 'B', encMaster.publicKey, keyB,
                              initB.r, initB.bigR, initA.bigR); // B 发送 rb.sB
final ra = sm9ExchangeConfirm(16, 'A', 'B', encMaster.publicKey, keyA,
                              initA.r, initA.bigR, initB.bigR, rb.sB); // A 发送 ra.sA
final done = sm9ExchangeCheck(rb.s2, ra.sA);  // ra.sharedKey == rb.sharedKey
```

编码见 `testvectors/SM9-SPEC.md`：G1 点 `04||x||y`，G2 点 `04||x1||x0||y1||y0`，签名 `h||S`，密文 `C1||C3||C2`（C1 带 04 前缀）。

## 安全说明

- **输入校验与其他语言一致：** SM4 密钥和 IV 必须正好 16 字节；签名、密文（以及 SM9 的确认值）只接受小写十六进制，公钥、私钥不区分大小写；不在曲线上的点、超出范围的私钥、错误长度、错误填充一律报错（`SmxException`）或返回 `false`。解密失败统一抛出 `SmxException('decryption failed')`。SM2 和 SM9 都拒绝 KDF 输出全为零的密文。字符串中未配对的代理项（Dart 默认编码会悄悄替换成 U+FFFD）会被拒绝。
- **随机数：** 只使用 `Random.secure()`，拒绝采样得到 [1, n-1] 中的均匀随机数，没有取模偏差；平台不提供安全随机源时直接报错，不会退回到其他来源。
- **侧信道：** 私钥参与的标量乘法（SM2 的密钥生成、签名、解密、密钥交换，SM9 的主密钥和用户密钥生成、签名、加密、密钥封装、密钥交换）和 GT 中的幂运算使用固定窗口和掩码查表，读取整张表，没有依赖秘密数据的分支或内存地址；域运算使用 9 个 29 位分量的 Montgomery 表示，没有依赖数值的分支。**但 Dart VM 本身不提供常数时间保证**，本库只能做到源码层面没有依赖秘密数据的分支和查表。验签等只处理公开数据的运算使用可变时间算法。
- **密钥缓存：** 默认缓存最近使用的公钥的点表、SM9 主公钥的解码结果与配对值，以及私钥的 SM3 摘要（用于查找对应的公钥、记住 SM9 用户私钥已通过子群检查），不保存任何私钥本身。缓存会通过计时或内存暴露最近使用过哪些密钥。调用 `setKeyCacheEnabled(false)` 或设置环境变量 `SMX_DISABLE_KEY_CACHE=1` 可以关闭，`clearKeyCaches()` 随时清空。
- **SM4-CBC 只提供保密性，不提供完整性。** 同一个 `SM4` 对象每次加密都使用 `setKey` 时的 IV，请为每条消息使用新的随机 IV。

## 测试与性能

```bash
dart pub get
dart test                       # 设置 SMX_SLOW_TESTS=1 会额外运行 1 GiB 的 SM3 向量
dart run benchmark/bench.dart   # JIT
dart compile exe benchmark/bench.dart -o bench && ./bench   # AOT
```

测试使用仓库共享的向量：`testvectors/security-vectors.json`、Python 测试中的已知答案（`test/support/sm2_kat_vectors.dart`），以及 `testvectors/sm9-vectors.json` 中的全部 SM9 向量（GB/T 38635.5 附录 A 至 D、额外向量和所有非法输入）。

`lib/src/field/*.g.dart` 是生成的代码，修改生成器后运行：

```bash
dart run tool/gen_field.dart && dart format lib
```
