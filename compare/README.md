# 与 OpenSSL、BouncyCastle 的性能对比

本目录用同一套操作，对比 SMX 的八种实现与 OpenSSL、BouncyCastle 的性能。在 Apple M2 上改造前后的对比，以及与 OpenSSL 3.6.5 的对比，见 [`apple-m2/`](apple-m2/README.md)。

## 测试环境（2026-11-06）

- CPU：Intel Core i5-13500H，固定在一个性能核上运行（`taskset -c 6`；JVM 用 6、7 两个线程）
- 系统：Ubuntu 24.04，x86_64，测试时机器空闲
- 对比对象：OpenSSL 3.0.13（Ubuntu 软件包，`EVP` 接口）、BouncyCastle 1.86（`bcprov-jdk18on`，轻量级 API，不经过 JCA）
- 运行时：gcc 13.3、rustc 1.99、Go 1.25、.NET 8、OpenJDK 21.0.9（C2）、Node.js 18.20.5、CPython 3.12.3、Swift 6.2.3
- 每项取多次运行中的最好值；原始输出在 `results-2026-11-06/`
- SM4 为 CBC + PKCS#7；SM2 签名使用默认用户 ID，对 32 字节消息签名；SM2 加解密为 32 字节明文

## 结果

### SM2（µs/次，越小越好）

| 操作 | OpenSSL | BouncyCastle | C | Rust | Go | C# | Swift | Java | JS | Python |
|---|---|---|---|---|---|---|---|---|---|---|
| 密钥生成 | 199 | 304 | 19.1 | **12.9** | 13.8 | 32.0 | 14.3 | 37.6 | 75.8 | 235 |
| 签名 | 202 | 311 | 37.6 | **27.5** | 31.7 | 38.9 | 33.0 | 77.1 | 212 | 316 |
| 验签 | 192 | 367 | 67.2 | 64.8 | 49.0 | 107 | **45.5** | 221 | 261 | 449 |
| 加密 | 377 | 1200 | 78.7 | 76.9 | 65.2 | 144 | **65.2** | 255 | 369 | 1292 |
| 解密 | 192 | 897 | 66.2 | 63.6 | 58.1 | 126 | **51.4** | 218 | 294 | 1162 |

### SM3（MB/s，越大越好）

| 输入长度 | OpenSSL | BouncyCastle | C | Rust | Go | C# | Swift | Java | JS | Python |
|---|---|---|---|---|---|---|---|---|---|---|
| 64 B | 128 | 133 | 237 | **246** | 206 | 149 | 152 | 125 | 131 | 0.63 |
| 1 KiB | 405 | 268 | 500 | **507** | 411 | 445 | 443 | 263 | 418 | 1.07 |
| 1 MiB | 471 | 288 | 543 | **543** | 440 | 490 | 506 | 284 | 499 | 1.12 |

### SM4-CBC，1 MiB（MB/s，越大越好）

| 操作 | OpenSSL | BouncyCastle | C | Rust | Go | C# | Swift | Java | JS | Python |
|---|---|---|---|---|---|---|---|---|---|---|
| 加密 | **157** | 101 | 117 | 123 | 109 | 79 | 32.5 | 26.4 | 26.6 | 0.13 |
| 解密 | 177 | 103 | 815 | **1298** | 519 | 379 | 39.0 | 24.6 | 36.7 | 10.3 |

## 结论

- **SM2：** C、Rust、Go、Swift、C# 的签名比 OpenSSL 快 5 到 7 倍，加解密和验签快 1.5 到 6 倍。Java 比 BouncyCastle 快 1.7 到 8 倍。OpenSSL 3.0 的 SM2 使用通用曲线代码。较新版本的 OpenSSL 缩小了这个差距：在 Apple M2 上，3.6.5 的签名比 3.0.13 快约 3 倍，但仍慢于 Rust、Go、Swift，见 [`apple-m2/`](apple-m2/README.md)。
- **SM3：** C、Rust、C#、Swift、JS 在三种长度上都快于 OpenSSL；Go 在 64 B 和 1 KiB 上更快，在 1 MiB 上慢约 7%。Java 与 BouncyCastle 持平，受 JVM 生成代码的限制。
- **SM4 解密：** 用 AES-NI/GFNI 并行处理多个分组，C、Rust、Go、C# 比 OpenSSL 快 2 到 7 倍。
- **SM4 加密：** CBC 加密只能逐块进行。本库在所有平台上都不使用依赖秘密数据的查表，以避免缓存时序攻击，所以比 OpenSSL 慢 20% 到 50%。Java、JS、Swift、Python 没有可用的硬件指令，使用布尔电路实现 S 盒，速度较慢，这是为常数时间付出的代价。
- **Python：** CPython 的整数和字节运算本身较慢，不适合处理大量数据。需要高吞吐时，请使用其他语言的实现。

**这不是同等安全级别的比较。** 据我们所知，OpenSSL 3.0 和 BouncyCastle 的 SM4 使用查表实现，存在缓存时序风险，SMX 则不使用这类实现。这一点是根据它们公开的实现方式判断的，本次没有核查其源码。

## 互通性

八种实现与 OpenSSL 3.0.13 和 BouncyCastle 1.86 双向互通：签名与验签、SM2 加解密、SM3、SM4-CBC，以及与 BouncyCastle 的 SM2 密钥交换（OpenSSL 3.0 不提供密钥交换）。

一处差异：GB/T 32918.4 要求解密时拒绝 KDF 输出全为零的密文，SMX 照此执行，而 OpenSSL 和 BouncyCastle 不检查。正常加密方会重新选择随机数，所以只有对方不遵守标准时才会遇到；对 1 字节明文，这种情况约每 256 次出现一次。

## 复现

```bash
cd java && mvn -q test && cd ..                    # Java 需要先编译
BC_JAR=/path/to/bcprov-jdk18on-1.86.jar CORE=6 compare/run-all.sh
python3 compare/summarize.py compare/out
```

`run-all.sh` 需要 `taskset`、OpenSSL 3 头文件（如 `libssl-dev`）和各语言的工具链。请在空闲的机器上运行，其他负载会明显影响结果。
