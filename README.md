# SMX - 国密算法多语言实现

完全基于国家密码管理局发布的商用密码算法标准，在**零第三方依赖**的前提下，实现 SM2、SM3、SM4 国密核心算法在 **Java、JavaScript、Swift、Rust、Go、C、C#、Python** 八种主流编程语言下的全维度落地。

所有实现均严格遵循国家密码管理局发布的算法规范与测试用例，算法输出与官方测试基准完全一致，可直接应用于商用密码产品的研发与部署。

## 功能矩阵

| 功能 | Java | JavaScript | Swift | Rust | Go | C | C# | Python |
|------|:----:|:----------:|:-----:|:----:|:--:|:-:|:--:|:------:|
| SM3 哈希 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM4 对称加解密 (CBC/PKCS7) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 非对称加解密 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 数字签名/验签 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 密钥交换 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## 项目结构

```
smx/
├── java/            # Java 实现 (Maven, site.aicc:gm-java)
├── javascript/      # JavaScript 实现 (npm, ES Module)
├── swift/           # Swift 实现 (SwiftPM, GMSwift)
├── rust/            # Rust 实现 (Cargo, gm-rust)
├── go/              # Go 实现 (Go Module, smx)
├── c/               # C 实现 (Makefile, C99)
├── csharp/          # C# 实现 (.NET 8, SMX)
├── python/          # Python 实现 (pyproject, gm-python)
├── demo/            # 跨语言密钥交换与加密通信Demo
│   ├── server-java/     # Java HTTP 服务端 (B侧)
│   ├── client-js/       # JavaScript 客户端 (A侧)
│   ├── client-rust/     # Rust 客户端 (A侧)
│   ├── client-swift/    # Swift 客户端 (A侧)
│   ├── client-go/       # Go 客户端 (A侧)
│   ├── client-c/        # C 客户端 (A侧, libcurl)
│   ├── client-csharp/   # C# 客户端 (A侧, .NET 8)
│   ├── client-python/   # Python 客户端 (A侧)
│   └── run-tests.sh     # 一键测试脚本
└── doc/             # 算法规范文档 (PDF)
```

## 各语言实现

### Java

```bash
cd java
mvn test        # 运行测试
mvn install     # 安装到本地仓库
```

- **构建工具：** Maven
- **包名：** `site.aicc` (`gm-java:1.0.0`)
- **最低版本：** Java 8+
- **依赖：** 无（仅 JUnit 用于测试）

### JavaScript

```bash
cd javascript
npm test        # 运行测试
```

- **构建工具：** npm (ES Module)
- **包名：** `gm-js`
- **运行环境：** Node.js (ES Module)
- **依赖：** 无

### Swift

```bash
cd swift
swift test      # 运行测试
swift build     # 编译
```

- **构建工具：** Swift Package Manager
- **库名：** `GMSwift`
- **最低版本：** Swift 5.7+, iOS 15+, macOS 10.13+
- **依赖：** 无

### Rust

```bash
cd rust
cargo test      # 运行测试
cargo build     # 编译
```

- **构建工具：** Cargo
- **包名：** `gm-rust`
- **最低版本：** Rust 1.85（2024 edition）
- **依赖：** 无

### Go

```bash
cd go
go test ./...   # 运行测试
```

- **构建工具：** Go Modules
- **模块名：** `smx`
- **最低版本：** Go 1.21+
- **依赖：** 无

### C

```bash
cd c
make test       # 编译并运行测试
```

- **构建工具：** Makefile (gcc)
- **标准：** C99
- **依赖：** 无（核心库），libcurl（仅Demo客户端）

### C#

```bash
cd csharp
dotnet test     # 运行测试
dotnet build    # 编译
```

- **构建工具：** .NET SDK
- **库名：** `SMX`
- **最低版本：** .NET 8.0
- **依赖：** 无（仅 xunit 用于测试）

### Python

```bash
cd python
python3 -m unittest discover -s tests -t .   # 运行测试（无需安装任何依赖）
python3 -m pytest                            # 也可以使用 pytest 运行
SMX_SLOW_TESTS=1 python3 -m unittest discover -s tests -t .   # 包括 512 MiB/1 GiB 的 SM3 慢测试
```

- **构建工具：** setuptools (pyproject.toml)
- **包名：** `gm-python`（导入名 `smx`）
- **最低版本：** Python 3.9+
- **依赖：** 无（pytest 可选，仅用于测试）

## 安全说明

### 输入要求

- **SM4 密钥和 IV 必须正好 16 字节**（或 32 位十六进制）。早期版本会把其他长度的“文本密钥”哈希或截断成密钥，实际强度只有约 64 位，现在会直接报错。用这种密钥加密过的旧数据无法用新版本解密，需要用旧版本解密后重新加密。
- **签名和密文的十六进制必须是小写**，与本库的输出一致，这样一个签名只有一种字符串形式。公钥和私钥的十六进制仍然不区分大小写。
- 非法输入（不在曲线上的点、超出范围的私钥或签名、长度错误、错误的填充等）一律按各语言的惯例报错或返回失败。每种语言的公开接口都经过模糊测试，没有发现崩溃或卡死，但模糊测试不能证明完全不存在这类问题。

### SM4-CBC 的局限

- **CBC 只提供保密性，不提供完整性。** 密文可以被篡改而不被发现，需要完整性时请另外使用 MAC（例如 HMAC-SM3）并先验证再解密。
- **同一个 SM4 对象设置一次密钥后，每次加密都使用同一个 IV。** 相同的明文会得到相同的密文。请为每条消息使用新的随机 IV。
- 字符串形式的解密结果需要做 UTF-8 校验，校验耗时仍与明文内容有关。处理二进制数据或要求更严格的时序时，请使用返回字节的解密接口。

### 侧信道

- 私钥参与的运算（密钥生成、签名、解密、密钥交换）使用固定窗口和掩码查表，不存在依赖秘密数据的分支或内存地址。C、Rust、Swift 带有检查编译结果的工具，例如 C 的 `make check-ct`、`rust/tools/check_ct_asm.py`、`swift/Tools/check_constant_time.py`；换编译器版本后应重新运行。
- SM4 在所有平台上都不使用依赖秘密数据的查表：有 AES-NI、GFNI 或 ARM AES 指令时使用硬件实现，否则使用布尔电路实现的 S 盒。
- Java、C#、JavaScript、Python 运行在托管环境中，运行时本身不提供常数时间保证，本库只能做到源码层面没有依赖秘密数据的分支和查表。
- 验签只处理公开数据，使用可变时间的算法以提高速度。

### 需要更换的旧密钥

以下环境用旧版本生成的密钥，其随机数来源不安全，**应当更换**，这些密钥上的旧签名也不应再视为可靠：

- JavaScript 运行在 Node.js 18 及更早版本：随机数完全来自 `Math.random`
- JavaScript 运行在浏览器或 Node.js 20 及以上：混入了 `Math.random` 和 RC4，风险较低，但仍建议更换
- Rust 编译到 wasm：随机数来自以时间为种子的线性同余生成器

### 与其他实现的差异

GB/T 32918.4 要求解密时拒绝 KDF 输出全为零的密文，本库照此执行，而 OpenSSL 3.0 和 BouncyCastle 1.86 不检查。对 1 字节明文，这种情况约每 256 次出现一次。

## 性能

在 Intel i5-13500H 的单个性能核上，与 OpenSSL 3.0.13 和 BouncyCastle 1.86 的对比（节选，完整结果和复现方法见 [`compare/`](compare/README.md)）：

| 操作 | OpenSSL | BouncyCastle | C | Rust | Go | Java |
|---|---|---|---|---|---|---|
| SM2 签名（µs） | 202 | 311 | 37.6 | 27.5 | 31.7 | 77.1 |
| SM2 验签（µs） | 192 | 367 | 67.2 | 64.8 | 49.0 | 221 |
| SM3 1 MiB（MB/s） | 471 | 288 | 543 | 543 | 440 | 284 |
| SM4 加密 1 MiB（MB/s） | 157 | 101 | 117 | 123 | 109 | 26.4 |
| SM4 解密 1 MiB（MB/s） | 177 | 103 | 815 | 1298 | 519 | 24.6 |

SM4 加密慢于 OpenSSL，是因为本库不使用依赖秘密数据的查表。

## 跨语言Demo

Demo 验证八种语言的 SM2 实现能够完成**密钥交换协议**并使用协商密钥进行 **SM4 加密解密通信**。

### 架构

```
┌─────────────┐     HTTP      ┌─────────────┐
│ JS Client   │─────────────>│             │
├─────────────┤              │             │
│ Rust Client │─────────────>│   Java      │
├─────────────┤              │   Server    │
│Swift Client │─────────────>│   (B侧)     │
├─────────────┤              │             │
│ Go Client   │─────────────>│             │
├─────────────┤              │             │
│  C Client   │─────────────>│             │
├─────────────┤              │             │
│  C# Client  │─────────────>│             │
├─────────────┤              │             │
│Python Client│─────────────>│             │
└─────────────┘              └─────────────┘
     (A侧)
```

### 密钥交换流程

```
Client(A)                          Server(B)
   │                                   │
   │ 生成 dA/pA, ra/Ra                  │
   │ POST /api/keyswap/init            │
   ├──────────────────────────────────>│
   │                                   │ 生成 rb/Rb, 计算 Sb, Kb
   │        {sessionId, pB, Rb, Sb}    │
   │<──────────────────────────────────┤
   │                                   │
   │ 计算 Sa, Ka, 验证 Sb               │
   │ POST /api/keyswap/confirm {Sa}    │
   ├──────────────────────────────────>│
   │                                   │ 验证 Sa
   │                       {success}   │
   │<──────────────────────────────────┤
   │                                   │
   │ ========= Ka == Kb 密钥协商完成 =========│
   │                                   │
   │ SM4(Ka) 加密消息                    │
   │ POST /api/crypto/test             │
   ├──────────────────────────────────>│
   │                                   │ SM4(Kb) 解密验证 + 加密回复
   │     {decryptMatch, ciphertext}    │
   │<──────────────────────────────────┤
   │ SM4(Ka) 解密回复                    │
```

### 一键测试

```bash
cd demo
./run-tests.sh
```

## 算法简介

### SM2 椭圆曲线公钥密码算法

基于椭圆曲线点群离散对数难题，256 位安全等级等效于 2048 位 RSA。包含三大核心组件：
- **SM2-1** 椭圆曲线数字签名算法
- **SM2-2** 椭圆曲线密钥交换协议
- **SM2-3** 椭圆曲线公钥加密算法

### SM3 杂凑算法

输出 256 位哈希值，安全性显著高于 MD5 (128 位) 和 SHA-1 (160 位)，适用于数字签名、消息认证码、随机数生成等场景。

### SM4 分组密码算法

密钥长度与分组长度均为 128 位，与 AES 参数一致，是国密体系中对称加密的核心算法。本实现采用 CBC 模式 + PKCS7 填充。

## 参考文档

`doc/` 目录包含国家密码管理局发布的算法规范文档：

| 文档 | 说明 |
|------|------|
| `sm2.pdf` | SM2 椭圆曲线公钥密码算法规范 |
| `sm2_param.pdf` | SM2 推荐曲线参数 |
| `sm3.pdf` | SM3 杂凑算法规范 |
| `SM4.pdf` | SM4 分组密码算法规范 |
| `SM9.pdf` | SM9 标识密码算法规范 |

## License

[Apache License 2.0](LICENSE)
