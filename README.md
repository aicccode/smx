# SMX - 国密算法多语言实现

完全基于国家密码管理局发布的商用密码算法标准，在**零第三方依赖**的前提下，实现 SM2、SM3、SM4 国密核心算法在 **Java、JavaScript、Swift、Rust、Go、C** 六种主流编程语言下的全维度落地。

所有实现均严格遵循国家密码管理局发布的算法规范与测试用例，算法输出与官方测试基准完全一致，可直接应用于商用密码产品的研发与部署。

## 功能矩阵

| 功能 | Java | JavaScript | Swift | Rust | Go | C |
|------|:----:|:----------:|:-----:|:----:|:--:|:-:|
| SM3 哈希 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM4 对称加解密 (CBC/PKCS7) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 非对称加解密 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 数字签名/验签 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SM2 密钥交换 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |

## 项目结构

```
smx/
├── java/            # Java 实现 (Maven, site.aicc:gm-java)
├── javascript/      # JavaScript 实现 (npm, ES Module)
├── swift/           # Swift 实现 (SwiftPM, GMSwift)
├── rust/            # Rust 实现 (Cargo, gm-rust)
├── go/              # Go 实现 (Go Module, smx)
├── c/               # C 实现 (Makefile, C99)
├── demo/            # 跨语言密钥交换与加密通信Demo
│   ├── server-java/     # Java HTTP 服务端 (B侧)
│   ├── client-js/       # JavaScript 客户端 (A侧)
│   ├── client-rust/     # Rust 客户端 (A侧)
│   ├── client-swift/    # Swift 客户端 (A侧)
│   ├── client-go/       # Go 客户端 (A侧)
│   ├── client-c/        # C 客户端 (A侧, libcurl)
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
- **最低版本：** Rust 2024 edition
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

## 跨语言Demo

Demo 验证六种语言的 SM2 实现能够完成**密钥交换协议**并使用协商密钥进行 **SM4 加密解密通信**。

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
