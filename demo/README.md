# SM2跨语言密钥交换与加密通信Demo

本Demo验证Java、JavaScript、Rust、Swift、Go、C、C#、Python、Dart九种语言的SM2实现能够完成密钥交换协议并使用协商密钥进行加密解密通信。

## 架构

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
├─────────────┤              │             │
│ Dart Client │─────────────>│             │
└─────────────┘              └─────────────┘
     (A侧)
```

## 目录结构

```
demo/
├── README.md                    # 本文件
├── run-tests.sh                 # 一键测试脚本
├── server-java/                 # Java HTTP服务端
├── client-js/                   # JavaScript客户端
├── client-rust/                 # Rust客户端
├── client-swift/                # Swift客户端
├── client-go/                   # Go客户端
├── client-c/                    # C客户端（使用libcurl）
├── client-csharp/               # C#客户端（.NET 8）
├── client-python/               # Python客户端（仅标准库）
└── client-dart/                 # Dart客户端（仅 dart:io）
```

## API接口

### POST /api/keyswap/init
A发起密钥交换
```json
// Request
{"IDa": "string", "pA": "04...", "Ra": "04...", "keyLen": 16}

// Response
{"sessionId": "uuid", "IDb": "string", "pB": "04...", "Rb": "04...", "Sb": "hex64"}
```

### POST /api/keyswap/confirm
A确认密钥交换
```json
// Request
{"sessionId": "uuid", "Sa": "hex64"}

// Response
{"success": true}
```

### POST /api/crypto/test
加密通信测试
```json
// Request
{"sessionId": "uuid", "clientCiphertext": "hex", "clientPlaintext": "string"}

// Response
{"clientDecrypted": "string", "clientDecryptMatch": true, "serverPlaintext": "string", "serverCiphertext": "hex"}
```

## 安全提示

本 Demo 只用于演示各语言实现能够互通，**不要直接用于生产环境**：

- **服务端身份默认不验证。** 客户端信任服务端返回的 `pB`，任何能冒充服务端地址的人都能完成密钥交换并解密通信，换成 HTTPS 也解决不了。需要验证时：
  1. 启动服务端时用环境变量 `SM2_DEMO_SERVER_PRIVATE_KEY` 指定固定私钥（64 位十六进制），否则每次启动随机生成。
  2. 客户端设置 `SM2_DEMO_SERVER_PUBKEY` 为对应的公钥（`04` 开头的 130 位十六进制）。公钥不一致时，客户端会直接失败。
  3. 未设置时，客户端会提示服务端未经认证。
- **通信使用明文 HTTP，SM4 使用固定的全零 IV**，所以相同的明文会得到相同的密文。
- **`/api/crypto/test` 会为任何持有 `sessionId` 的人解密**，只用于测试。
- 服务端只接受 `keyLen` 为 16，会限制会话数量、请求大小和连接耗时，但对大规模连接攻击仍应放在反向代理之后。

## 快速开始

### 一键测试

```bash
./run-tests.sh
```

### 分步测试

1. 启动Java服务端
```bash
cd server-java
mvn compile exec:java
```

2. 测试JavaScript客户端
```bash
cd client-js
npm install
node test-demo.mjs
```

3. 测试Rust客户端
```bash
cd client-rust
cargo run
```

4. 测试Swift客户端
```bash
cd client-swift
swift run
```

5. 测试Go客户端
```bash
cd client-go
go run .
```

6. 测试C客户端（需要先启动Java服务端，依赖libcurl）
```bash
cd client-c
make && ./demo
```

7. 测试C#客户端
```bash
cd client-csharp
dotnet run
```

8. 测试Python客户端
```bash
cd client-python
python3 main.py
```

9. 测试Dart客户端
```bash
cd client-dart
dart pub get && dart run bin/main.dart
```

## 密钥交换流程

```
Client(A)                          Server(B)
   │                                   │
   │ 生成ra, Ra                         │
   │ POST /init {IDa,pA,Ra}            │
   ├──────────────────────────────────>│
   │                                   │ 生成rb, Rb
   │                                   │ 计算Sb, Kb (getSb)
   │           {sessionId,IDb,pB,Rb,Sb}│
   │<──────────────────────────────────┤
   │                                   │
   │ 计算Sa, Ka (getSa)                 │
   │ 验证Sb                             │
   │ POST /confirm {sessionId,Sa}      │
   ├──────────────────────────────────>│
   │                                   │ 验证Sa (checkSa)
   │                       {success}   │
   │<──────────────────────────────────┤
   │                                   │
   │ ====== 密钥协商完成 Ka==Kb ======  │
```
