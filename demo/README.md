# SM2跨语言密钥交换与加密通信Demo

本Demo验证Java、JavaScript、Rust、Swift、Go、C六种语言的SM2实现能够完成密钥交换协议并使用协商密钥进行加密解密通信。

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
└── client-c/                    # C客户端（使用libcurl）
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
