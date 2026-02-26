#!/bin/bash

# SM2 跨语言密钥交换测试脚本
# 自动启动服务端并运行各客户端测试

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "=========================================="
echo " SM2 跨语言密钥交换与加密通信Demo测试"
echo "=========================================="
echo ""

# 构建并安装Java SM2模块到本地仓库
echo -e "${YELLOW}[1/8] 构建并安装Java SM2模块...${NC}"
cd ../java
mvn -q install -DskipTests
echo -e "${GREEN}Java SM2模块构建并安装完成${NC}"

# 启动Java服务端
echo -e "${YELLOW}[2/8] 启动Java服务端...${NC}"
cd "$SCRIPT_DIR/server-java"
mvn -q compile
mvn -q exec:java -Dexec.mainClass="site.aicc.demo.DemoServer" &
SERVER_PID=$!
echo "服务端PID: $SERVER_PID"

# 等待服务端启动
sleep 3
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo -e "${RED}服务端启动失败${NC}"
    exit 1
fi
echo -e "${GREEN}服务端已启动${NC}"
echo ""

# 清理函数
cleanup() {
    echo ""
    echo -e "${YELLOW}清理中...${NC}"
    if [ ! -z "$SERVER_PID" ]; then
        kill $SERVER_PID 2>/dev/null || true
    fi
    echo -e "${GREEN}清理完成${NC}"
}
trap cleanup EXIT

# 测试JavaScript客户端
echo "=========================================="
echo -e "${YELLOW}[3/8] 测试JavaScript客户端...${NC}"
echo "=========================================="
cd "$SCRIPT_DIR/client-js"
if node test-demo.mjs; then
    echo -e "${GREEN}JavaScript客户端测试通过${NC}"
else
    echo -e "${RED}JavaScript客户端测试失败${NC}"
fi
echo ""

# 测试Rust客户端
echo "=========================================="
echo -e "${YELLOW}[4/8] 测试Rust客户端...${NC}"
echo "=========================================="
cd "$SCRIPT_DIR/client-rust"
if cargo run -q 2>/dev/null; then
    echo -e "${GREEN}Rust客户端测试通过${NC}"
else
    echo -e "${RED}Rust客户端测试失败${NC}"
fi
echo ""

# 测试Swift客户端 (仅在macOS上)
echo "=========================================="
echo -e "${YELLOW}[5/8] 测试Swift客户端...${NC}"
echo "=========================================="
cd "$SCRIPT_DIR/client-swift"
if swift run 2>/dev/null; then
    echo -e "${GREEN}Swift客户端测试通过${NC}"
else
    echo -e "${RED}Swift客户端测试失败${NC}"
fi
echo ""

# 测试Go客户端
echo "=========================================="
echo -e "${YELLOW}[6/8] 测试Go客户端...${NC}"
echo "=========================================="
cd "$SCRIPT_DIR/client-go"
if go run . 2>/dev/null; then
    echo -e "${GREEN}Go客户端测试通过${NC}"
else
    echo -e "${RED}Go客户端测试失败${NC}"
fi
echo ""

# 测试C客户端 (独立测试，不依赖服务端)
echo "=========================================="
echo -e "${YELLOW}[7/8] 测试C客户端...${NC}"
echo "=========================================="
cd "$SCRIPT_DIR/client-c"
if make -s test 2>/dev/null; then
    echo -e "${GREEN}C客户端测试通过${NC}"
else
    echo -e "${RED}C客户端测试失败${NC}"
fi
echo ""

# 汇总
echo "=========================================="
echo -e "${YELLOW}[8/8] 测试完成${NC}"
echo "=========================================="
echo ""
echo "所有测试已完成，服务端将关闭。"
