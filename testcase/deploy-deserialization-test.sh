#!/bin/bash
# 反序列化攻击检测测试 - Windows 11 + Tomcat 部署脚本
# 用法: 在 Git Bash 中执行: bash testcase/deploy-deserialization-test.sh
#       或在 WSL 中执行: bash testcase/deploy-deserialization-test.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TEST_JSP="deserialization-test.jsp"
TEST_JSP_PATH="$SCRIPT_DIR/$TEST_JSP"

echo "=== RASP 反序列化检测测试部署 (Windows 11 + Tomcat) ==="

detect_os() {
    case "$(uname -s)" in
        MINGW*|MSYS*|CYGWIN*) echo "gitbash" ;;
        Linux)
            if grep -qi microsoft /proc/version 2>/dev/null; then
                echo "wsl"
            else
                echo "linux"
            fi
            ;;
        *) echo "unknown" ;;
    esac
}

OS_TYPE=$(detect_os)

case "$OS_TYPE" in
    gitbash|wsl)
        echo "[检测] 运行环境: Windows (bash)"
        ;;
    linux)
        echo "[检测] 运行环境: Linux"
        ;;
    *)
        echo "[警告] 未知运行环境: $(uname -s)，将按 Windows 模式处理"
        OS_TYPE="windows"
        ;;
esac

detect_tomcat() {
    local candidates=(
        "/c/xampp/tomcat"
        "/c/Program Files/Apache Software Foundation/Tomcat 8.5"
        "/c/tomcat85"
        "/c/tomcat"
        "/d/xampp/tomcat"
        "/e/xampp/tomcat"
        "$HOME/xampp/tomcat"
    )
    for dir in "${candidates[@]}"; do
        if [ -d "$dir/webapps" ] && [ -f "$dir/bin/catalina.bat" ]; then
            echo "$dir"
            return 0
        fi
    done
    return 1
}

if [ -n "${TOMCAT_HOME:-}" ] && [ -d "$TOMCAT_HOME/webapps" ]; then
    TOMCAT_HOME="$TOMCAT_HOME"
    echo "[检测] TOMCAT_HOME 环境变量: $TOMCAT_HOME"
else
    echo "[检测] 正在搜索 Tomcat 安装目录..."
    TOMCAT_HOME=$(detect_tomcat) || true
    if [ -z "$TOMCAT_HOME" ]; then
        echo "错误: 未找到 Tomcat 安装目录"
        echo ""
        echo "请通过以下方式指定:"
        echo "  Git Bash:  export TOMCAT_HOME=/c/xampp/tomcat"
        echo "  CMD:       set TOMCAT_HOME=C:\\xampp\\tomcat"
        echo "  PowerShell: \$env:TOMCAT_HOME='C:\\xampp\\tomcat'"
        echo ""
        echo "常见 Tomcat 路径:"
        echo "  XAMPP:  C:\\xampp\\tomcat"
        echo "  独立安装: C:\\Program Files\\Apache Software Foundation\\Tomcat 8.5"
        exit 1
    fi
    echo "[检测] 自动发现 Tomcat: $TOMCAT_HOME"
fi

TARGET_DIR="$TOMCAT_HOME/webapps/examples"

if [ ! -d "$TARGET_DIR" ]; then
    echo "错误: Tomcat examples 目录不存在: $TARGET_DIR"
    echo "请确认 examples webapp 已部署"
    exit 1
fi

if [ ! -f "$TEST_JSP_PATH" ]; then
    echo "错误: 找不到测试文件: $TEST_JSP_PATH"
    exit 1
fi

cp "$TEST_JSP_PATH" "$TARGET_DIR/"
echo "[部署] $TEST_JSP → $TARGET_DIR/"

FASTJSON_JAR="$TOMCAT_HOME/lib/fastjson-1.2.24.jar"
FASTJSON_ALT="$TARGET_DIR/WEB-INF/lib/fastjson-1.2.24.jar"

if [ -f "$FASTJSON_JAR" ]; then
    echo "[FastJSON] 已就绪 ($FASTJSON_JAR)"
elif [ -f "$FASTJSON_ALT" ]; then
    echo "[FastJSON] 已就绪 ($FASTJSON_ALT)"
else
    echo ""
    echo "============================================================"
    echo "  FastJSON 测试依赖 fastjson-1.2.24.jar"
    echo ""
    echo "  下载方式:"
    echo "    Git Bash:"
    echo "      curl -o \"$FASTJSON_JAR\" \\"
    echo "        https://repo1.maven.org/maven2/com/alibaba/fastjson/1.2.24/fastjson-1.2.24.jar"
    echo ""
    echo "    PowerShell:"
    echo "      Invoke-WebRequest -Uri 'https://repo1.maven.org/.../fastjson-1.2.24.jar' \\"
    echo "        -OutFile '$FASTJSON_JAR'"
    echo ""
    echo "  或手动下载放入:"
    echo "    %CATALINA_HOME%\\lib\\"
    echo "    或 webapps\\examples\\WEB-INF\\lib\\"
    echo "============================================================"
fi

echo ""
echo "========================================"
echo "  部署完成"
echo "========================================"
echo ""
echo "测试页面:"
echo "  http://localhost:8080/examples/$TEST_JSP"
echo ""
echo "告警面板:"
echo "  http://localhost:5100/alerts"

if [ -f "$TOMCAT_HOME/bin/catalina.bat" ]; then
    echo ""
    echo "启动 Tomcat (如未启动):"
    echo "  CMD:     %CATALINA_HOME%\\bin\\startup.bat"
    echo "  Git Bash: \"$TOMCAT_HOME/bin/startup.sh\"  (如安装了 Cygwin)"
fi

echo ""
echo "预期检测结果:"
echo "  测试用例              判定      分数"
echo "  ─────────────────────────────────────"
echo "  JNDI LDAP  (1389)    BLOCK     50  (基础30 + JNDI端口20)"
echo "  JNDI RMI   (1099)    BLOCK     50  (基础30 + JNDI端口20)"
echo "  JNDI LDAPS (636)     BLOCK     50  (基础30 + LDAP端口20)"
echo "  JNDI DNS   (5353)    ALARM     30  (基础30)"
echo "  SSRF Socket(4444)    ALARM     30  (基础30)"
echo "  SSRF URL   (8000)    ALARM     30  (基础30)"
echo "  SSRF NonStd(9090)    ALARM     30  (基础30)"
echo "  FastJSON JNDI        依赖 FastJSON jar"
echo "  MySQL      (3306)    PASS      0   (已知服务端口白名单)"
echo "  HTTPS      (443)     PASS      0   (已知服务端口白名单)"
echo ""
echo "告警日志:"
echo "  %CATALINA_HOME%\\logs\\stack-anomaly-alert.log"
echo "  或 tail -f \"$TOMCAT_HOME/logs/stack-anomaly-alert.log\""
echo ""
echo "注意事项:"
echo "  1. 确保 Agent 已通过 -javaagent 参数加载到 Tomcat JVM"
echo "  2. 学习期结束后(默认5分钟)检测才生效"
echo "  3. RASP 阻断时页面会返回 403 + BlockReason 响应头"
echo "  4. 告警级不会阻断请求，仅记录日志和面板显示"
