#!/bin/bash
# 基线文件解析工具
# 用法: ./inspect-baseline.sh [baseline文件路径] [--detail|--urls|--ctpg]
#
# 示例:
#   ./inspect-baseline.sh /tmp/rasp/baseline.dat             # 概览
#   ./inspect-baseline.sh /tmp/rasp/baseline.dat --detail    # 所有详情
#   ./inspect-baseline.sh /tmp/rasp/baseline.dat --urls      # 仅URL基线
#   ./inspect-baseline.sh /tmp/rasp/baseline.dat --ctpg      # 仅调用转移图

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
JAR="$SCRIPT_DIR/../target/stack-anomaly-detector-1.0.0-shaded.jar"

if [ ! -f "$JAR" ]; then
    echo "错误: 找不到 jar 文件: $JAR"
    echo "请先执行 mvn package"
    exit 1
fi

java -cp "$JAR" com.defense.rasp.tool.BaselineInspector "$@"
