#!/usr/bin/env python3
"""
Stack Anomaly Detector Syslog 接收器
用于测试阶段验证告警和模型结果的外发是否正常。

用法:
  python3 tools/syslog-receiver.py               # 默认端口 514
  python3 tools/syslog-receiver.py 1514           # 指定端口
  python3 tools/syslog-receiver.py 514 --json     # JSON 格式化输出
  python3 tools/syslog-receiver.py 514 --file /tmp/syslog-output.log  # 输出到文件
"""

import socket
import sys
import json
import time
from datetime import datetime


def format_syslog(data):
    """解析 syslog RFC 5424 消息并提取 JSON payload"""
    text = data.decode("utf-8", errors="replace")

    # RFC 5424 格式: <PRI>VERSION TIMESTAMP HOSTNAME APPNAME PROCID MSGID [SD] MESSAGE
    # 提取 PRI 和 VERSION
    pri_end = text.index(">") + 1 if ">" in text else 0
    pri = text[:pri_end]

    # 提取结构化数据之前的部分
    parts = text[pri_end:].split(" ", 6)
    if len(parts) < 7:
        return text

    timestamp, hostname, appname, procid, msgid, sd, message = parts[0], parts[1], parts[2], parts[3], parts[4], parts[5], parts[6]

    # 尝试解析 JSON message body
    try:
        body = json.loads(message)
        msg_type = body.get("type", "unknown")
        app = body.get("app", "?")
        level = body.get("level", "")
        prefix = body.get("prefix", "")

        # 根据类型格式化输出
        if msg_type == "alert":
            msg = body.get("message", "")
            return f"[{timestamp[:23]}] {app} [{prefix}] {msg}"
        elif msg_type == "model":
            ssf = body.get("ssf_count", 0)
            ctpg = body.get("ctpg_size", 0)
            url = body.get("url_path_count", 0)
            return f"[{timestamp[:23]}] {app} MODEL: SSF={ssf} CTPG={ctpg} URL={url}"
        else:
            return text
    except (json.JSONDecodeError, KeyError):
        return text


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 and sys.argv[1].isdigit() else 514
    json_mode = "--json" in sys.argv
    file_output = None
    if "--file" in sys.argv:
        idx = sys.argv.index("--file")
        if idx + 1 < len(sys.argv):
            file_output = sys.argv[idx + 1]

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", port))
    sock.settimeout(1.0)

    print(f"=== Syslog Receiver ===  port={port}  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} ===")
    print("等待 RASP Agent 外发消息 ... (Ctrl+C 退出)")
    print()

    fh = open(file_output, "a") if file_output else None

    try:
        count = 0
        while True:
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            count += 1

            if json_mode:
                text = data.decode("utf-8", errors="replace")
                # 提取 JSON body (最后一个空格之后)
                space_idx = text.rfind(" ")
                if space_idx > 0:
                    try:
                        body = json.loads(text[space_idx + 1:])
                        print(json.dumps(body, indent=2, ensure_ascii=False))
                    except json.JSONDecodeError:
                        print(text)
                else:
                    print(text)
            else:
                formatted = format_syslog(data)
                ts = datetime.now().strftime("%H:%M:%S")
                print(f"[{ts}] #{count} {formatted}")

            if fh:
                fh.write(data.decode("utf-8", errors="replace"))
                fh.flush()

    except KeyboardInterrupt:
        print("\n已停止。共接收 {0} 条消息。".format(count))
    finally:
        sock.close()
        if fh:
            fh.close()


if __name__ == "__main__":
    main()
