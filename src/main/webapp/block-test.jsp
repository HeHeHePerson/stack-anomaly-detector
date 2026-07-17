<%@ page contentType="text/html; charset=UTF-8" %>
<%
String action = request.getParameter("action");
String targetFile = request.getParameter("file");
String cmd = request.getParameter("cmd");

if ("read".equals(action)) {
    try {
        new java.io.FileInputStream(targetFile != null ? targetFile : "/etc/passwd");
    } catch (Exception e) { }
} else if ("write".equals(action)) {
    try {
        new java.io.FileOutputStream(application.getRealPath("/") + "shell.jsp");
    } catch (Exception e) { }
} else if ("exec".equals(action)) {
    try {
        Runtime.getRuntime().exec(cmd != null ? cmd : "id");
    } catch (Exception e) { }
} else if ("net".equals(action)) {
    try {
        new java.net.Socket("127.0.0.1", 22);
    } catch (Exception e) { }
}
%>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>阻断页面测试</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#0f1119;color:#d0d4e0;padding:40px}
.card{background:#151829;border:1px solid #1e2358;border-radius:8px;padding:24px;margin-bottom:16px;max-width:800px}
.card h2{font-size:16px;color:#8890b5;margin-bottom:16px}
.btn{padding:8px 20px;border-radius:4px;font-size:13px;cursor:pointer;border:1px solid #2a3060;background:#1a2040;color:#b0b8d0;margin:4px}
.btn:hover{background:#222850;color:#fff}
.btn-danger{background:#3d1520;border-color:#5a2030;color:#f87171}
.btn-danger:hover{background:#4d2030}
.note{font-size:11px;color:#505880;margin-top:8px}
</style>
</head>
<body>

<div class="card">
  <h2>阻断页面测试工具</h2>
  <p class="note">点击下方按钮触发攻击行为，RASP 将返回 403 阻断页面。</p>
  <p class="note" style="color:#f59e0b">警告: 点击后页面将被阻断页面替换。测试完成后请点"刷新本页"返回。</p>
</div>

<div class="card">
  <h2>文件读取攻击</h2>
  <a href="?action=read&file=/etc/passwd" class="btn btn-danger">读取 /etc/passwd</a>
  <a href="?action=read&file=/etc/shadow" class="btn btn-danger">读取 /etc/shadow</a>
  <p class="note">异常调用栈 + 敏感文件(60分) → 总分 >= 50 → 阻断</p>
</div>

<div class="card">
  <h2>文件写入攻击</h2>
  <a href="?action=write" class="btn btn-danger">写入 WebShell (shell.jsp)</a>
  <p class="note">新进程写文件 + 敏感路径 → 阻断</p>
</div>

<div class="card">
  <h2>命令执行攻击</h2>
  <a href="?action=exec&cmd=id" class="btn btn-danger">Runtime.exec("id")</a>
  <a href="?action=exec&cmd=whoami" class="btn btn-danger">Runtime.exec("whoami")</a>
  <p class="note">DangerousClass 检测(20分) + 异常调用栈 → 阻断</p>
</div>

<div class="card">
  <h2>Socket 网络连接</h2>
  <a href="?action=net" class="btn btn-danger">连接 127.0.0.1:22</a>
  <p class="note">异常网络连接检测</p>
</div>

<div class="card" style="background:#0d2818;border-color:#1a5a30">
  <h2 style="color:#4ade80">正常请求</h2>
  <a href="?" class="btn" style="color:#4ade80;text-decoration:none">刷新本页 (正常访问)</a>
  <p class="note">验证正常页面渲染不受影响</p>
</div>

</body>
</html>
