<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="com.defense.rasp.stackmodel.*" %>
<%@ page import="java.util.*" %>
<%
// ---- Handle POST actions ----
String msg = "";
String action = request.getParameter("action");
if (action != null) {
    try {
        if ("remove_ssf".equals(action)) {
            int hash = Integer.parseInt(request.getParameter("hash"));
            if (BaselineLearningEngine.removeFingerprint(hash)) {
                msg = "已移除 SSF 指纹: " + hash;
            } else {
                msg = "未找到该指纹";
            }
        } else if ("remove_ctpg".equals(action)) {
            String source = request.getParameter("source");
            String target = request.getParameter("target");
            if (BaselineLearningEngine.removeTransition(source, target)) {
                msg = "已移除 CTPG 转移: " + source + " -> " + target;
            } else {
                msg = "未找到该转移";
            }
        } else if ("remove_url".equals(action)) {
            String path = request.getParameter("path");
            if (UrlBaselineModel.removeUrlPath(path)) {
                msg = "已移除 URL 基线路径: " + path;
            } else {
                msg = "未找到该路径";
            }
        } else if ("relearn".equals(action)) {
            BaselineLearningEngine.resetLearning();
            msg = "学习状态已重置，进入重新学习";
        } else if ("force_complete".equals(action)) {
            if (BaselineLearningEngine.forceLearningComplete()) {
                msg = "学习阶段已强制结束";
            } else {
                msg = "已在检测阶段";
            }
        }
    } catch (Exception e) {
        msg = "操作失败: " + e.getMessage();
    }
}
%>
<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<title>RASP 模型管理控制台</title>
<style>
  body { font-family: monospace; margin: 20px; background: #1a1a2e; color: #e0e0e0; }
  h1 { color: #00d4ff; }
  .status { background: #16213e; padding: 12px; border-radius: 6px; margin-bottom: 16px; }
  .status .label { color: #888; }
  .status .value { color: #00d4ff; font-weight: bold; }
  .msg { background: #0f3460; color: #00ff88; padding: 8px 12px; border-radius: 4px; margin-bottom: 16px; }
  .tabs { display: flex; gap: 4px; margin-bottom: 16px; }
  .tab-btn { padding: 8px 20px; border: 1px solid #333; background: #16213e; color: #aaa; cursor: pointer; border-radius: 6px 6px 0 0; }
  .tab-btn.active { background: #0f3460; color: #00d4ff; border-bottom: 2px solid #00d4ff; }
  .tab-content { display: none; }
  .tab-content.active { display: block; }
  table { width: 100%; border-collapse: collapse; font-size: 12px; }
  th { background: #16213e; color: #00d4ff; padding: 8px; text-align: left; border-bottom: 2px solid #333; position: sticky; top: 0; }
  td { padding: 6px 8px; border-bottom: 1px solid #222; vertical-align: top; }
  tr:hover td { background: #0a1628; }
  .remove-btn { padding: 2px 10px; background: #c0392b; color: #fff; border: none; border-radius: 3px; cursor: pointer; font-size: 11px; }
  .remove-btn:hover { background: #e74c3c; }
  .action-bar { display: flex; gap: 12px; margin: 16px 0; }
  .action-btn { padding: 8px 24px; border: none; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 13px; }
  .btn-relearn { background: #e67e22; color: #fff; }
  .btn-relearn:hover { background: #f39c12; }
  .btn-force { background: #8e44ad; color: #fff; }
  .btn-force:hover { background: #9b59b6; }
  .sig-list { max-height: 200px; overflow-y: auto; margin: 4px 0; line-height: 1.6; }
  .sig-item { color: #aaa; font-size: 11px; }
  .sig-item.rasp { color: #555; }
  .params { color: #f1c40f; font-size: 11px; }
  .no-data { color: #666; padding: 40px; text-align: center; }
</style>
</head>
<body>

<h1>RASP 模型管理控制台</h1>

<div class="status">
  <span class="label">学习状态:</span>
  <span class="value"><%= BaselineLearningEngine.isLearningPhase() ? "学习中" : "检测中" %></span>
  &nbsp;|&nbsp;
  <span class="label">进度:</span>
  <span class="value"><%= BaselineLearningEngine.getLearningProgress() %>%</span>
  &nbsp;|&nbsp;
  <span class="label">SSF 指纹:</span>
  <span class="value"><%= BaselineLearningEngine.getLearnedFingerprintCount() %></span>
  &nbsp;|&nbsp;
  <span class="label">CTPG 节点:</span>
  <span class="value"><%= BaselineLearningEngine.getTransitionGraphSize() %></span>
  &nbsp;|&nbsp;
  <span class="label">URL 基线:</span>
  <span class="value"><%= UrlBaselineModel.getBaselineEntries().size() %></span>
  &nbsp;|&nbsp;
  <span class="label">学习时长:</span>
  <span class="value"><%= BaselineLearningEngine.LEARNING_DURATION_MS / 1000 %>s</span>
</div>

<% if (!msg.isEmpty()) { %>
<div class="msg"><%= msg %></div>
<% } %>

<div class="action-bar">
  <form method="post" style="display:inline">
    <input type="hidden" name="action" value="relearn">
    <button type="submit" class="action-btn btn-relearn" onclick="return confirm('确认重新学习？这将清空所有已学习的基线数据。')">重新学习</button>
  </form>
  <% if (BaselineLearningEngine.isLearningPhase()) { %>
  <form method="post" style="display:inline">
    <input type="hidden" name="action" value="force_complete">
    <button type="submit" class="action-btn btn-force">强制结束学习</button>
  </form>
  <% } %>
  <button class="action-btn" style="background:#2c3e50;color:#aaa" onclick="location.reload()">刷新数据</button>
</div>

<div class="tabs">
  <button class="tab-btn active" onclick="switchTab('ssf')">SSF 调用栈指纹</button>
  <button class="tab-btn" onclick="switchTab('ctpg')">CTPG 方法转移图</button>
  <button class="tab-btn" onclick="switchTab('url')">URL 基线</button>
</div>

<!-- SSF Tab -->
<div id="tab-ssf" class="tab-content active">
  <%
    List<StackTemporalEngine.StackFingerprint> fps =
        BaselineLearningEngine.getFingerprintObjects();
    Collections.sort(fps, new Comparator<StackTemporalEngine.StackFingerprint>() {
        public int compare(StackTemporalEngine.StackFingerprint a, StackTemporalEngine.StackFingerprint b) {
            return Integer.compare(b.methodSignatures.size(), a.methodSignatures.size());
        }
    });
  %>
  <p style="color:#888">共 <%= fps.size() %> 条指纹（按调用栈深度降序）</p>
  <div style="max-height:70vh;overflow-y:auto">
  <table>
    <tr><th style="width:30px">#</th><th style="width:100px">Hash</th><th style="width:50px">深度</th><th style="width:60px">频次</th><th style="width:60px">阶段</th><th>调用链</th><th style="width:50px"></th></tr>
    <%
      int idx = 0;
      for (StackTemporalEngine.StackFingerprint fp : fps) {
        idx++;
        long freq = BaselineLearningEngine.getFingerprintFrequency(fp.fingerprintHash);
        boolean isStartup = BaselineLearningEngine.isStartupFingerprint(fp.fingerprintHash);
        boolean isRuntime = BaselineLearningEngine.isRuntimeFingerprint(fp.fingerprintHash);
        String phase = isStartup ? (isRuntime ? "双重" : "启动") : (isRuntime ? "运行" : "-");
    %>
    <tr>
      <td><%= idx %></td>
      <td><%= fp.fingerprintHash %></td>
      <td><%= fp.methodSignatures.size() %></td>
      <td><%= freq %></td>
      <td><%= phase %></td>
      <td>
        <div class="sig-list">
          <% for (String sig : fp.methodSignatures) { %>
            <div class="sig-item"><%= sig %></div>
          <% } %>
        </div>
      </td>
      <td>
        <form method="post" onsubmit="return confirm('确认移除该 SSF 指纹？')">
          <input type="hidden" name="action" value="remove_ssf">
          <input type="hidden" name="hash" value="<%= fp.fingerprintHash %>">
          <button type="submit" class="remove-btn">移除</button>
        </form>
      </td>
    </tr>
    <% } %>
    <% if (fps.isEmpty()) { %>
    <tr><td colspan="7" class="no-data">暂无数据</td></tr>
    <% } %>
  </table>
  </div>
</div>

<!-- CTPG Tab -->
<div id="tab-ctpg" class="tab-content">
  <%
    Map<String, StackTemporalEngine.TransitionNode> graph =
        BaselineLearningEngine.getTransitionGraph();
    List<Map.Entry<String, StackTemporalEngine.TransitionNode>> sortedNodes =
        new ArrayList<Map.Entry<String, StackTemporalEngine.TransitionNode>>(graph.entrySet());
    Collections.sort(sortedNodes, new Comparator<Map.Entry<String, StackTemporalEngine.TransitionNode>>() {
        public int compare(Map.Entry<String, StackTemporalEngine.TransitionNode> a,
                          Map.Entry<String, StackTemporalEngine.TransitionNode> b) {
            return Long.compare(b.getValue().getTotalTransitions(), a.getValue().getTotalTransitions());
        }
    });
  %>
  <p style="color:#888">共 <%= sortedNodes.size() %> 个源方法节点</p>
  <div style="max-height:70vh;overflow-y:auto">
  <table>
    <tr><th style="width:30px">#</th><th>源方法</th><th style="width:70px">总转移</th><th style="width:70px">目标数</th><th>目标方法 (概率)</th><th style="width:50px"></th></tr>
    <%
      int nIdx = 0;
      for (Map.Entry<String, StackTemporalEngine.TransitionNode> entry : sortedNodes) {
        nIdx++;
        StackTemporalEngine.TransitionNode node = entry.getValue();
        Map<String, Double> probs = new TreeMap<String, Double>(node.getAllProbabilities());
        List<Map.Entry<String, Double>> sortedTargets = new ArrayList<Map.Entry<String, Double>>(probs.entrySet());
        Collections.sort(sortedTargets, new Comparator<Map.Entry<String, Double>>() {
            public int compare(Map.Entry<String, Double> a, Map.Entry<String, Double> b) {
                return Double.compare(b.getValue(), a.getValue());
            }
        });
    %>
    <tr>
      <td><%= nIdx %></td>
      <td style="color:#00d4ff"><%= node.sourceMethod %></td>
      <td><%= node.getTotalTransitions() %></td>
      <td><%= probs.size() %></td>
      <td>
        <% for (Map.Entry<String, Double> t : sortedTargets) { %>
          <div class="sig-item" style="display:flex;justify-content:space-between">
            <span><%= t.getKey() %></span>
            <span style="color:#f1c40f"><%= String.format("%.1f%%", t.getValue() * 100) %></span>
            <% if (t.getValue() < 0.01) { %>
            <form method="post" style="display:inline;margin-left:8px">
              <input type="hidden" name="action" value="remove_ctpg">
              <input type="hidden" name="source" value="<%= node.sourceMethod %>">
              <input type="hidden" name="target" value="<%= t.getKey() %>">
              <button type="submit" class="remove-btn" style="font-size:10px;padding:1px 6px">移除</button>
            </form>
            <% } %>
          </div>
        <% } %>
      </td>
      <td></td>
    </tr>
    <% } %>
    <% if (sortedNodes.isEmpty()) { %>
    <tr><td colspan="6" class="no-data">暂无数据</td></tr>
    <% } %>
  </table>
  </div>
</div>

<!-- URL Tab -->
<div id="tab-url" class="tab-content">
  <%
    Map<String, UrlBaselineModel.UrlBaseline> urlEntries =
        UrlBaselineModel.getBaselineEntries();
    List<Map.Entry<String, UrlBaselineModel.UrlBaseline>> sortedUrls =
        new ArrayList<Map.Entry<String, UrlBaselineModel.UrlBaseline>>(urlEntries.entrySet());
    Collections.sort(sortedUrls, new Comparator<Map.Entry<String, UrlBaselineModel.UrlBaseline>>() {
        public int compare(Map.Entry<String, UrlBaselineModel.UrlBaseline> a,
                          Map.Entry<String, UrlBaselineModel.UrlBaseline> b) {
            return Long.compare(b.getValue().totalVisits.get(), a.getValue().totalVisits.get());
        }
    });
  %>
  <p style="color:#888">共 <%= sortedUrls.size() %> 条基线路径（总请求数: <%= UrlBaselineModel.getTotalUrlsLearned() %>）</p>
  <div style="max-height:70vh;overflow-y:auto">
  <table>
    <tr><th style="width:30px">#</th><th>路径</th><th style="width:70px">访问次数</th><th style="width:80px">速率/min</th><th>参数名</th><th style="width:50px"></th></tr>
    <%
      int uIdx = 0;
      for (Map.Entry<String, UrlBaselineModel.UrlBaseline> entry : sortedUrls) {
        uIdx++;
        UrlBaselineModel.UrlBaseline ub = entry.getValue();
    %>
    <tr>
      <td><%= uIdx %></td>
      <td style="color:#00d4ff"><%= ub.path %></td>
      <td><%= ub.totalVisits.get() %></td>
      <td><%= String.format("%.1f", ub.visitsPerMinute()) %></td>
      <td>
        <% for (String pk : ub.paramKeys) { %>
          <span class="params"><%= pk %></span>&nbsp;
        <% } %>
      </td>
      <td>
        <form method="post" onsubmit="return confirm('确认移除该 URL 基线路径？后续访问将触发新URL告警。')">
          <input type="hidden" name="action" value="remove_url">
          <input type="hidden" name="path" value="<%= ub.path %>">
          <button type="submit" class="remove-btn">移除</button>
        </form>
      </td>
    </tr>
    <% } %>
    <% if (sortedUrls.isEmpty()) { %>
    <tr><td colspan="6" class="no-data">暂无数据</td></tr>
    <% } %>
  </table>
  </div>
</div>

<script>
function switchTab(tabName) {
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + tabName).classList.add('active');
  document.querySelectorAll('.tab-btn').forEach(el => {
    if (el.textContent.toLowerCase().includes(tabName)) el.classList.add('active');
  });
}
</script>

</body>
</html>
