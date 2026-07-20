package com.defense.rasp.agent;

import java.io.File;
import java.util.HashMap;
import java.util.Map;

/**
 * Agent 运行时配置，解析 -javaagent 参数
 */
public class AgentConfig {

    public enum BlockMode {
        MONITOR("monitor"),
        BLOCK("block");

        private final String value;
        BlockMode(String value) { this.value = value; }
        
        public static BlockMode fromString(String s) {
            if (s == null) return MONITOR;
            for (BlockMode m : values()) {
                if (m.value.equalsIgnoreCase(s.trim())) return m;
            }
            return MONITOR;
        }
    }

    private static BlockMode blockMode = BlockMode.MONITOR;
    private static long learningDurationMs = 300_000;
    private static boolean debugLogEnabled = false;
    private static boolean verboseInfoEnabled = false;
    private static String managerUrl = null;
    private static String managerToken = null;
    private static String forwardType = null;
    private static String forwardSyslogHost = "localhost";
    private static int forwardSyslogPort = 514;
    private static String forwardAppName = "";
    private static String baselineFilePath = null;
    private static int fpBanThreshold = 10;
    private static int fpBanWindowSec = 60;
    private static int fpBanDurationSec = 300;
    private static int correlationWindowSec = 300;
    private static int correlationThreshold = 150;
    private static String rawAgentArgs = null;

    public static BlockMode getBlockMode() { return blockMode; }
    public static long getLearningDurationMs() { return learningDurationMs; }
    public static boolean isDebugLogEnabled() { return debugLogEnabled; }
    public static boolean isVerboseInfoEnabled() { return verboseInfoEnabled; }
    public static String getManagerUrl() { return managerUrl; }
    public static String getManagerToken() { return managerToken; }

    public static String getConfigJson() {
        StringBuilder sb = new StringBuilder(512);
        sb.append("{");
        sb.append("\"block.mode\":\"").append(blockMode.name()).append("\",");
        sb.append("\"learning.duration\":").append(learningDurationMs).append(",");
        sb.append("\"debug.log\":").append(debugLogEnabled).append(",");
        sb.append("\"fp.ban.threshold\":").append(fpBanThreshold).append(",");
        sb.append("\"fp.ban.window\":").append(fpBanWindowSec).append(",");
        sb.append("\"fp.ban.duration\":").append(fpBanDurationSec).append(",");
        if (forwardType != null) {
            sb.append("\"forward.type\":\"").append(escapeJson(forwardType)).append("\",");
            sb.append("\"forward.syslog.host\":\"").append(escapeJson(forwardSyslogHost)).append("\",");
            sb.append("\"forward.syslog.port\":").append(forwardSyslogPort).append(",");
            sb.append("\"forward.app.name\":\"").append(escapeJson(forwardAppName)).append("\",");
        }
        sb.append("\"correlation.window\":").append(correlationWindowSec).append(",");
        sb.append("\"correlation.threshold\":").append(correlationThreshold);
        if (baselineFilePath != null) {
            sb.append(",\"baseline.file\":\"").append(escapeJson(baselineFilePath)).append("\"");
        }
        sb.append("}");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static void parseArgs(String agentArgs) {
        rawAgentArgs = agentArgs;
        String defaultPath = getDefaultBaselinePath();
        com.defense.rasp.stackmodel.BaselineLearningEngine.setBaselineFilePath(defaultPath);

        if (agentArgs == null || agentArgs.isEmpty()) {
            System.out.println("[StackAnomalyDetector] 基线文件路径(默认): " + defaultPath);
            System.out.println("[StackAnomalyDetector] 配置加载完成 - 阻断模式: " + blockMode +
                    ", 学习时长: " + learningDurationMs + "ms" +
                    ", debug日志: " + debugLogEnabled +
                    ", 详细INFO: " + verboseInfoEnabled);
            return;
        }

        Map<String, String> params = new HashMap<>();
        for (String pair : agentArgs.split("[,;]")) {
            String[] kv = pair.split("=", 2);
            if (kv.length == 2) {
                params.put(kv[0].trim(), kv[1].trim());
            }
        }

        if (params.containsKey("block.mode")) {
            blockMode = BlockMode.fromString(params.get("block.mode"));
        }

        if (params.containsKey("learning.duration")) {
            try {
                learningDurationMs = Long.parseLong(params.get("learning.duration"));
                com.defense.rasp.stackmodel.BaselineLearningEngine.LEARNING_DURATION_MS = learningDurationMs;
            } catch (NumberFormatException e) {
                System.out.println("[StackAnomalyDetector] 无效的学习时长参数: " + params.get("learning.duration") + "，使用默认值 300000ms");
            }
        }

        if (params.containsKey("debug.log")) {
            debugLogEnabled = Boolean.parseBoolean(params.get("debug.log"));
        }

        if (params.containsKey("verbose.info")) {
            verboseInfoEnabled = Boolean.parseBoolean(params.get("verbose.info"));
        }

        if (params.containsKey("baseline.report")) {
            boolean enabled = Boolean.parseBoolean(params.get("baseline.report"));
            com.defense.rasp.stackmodel.BaselineLearningEngine.setBaselineReportEnabled(enabled);
        }

        if (params.containsKey("url.param.threshold")) {
            try {
                int threshold = Integer.parseInt(params.get("url.param.threshold"));
                if (threshold >= 100 && threshold <= 1000) {
                    com.defense.rasp.stackmodel.UrlBaselineModel.setParamLengthThresholdPercent(threshold);
                    System.out.println("[StackAnomalyDetector] URL参数值长度阈值: " + threshold + "%");
                } else {
                    System.out.println("[StackAnomalyDetector] URL参数值长度阈值超出范围(100-1000): " + threshold + "，使用默认 150");
                }
            } catch (NumberFormatException e) {
                System.out.println("[StackAnomalyDetector] 无效的URL参数阈值: " + params.get("url.param.threshold") + "，使用默认 150");
            }
        }

        if (params.containsKey("url.freq.threshold")) {
            try {
                double threshold = Double.parseDouble(params.get("url.freq.threshold"));
                if (threshold >= 1.0 && threshold <= 10.0) {
                    com.defense.rasp.stackmodel.UrlBaselineModel.setFrequencyThresholdMultiplier(threshold);
                    System.out.println("[StackAnomalyDetector] URL频率阈值: " + threshold + "x");
                } else {
                    System.out.println("[StackAnomalyDetector] URL频率阈值超出范围(1.0-10.0): " + threshold + "，使用默认 1.5");
                }
            } catch (NumberFormatException e) {
                System.out.println("[StackAnomalyDetector] 无效的URL频率阈值: " + params.get("url.freq.threshold") + "，使用默认 1.5");
            }
        }

        if (params.containsKey("forward.type")) {
            String ft = params.get("forward.type");
            forwardType = ft;
            String app = params.containsKey("forward.app.name") ? params.get("forward.app.name") : "";
            forwardAppName = app;
            String host = params.containsKey("forward.syslog.host") ? params.get("forward.syslog.host") : "localhost";
            forwardSyslogHost = host;
            int port = 514;
            if (params.containsKey("forward.syslog.port")) {
                try { port = Integer.parseInt(params.get("forward.syslog.port")); } catch (NumberFormatException ignored) {}
            }
            forwardSyslogPort = port;
            com.defense.rasp.forward.ForwardManager.init(ft, app, host, port);
        }

        if (params.containsKey("baseline.file")) {
            String path = params.get("baseline.file");
            if (path != null && !path.isEmpty() && !"none".equalsIgnoreCase(path) && !"false".equalsIgnoreCase(path)) {
                baselineFilePath = path;
                com.defense.rasp.stackmodel.BaselineLearningEngine.setBaselineFilePath(path);
                System.out.println("[StackAnomalyDetector] 基线文件路径: " + path);
            } else {
                baselineFilePath = null;
                com.defense.rasp.stackmodel.BaselineLearningEngine.setBaselineFilePath(null);
                System.out.println("[StackAnomalyDetector] 基线持久化已禁用");
            }
        } else {
            baselineFilePath = defaultPath;
            System.out.println("[StackAnomalyDetector] 基线文件路径(默认): " + defaultPath);
        }

        if (params.containsKey("correlation.window")) {
            try {
                int w = Integer.parseInt(params.get("correlation.window"));
                if (w > 0) {
                    correlationWindowSec = w;
                    com.defense.rasp.stackmodel.AttackCorrelationEngine.setWindowSeconds(w);
                    System.out.println("[StackAnomalyDetector] 跨请求关联窗口: " + w + "s");
                }
            } catch (NumberFormatException ignored) {}
        }

        if (params.containsKey("correlation.threshold")) {
            try {
                int t = Integer.parseInt(params.get("correlation.threshold"));
                if (t > 0) {
                    correlationThreshold = t;
                    com.defense.rasp.stackmodel.AttackCorrelationEngine.setScoreThreshold(t);
                    System.out.println("[StackAnomalyDetector] 跨请求关联阈值: " + t);
                }
            } catch (NumberFormatException ignored) {}
        }

        if (params.containsKey("fp.ban.threshold")) {
            try {
                int t = Integer.parseInt(params.get("fp.ban.threshold"));
                if (t > 0) {
                    fpBanThreshold = t;
                    com.defense.rasp.stackmodel.FingerprintBanEngine.setAttackThreshold(t);
                    System.out.println("[StackAnomalyDetector] 指纹封禁阈值: " + t + " 次");
                }
            } catch (NumberFormatException ignored) {}
        }

        if (params.containsKey("fp.ban.window")) {
            try {
                int w = Integer.parseInt(params.get("fp.ban.window"));
                if (w > 0) {
                    fpBanWindowSec = w;
                    com.defense.rasp.stackmodel.FingerprintBanEngine.setAttackWindowMs(w * 1000L);
                    System.out.println("[StackAnomalyDetector] 指纹攻击窗口: " + w + "s");
                }
            } catch (NumberFormatException ignored) {}
        }

        if (params.containsKey("fp.ban.duration")) {
            try {
                int d = Integer.parseInt(params.get("fp.ban.duration"));
                if (d > 0) {
                    fpBanDurationSec = d;
                    com.defense.rasp.stackmodel.FingerprintBanEngine.setBanDurationMs(d * 1000L);
                    System.out.println("[StackAnomalyDetector] 指纹封禁时长: " + d + "s");
                }
            } catch (NumberFormatException ignored) {}
        }

        if (params.containsKey("manager.url")) {
            managerUrl = params.get("manager.url");
            if (managerToken == null) managerToken = "";
            System.out.println("[StackAnomalyDetector] 集中管理地址: " + managerUrl);
        }

        if (params.containsKey("manager.token")) {
            managerToken = params.get("manager.token");
        }

        System.out.println("[StackAnomalyDetector] 配置加载完成 - 阻断模式: " + blockMode + 
                ", 学习时长: " + learningDurationMs + "ms" +
                ", debug日志: " + debugLogEnabled +
                ", 详细INFO: " + verboseInfoEnabled);
    }

    private static String getDefaultBaselinePath() {
        String tmpDir = System.getProperty("java.io.tmpdir");
        if (tmpDir == null || tmpDir.isEmpty()) {
            String os = System.getProperty("os.name", "").toLowerCase();
            tmpDir = os.contains("win") ? "C:\\Windows\\Temp" : "/tmp";
        }
        if (tmpDir.endsWith(File.separator)) {
            tmpDir = tmpDir.substring(0, tmpDir.length() - 1);
        }
        return tmpDir + File.separator + "rasp" + File.separator + "baseline.dat";
    }
}
