package com.defense.rasp.agent;

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

    public static BlockMode getBlockMode() { return blockMode; }
    public static long getLearningDurationMs() { return learningDurationMs; }
    public static boolean isDebugLogEnabled() { return debugLogEnabled; }
    public static boolean isVerboseInfoEnabled() { return verboseInfoEnabled; }

    public static void parseArgs(String agentArgs) {
        if (agentArgs == null || agentArgs.isEmpty()) return;

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
            String app = params.containsKey("forward.app.name") ? params.get("forward.app.name") : "";
            String host = params.containsKey("forward.syslog.host") ? params.get("forward.syslog.host") : "localhost";
            int port = 514;
            if (params.containsKey("forward.syslog.port")) {
                try { port = Integer.parseInt(params.get("forward.syslog.port")); } catch (NumberFormatException ignored) {}
            }
            com.defense.rasp.forward.ForwardManager.init(ft, app, host, port);
        }

        System.out.println("[StackAnomalyDetector] 配置加载完成 - 阻断模式: " + blockMode + 
                ", 学习时长: " + learningDurationMs + "ms" +
                ", debug日志: " + debugLogEnabled +
                ", 详细INFO: " + verboseInfoEnabled);
    }
}
