package com.defense.rasp.forward;

public class ForwardManager {

    public static final String TYPE_ALERT = "alert";
    public static final String TYPE_MODEL = "model";

    private static volatile Forwarder forwarder;
    private static volatile String appName = "unknown";
    private static volatile boolean enabled = false;
    private static volatile boolean modelReportSent = false;

    public static void init(String type, String app, String host, int port) {
        appName = (app != null && !app.isEmpty()) ? app : "rasp-agent";
        if (type == null || type.isEmpty() || "none".equalsIgnoreCase(type)) {
            enabled = false;
            return;
        }
        switch (type.toLowerCase()) {
            case "syslog":
                forwarder = new SyslogForwarder(host, port);
                break;
            case "kafka":
                forwarder = tryCreateKafkaForwarder();
                break;
            default:
                System.err.println("[ForwardManager] 不支持的转发类型: " + type);
                enabled = false;
                return;
        }
        if (forwarder != null) {
            enabled = true;
            System.out.println("[ForwardManager] 转发已启用 type=" + type + " app=" + appName + " host=" + host + ":" + port);
        } else {
            System.err.println("[ForwardManager] 转发器初始化失败 type=" + type);
            enabled = false;
        }
    }

    private static Forwarder tryCreateKafkaForwarder() {
        try {
            Class<?> clz = Class.forName("com.defense.rasp.forward.KafkaForwarder");
            return (Forwarder) clz.newInstance();
        } catch (Exception e) {
            System.err.println("[ForwardManager] Kafka客户端不可用: " + e.getMessage());
            return null;
        }
    }

    private static String buildHeader(String type) {
        long now = System.currentTimeMillis();
        return "{\"type\":\"" + type + "\",\"app\":\"" + escapeJson(appName)
                + "\",\"timestamp\":\"" + now + "\",";
    }

    public static void sendAlert(String level, String prefix, String message) {
        if (!enabled || forwarder == null) return;
        try {
            String json = buildHeader(TYPE_ALERT)
                    + "\"level\":\"" + escapeJson(level) + "\""
                    + ",\"prefix\":\"" + escapeJson(prefix) + "\""
                    + ",\"message\":\"" + escapeJson(message) + "\"}";
            forwarder.send(json);
        } catch (Exception e) {
            System.err.println("[ForwardManager] 告警转发失败: " + e.getMessage());
        }
    }

    public static void sendModelReport(String ssfSection, String ctpgSection,
                                        String urlSection, int fingerprintCount,
                                        int ctpgSize, int urlPathCount, long totalUrlRequests) {
        if (!enabled || forwarder == null) return;
        if (modelReportSent) return;
        try {
            String json = buildHeader(TYPE_MODEL)
                    + "\"ssf_count\":" + fingerprintCount
                    + ",\"ctpg_size\":" + ctpgSize
                    + ",\"url_path_count\":" + urlPathCount
                    + ",\"url_total_requests\":" + totalUrlRequests
                    + ",\"ssf_fingerprints\":" + ssfSection
                    + ",\"ctpg_transitions\":" + ctpgSection
                    + ",\"url_paths\":" + urlSection + "}";
            forwarder.send(json);
            modelReportSent = true;
        } catch (Exception e) {
            System.err.println("[ForwardManager] 模型报告转发失败: " + e.getMessage());
        }
    }

    public static void resetModelReportFlag() {
        modelReportSent = false;
    }

    public static void shutdown() {
        enabled = false;
        if (forwarder != null) {
            try { forwarder.close(); } catch (Exception ignored) {}
            forwarder = null;
        }
    }

    public static String escapeJson(String s) {
        if (s == null) return "";
        StringBuilder sb = new StringBuilder(s.length() + 10);
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append("\\u").append(String.format("%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }
}
