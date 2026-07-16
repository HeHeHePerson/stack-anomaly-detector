package com.defense.rasp.agent;

import com.defense.rasp.stackmodel.AlertLogger;

import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Timer;
import java.util.TimerTask;

public class HeartbeatReporter {

    private static final Timer timer = new Timer("RASP-Heartbeat", true);
    private static volatile String managerUrl;
    private static volatile String agentId;
    private static volatile String hostname;

    public static void start(String url, String id, String host, int intervalSeconds) {
        if (url == null || url.isEmpty()) return;
        managerUrl = url.replaceAll("/$", "");
        agentId = id;
        hostname = host;

        timer.scheduleAtFixedRate(new TimerTask() {
            @Override
            public void run() {
                sendHeartbeat();
            }
        }, 5000, intervalSeconds * 1000L);

        AlertLogger.info("[Heartbeat] 心跳上报已启动, 间隔=" + intervalSeconds + "s, 地址=" + managerUrl);
    }

    public static void stop() {
        timer.cancel();
    }

    private static void sendHeartbeat() {
        if (managerUrl == null || agentId == null) return;
        try {
            String json = String.format(
                "{\"agent_id\":\"%s\",\"hostname\":\"%s\",\"version\":\"1.3.0\"," +
                "\"block_mode\":\"%s\",\"learning_done\":%b," +
                "\"fingerprint_count\":%d,\"alert_count\":%d,\"block_count\":%d," +
                "\"baseline_size\":%d}",
                agentId, hostname,
                AgentConfig.getBlockMode().name(),
                com.defense.rasp.stackmodel.BaselineLearningEngine.isLearningComplete(),
                com.defense.rasp.stackmodel.FingerprintBanEngine.getBannedFingerprints().size(),
                AlertLogger.getAlarmCount(),
                AlertLogger.getBlockCount(),
                com.defense.rasp.stackmodel.BaselineLearningEngine.getBaselineFileSize()
            );

            HttpURLConnection conn = (HttpURLConnection) new URL(managerUrl + "/api/v1/heartbeat").openConnection();
            conn.setRequestMethod("POST");
            conn.setRequestProperty("Content-Type", "application/json");
            conn.setDoOutput(true);
            conn.setConnectTimeout(5000);
            conn.setReadTimeout(5000);

            OutputStream os = conn.getOutputStream();
            os.write(json.getBytes("UTF-8"));
            os.flush();
            os.close();

            int code = conn.getResponseCode();
            if (code == 200) {
                AlertLogger.debug("[Heartbeat] 心跳成功");
            } else {
                AlertLogger.warn("[Heartbeat] 心跳返回 " + code);
            }
            conn.disconnect();
        } catch (Exception e) {
            AlertLogger.debug("[Heartbeat] 心跳失败: " + e.getMessage());
        }
    }
}
