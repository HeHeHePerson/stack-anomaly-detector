package com.defense.rasp.stackmodel;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * URL 基线统计模型：学习期统计正常请求 URL 及其参数，
 * 检测期识别新 URL、新参数、频率异常等偏离基线的行为。
 */
public class UrlBaselineModel {

    private static final ConcurrentHashMap<String, UrlBaseline> BASELINE = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, long[]> RECENT_TIMESTAMPS = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> LAST_FREQ_ALARM = new ConcurrentHashMap<>();
    private static final int FREQUENCY_WINDOW_SIZE = 10;
    private static volatile double FREQUENCY_THRESHOLD_MULTIPLIER = 1.5;
    private static volatile int URL_PARAM_LENGTH_THRESHOLD_PERCENT = 150;
    private static final long FREQUENCY_ALARM_COOLDOWN_MS = 30_000;
    private static final Set<String> ALARMED_NEW_URLS = ConcurrentHashMap.newKeySet();
    private static final AtomicLong TOTAL_URLS_LEARNED = new AtomicLong();
    private static volatile boolean learningComplete = false;

    public static class UrlBaseline implements java.io.Serializable {
        private static final long serialVersionUID = 20260706003L;
        public final String path;
        public final AtomicLong totalVisits = new AtomicLong();
        public final Set<String> paramKeys = ConcurrentHashMap.newKeySet();
        public final ConcurrentHashMap<String, Integer> paramMaxLengths = new ConcurrentHashMap<>();
        public long learningDurationMs;

        UrlBaseline(String path, long durationMs) {
            this.path = path;
            this.learningDurationMs = durationMs;
        }

        public double visitsPerMinute() {
            if (learningDurationMs <= 0) return 0;
            return (double) totalVisits.get() / (learningDurationMs / 60000.0);
        }
    }

    public static void finishLearning() {
        learningComplete = true;
        long total = TOTAL_URLS_LEARNED.get();
        AlertLogger.warn("[URL] URL基线学习完成, 基线路径数=" + BASELINE.size()
                + " 总请求数=" + total);
    }

    public static void learnUrl(String uri) {
        if (learningComplete) return;
        if (BaselineLearningEngine.isLearningPhase()
                && System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME
                > BaselineLearningEngine.LEARNING_DURATION_MS) {
            learningComplete = true;
            return;
        }

        String path = normalizePath(uri);
        TOTAL_URLS_LEARNED.incrementAndGet();
        long duration = BaselineLearningEngine.LEARNING_DURATION_MS;

        UrlBaseline baseline = BASELINE.computeIfAbsent(path,
                k -> new UrlBaseline(k, duration));
        baseline.totalVisits.incrementAndGet();

        String query = extractQuery(uri);
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eqIdx = pair.indexOf('=');
                String key = eqIdx >= 0 ? pair.substring(0, eqIdx) : pair;
                String value = eqIdx >= 0 ? pair.substring(eqIdx + 1) : "";
                if (!key.isEmpty()) {
                    baseline.paramKeys.add(key);
                    int valLen = value.length();
                    Integer existing = baseline.paramMaxLengths.get(key);
                    if (existing == null || valLen > existing) {
                        baseline.paramMaxLengths.put(key, valLen);
                    }
                }
            }
        }
    }

    public static void checkUrl(String uri, int status) {
        if (!learningComplete) return;
        if (status < 200 || status >= 400) return;

        String path = normalizePath(uri);
        UrlBaseline baseline = BASELINE.get(path);

        if (baseline == null) {
            if (ALARMED_NEW_URLS.add(path)) {
                AlertLogger.alarm("[URL] 新URL首次出现: " + path);
            }
            return;
        }

        String query = extractQuery(uri);
        if (query != null && !query.isEmpty()) {
            for (String pair : query.split("&")) {
                if (pair.isEmpty()) continue;
                int eqIdx = pair.indexOf('=');
                String key = eqIdx >= 0 ? pair.substring(0, eqIdx) : pair;
                String value = eqIdx >= 0 ? pair.substring(eqIdx + 1) : "";
                if (!key.isEmpty() && !baseline.paramKeys.contains(key)) {
                    AlertLogger.alarm("[URL] 新参数: " + path + " ?" + key + "=...");
                    break;
                }
                if (!key.isEmpty()) {
                    Integer maxLen = baseline.paramMaxLengths.get(key);
                    int valLen = value.length();
                    if (maxLen != null && maxLen > 0 && valLen > maxLen * URL_PARAM_LENGTH_THRESHOLD_PERCENT / 100.0) {
                        AlertLogger.alarm("[URL] 参数值长度超阈值: " + path + " ?" + key
                                + "=" + valLen + " (基线最大=" + maxLen
                                + ", 阈值=" + URL_PARAM_LENGTH_THRESHOLD_PERCENT + "%)");
                    }
                }
            }
        }

        long[] timestamps = RECENT_TIMESTAMPS.computeIfAbsent(path,
                k -> new long[FREQUENCY_WINDOW_SIZE]);
        long now = System.currentTimeMillis();
        System.arraycopy(timestamps, 0, timestamps, 1, FREQUENCY_WINDOW_SIZE - 1);
        timestamps[0] = now;

        long oldest = timestamps[FREQUENCY_WINDOW_SIZE - 1];
        if (oldest > 0) {
            double actualRate = (double) (FREQUENCY_WINDOW_SIZE - 1)
                    / ((now - oldest) / 60000.0);
            double baselineRate = baseline.visitsPerMinute();
            if (baselineRate > 0 && actualRate > baselineRate * FREQUENCY_THRESHOLD_MULTIPLIER) {
                Long lastAlarm = LAST_FREQ_ALARM.get(path);
                if (lastAlarm == null || now - lastAlarm > FREQUENCY_ALARM_COOLDOWN_MS) {
                    LAST_FREQ_ALARM.put(path, now);
                    AlertLogger.alarm("[URL] 访问频率异常: " + path
                            + " (基线=" + String.format("%.1f", baselineRate)
                            + "/min, 当前=" + String.format("%.1f", actualRate)
                            + "/min, 阈值=" + String.format("%.0f", FREQUENCY_THRESHOLD_MULTIPLIER * 100) + "%)");
                }
            }
        }
    }

    static String normalizePath(String uri) {
        if (uri == null) return "/";
        int qIdx = uri.indexOf('?');
        String path = qIdx >= 0 ? uri.substring(0, qIdx) : uri;
        if (path.length() > 1 && path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        return path;
    }

    static String extractQuery(String uri) {
        if (uri == null) return null;
        int qIdx = uri.indexOf('?');
        return qIdx >= 0 && qIdx < uri.length() - 1 ? uri.substring(qIdx + 1) : null;
    }

    // ===== 模型查询与微调接口 =====

    public static Map<String, UrlBaseline> getBaselineEntries() {
        return new LinkedHashMap<>(BASELINE);
    }

    public static long getTotalUrlsLearned() {
        return TOTAL_URLS_LEARNED.get();
    }

    public static boolean isLearningComplete() {
        return learningComplete;
    }

    public static double getFrequencyThresholdMultiplier() {
        return FREQUENCY_THRESHOLD_MULTIPLIER;
    }

    public static void setFrequencyThresholdMultiplier(double multiplier) {
        FREQUENCY_THRESHOLD_MULTIPLIER = multiplier;
    }

    public static int getParamLengthThresholdPercent() {
        return URL_PARAM_LENGTH_THRESHOLD_PERCENT;
    }

    public static void setParamLengthThresholdPercent(int percent) {
        URL_PARAM_LENGTH_THRESHOLD_PERCENT = percent;
    }

    public static boolean removeUrlPath(String path) {
        UrlBaseline removed = BASELINE.remove(path);
        if (removed != null) {
            RECENT_TIMESTAMPS.remove(path);
            LAST_FREQ_ALARM.remove(path);
            AlertLogger.warn("[ModelMgmt] 移除URL基线路径: " + path);
            return true;
        }
        return false;
    }

    public static String getReportSection() {
        StringBuilder sb = new StringBuilder();
        sb.append("--- URL 基线 (URL Profile) ---\n");
        sb.append("总路径数: ").append(BASELINE.size()).append("\n");
        sb.append("总请求数: ").append(TOTAL_URLS_LEARNED.get()).append("\n");
        sb.append("(按访问次数降序)\n\n");

        List<Map.Entry<String, UrlBaseline>> sorted =
                new ArrayList<>(BASELINE.entrySet());
        sorted.sort((a, b) ->
                Long.compare(b.getValue().totalVisits.get(), a.getValue().totalVisits.get()));

        int count = 0;
        for (Map.Entry<String, UrlBaseline> e : sorted) {
            UrlBaseline ub = e.getValue();
            count++;
            if (count > 50) {
                sb.append("  ... (").append(sorted.size() - 50).append(" more)\n");
                break;
            }
            sb.append(String.format("  [%3d] %-60s 访问=%d次 (%.1f/min)  参数=%s  值最大长度=%s\n",
                    count, ub.path, ub.totalVisits.get(),
                    ub.visitsPerMinute(), ub.paramKeys, ub.paramMaxLengths));
        }
        sb.append("\n");
        return sb.toString();
    }

    public static void restoreFrom(Map<String, UrlBaseline> baselines, long totalLearned) {
        BASELINE.clear();
        BASELINE.putAll(baselines);
        TOTAL_URLS_LEARNED.set(totalLearned);
        learningComplete = true;
    }

    public static void reset() {
        BASELINE.clear();
        RECENT_TIMESTAMPS.clear();
        LAST_FREQ_ALARM.clear();
        ALARMED_NEW_URLS.clear();
        TOTAL_URLS_LEARNED.set(0);
        learningComplete = false;
    }
}
