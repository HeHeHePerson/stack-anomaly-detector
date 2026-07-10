package com.defense.rasp.stackmodel;

import java.util.concurrent.ConcurrentHashMap;

/**
 * 跨请求攻击关联引擎：按客户端 IP 在时间窗口内累积风险分数，
 * 当累计分数超过阈值时触发 [CORRELATION] 告警，防止攻击者将恶意操作拆分到多次请求中规避检测。
 */
public class AttackCorrelationEngine {

    private static final ConcurrentHashMap<String, WindowState> WINDOWS = new ConcurrentHashMap<>();
    private static volatile int windowSeconds = 60;
    private static volatile int scoreThreshold = 100;

    private static class WindowState {
        final long windowStart;
        int totalScore;
        WindowState(long start, int score) {
            this.windowStart = start;
            this.totalScore = score;
        }
    }

    /**
     * 记录一次风险分数事件。
     *
     * @param remoteAddr 客户端 IP 地址
     * @param score      本次检测的风险分数
     * @return true 表示窗口内累计分数超过阈值，应触发关联告警
     */
    public static boolean recordScore(String remoteAddr, int score) {
        if (remoteAddr == null || score <= 0) return false;
        long now = System.currentTimeMillis();

        WindowState state = WINDOWS.compute(remoteAddr, (k, v) -> {
            if (v == null || (now - v.windowStart) > windowSeconds * 1000L) {
                return new WindowState(now, score);
            }
            v.totalScore += score;
            return v;
        });

        if (state.totalScore >= scoreThreshold) {
            WINDOWS.remove(remoteAddr);
            return true;
        }
        return false;
    }

    public static void setWindowSeconds(int s) {
        if (s > 0) windowSeconds = s;
    }

    public static void setScoreThreshold(int t) {
        if (t > 0) scoreThreshold = t;
    }

    public static int getWindowSeconds() {
        return windowSeconds;
    }

    public static int getScoreThreshold() {
        return scoreThreshold;
    }
}
