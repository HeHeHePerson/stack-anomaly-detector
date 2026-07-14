package com.defense.rasp.stackmodel;

import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * 浏览器指纹封禁引擎：
 * 1. 统计同一指纹在时间窗口内的攻击次数
 * 2. 超过阈值后封禁该指纹一段时间
 * 3. 封禁期间该指纹的所有请求直接返回友好页面
 */
public class FingerprintBanEngine {

    private static final ConcurrentHashMap<String, CopyOnWriteArrayList<Long>> ATTACK_HISTORY = new ConcurrentHashMap<>();
    private static final ConcurrentHashMap<String, Long> BANNED = new ConcurrentHashMap<>();

    private static volatile int attackThreshold = 10;
    private static volatile long attackWindowMs = 60_000;
    private static volatile long banDurationMs = 300_000;

    static {
        Thread cleaner = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(60_000);
                    long now = System.currentTimeMillis();
                    ATTACK_HISTORY.values().forEach(ts -> ts.removeIf(t -> now - t > attackWindowMs));
                    ATTACK_HISTORY.entrySet().removeIf(e -> e.getValue().isEmpty());
                    BANNED.entrySet().removeIf(e -> now > e.getValue());
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "FP-Ban-Cleaner");
        cleaner.setDaemon(true);
        cleaner.start();
    }

    public static void recordAttack(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) return;
        long now = System.currentTimeMillis();

        CopyOnWriteArrayList<Long> timestamps = ATTACK_HISTORY.computeIfAbsent(
                fingerprint, k -> new CopyOnWriteArrayList<Long>());
        timestamps.add(now);
        timestamps.removeIf(ts -> now - ts > attackWindowMs);

        if (timestamps.size() >= attackThreshold) {
            long banUntil = now + banDurationMs;
            BANNED.put(fingerprint, banUntil);
            ATTACK_HISTORY.remove(fingerprint);
            AlertLogger.warn("[FP-BAN] 指纹已封禁: " + fingerprint.substring(0, Math.min(16, fingerprint.length()))
                    + "... 封禁至 " + new java.util.Date(banUntil));
        }
    }

    public static boolean isBanned(String fingerprint) {
        if (fingerprint == null || fingerprint.isEmpty()) return false;
        Long banUntil = BANNED.get(fingerprint);
        if (banUntil == null) return false;
        if (System.currentTimeMillis() > banUntil) {
            BANNED.remove(fingerprint);
            return false;
        }
        return true;
    }

    public static long getBanRemainingSeconds(String fingerprint) {
        Long banUntil = BANNED.get(fingerprint);
        if (banUntil == null) return 0;
        return Math.max(0, (banUntil - System.currentTimeMillis()) / 1000);
    }

    public static List<String> getBannedFingerprints() {
        long now = System.currentTimeMillis();
        BANNED.entrySet().removeIf(e -> now > e.getValue());
        return new java.util.ArrayList<>(BANNED.keySet());
    }

    public static boolean unban(String fingerprint) {
        return BANNED.remove(fingerprint) != null;
    }

    // ===== 参数配置 =====

    public static void setAttackThreshold(int n) { if (n > 0) attackThreshold = n; }
    public static void setAttackWindowMs(long ms) { if (ms > 0) attackWindowMs = ms; }
    public static void setBanDurationMs(long ms) { if (ms > 0) banDurationMs = ms; }

    public static int getAttackThreshold() { return attackThreshold; }
    public static long getAttackWindowMs() { return attackWindowMs; }
    public static long getBanDurationMs() { return banDurationMs; }
}
