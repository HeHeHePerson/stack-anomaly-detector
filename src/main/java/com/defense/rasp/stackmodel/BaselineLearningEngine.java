
package com.defense.rasp.stackmodel;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * 基线学习引擎：在应用启动和运行初期学习正常调用模式
 */
public class BaselineLearningEngine {

    /**
     * 正常SSF指纹库（启动期收集）
     */
    private static final Set<Integer> NORMAL_STARTUP_FINGERPRINTS = ConcurrentHashMap.newKeySet();

    /**
     * 正常SSF指纹库（运行期收集，仅来自可信线程）
     */
    private static final Set<Integer> NORMAL_RUNTIME_FINGERPRINTS = ConcurrentHashMap.newKeySet();

    /**
     * 存储完整指纹对象用于相似度计算
     */
    private static final Set<StackTemporalEngine.StackFingerprint> FINGERPRINT_OBJECTS = 
            ConcurrentHashMap.newKeySet();

    /**
     * 正常转移概率阈值：低于此概率的转移视为异常
     */
    private static final double MIN_NORMAL_PROBABILITY = 0.01;

    /**
     * 学习阶段标记
     */
    private static volatile boolean isLearningPhase = true;

    /**
     * 学习期时长（毫秒）- 默认5分钟
     */
    public static volatile long LEARNING_DURATION_MS = 300_000;

    /**
     * 学习开始时间
     */
    public static volatile long LEARNING_START_TIME = System.currentTimeMillis();

    /**
     * 启动期判定阈值（毫秒）- 前2分钟为启动期
     */
    private static volatile long STARTUP_PERIOD_MS = 120_000;

    /**
     * 学习期监控线程池
     */
    private static final ScheduledExecutorService LEARNING_MONITOR = 
            Executors.newSingleThreadScheduledExecutor(r -> {
                Thread t = new Thread(r, "BaselineLearning-Monitor");
                t.setDaemon(true);
                return t;
            });

    static {
        startLearningMonitor();
    }

    private static void startLearningMonitor() {
        LEARNING_MONITOR.scheduleAtFixedRate(() -> {
            if (isLearningPhase) {
                long elapsed = System.currentTimeMillis() - LEARNING_START_TIME;
                if (elapsed > LEARNING_DURATION_MS) {
                    isLearningPhase = false;
                    AlertLogger.info("[BaselineLearning] 基线学习完成，进入检测模式");
                    AlertLogger.info("[BaselineLearning] 学习到的指纹数量: " + 
                            (NORMAL_STARTUP_FINGERPRINTS.size() + NORMAL_RUNTIME_FINGERPRINTS.size()));
                    AlertLogger.info("[BaselineLearning] 转移图大小: " + 
                            StackTemporalEngine.TRANSITION_GRAPH.size());
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    /**
     * 学习一次正常的调用栈
     */
    public static void learnNormalStack(StackTraceElement[] stack, boolean isStartupPhase) {
        AlertLogger.info("[BaselineLearning] learnNormalStack 调用，学习期: " + isLearningPhase);
        
        if (!isLearningPhase) {
            AlertLogger.info("[BaselineLearning] 学习期已结束，跳过学习");
            return;
        }

        if (stack == null || stack.length == 0) {
            AlertLogger.warn("[BaselineLearning] 调用栈为空，跳过学习");
            return;
        }

        // 检查学习期是否结束
        if (System.currentTimeMillis() - LEARNING_START_TIME > LEARNING_DURATION_MS) {
            isLearningPhase = false;
            AlertLogger.info("[BaselineLearning] 基线学习完成，进入检测模式");
            return;
        }

        StackTemporalEngine.StackFingerprint fingerprint =
                new StackTemporalEngine.StackFingerprint(stack);

        AlertLogger.info("[BaselineLearning] 学习指纹: " + fingerprint.fingerprintHash);
        AlertLogger.info("[BaselineLearning] 方法签名数量: " + fingerprint.methodSignatures.size());

        if (isStartupPhase) {
            NORMAL_STARTUP_FINGERPRINTS.add(fingerprint.fingerprintHash);
            AlertLogger.info("[BaselineLearning] 添加到启动期指纹库，当前启动期指纹数: " + NORMAL_STARTUP_FINGERPRINTS.size());
        } else {
            NORMAL_RUNTIME_FINGERPRINTS.add(fingerprint.fingerprintHash);
            AlertLogger.info("[BaselineLearning] 添加到运行期指纹库，当前运行期指纹数: " + NORMAL_RUNTIME_FINGERPRINTS.size());
        }

        // 保存完整指纹对象用于相似度计算
        FINGERPRINT_OBJECTS.add(fingerprint);

        // 学习转移概率
        List<String> sigs = fingerprint.methodSignatures;
        AlertLogger.info("[BaselineLearning] 转移学习 - 方法签名: " + sigs);
        for (int i = 0; i < sigs.size() - 1; i++) {
            String source = sigs.get(i);
            String target = sigs.get(i + 1);

            StackTemporalEngine.TransitionNode node =
                    StackTemporalEngine.TRANSITION_GRAPH.computeIfAbsent(
                            source, k -> new StackTemporalEngine.TransitionNode(source));
            node.recordTransition(target);
        }
        
        AlertLogger.info("[BaselineLearning] 学习完成，转移图大小: " + StackTemporalEngine.TRANSITION_GRAPH.size());
    }

    /**
     * 检测当前调用栈是否偏离基线
     * @return 异常分数（0-100）
     */
    public static int detectAnomaly(StackTraceElement[] stack, String targetFile) {
        return detectAnomalyInternal(stack, targetFile, false);
    }

    /**
     * 强制检测模式（用于测试，忽略学习期）
     * @return 异常分数（0-100）
     */
    public static int forceDetectAnomaly(StackTraceElement[] stack, String targetFile) {
        return detectAnomalyInternal(stack, targetFile, true);
    }

    /**
     * 内部检测逻辑
     * @param forceDetect 是否强制检测（用于测试）
     */
    private static int detectAnomalyInternal(StackTraceElement[] stack, String targetFile, boolean forceDetect) {
        if (isLearningPhase && !forceDetect) {
            long elapsed = System.currentTimeMillis() - LEARNING_START_TIME;
            if (elapsed > LEARNING_DURATION_MS) {
                isLearningPhase = false;
                AlertLogger.info("[BaselineLearning] 基线学习完成，进入检测模式");
            } else {
                learnNormalStack(stack, elapsed < STARTUP_PERIOD_MS);
                return 0;
            }
        }

        int anomalyScore = 0;
        StackTemporalEngine.StackFingerprint current =
                new StackTemporalEngine.StackFingerprint(stack);

        // 1. SSF指纹匹配
        boolean isKnownStartup = NORMAL_STARTUP_FINGERPRINTS.contains(current.fingerprintHash);
        boolean isKnownRuntime = NORMAL_RUNTIME_FINGERPRINTS.contains(current.fingerprintHash);

        if (!isKnownStartup && !isKnownRuntime) {
            anomalyScore += 30;

            // 计算与已知指纹的最大相似度
            double maxSimilarity = computeMaxSimilarity(current);
            if (maxSimilarity < 0.3) {
                anomalyScore += 20;
            }
        }

        // 2. CTPG转移概率检测
        List<String> sigs = current.methodSignatures;
        double minProbability = 1.0;
        String weakestTransition = null;

        for (int i = 0; i < sigs.size() - 1; i++) {
            String source = sigs.get(i);
            String target = sigs.get(i + 1);

            StackTemporalEngine.TransitionNode node =
                    StackTemporalEngine.TRANSITION_GRAPH.get(source);
            if (node == null) {
                minProbability = 0.0;
                weakestTransition = source + " -> " + target + " (未知源)";
                break;
            }

            double prob = node.getProbability(target);
            if (prob < minProbability) {
                minProbability = prob;
                weakestTransition = source + " -> " + target;
            }
        }

        if (minProbability < MIN_NORMAL_PROBABILITY) {
            anomalyScore += 35;
            AlertLogger.alarm("[CTPG] 异常转移: " + weakestTransition +
                    ", 概率=" + minProbability);
        } else if (minProbability < 0.1) {
            anomalyScore += 15;
        }

        // 3. TTT线程轨迹检测
        long threadId = Thread.currentThread().getId();
        StackTemporalEngine.ThreadTrajectory trajectory =
                StackTemporalEngine.getOrCreateTrajectory(threadId, 
                        Thread.currentThread().getName());
        if (trajectory != null) {
            List<String> anomalies = trajectory.detectAnomalies();
            for (String anomaly : anomalies) {
                anomalyScore += 20;
                AlertLogger.alarm("[TTT] 轨迹异常: " + anomaly);
            }
        }

        // 4. 敏感文件访问检测
        if (targetFile != null) {
            anomalyScore += checkSensitiveFileAccess(targetFile);
        }

        // 5. 危险类检测
        anomalyScore += checkDangerousClasses(current);

        return Math.min(anomalyScore, 100);
    }

    /**
     * 计算当前指纹与已知指纹的最大相似度
     * 使用最长公共子序列(LCS)计算相似度
     */
    private static double computeMaxSimilarity(StackTemporalEngine.StackFingerprint current) {
        double maxSimilarity = 0.0;
        List<String> currentSigs = current.methodSignatures;

        for (StackTemporalEngine.StackFingerprint known : FINGERPRINT_OBJECTS) {
            List<String> knownSigs = known.methodSignatures;
            int lcsLength = computeLCSLength(currentSigs, knownSigs);
            double similarity = (double) lcsLength / Math.max(currentSigs.size(), knownSigs.size());
            maxSimilarity = Math.max(maxSimilarity, similarity);
        }

        return maxSimilarity;
    }

    /**
     * 计算两个列表的最长公共子序列长度
     */
    private static int computeLCSLength(List<String> a, List<String> b) {
        int[][] dp = new int[a.size() + 1][b.size() + 1];

        for (int i = 1; i <= a.size(); i++) {
            for (int j = 1; j <= b.size(); j++) {
                if (a.get(i - 1).equals(b.get(j - 1))) {
                    dp[i][j] = dp[i - 1][j - 1] + 1;
                } else {
                    dp[i][j] = Math.max(dp[i - 1][j], dp[i][j - 1]);
                }
            }
        }

        return dp[a.size()][b.size()];
    }

    /**
     * 检查是否处于学习期
     */
    public static boolean isLearningPhase() {
        return isLearningPhase;
    }

    /**
     * 获取学习进度（0-100）
     */
    public static int getLearningProgress() {
        if (!isLearningPhase) return 100;
        long elapsed = System.currentTimeMillis() - LEARNING_START_TIME;
        return (int) Math.min((elapsed * 100) / LEARNING_DURATION_MS, 100);
    }

    /**
     * 获取已学习的指纹数量
     */
    public static int getLearnedFingerprintCount() {
        return NORMAL_STARTUP_FINGERPRINTS.size() + NORMAL_RUNTIME_FINGERPRINTS.size();
    }

    /**
     * 获取转移图节点数量
     */
    public static int getTransitionGraphSize() {
        return StackTemporalEngine.TRANSITION_GRAPH.size();
    }

    /**
     * 重置学习状态（用于测试或重新学习）
     */
    public static void resetLearning() {
        NORMAL_STARTUP_FINGERPRINTS.clear();
        NORMAL_RUNTIME_FINGERPRINTS.clear();
        FINGERPRINT_OBJECTS.clear();
        StackTemporalEngine.TRANSITION_GRAPH.clear();
        isLearningPhase = true;
        LEARNING_START_TIME = System.currentTimeMillis();
        AlertLogger.info("[BaselineLearning] 学习状态已重置");
    }

    /**
     * 关闭学习期监控（用于测试）
     */
    public static void shutdownLearningMonitor() {
        LEARNING_MONITOR.shutdown();
    }

    /**
     * 设置学习期时长（用于测试）
     * @param durationMs 学习期时长，单位毫秒
     */
    public static void setLearningDuration(long durationMs) {
        LEARNING_DURATION_MS = durationMs;
    }

    /**
     * 设置启动期阈值（用于测试）
     * @param periodMs 启动期阈值，单位毫秒
     */
    public static void setStartupPeriod(long periodMs) {
        STARTUP_PERIOD_MS = periodMs;
    }

    /**
     * 恢复默认学习期配置
     */
    public static void restoreDefaultConfig() {
        LEARNING_DURATION_MS = 300_000;
        STARTUP_PERIOD_MS = 120_000;
    }

    /**
     * 检测敏感文件访问
     * @param filePath 文件路径
     * @return 异常分数增量
     */
    private static int checkSensitiveFileAccess(String filePath) {
        if (filePath == null) return 0;
        
        String lowerPath = filePath.toLowerCase();
        
        String[] sensitivePaths = {
            "tomcat-users.xml",
            "web.xml",
            "server.xml",
            "context.xml",
            "manager.xml",
            "host-manager.xml",
            ".properties",
            ".yml",
            ".yaml",
            ".xml",
            ".conf",
            ".ini",
            ".key",
            ".pem",
            ".crt",
            ".keystore",
            ".truststore",
            "passwd",
            "shadow",
            "etc/",
            "/etc/",
            "conf/",
            "/conf/",
            "tomcat/",
            "/tomcat/",
            "mysql",
            "postgres",
            "database",
            "redis",
            "rabbitmq"
        };
        
        for (String sensitive : sensitivePaths) {
            if (lowerPath.contains(sensitive)) {
                AlertLogger.alarm("[SensitiveFile] 敏感文件访问: " + filePath);
                return 30;
            }
        }
        
        return 0;
    }

    /**
     * 检测危险类调用
     * @param fingerprint 当前指纹
     * @return 异常分数增量
     */
    private static int checkDangerousClasses(StackTemporalEngine.StackFingerprint fingerprint) {
        int score = 0;
        
        String[] dangerousClasses = {
            "java.lang.reflect.Method.invoke",
            "java.lang.reflect.Constructor.newInstance",
            "java.lang.Runtime.exec",
            "java.lang.ProcessBuilder",
            "java.lang.ClassLoader.defineClass",
            "java.lang.ClassLoader.loadClass",
            "java.lang.Class.forName",
            "sun.misc.Unsafe",
            "java.nio.file.Files",
            "java.io.FileInputStream",
            "java.io.FileOutputStream",
            "java.io.FileReader",
            "java.io.FileWriter",
            "java.nio.channels.FileChannel",
            "javax.script.ScriptEngine",
            "groovy.lang.GroovyShell",
            "org.mozilla.javascript.Context"
        };
        
        boolean hasReflection = false;
        boolean hasFileIO = false;
        
        for (String sig : fingerprint.methodSignatures) {
            if (sig.contains("reflect") || sig.contains("Method.invoke") || sig.contains("Constructor.newInstance")) {
                hasReflection = true;
            }
            if (sig.contains("File") || sig.contains("Files") || sig.contains("NIO") || sig.contains("nio")) {
                hasFileIO = true;
            }
            
            for (String dangerous : dangerousClasses) {
                if (sig.contains(dangerous)) {
                    score += 20;
                    AlertLogger.alarm("[DangerousClass] 危险类调用: " + sig);
                    break;
                }
            }
        }
        
        if (hasReflection && hasFileIO) {
            score += 30;
            AlertLogger.alarm("[MemoryHorse] 检测到反射调用文件操作，可能为内存马行为");
        }
        
        return score;
    }
}
