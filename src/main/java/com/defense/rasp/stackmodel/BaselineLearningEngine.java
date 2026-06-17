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

    private static final Set<Integer> NORMAL_STARTUP_FINGERPRINTS = ConcurrentHashMap.newKeySet();
    private static final Set<Integer> NORMAL_RUNTIME_FINGERPRINTS = ConcurrentHashMap.newKeySet();
    private static final Set<StackTemporalEngine.StackFingerprint> FINGERPRINT_OBJECTS = 
            ConcurrentHashMap.newKeySet();
    private static final double MIN_NORMAL_PROBABILITY = 0.01;
    private static volatile boolean isLearningPhase = true;
    public static volatile long LEARNING_DURATION_MS = 300_000;
    public static volatile long LEARNING_START_TIME = System.currentTimeMillis();
    private static volatile long STARTUP_PERIOD_MS = 120_000;

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
                    int totalFingerprints = NORMAL_STARTUP_FINGERPRINTS.size() + NORMAL_RUNTIME_FINGERPRINTS.size();
                    int graphSize = StackTemporalEngine.TRANSITION_GRAPH.size();
                    AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式。指纹数=" +
                            totalFingerprints + " 转移图大小=" + graphSize);
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    public static void learnNormalStack(StackTraceElement[] stack, boolean isStartupPhase) {
        if (!isLearningPhase) return;
        if (stack == null || stack.length == 0) return;

        if (System.currentTimeMillis() - LEARNING_START_TIME > LEARNING_DURATION_MS) {
            isLearningPhase = false;
            AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式");
            return;
        }

        StackTemporalEngine.StackFingerprint fingerprint =
                new StackTemporalEngine.StackFingerprint(stack);

        AlertLogger.debug("[BaselineLearning] 指纹=" + fingerprint.fingerprintHash +
                " 方法数=" + fingerprint.methodSignatures.size());

        if (isStartupPhase) {
            NORMAL_STARTUP_FINGERPRINTS.add(fingerprint.fingerprintHash);
        } else {
            NORMAL_RUNTIME_FINGERPRINTS.add(fingerprint.fingerprintHash);
        }

        FINGERPRINT_OBJECTS.add(fingerprint);

        List<String> sigs = fingerprint.methodSignatures;
        for (int i = 0; i < sigs.size() - 1; i++) {
            String source = sigs.get(i);
            String target = sigs.get(i + 1);
            StackTemporalEngine.TransitionNode node =
                    StackTemporalEngine.TRANSITION_GRAPH.computeIfAbsent(
                            source, k -> new StackTemporalEngine.TransitionNode(source));
            node.recordTransition(target);
        }

        AlertLogger.countLearnSkipped();
    }

    public static int detectAnomaly(StackTraceElement[] stack, String targetFile) {
        return detectAnomalyInternal(stack, targetFile, false);
    }

    public static int forceDetectAnomaly(StackTraceElement[] stack, String targetFile) {
        return detectAnomalyInternal(stack, targetFile, true);
    }

    private static int detectAnomalyInternal(StackTraceElement[] stack, String targetFile, boolean forceDetect) {
        if (isLearningPhase && !forceDetect) {
            long elapsed = System.currentTimeMillis() - LEARNING_START_TIME;
            if (elapsed > LEARNING_DURATION_MS) {
                isLearningPhase = false;
                AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式");
            } else {
                learnNormalStack(stack, elapsed < STARTUP_PERIOD_MS);
                return 0;
            }
        }

        int anomalyScore = 0;
        StackTemporalEngine.StackFingerprint current =
                new StackTemporalEngine.StackFingerprint(stack);

        boolean isKnownStartup = NORMAL_STARTUP_FINGERPRINTS.contains(current.fingerprintHash);
        boolean isKnownRuntime = NORMAL_RUNTIME_FINGERPRINTS.contains(current.fingerprintHash);

        if (!isKnownStartup && !isKnownRuntime) {
            anomalyScore += 30;
            double maxSimilarity = computeMaxSimilarity(current);
            if (maxSimilarity < 0.3) {
                anomalyScore += 20;
            }
            AlertLogger.debug("[SSF] 未知指纹=" + current.fingerprintHash +
                    " 最大相似度=" + String.format("%.2f", maxSimilarity));
        }

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
                    " 概率=" + String.format("%.4f", minProbability));
        } else if (minProbability < 0.1) {
            anomalyScore += 15;
            AlertLogger.debug("[CTPG] 低概率转移: " + weakestTransition +
                    " 概率=" + String.format("%.4f", minProbability));
        }

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

        if (targetFile != null) {
            int fileScore = checkSensitiveFileAccess(targetFile);
            anomalyScore += fileScore;
        }

        anomalyScore += checkDangerousClasses(current);

        if (anomalyScore > 0) {
            AlertLogger.debug("[检测] 总分=" + anomalyScore + " 文件=" + targetFile +
                    " SSF=" + current.fingerprintHash);
        }

        return Math.min(anomalyScore, 100);
    }

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

    public static boolean isLearningPhase() {
        return isLearningPhase;
    }

    public static int getLearningProgress() {
        if (!isLearningPhase) return 100;
        long elapsed = System.currentTimeMillis() - LEARNING_START_TIME;
        return (int) Math.min((elapsed * 100) / LEARNING_DURATION_MS, 100);
    }

    public static int getLearnedFingerprintCount() {
        return NORMAL_STARTUP_FINGERPRINTS.size() + NORMAL_RUNTIME_FINGERPRINTS.size();
    }

    public static int getTransitionGraphSize() {
        return StackTemporalEngine.TRANSITION_GRAPH.size();
    }

    public static void resetLearning() {
        NORMAL_STARTUP_FINGERPRINTS.clear();
        NORMAL_RUNTIME_FINGERPRINTS.clear();
        FINGERPRINT_OBJECTS.clear();
        StackTemporalEngine.TRANSITION_GRAPH.clear();
        isLearningPhase = true;
        LEARNING_START_TIME = System.currentTimeMillis();
        AlertLogger.warn("[BaselineLearning] 学习状态已重置");
    }

    public static void shutdownLearningMonitor() {
        LEARNING_MONITOR.shutdown();
    }

    public static void setLearningDuration(long durationMs) {
        LEARNING_DURATION_MS = durationMs;
    }

    public static void setStartupPeriod(long periodMs) {
        STARTUP_PERIOD_MS = periodMs;
    }

    public static void restoreDefaultConfig() {
        LEARNING_DURATION_MS = 300_000;
        STARTUP_PERIOD_MS = 120_000;
    }

    private static int checkSensitiveFileAccess(String filePath) {
        if (filePath == null) return 0;
        String lowerPath = filePath.toLowerCase();
        String[] sensitivePaths = {
            "tomcat-users.xml", "web.xml", "server.xml", "context.xml",
            "manager.xml", "host-manager.xml", ".properties", ".yml", ".yaml",
            ".xml", ".conf", ".ini", ".key", ".pem", ".crt",
            ".keystore", ".truststore", "passwd", "shadow",
            "etc/", "/etc/", "conf/", "/conf/",
            "tomcat/", "/tomcat/", "mysql", "postgres", "database",
            "redis", "rabbitmq"
        };
        for (String sensitive : sensitivePaths) {
            if (lowerPath.contains(sensitive)) {
                AlertLogger.alarm("[SensitiveFile] 敏感文件访问: " + filePath);
                return 30;
            }
        }
        return 0;
    }

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
