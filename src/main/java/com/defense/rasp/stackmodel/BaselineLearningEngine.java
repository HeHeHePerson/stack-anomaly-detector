package com.defense.rasp.stackmodel;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private static final ConcurrentHashMap<Integer, Long> FINGERPRINT_FREQUENCIES = 
            new ConcurrentHashMap<>();
    private static final double MIN_NORMAL_PROBABILITY = 0.01;
    private static volatile boolean isLearningPhase = true;
    public static volatile long LEARNING_DURATION_MS = 300_000;
    public static volatile long LEARNING_START_TIME = System.currentTimeMillis();
    private static volatile long STARTUP_PERIOD_MS = 120_000;
    private static volatile boolean baselineReportEnabled = true;
    private static volatile boolean baselineReportGenerated = false;

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
                    UrlBaselineModel.finishLearning();
                    int totalFingerprints = NORMAL_STARTUP_FINGERPRINTS.size() + NORMAL_RUNTIME_FINGERPRINTS.size();
                    int graphSize = StackTemporalEngine.TRANSITION_GRAPH.size();
                    AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式。指纹数=" +
                            totalFingerprints + " 转移图大小=" + graphSize);
                    generateReportIfNeeded();
                    forwardModelReport();
                    saveBaseline();
                }
            }
        }, 30, 30, TimeUnit.SECONDS);
    }

    public static void learnNormalStack(StackTraceElement[] stack, boolean isStartupPhase) {
        if (!isLearningPhase) return;
        if (stack == null || stack.length == 0) return;

        if (System.currentTimeMillis() - LEARNING_START_TIME > LEARNING_DURATION_MS) {
            isLearningPhase = false;
            UrlBaselineModel.finishLearning();
            AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式");
            generateReportIfNeeded();
            forwardModelReport();
            saveBaseline();
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
        FINGERPRINT_FREQUENCIES.merge(fingerprint.fingerprintHash, 1L, Long::sum);

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
                UrlBaselineModel.finishLearning();
                AlertLogger.warn("[BaselineLearning] 基线学习完成，进入检测模式");
                forwardModelReport();
                saveBaseline();
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

    // ===== 模型查询与微调接口 =====

    public static List<StackTemporalEngine.StackFingerprint> getFingerprintObjects() {
        return new ArrayList<>(FINGERPRINT_OBJECTS);
    }

    public static long getFingerprintFrequency(int hash) {
        return FINGERPRINT_FREQUENCIES.getOrDefault(hash, 0L);
    }

    public static boolean isStartupFingerprint(int hash) {
        return NORMAL_STARTUP_FINGERPRINTS.contains(hash);
    }

    public static boolean isRuntimeFingerprint(int hash) {
        return NORMAL_RUNTIME_FINGERPRINTS.contains(hash);
    }

    public static boolean removeFingerprint(int hash) {
        boolean removed = false;
        if (NORMAL_STARTUP_FINGERPRINTS.remove(hash)) removed = true;
        if (NORMAL_RUNTIME_FINGERPRINTS.remove(hash)) removed = true;
        if (removed) {
            FINGERPRINT_OBJECTS.removeIf(fp -> fp.fingerprintHash == hash);
            FINGERPRINT_FREQUENCIES.remove(hash);
            AlertLogger.warn("[ModelMgmt] 移除SSF指纹: " + hash);
        }
        return removed;
    }

    public static Map<String, StackTemporalEngine.TransitionNode> getTransitionGraph() {
        return new HashMap<>(StackTemporalEngine.TRANSITION_GRAPH);
    }

    public static boolean removeTransition(String sourceMethod, String targetMethod) {
        StackTemporalEngine.TransitionNode node =
                StackTemporalEngine.TRANSITION_GRAPH.get(sourceMethod);
        if (node == null) return false;
        boolean removed = node.removeTarget(targetMethod);
        if (removed) {
            AlertLogger.warn("[ModelMgmt] 移除CTPG转移: " + sourceMethod + " -> " + targetMethod);
        }
        return removed;
    }

    public static boolean forceLearningComplete() {
        if (isLearningPhase) {
            isLearningPhase = false;
            UrlBaselineModel.finishLearning();
            AlertLogger.warn("[ModelMgmt] 学习阶段被手动结束");
            forwardModelReport();
            saveBaseline();
            return true;
        }
        return false;
    }

    public static void resetLearning() {
        NORMAL_STARTUP_FINGERPRINTS.clear();
        NORMAL_RUNTIME_FINGERPRINTS.clear();
        FINGERPRINT_OBJECTS.clear();
        FINGERPRINT_FREQUENCIES.clear();
        StackTemporalEngine.TRANSITION_GRAPH.clear();
        UrlBaselineModel.reset();
        baselineReportGenerated = false;
        com.defense.rasp.forward.ForwardManager.resetModelReportFlag();
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

    public static void setBaselineReportEnabled(boolean enabled) {
        baselineReportEnabled = enabled;
    }

    private static void generateReportIfNeeded() {
        if (!baselineReportEnabled || baselineReportGenerated) return;
        baselineReportGenerated = true;
        generateBaselineReport();
    }

    private static void forwardModelReport() {
        try {
            int fCount = FINGERPRINT_OBJECTS.size();
            int gSize = StackTemporalEngine.TRANSITION_GRAPH.size();
            int urlCount = UrlBaselineModel.getBaselineEntries().size();
            long urlTotal = UrlBaselineModel.getTotalUrlsLearned();

            StringBuilder ssfJson = new StringBuilder("[");
            boolean first = true;
            for (StackTemporalEngine.StackFingerprint fp : FINGERPRINT_OBJECTS) {
                if (!first) ssfJson.append(",");
                first = false;
                ssfJson.append("\"").append(com.defense.rasp.forward.ForwardManager.escapeJson(
                    fp.fingerprintHash + ":" + fp.methodSignatures.size())).append("\"");
            }
            ssfJson.append("]");

            StringBuilder ctpgJson = new StringBuilder("[");
            first = true;
            for (Map.Entry<String, StackTemporalEngine.TransitionNode> e : StackTemporalEngine.TRANSITION_GRAPH.entrySet()) {
                if (!first) ctpgJson.append(",");
                first = false;
                ctpgJson.append("\"").append(com.defense.rasp.forward.ForwardManager.escapeJson(
                    e.getKey() + ":" + e.getValue().getTotalTransitions())).append("\"");
            }
            ctpgJson.append("]");

            StringBuilder urlJson = new StringBuilder("[");
            first = true;
            for (Map.Entry<String, UrlBaselineModel.UrlBaseline> e : UrlBaselineModel.getBaselineEntries().entrySet()) {
                if (!first) urlJson.append(",");
                first = false;
                urlJson.append("\"").append(com.defense.rasp.forward.ForwardManager.escapeJson(
                    e.getKey())).append("\"");
            }
            urlJson.append("]");

            com.defense.rasp.forward.ForwardManager.sendModelReport(
                ssfJson.toString(), ctpgJson.toString(), urlJson.toString(),
                fCount, gSize, urlCount, urlTotal);
        } catch (Exception ex) {
            System.err.println("[ForwardManager] 模型报告构建失败: " + ex.getMessage());
        }
    }

    private static String baselineFilePath = null;

    public static void setBaselineFilePath(String path) {
        baselineFilePath = path;
    }

    public static String getBaselineFilePath() {
        return baselineFilePath;
    }

    public static void saveBaseline() {
        if (baselineFilePath == null || baselineFilePath.isEmpty()) return;
        java.io.ObjectOutputStream oos = null;
        try {
            Map<Integer, Long> fpFreqs = new HashMap<>(FINGERPRINT_FREQUENCIES);
            Set<Integer> startupFps = new HashSet<>(NORMAL_STARTUP_FINGERPRINTS);
            Set<Integer> runtimeFps = new HashSet<>(NORMAL_RUNTIME_FINGERPRINTS);
            Set<StackTemporalEngine.StackFingerprint> fpObjs = new HashSet<>(FINGERPRINT_OBJECTS);
            Map<String, StackTemporalEngine.TransitionNode> graph = new HashMap<>(StackTemporalEngine.TRANSITION_GRAPH);
            Map<String, UrlBaselineModel.UrlBaseline> urlBls = new HashMap<>(UrlBaselineModel.getBaselineEntries());
            long totalUrl = UrlBaselineModel.getTotalUrlsLearned();

            java.io.File f = new java.io.File(baselineFilePath);
            if (f.getParentFile() != null) f.getParentFile().mkdirs();
            oos = new java.io.ObjectOutputStream(new java.io.FileOutputStream(f));
            oos.writeObject(startupFps);
            oos.writeObject(runtimeFps);
            oos.writeObject(fpObjs);
            oos.writeObject(fpFreqs);
            oos.writeObject(graph);
            oos.writeObject(urlBls);
            oos.writeLong(totalUrl);
            oos.writeLong(LEARNING_DURATION_MS);
            oos.writeLong(STARTUP_PERIOD_MS);
            oos.flush();
            AlertLogger.warn("[BaselineSerializer] 基线已保存: " + baselineFilePath
                + " SSF=" + startupFps.size() + "+" + runtimeFps.size()
                + " CTPG=" + graph.size() + " URL=" + urlBls.size());
        } catch (Exception e) {
            System.err.println("[BaselineSerializer] 基线保存失败: " + e.getMessage());
            e.printStackTrace();
        } finally {
            if (oos != null) { try { oos.close(); } catch (Exception ignored) {} }
        }
    }

    @SuppressWarnings("unchecked")
    public static boolean loadBaseline(String path) {
        java.io.File f = new java.io.File(path);
        if (!f.exists()) {
            System.out.println("[BaselineSerializer] 基线文件不存在，跳过加载: " + path);
            return false;
        }
        java.io.ObjectInputStream ois = null;
        try {
            ois = new java.io.ObjectInputStream(new java.io.FileInputStream(f));
            Set<Integer> startupFps = (Set<Integer>) ois.readObject();
            Set<Integer> runtimeFps = (Set<Integer>) ois.readObject();
            Set<StackTemporalEngine.StackFingerprint> fpObjs = (Set<StackTemporalEngine.StackFingerprint>) ois.readObject();
            Map<Integer, Long> fpFreqs = (Map<Integer, Long>) ois.readObject();
            Map<String, StackTemporalEngine.TransitionNode> graph = (Map<String, StackTemporalEngine.TransitionNode>) ois.readObject();
            Map<String, UrlBaselineModel.UrlBaseline> urlBls = (Map<String, UrlBaselineModel.UrlBaseline>) ois.readObject();
            long totalUrl = ois.readLong();
            long savedLearnDuration = ois.readLong();
            long savedStartupPeriod = ois.readLong();

            NORMAL_STARTUP_FINGERPRINTS.clear();
            NORMAL_STARTUP_FINGERPRINTS.addAll(startupFps);
            NORMAL_RUNTIME_FINGERPRINTS.clear();
            NORMAL_RUNTIME_FINGERPRINTS.addAll(runtimeFps);
            FINGERPRINT_OBJECTS.clear();
            FINGERPRINT_OBJECTS.addAll(fpObjs);
            FINGERPRINT_FREQUENCIES.clear();
            FINGERPRINT_FREQUENCIES.putAll(fpFreqs);
            StackTemporalEngine.TRANSITION_GRAPH.clear();
            StackTemporalEngine.TRANSITION_GRAPH.putAll(graph);
            UrlBaselineModel.restoreFrom(urlBls, totalUrl);

            isLearningPhase = false;
            LEARNING_START_TIME = System.currentTimeMillis();
            AlertLogger.warn("[BaselineSerializer] 基线已加载: " + path
                + " SSF=" + (startupFps.size() + runtimeFps.size())
                + " CTPG=" + graph.size() + " URL=" + urlBls.size()
                + " (跳过学习，直接进入检测模式)");
            System.out.println("[StackAnomalyDetector] 基线已从文件加载，跳过学习阶段");
            return true;
        } catch (Exception e) {
            System.err.println("[BaselineSerializer] 基线加载失败: " + e.getMessage());
            e.printStackTrace();
            return false;
        } finally {
            if (ois != null) { try { ois.close(); } catch (Exception ignored) {} }
        }
    }

    private static void generateBaselineReport() {
        Path reportPath = getReportPath();
        try {
            java.nio.file.Files.createDirectories(reportPath.getParent());
            PrintWriter pw = new PrintWriter(
                    new FileWriter(reportPath.toFile(), false), true);

            pw.println("============================================");
            pw.println("  RASP 基线学习报告");
            pw.println("============================================");
            pw.println("学习开始: " + java.time.LocalDateTime.now()
                    .minusNanos(TimeUnit.MILLISECONDS.toNanos(System.currentTimeMillis() - LEARNING_START_TIME))
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            pw.println("学习完成: " + java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            pw.println("学习时长: " + (LEARNING_DURATION_MS / 1000) + "s");
            pw.println("启动期时长: " + (STARTUP_PERIOD_MS / 1000) + "s");
            pw.println();

            int totalEdges = 0;
            for (StackTemporalEngine.TransitionNode node : StackTemporalEngine.TRANSITION_GRAPH.values()) {
                totalEdges += node.getTotalTransitions();
            }

            pw.println("--- 统计摘要 ---");
            pw.println("启动期指纹数: " + NORMAL_STARTUP_FINGERPRINTS.size());
            pw.println("运行期指纹数: " + NORMAL_RUNTIME_FINGERPRINTS.size());
            pw.println("总唯一指纹数: " + FINGERPRINT_OBJECTS.size());
            pw.println("CTPG 转移图节点数: " + StackTemporalEngine.TRANSITION_GRAPH.size());
            pw.println("CTPG 总转移边数: " + totalEdges);
            pw.println("总学习事件数: " + FINGERPRINT_FREQUENCIES.values().stream().mapToLong(Long::longValue).sum());
            pw.println();

            pw.println("--- 调用栈指纹 (SSF) ---");
            pw.println("(按方法数降序排列，显示所有指纹)");
            pw.println();

            List<StackTemporalEngine.StackFingerprint> sortedFingerprints = 
                    new ArrayList<>(FINGERPRINT_OBJECTS);
            sortedFingerprints.sort((a, b) -> Integer.compare(
                    b.methodSignatures.size(), a.methodSignatures.size()));

            int idx = 0;
            for (StackTemporalEngine.StackFingerprint fp : sortedFingerprints) {
                idx++;
                long freq = FINGERPRINT_FREQUENCIES.getOrDefault(fp.fingerprintHash, 0L);
                boolean isStartup = NORMAL_STARTUP_FINGERPRINTS.contains(fp.fingerprintHash);
                boolean isRuntime = NORMAL_RUNTIME_FINGERPRINTS.contains(fp.fingerprintHash);
                String phase = isStartup ? "启动期" : (isRuntime ? "运行期" : "双重");
                if (isStartup && isRuntime) phase = "启动+运行";

                pw.println("[指纹 " + idx + "] hash=" + fp.fingerprintHash +
                        "  方法数=" + fp.methodSignatures.size() +
                        "  频次=" + freq +
                        "  阶段=" + phase);

                for (String sig : fp.methodSignatures) {
                    pw.println("  " + sig);
                }
                pw.println();
            }

            pw.println("--- 方法转移图 (CTPG) ---");
            pw.println("(按源方法字母序，仅显示总转移 >= 5 的源方法)");
            pw.println();

            List<Map.Entry<String, StackTemporalEngine.TransitionNode>> sortedNodes =
                    new ArrayList<>(StackTemporalEngine.TRANSITION_GRAPH.entrySet());
            sortedNodes.sort(Map.Entry.comparingByKey());

            int shownNodes = 0;
            for (Map.Entry<String, StackTemporalEngine.TransitionNode> entry : sortedNodes) {
                StackTemporalEngine.TransitionNode node = entry.getValue();
                if (node.getTotalTransitions() < 5) continue;
                shownNodes++;

                pw.println(entry.getKey() + " (总转移=" + node.getTotalTransitions() +
                        ", 目标数=" + node.getAllProbabilities().size() + ")");

                Map<String, Double> probs = node.getAllProbabilities();
                List<Map.Entry<String, Double>> sortedTargets = new ArrayList<>(probs.entrySet());
                sortedTargets.sort((a, b) -> Double.compare(b.getValue(), a.getValue()));

                for (Map.Entry<String, Double> target : sortedTargets) {
                    pw.println(String.format("  → %s: %.1f%%",
                            target.getKey(), target.getValue() * 100));
                }
                pw.println();
            }

            if (shownNodes == 0) {
                pw.println("(无转移 >= 5 的源方法)");
                pw.println();
            }

            pw.println(UrlBaselineModel.getReportSection());

            pw.println("============================================");
            pw.println("报告生成时间: " + java.time.LocalDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")));
            pw.println("============================================");

            pw.close();
            AlertLogger.warn("[BaselineLearning] 基线报告已生成: " + reportPath.toAbsolutePath());
        } catch (Exception e) {
            AlertLogger.error("[BaselineLearning] 基线报告生成失败: " + e.getMessage());
        }
    }

    private static Path getReportPath() {
        String[] possiblePaths = {
            System.getProperty("catalina.base"),
            System.getProperty("jboss.server.base.dir"),
            System.getProperty("weblogic.home"),
            System.getProperty("user.dir"),
            System.getProperty("java.io.tmpdir"),
            "."
        };
        for (String basePath : possiblePaths) {
            if (basePath != null && !basePath.isEmpty()) {
                return Paths.get(basePath, "stack-anomaly-baseline-report.log");
            }
        }
        return Paths.get("stack-anomaly-baseline-report.log");
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
