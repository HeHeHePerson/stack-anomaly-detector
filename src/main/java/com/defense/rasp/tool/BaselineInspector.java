package com.defense.rasp.tool;

import com.defense.rasp.stackmodel.BaselineLearningEngine;
import com.defense.rasp.stackmodel.StackTemporalEngine;
import com.defense.rasp.stackmodel.UrlBaselineModel;
import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

public class BaselineInspector {

    private static final SimpleDateFormat DATE_FMT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");

    public static void main(String[] args) {
        String path = args.length > 0 ? args[0] : "/tmp/rasp/baseline.dat";
        File f = new File(path);
        if (!f.exists()) {
            System.out.println("基线文件不存在: " + path);
            System.exit(1);
        }

        System.out.println("基线文件: " + path);
        System.out.println("文件大小: " + formatSize(f.length()));
        System.out.println("最后修改: " + DATE_FMT.format(new Date(f.lastModified())));
        System.out.println();

        try (ObjectInputStream ois = new ObjectInputStream(new BufferedInputStream(new FileInputStream(f)))) {
            Set<Integer> startupFps = (Set<Integer>) ois.readObject();
            Set<Integer> runtimeFps = (Set<Integer>) ois.readObject();
            Set<StackTemporalEngine.StackFingerprint> fpObjs = (Set<StackTemporalEngine.StackFingerprint>) ois.readObject();
            Map<Integer, Long> fpFreqs = (Map<Integer, Long>) ois.readObject();
            Map<String, StackTemporalEngine.TransitionNode> graph = (Map<String, StackTemporalEngine.TransitionNode>) ois.readObject();
            Map<String, UrlBaselineModel.UrlBaseline> urlBls = (Map<String, UrlBaselineModel.UrlBaseline>) ois.readObject();
            long totalUrls = ois.readLong();
            long learningDuration = ois.readLong();
            long startupPeriod = ois.readLong();

            printOverview(startupFps, runtimeFps, fpObjs, fpFreqs, graph, urlBls, learningDuration, startupPeriod);
            System.out.println();

            boolean detail = args.length > 1 && "--detail".equals(args[1]);
            boolean urls = args.length > 1 && "--urls".equals(args[1]);
            boolean ctpg = args.length > 1 && "--ctpg".equals(args[1]);

            if (detail || urls) printUrlBaselines(urlBls, totalUrls, learningDuration);
            if (detail || ctpg) printTransitionGraph(graph);
            if (detail) printFingerprintDetails(fpObjs, fpFreqs);

        } catch (Exception e) {
            System.err.println("解析失败: " + e.getMessage());
            e.printStackTrace();
            System.exit(1);
        }
    }

    private static void printOverview(Set<Integer> startupFps, Set<Integer> runtimeFps,
            Set<StackTemporalEngine.StackFingerprint> fpObjs, Map<Integer, Long> fpFreqs,
            Map<String, StackTemporalEngine.TransitionNode> graph,
            Map<String, UrlBaselineModel.UrlBaseline> urlBls, long learningDuration, long startupPeriod) {

        System.out.println("========== 基线概览 ==========");

        System.out.printf("  学习时长:    %.1f 分钟 (%d ms)%n",
                learningDuration / 60000.0, learningDuration);
        System.out.printf("  启动期时长:  %.1f 分钟 (%d ms)%n",
                startupPeriod / 60000.0, startupPeriod);

        System.out.println();
        System.out.println("--- 栈指纹 (SSF) ---");
        System.out.printf("  启动期指纹:  %d%n", startupFps.size());
        System.out.printf("  运行期指纹:  %d%n", runtimeFps.size());
        System.out.printf("  指纹对象:    %d%n", fpObjs.size());
        System.out.printf("  频率映射:    %d%n", fpFreqs.size());

        long totalFrequency = 0;
        for (Long freq : fpFreqs.values()) totalFrequency += freq;
        System.out.printf("  总频次:      %d%n", totalFrequency);

        System.out.println();
        System.out.println("--- 调用转移图 (CTPG) ---");
        System.out.printf("  源节点数:    %d%n", graph.size());

        long totalTransitions = 0;
        long totalEdges = 0;
        for (StackTemporalEngine.TransitionNode node : graph.values()) {
            totalTransitions += node.getTotalTransitions();
            totalEdges += node.getTargetCounts().size();
        }
        System.out.printf("  边总数:      %d%n", totalEdges);
        System.out.printf("  转移总次数:  %d%n", totalTransitions);

        System.out.println();
        System.out.println("--- URL 基线 ---");
        System.out.printf("  URL 条目:    %d%n", urlBls.size());

        double totalVpm = 0;
        for (UrlBaselineModel.UrlBaseline bl : urlBls.values()) {
            totalVpm += bl.visitsPerMinute();
        }
        System.out.printf("  总访问频率:  %.1f 次/分钟%n", totalVpm);

        System.out.println("=============================");
    }

    private static void printUrlBaselines(Map<String, UrlBaselineModel.UrlBaseline> urlBls,
            long totalUrls, long learningDuration) {
        System.out.println();
        System.out.println("========== URL 基线详情 ==========");
        System.out.printf("总URL学习: %d%n", totalUrls);
        System.out.println();

        List<Map.Entry<String, UrlBaselineModel.UrlBaseline>> sorted = new ArrayList<>(urlBls.entrySet());
        sorted.sort((a, b) -> Double.compare(b.getValue().visitsPerMinute(), a.getValue().visitsPerMinute()));

        System.out.printf("%-4s %-8s %-8s %-8s %s%n", "序号", "访问次数", "次/分钟", "参数数", "路径");
        System.out.println("------------------------------------------------------------------------");

        int i = 1;
        for (Map.Entry<String, UrlBaselineModel.UrlBaseline> e : sorted) {
            UrlBaselineModel.UrlBaseline bl = e.getValue();
            System.out.printf("%-4d %-8d %-8.1f %-8d %s%n",
                    i++, bl.totalVisits.get(), bl.visitsPerMinute(),
                    bl.paramKeys.size(), e.getKey());
        }
        System.out.println("====================================");
    }

    private static void printTransitionGraph(Map<String, StackTemporalEngine.TransitionNode> graph) {
        System.out.println();
        System.out.println("========== 调用转移图详情 (CTPG) ==========");

        List<Map.Entry<String, StackTemporalEngine.TransitionNode>> sorted = new ArrayList<>(graph.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue().getTotalTransitions(), a.getValue().getTotalTransitions()));

        int count = 0;
        for (Map.Entry<String, StackTemporalEngine.TransitionNode> e : sorted) {
            if (count >= 50) {
                System.out.println("... (省略 " + (sorted.size() - 50) + " 个节点，使用 --ctpg 查看完整)");
                break;
            }
            StackTemporalEngine.TransitionNode node = e.getValue();
            System.out.println();
            System.out.printf("[%s] 总转移: %d%n", e.getKey(), node.getTotalTransitions());

            Map<String, Long> targets = new HashMap<>(node.getTargetCounts());
            List<Map.Entry<String, Long>> targetList = new ArrayList<>(targets.entrySet());
            targetList.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

            int shown = 0;
            for (Map.Entry<String, Long> te : targetList) {
                if (shown >= 5) {
                    System.out.printf("  ... 还有 %d 个目标%n", targetList.size() - 5);
                    break;
                }
                double prob = te.getValue() / (double) node.getTotalTransitions();
                System.out.printf("  -> %-60s %6d (%.2f%%)\n",
                        te.getKey(), te.getValue(), prob * 100);
                shown++;
            }
            count++;
        }
        System.out.println("============================================");
    }

    private static void printFingerprintDetails(Set<StackTemporalEngine.StackFingerprint> fpObjs,
            Map<Integer, Long> fpFreqs) {
        System.out.println();
        System.out.println("========== 指纹详情 ==========");

        Map<Integer, StackTemporalEngine.StackFingerprint> lookup = new HashMap<>();
        for (StackTemporalEngine.StackFingerprint fp : fpObjs) {
            lookup.put(fp.fingerprintHash, fp);
        }

        List<Map.Entry<Integer, Long>> sorted = new ArrayList<>(fpFreqs.entrySet());
        sorted.sort((a, b) -> Long.compare(b.getValue(), a.getValue()));

        for (Map.Entry<Integer, Long> e : sorted) {
            System.out.printf("[hash=%08x] 频次: %d%n", e.getKey(), e.getValue());
            StackTemporalEngine.StackFingerprint fp = lookup.get(e.getKey());
            if (fp != null) {
                for (String sig : fp.methodSignatures) {
                    System.out.printf("  %s%n", sig);
                }
            } else {
                System.out.println("  (指纹对象未在集合中)");
            }
        }
        System.out.println("============================");
    }

    private static String formatSize(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        return String.format("%.2f MB", bytes / (1024.0 * 1024.0));
    }
}
