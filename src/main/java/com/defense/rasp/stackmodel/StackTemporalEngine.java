
package com.defense.rasp.stackmodel;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;

/**
 * 调用栈时空建模核心引擎
 * 包含SSF（栈签名指纹）、CTPG（调用转移概率图）、TTT（线程时序轨迹）三种模型
 */
public class StackTemporalEngine {

    /**
     * 调用转移概率图（CTPG）
     * key: 源方法签名, value: 转移节点（包含目标方法及概率）
     */
    public static final ConcurrentHashMap<String, TransitionNode> TRANSITION_GRAPH =
            new ConcurrentHashMap<>();

    /**
     * 线程轨迹缓存（TTT）
     * key: 线程ID, value: 线程轨迹对象
     */
    private static final ConcurrentHashMap<Long, ThreadTrajectory> THREAD_TRAJECTORIES =
            new ConcurrentHashMap<>();

    /**
     * 清理过期线程轨迹的周期（毫秒）
     */
    private static final long CLEANUP_INTERVAL_MS = 60_000;

    static {
        // 启动后台清理线程，防止内存泄漏
        Thread cleanupThread = new Thread(() -> {
            while (true) {
                try {
                    Thread.sleep(CLEANUP_INTERVAL_MS);
                    cleanupExpiredTrajectories();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    break;
                }
            }
        }, "TrajectoryCleanup");
        cleanupThread.setDaemon(true);
        cleanupThread.start();
    }

    /**
     * 清理过期的线程轨迹
     */
    private static void cleanupExpiredTrajectories() {
        long currentTime = System.currentTimeMillis();
        THREAD_TRAJECTORIES.entrySet().removeIf(entry -> {
            ThreadTrajectory trajectory = entry.getValue();
            return currentTime - trajectory.getLastUpdateTime() > 30_000; // 30秒过期
        });
    }

    /**
     * 获取或创建线程轨迹
     */
    public static ThreadTrajectory getOrCreateTrajectory(long threadId, String threadName) {
        return THREAD_TRAJECTORIES.computeIfAbsent(threadId,
                k -> new ThreadTrajectory(threadId, threadName));
    }

    /**
     * 移除线程轨迹
     */
    public static void removeTrajectory(long threadId) {
        THREAD_TRAJECTORIES.remove(threadId);
    }

    /**
     * 栈签名指纹（SSF）
     * 将调用栈转换为可哈希的签名
     */
    public static class StackFingerprint {
        public final String methodSignature;
        public final int fingerprintHash;
        public final List<String> methodSignatures;

        public StackFingerprint(StackTraceElement[] stack) {
            this.methodSignatures = extractMethodSignatures(stack);
            this.methodSignature = String.join("|", this.methodSignatures);
            this.fingerprintHash = this.methodSignature.hashCode();
        }

        private List<String> extractMethodSignatures(StackTraceElement[] stack) {
            List<String> sigs = new ArrayList<>();
            for (StackTraceElement element : stack) {
                if (element == null) continue;
                String cn = element.getClassName();
                String mn = element.getMethodName();
                if (cn.startsWith("com.defense.rasp.")) continue;
                if (cn.equals("java.lang.Thread") && mn.equals("getStackTrace")) continue;
                sigs.add(cn + "." + mn);
            }
            return sigs;
        }

        @Override
        public boolean equals(Object o) {
            if (this == o) return true;
            if (o == null || getClass() != o.getClass()) return false;
            StackFingerprint that = (StackFingerprint) o;
            return fingerprintHash == that.fingerprintHash &&
                    Objects.equals(methodSignature, that.methodSignature);
        }

        @Override
        public int hashCode() {
            return fingerprintHash;
        }
    }

    /**
     * 转移节点（CTPG组成单元）
     */
    public static class TransitionNode {
        public final String sourceMethod;
        private final ConcurrentHashMap<String, Long> targetCounts;
        private long totalTransitions;

        public TransitionNode(String sourceMethod) {
            this.sourceMethod = sourceMethod;
            this.targetCounts = new ConcurrentHashMap<>();
            this.totalTransitions = 0;
        }

        /**
         * 记录一次转移
         */
        public void recordTransition(String targetMethod) {
            targetCounts.merge(targetMethod, 1L, Long::sum);
            totalTransitions++;
        }

        /**
         * 获取转移到目标方法的概率
         */
        public double getProbability(String targetMethod) {
            if (totalTransitions == 0) return 0.0;
            Long count = targetCounts.get(targetMethod);
            return count == null ? 0.0 : (double) count / totalTransitions;
        }

        /**
         * 获取总转移次数
         */
        public long getTotalTransitions() {
            return totalTransitions;
        }

        /**
         * 获取所有目标方法及其概率
         */
        public Map<String, Double> getAllProbabilities() {
            Map<String, Double> probabilities = new HashMap<>();
            for (Map.Entry<String, Long> entry : targetCounts.entrySet()) {
                probabilities.put(entry.getKey(), (double) entry.getValue() / totalTransitions);
            }
            return probabilities;
        }

        public boolean removeTarget(String targetMethod) {
            Long count = targetCounts.remove(targetMethod);
            if (count != null) {
                totalTransitions -= count;
                return true;
            }
            return false;
        }
    }

    /**
     * 调用事件（TTT组成单元）
     */
    public static class CallEvent {
        public enum EventType { ENTER, EXIT }

        public final long timestamp;
        public final String methodSignature;
        public final EventType eventType;

        public CallEvent(long timestamp, String methodSignature, EventType eventType) {
            this.timestamp = timestamp;
            this.methodSignature = methodSignature;
            this.eventType = eventType;
        }
    }

    /**
     * 线程时序轨迹（TTT）
     */
    public static class ThreadTrajectory {
        public final long threadId;
        public final String threadName;
        private final CopyOnWriteArrayList<CallEvent> events;
        private volatile long lastUpdateTime;

        public ThreadTrajectory(long threadId, String threadName) {
            this.threadId = threadId;
            this.threadName = threadName;
            this.events = new CopyOnWriteArrayList<>();
            this.lastUpdateTime = System.currentTimeMillis();
        }

        /**
         * 添加调用事件
         */
        public void addEvent(CallEvent event) {
            events.add(event);
            this.lastUpdateTime = System.currentTimeMillis();
            
            // 限制事件数量，防止内存溢出
            if (events.size() > 1000) {
                events.subList(0, 500).clear();
            }
        }

        /**
         * 获取最近N个事件
         */
        public List<CallEvent> getRecentEvents(int count) {
            int size = events.size();
            if (size <= count) {
                return new ArrayList<>(events);
            }
            return new ArrayList<>(events.subList(size - count, size));
        }

        /**
         * 检测轨迹异常
         */
        public List<String> detectAnomalies() {
            List<String> anomalies = new ArrayList<>();

            // 过滤出进入事件
            List<CallEvent> enterEvents = events.stream()
                    .filter(e -> e.eventType == CallEvent.EventType.ENTER)
                    .collect(Collectors.toList());

            // 模式1：调用顺序异常（检测常见后门特征）
            for (int i = 0; i < enterEvents.size() - 1; i++) {
                String current = enterEvents.get(i).methodSignature;
                String next = enterEvents.get(i + 1).methodSignature;

                if (isSuspiciousTransition(current, next)) {
                    anomalies.add("SUSPICIOUS_TRANSITION: " + current + " -> " + next);
                }
            }

            // 模式2：Web请求链直接触达IO（缺少中间层）
            boolean hasWebEntry = enterEvents.stream().anyMatch(e -> tagMethod(e.methodSignature)
                    .matches("tomcat-core|servlet-api"));
            boolean hasBusinessLayer = enterEvents.stream().anyMatch(e -> tagMethod(e.methodSignature)
                    .matches("spring-core|user-code"));
            boolean hasIO = enterEvents.stream().anyMatch(e -> tagMethod(e.methodSignature)
                    .matches("java-io|java-nio"));

            if (hasWebEntry && !hasBusinessLayer && hasIO) {
                anomalies.add("WEB_TO_IO_DIRECT: Web请求链缺少业务中间层直接触达IO");
            }

            // 模式3：调用深度异常（Web入口到IO的深度 < 3）
            if (hasWebEntry && hasIO) {
                int webIndex = -1, ioIndex = -1;
                for (int i = 0; i < enterEvents.size(); i++) {
                    String tag = tagMethod(enterEvents.get(i).methodSignature);
                    if (webIndex == -1 && tag.matches("tomcat-core|servlet-api")) {
                        webIndex = i;
                    }
                    if (tag.matches("java-io|java-nio")) {
                        ioIndex = i;
                    }
                }
                if (webIndex != -1 && ioIndex != -1 && (ioIndex - webIndex) < 3) {
                    anomalies.add("SHALLOW_CALL_DEPTH: Web到IO调用深度异常(" + (ioIndex - webIndex) + ")");
                }
            }

            // 模式4：反射深度检测
            int reflectDepth = detectReflectDepth(enterEvents);
            if (reflectDepth > 3) {
                anomalies.add("DEEP_REFLECTION: 反射调用嵌套深度异常(" + reflectDepth + ")");
            }

            return anomalies;
        }

        /**
         * 检测反射嵌套深度
         */
        private int detectReflectDepth(List<CallEvent> enterEvents) {
            int maxDepth = 0;
            int currentDepth = 0;

            for (CallEvent event : enterEvents) {
                String tag = tagMethod(event.methodSignature);
                if (tag.matches("java-reflect|jdk-reflect")) {
                    currentDepth++;
                    maxDepth = Math.max(maxDepth, currentDepth);
                } else {
                    currentDepth = 0;
                }
            }

            return maxDepth;
        }

        /**
         * 判断是否为可疑转移
         */
        private boolean isSuspiciousTransition(String current, String next) {
            // 检测常见的攻击模式
            boolean isReflect = current.contains("reflect") || current.contains("Method");
            boolean isIO = next.contains("FileInputStream") || 
                           next.contains("Files.read") || 
                           next.contains("NIO");

            if (isReflect && isIO) {
                return true;
            }

            // 检测类加载器异常使用
            if (current.contains("ClassLoader") && next.contains("defineClass")) {
                return true;
            }

            return false;
        }

        /**
         * 方法分类标签
         */
        private String tagMethod(String signature) {
            if (signature.contains("org.apache.catalina")) return "tomcat-core";
            if (signature.contains("javax.servlet")) return "servlet-api";
            if (signature.contains("java.lang.reflect")) return "java-reflect";
            if (signature.contains("sun.reflect")) return "jdk-reflect";
            if (signature.contains("java.io")) return "java-io";
            if (signature.contains("java.nio")) return "java-nio";
            if (signature.contains("org.springframework")) return "spring-core";
            return "user-code";
        }

        public long getLastUpdateTime() {
            return lastUpdateTime;
        }

        public int getEventCount() {
            return events.size();
        }
    }
}
