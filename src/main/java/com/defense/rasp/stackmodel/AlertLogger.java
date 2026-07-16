package com.defense.rasp.stackmodel;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

public class AlertLogger {

    private static final String LOG_FILE_NAME = "stack-anomaly-alerts.log";
    private static final DateTimeFormatter TIMESTAMP_FORMAT = 
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final ReentrantLock LOCK = new ReentrantLock();
    private static PrintWriter writer = null;
    private static volatile boolean debugEnabled = false;
    private static volatile boolean writeInfoToFile = false;

    // 定期摘要计数器
    private static final AtomicLong readSkipped = new AtomicLong();
    private static final AtomicLong writeSkipped = new AtomicLong();
    private static final AtomicLong deleteSkipped = new AtomicLong();
    private static final AtomicLong execSkipped = new AtomicLong();
    private static final AtomicLong httpSkipped = new AtomicLong();
    private static final AtomicLong learnSkipped = new AtomicLong();
    private static final AtomicLong alarmCount = new AtomicLong();
    private static final AtomicLong blockCount = new AtomicLong();
    private static volatile long lastSummaryTime = System.currentTimeMillis();
    private static final long SUMMARY_INTERVAL_MS = 60_000;
    private static final ReentrantLock SUMMARY_LOCK = new ReentrantLock();

    public static void setDebugEnabled(boolean enabled) {
        debugEnabled = enabled;
        System.out.println("[AlertLogger] debug日志: " + (enabled ? "开启" : "关闭"));
    }

    public static void setWriteInfoToFile(boolean enabled) {
        writeInfoToFile = enabled;
    }

    public static boolean isDebugEnabled() {
        return debugEnabled;
    }

    private static void ensureWriter() {
        if (writer != null) return;
        
        LOCK.lock();
        try {
            if (writer != null) return;
            
            Path logPath = getLogPath();
            try {
                Files.createDirectories(logPath.getParent());
                writer = new PrintWriter(new FileWriter(logPath.toFile(), true), true);
                writer.println("========================================");
                writer.println("Stack Anomaly Detector 告警日志");
                writer.println("启动时间: " + LocalDateTime.now().format(TIMESTAMP_FORMAT));
                writer.println("========================================");
                System.out.println("[AlertLogger] 日志文件已创建: " + logPath.toAbsolutePath());
            } catch (IOException e) {
                System.err.println("[AlertLogger] 无法创建日志文件: " + e.getMessage());
            }
        } finally {
            LOCK.unlock();
        }
    }

    private static Path getLogPath() {
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
                Path path = Paths.get(basePath, LOG_FILE_NAME);
                try {
                    if (Files.isWritable(path.getParent())) {
                        return path;
                    }
                } catch (Exception e) {
                }
            }
        }
        
        return Paths.get(System.getProperty("user.dir"), LOG_FILE_NAME);
    }

    /** debug: 仅在 -Drasp.debug=true 时输出 */
    public static void debug(String message) {
        if (!debugEnabled) return;
        String logMessage = formatMessage("DEBUG", message);
        writeToFile(logMessage);
    }

    /** info: 仅写文件不写 stdout，且受 writeInfoToFile 控制 */
    public static void info(String message) {
        String logMessage = formatMessage("INFO", message);
        if (writeInfoToFile) {
            writeToFile(logMessage);
        }
    }

    public static void warn(String message) {
        String logMessage = formatMessage("WARN", message);
        writeToFile(logMessage);
        forwardAlert("WARN", message);
    }

    public static void error(String message) {
        String logMessage = formatMessage("ERROR", message);
        System.err.println(logMessage);
        writeToFile(logMessage);
    }

    /** alarm: 实际告警，始终写入文件并输出到控制台 */
    public static void alarm(String message) {
        alarmCount.incrementAndGet();
        String logMessage = formatMessage("ALARM", message);
        System.out.println(logMessage);
        writeToFile(logMessage);
        forwardAlert("ALARM", message);
    }

    /** block: 阻断告警，始终写入文件 */
    public static void block(String message) {
        blockCount.incrementAndGet();
        String logMessage = formatMessage("BLOCK", message);
        writeToFile(logMessage);
        forwardAlert("BLOCK", message);
    }

    private static String formatMessage(String level, String message) {
        String timestamp = LocalDateTime.now().format(TIMESTAMP_FORMAT);
        return String.format("[%s] [%s] %s", timestamp, level, message);
    }

    private static void writeToFile(String message) {
        ensureWriter();
        if (writer == null) return;
        
        LOCK.lock();
        try {
            writer.println(message);
            writer.flush();
        } finally {
            LOCK.unlock();
        }
    }

    /**
     * 计数并定期输出摘要（info 级别，每 60 秒一次）
     * 避免每条操作都写日志
     */
    public static void infoSkipped(String category, AtomicLong counter) {
        counter.incrementAndGet();
        long now = System.currentTimeMillis();
        if (now - lastSummaryTime > SUMMARY_INTERVAL_MS && SUMMARY_LOCK.tryLock()) {
            try {
                if (now - lastSummaryTime > SUMMARY_INTERVAL_MS) {
                    long reads = readSkipped.getAndSet(0);
                    long writes = writeSkipped.getAndSet(0);
                    long deletes = deleteSkipped.getAndSet(0);
                    long execs = execSkipped.getAndSet(0);
                    long https = httpSkipped.getAndSet(0);
                    long learns = learnSkipped.getAndSet(0);
                    lastSummaryTime = now;
                    if (reads + writes + deletes + execs + https + learns > 0) {
                        String summary = String.format(
                            "[摘要] 近60秒: 文件读取=%d 文件写入=%d 文件删除=%d 命令执行=%d HTTP请求=%d 学习事件=%d",
                            reads, writes, deletes, execs, https, learns);
                        warn(summary);
                    }
                }
            } finally {
                SUMMARY_LOCK.unlock();
            }
        }
    }

    public static void countReadSkipped()   { infoSkipped("read", readSkipped); }
    public static void countWriteSkipped()  { infoSkipped("write", writeSkipped); }
    public static void countDeleteSkipped() { infoSkipped("delete", deleteSkipped); }
    public static void countExecSkipped()   { infoSkipped("exec", execSkipped); }
    public static void countHttpSkipped()   { infoSkipped("http", httpSkipped); }
    public static void countLearnSkipped()  { infoSkipped("learn", learnSkipped); }

    public static long getAlarmCount() { return alarmCount.get(); }
    public static long getBlockCount() { return blockCount.get(); }

    private static void forwardAlert(String level, String message) {
        try {
            String prefix = extractPrefix(message);
            com.defense.rasp.forward.ForwardManager.sendAlert(level, prefix, message);
        } catch (Exception ignored) {
        }
    }

    private static String extractPrefix(String message) {
        if (message == null) return "";
        int start = message.indexOf('[');
        int end = message.indexOf(']');
        if (start == 0 && end > start) {
            return message.substring(start, end + 1);
        }
        return "";
    }

    public static void close() {
        try { com.defense.rasp.forward.ForwardManager.shutdown(); } catch (Exception ignored) {}
        LOCK.lock();
        try {
            if (writer != null) {
                writer.println("========================================");
                writer.println("日志结束: " + LocalDateTime.now().format(TIMESTAMP_FORMAT));
                writer.println("========================================");
                writer.flush();
                writer.close();
                writer = null;
            }
        } finally {
            LOCK.unlock();
        }
    }
}
