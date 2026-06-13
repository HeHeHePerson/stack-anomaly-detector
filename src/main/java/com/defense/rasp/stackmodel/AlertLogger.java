package com.defense.rasp.stackmodel;

import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.locks.ReentrantLock;

public class AlertLogger {

    private static final String LOG_FILE_NAME = "stack-anomaly-alerts.log";
    private static final DateTimeFormatter TIMESTAMP_FORMAT = 
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS");
    private static final ReentrantLock LOCK = new ReentrantLock();
    private static PrintWriter writer = null;

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
                System.err.println("[AlertLogger] 将使用标准输出");
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

    public static void info(String message) {
        String logMessage = formatMessage("INFO", message);
        System.out.println(logMessage);
        writeToFile(logMessage);
    }

    public static void warn(String message) {
        String logMessage = formatMessage("WARN", message);
        System.out.println(logMessage);
        writeToFile(logMessage);
    }

    public static void error(String message) {
        String logMessage = formatMessage("ERROR", message);
        System.err.println(logMessage);
        writeToFile(logMessage);
    }

    public static void alarm(String message) {
        String logMessage = formatMessage("ALARM", message);
        System.out.println(logMessage);
        writeToFile(logMessage);
    }

    public static void block(String message) {
        String logMessage = formatMessage("BLOCK", message);
        System.err.println(logMessage);
        writeToFile(logMessage);
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

    public static void close() {
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