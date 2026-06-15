
package com.defense.rasp.stackmodel;

import java.nio.file.Path;

/**
 * 统一检测入口：整合所有时空模型进行判定
 */
public class TemporalGuard {

    /**
     * 高风险阈值：超过此分数将阻断操作
     */
    private static final int HIGH_RISK_THRESHOLD = 50;

    /**
     * 中风险阈值：超过此分数将告警
     */
    private static final int MEDIUM_RISK_THRESHOLD = 20;

    /**
     * 目录列举检测入口（由 ASM Hook 调用）
     * 拦截 File.list() 调用，检测冰蝎文件管理探测敏感目录的行为
     */
    public static void onFileList(java.io.File dir) {
        if (dir == null) return;
        String dirPath = dir.getAbsolutePath();
        
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        
        AlertLogger.info("[TemporalGuard] 目录列举检测触发: " + dirPath);
        AlertLogger.info("[TemporalGuard] 调用栈深度: " + stack.length);
        
        recordThreadEvent("java.io.FileSystem.list",
                StackTemporalEngine.CallEvent.EventType.ENTER);
        
        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;
        
        AlertLogger.info("[TemporalGuard] 学习期状态: " + (BaselineLearningEngine.isLearningPhase() ? "学习中" : "检测中"));
        AlertLogger.info("[TemporalGuard] 启动期状态: " + (isStartup ? "是" : "否"));
        
        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, dirPath);
        
        // 检测是否为敏感目录
        if (isSensitiveDirectory(dirPath)) {
            anomalyScore += 30;
            AlertLogger.alarm("[SensitiveDir] 检测到敏感目录列举: " + dirPath);
        }
        
        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险目录列举: 分数=" + anomalyScore + ", 目录=" + dirPath, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险目录列举: 分数=" + anomalyScore + ", 目录=" + dirPath, stack);
        }
    }

    /**
     * 文件读取检测入口（由 ASM Hook 调用）
     */
    public static void onFileRead(String filePath) {
        if (filePath == null) return;

        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        AlertLogger.info("[TemporalGuard] 文件读取检测触发: " + filePath);
        AlertLogger.info("[TemporalGuard] 调用栈深度: " + stack.length);
        if (stack.length > 0) {
            AlertLogger.info("[TemporalGuard] 调用栈[0]: " + stack[0]);
        }

        recordThreadEvent("java.io.FileInputStream.<init>",
                StackTemporalEngine.CallEvent.EventType.ENTER);

        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;

        AlertLogger.info("[TemporalGuard] 学习期状态: " + (BaselineLearningEngine.isLearningPhase() ? "学习中" : "检测中"));
        AlertLogger.info("[TemporalGuard] 启动期状态: " + (isStartup ? "是" : "否"));

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, filePath);

        if (isSensitiveFile(filePath)) {
            anomalyScore += 20;
        }

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险时空异常: 分数=" + anomalyScore + ", 文件=" + filePath, stack);
        }
    }

    /**
     * NIO 路径读取检测入口
     */
    public static void onPathRead(java.nio.file.Path path) {
        if (path != null) {
            onFileRead(path.toString());
        }
    }

    /**
     * 反射调用检测入口（由 ASM Hook 调用）
     * 检测冰蝎等通过反射调用敏感方法的行为
     */
    public static void onReflectInvoke(String[] methodInfo) {
        if (methodInfo == null || methodInfo.length != 2) return;
        
        String className = methodInfo[0];
        String methodName = methodInfo[1];
        String fullSignature = className + "." + methodName;
        
        StackTraceElement[] stack = Thread.currentThread().getStackTrace();
        
        AlertLogger.info("[TemporalGuard] 反射调用检测触发：" + fullSignature);
        
        // 记录到 TTT 线程轨迹
        recordThreadEvent(fullSignature, StackTemporalEngine.CallEvent.EventType.ENTER);
        
        // 检测是否为敏感方法的反射调用
        if (isSensitiveReflectCall(className, methodName)) {
            AlertLogger.alarm("[ReflectDetector] 检测到敏感方法的反射调用：" + fullSignature);
            int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null);
            
            if (anomalyScore >= HIGH_RISK_THRESHOLD) {
                block("高风险反射调用：分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
            } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
                alarm("中风险反射调用：分数=" + anomalyScore + ", 方法=" + fullSignature, stack);
            }
        }
    }

    /**
     * 判断是否为敏感的反射调用
     */
    private static boolean isSensitiveReflectCall(String className, String methodName) {
        // 文件读写相关
        if (className.startsWith("java.io") || className.startsWith("java.nio")) {
            return true;
        }
        
        // 类加载相关
        if (className.startsWith("java.lang.ClassLoader") || 
            className.startsWith("sun.misc.Launcher")) {
            return true;
        }
        
        // 方法调用相关
        if (className.equals("java.lang.reflect.Method") && 
            (methodName.equals("invoke") || methodName.equals("invokeExact"))) {
            return true;
        }
        
        // 构造函数相关
        if (className.equals("java.lang.reflect.Constructor") && 
            methodName.equals("newInstance")) {
            return true;
        }
        
        // 字段访问相关
        if (className.startsWith("java.lang.reflect.Field") && 
            (methodName.equals("get") || methodName.equals("set") || methodName.equals("getBoolean"))) {
            return true;
        }
        
        return false;
    }

    /**
     * 命令执行检测入口（由ASM Hook调用）
     */
    public static void onCommandExec(String command) {
        if (command == null || command.isEmpty()) return;

        StackTraceElement[] stack = Thread.currentThread().getStackTrace();

        AlertLogger.info("[TemporalGuard] 命令执行检测触发: " + command);
        AlertLogger.info("[TemporalGuard] 调用栈深度: " + stack.length);

        long jvmUptime = System.currentTimeMillis() - BaselineLearningEngine.LEARNING_START_TIME;
        boolean isStartup = jvmUptime < 120_000;

        AlertLogger.info("[TemporalGuard] 学习期状态: " + (BaselineLearningEngine.isLearningPhase() ? "学习中" : "检测中"));
        AlertLogger.info("[TemporalGuard] 启动期状态: " + (isStartup ? "是" : "否"));

        BaselineLearningEngine.learnNormalStack(stack, isStartup);
        int anomalyScore = BaselineLearningEngine.detectAnomaly(stack, null);

        anomalyScore += analyzeCommand(command);

        if (anomalyScore >= HIGH_RISK_THRESHOLD) {
            block("高风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
        } else if (anomalyScore >= MEDIUM_RISK_THRESHOLD) {
            alarm("中风险命令执行: 分数=" + anomalyScore + ", 命令=" + command, stack);
        }
    }

    /**
     * TTT方法进入事件（由ASM Hook调用）
     */
    public static void onMethodEnter(String methodSignature) {
        long threadId = Thread.currentThread().getId();
        String threadName = Thread.currentThread().getName();

        StackTemporalEngine.ThreadTrajectory trajectory =
                StackTemporalEngine.getOrCreateTrajectory(threadId, threadName);

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), methodSignature,
                StackTemporalEngine.CallEvent.EventType.ENTER));
    }

    /**
     * TTT方法退出事件（由ASM Hook调用）
     */
    public static void onMethodExit(String methodSignature) {
        long threadId = Thread.currentThread().getId();
        StackTemporalEngine.ThreadTrajectory trajectory =
                StackTemporalEngine.getOrCreateTrajectory(threadId, 
                        Thread.currentThread().getName());

        trajectory.addEvent(new StackTemporalEngine.CallEvent(
                System.currentTimeMillis(), methodSignature,
                StackTemporalEngine.CallEvent.EventType.EXIT));
    }

    /**
     * 分析命令内容，检测敏感操作
     * @param command 命令内容
     * @return 异常分数增量
     */
    private static int analyzeCommand(String command) {
        int score = 0;
        String lowerCommand = command.toLowerCase();

        String[] dangerousCommands = {
            "cat", "tac", "type", "more", "less", "head", "tail",
            "od", "strings", "hexdump", "xxd", "wc",
            "cp", "copy", "move", "mv", "rm", "del", "erase", "rmdir",
            "find", "grep", "awk", "sed", "cut", "sort", "uniq", "diff",
            "vim", "vi", "nano", "emacs", "ed", "pico",
            "powershell", "cmd", "bash", "sh", "zsh", "csh",
            "python", "python3", "perl", "ruby", "php", "node", "nodejs",
            "curl", "wget", "nc", "netcat", "telnet", "ftp",
            "chmod", "chown", "chgrp", "sudo", "su", "sudoers",
            "whoami", "id", "pwd", "ls", "dir", "cd",
            "tar", "gzip", "gunzip", "zip", "unzip", "7z", "rar", "unrar",
            "attrib", "fc", "findstr", "for", "pushd", "popd",
            "mount", "umount", "dd", "ln", "ln -s", "touch", "mkdir",
            "exec", "eval", "system"
        };

        String[] sensitiveFileKeywords = {
            "tomcat-users", "server.xml", "web.xml", "context.xml",
            ".properties", ".yml", ".yaml", ".xml", ".conf", ".ini",
            ".env", ".key", ".pem", ".crt", ".keystore", ".truststore",
            "passwd", "shadow", "etc/", "conf/", "tomcat/",
            "mysql", "postgres", "database", "redis", "rabbitmq", "kafka",
            "catalina.policy", "catalina.properties", "context.xml",
            "host-manager.xml", "manager.xml", "tomcat-users.xml",
            "application.properties", "application.yml", "bootstrap.yml",
            "logback.xml", "log4j.xml", "log4j.properties",
            "jdbc.properties", "datasource", "hibernate.cfg.xml",
            "mybatis-config.xml", "mapper.xml",
            "nginx.conf", "httpd.conf", "apache2.conf",
            "ssh/", "ssh_config", "sshd_config",
            "authorized_keys", "known_hosts", "id_rsa", "id_dsa",
            "svn", ".git", "hg", "cvs",
            "/etc/passwd", "/etc/shadow", "/etc/group",
            "/etc/sudoers", "/etc/hosts", "/etc/resolv.conf",
            "/etc/profile", "/etc/bashrc", "/root/.bashrc",
            "/root/.bash_profile", "/root/.ssh/", "/home/",
            "/var/log/", "/var/www/", "/var/lib/",
            "/tmp/", "/tmp/", "/var/tmp/", "/dev/shm/"
        };

        String[] suspiciousPatterns = {
            "|", ";", "&&", "||", "$(", "`", ">", "<", ">>", "<<",
            "base64", "decode", "encode", "-d", "-e",
            "exec", "system", "eval", "shell_exec", "passthru",
            "getshell", "webshell", "backdoor", "reverse", "bind",
            "nc -e", "nc -c", "netcat -e", "netcat -c",
            "bash -i", "python -c", "perl -e", "ruby -e", "php -r",
            "java -jar", "javaw", "cmd.exe", "cmd /c", "cmd /k",
            "powershell -c", "powershell -e", "powershell -EncodedCommand",
            "wscript", "cscript", "mshta", "regsvr32",
            "certutil", "bitsadmin", "msiexec", "rundll32",
            "at.exe", "schtasks", "taskschd.msc",
            "net user", "net localgroup", "net share",
            "sc create", "sc config", "sc start",
            "reg add", "reg query", "reg delete", "reg import",
            "/root/", "/home/", "/etc/", "/tmp/", "/var/",
            "c:\\windows\\", "c:\\system32\\", "c:\\users\\",
            "c:\\programdata\\", "c:\\temp\\", "c:\\windows\\temp\\"
        };

        boolean hasDangerousCmd = false;
        boolean hasSensitiveFile = false;
        boolean hasSuspiciousPattern = false;

        for (String cmd : dangerousCommands) {
            if (lowerCommand.contains(cmd)) {
                hasDangerousCmd = true;
                score += 10;
                AlertLogger.alarm("[CommandAnalysis] 检测到危险命令: " + cmd);
            }
        }

        for (String keyword : sensitiveFileKeywords) {
            if (lowerCommand.contains(keyword)) {
                hasSensitiveFile = true;
                score += 30;
                AlertLogger.alarm("[CommandAnalysis] 检测到敏感文件访问: " + keyword);
            }
        }

        for (String pattern : suspiciousPatterns) {
            if (lowerCommand.contains(pattern)) {
                hasSuspiciousPattern = true;
                score += 15;
                AlertLogger.alarm("[CommandAnalysis] 检测到可疑模式: " + pattern);
            }
        }

        if (hasDangerousCmd && hasSensitiveFile) {
            score += 30;
            AlertLogger.alarm("[CommandAnalysis] 高危行为: 危险命令访问敏感文件");
        }

        if (hasSuspiciousPattern && hasDangerousCmd) {
            score += 20;
            AlertLogger.alarm("[CommandAnalysis] 高危行为: 可疑模式配合危险命令");
        }

        return score;
    }

    /**
     * 判断是否为敏感文件
     */
    private static boolean isSensitiveFile(String filePath) {
        if (filePath == null) return false;
        String lowerPath = filePath.toLowerCase();
        
        // Web 容器配置文件 (Tomcat, BES, Jetty 等)
        String[] containerConfigFiles = {
            "tomcat-users.xml",
            "server.xml",
            "web.xml",
            "context.xml",
            "manager.xml",
            "host-manager.xml",
            "catalina.policy",
            "catalina.properties",
            "logging.properties",
            "bes.conf",
            "bes.xml",
            "httpd.conf",
            "apache2.conf",
            "nginx.conf",
            "jetty.xml",
            "jetty-env.xml"
        };
        
        // 应用配置文件
        String[] appConfigFiles = {
            "application.properties",
            "application.yml",
            "application.yaml",
            "bootstrap.properties",
            "bootstrap.yml",
            "logback.xml",
            "logback-spring.xml",
            "log4j.xml",
            "log4j.properties",
            "jdbc.properties",
            "datasource.properties",
            "hibernate.cfg.xml",
            "mybatis-config.xml",
            "mapper.xml",
            "persistence.xml",
            "weblogic.xml",
            "jboss-web.xml"
        };
        
        // 凭据和密钥文件
        String[] credentialFiles = {
            ".keystore",
            ".truststore",
            "keystore",
            "truststore",
            ".jks",
            ".p12",
            ".pfx",
            ".key",
            ".pem",
            ".crt",
            ".cer",
            ".der",
            "id_rsa",
            "id_dsa",
            "id_ecdsa",
            "id_ed25519",
            "authorized_keys",
            "known_hosts",
            ".ssh/"
        };
        
        // 环境变量和系统配置文件
        String[] envFiles = {
            ".env",
            ".env.local",
            ".env.production",
            ".env.development",
            ".bashrc",
            ".bash_profile",
            ".zshrc",
            ".profile",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/group",
            "/etc/sudoers",
            "/etc/hosts",
            "/etc/resolv.conf",
            "/etc/profile",
            "/etc/environment"
        };
        
        // 数据库和中间件配置
        String[] dbMiddlewareConfig = {
            "mysql",
            "postgres",
            "postgresql",
            "database",
            "datasource",
            "redis",
            "rabbitmq",
            "kafka",
            "zookeeper",
            "registry",
            "nacos",
            "consul",
            "etcd",
            "elasticsearch",
            "mongodb"
        };
        
        // 通用配置文件扩展名
        String[] configExtensions = {
            ".properties",
            ".xml",
            ".yml",
            ".yaml",
            ".conf",
            ".ini",
            ".cfg",
            ".config",
            ".json"
        };
        
        // 敏感关键词
        String[] sensitiveKeywords = {
            "password",
            "passwd",
            "credential",
            "secret",
            "token",
            "api_key",
            "apikey",
            "access_key",
            "private",
            "auth"
        };
        
        // 检查容器配置文件
        for (String file : containerConfigFiles) {
            if (lowerPath.contains(file)) {
                AlarmWithDetail("[SensitiveFile] 检测到 Web 容器配置文件：" + filePath);
                return true;
            }
        }
        
        // 检查应用配置文件
        for (String file : appConfigFiles) {
            if (lowerPath.contains(file)) {
                AlarmWithDetail("[SensitiveFile] 检测到应用配置文件：" + filePath);
                return true;
            }
        }
        
        // 检查凭据密钥文件
        for (String file : credentialFiles) {
            if (lowerPath.contains(file)) {
                AlarmWithDetail("[SensitiveFile] 检测到凭据密钥文件：" + filePath);
                return true;
            }
        }
        
        // 检查环境变量文件
        for (String file : envFiles) {
            if (lowerPath.contains(file)) {
                AlarmWithDetail("[SensitiveFile] 检测到环境变量/系统配置文件：" + filePath);
                return true;
            }
        }
        
        // 检查数据库中间件配置
        for (String keyword : dbMiddlewareConfig) {
            if (lowerPath.contains(keyword)) {
                AlarmWithDetail("[SensitiveFile] 检测到数据库/中间件配置文件：" + filePath);
                return true;
            }
        }
        
        // 检查配置文件扩展名 (需要同时包含 config 或 conf 等关键词)
        if (lowerPath.contains("config") || lowerPath.contains("conf") || 
            lowerPath.contains("setting") || lowerPath.contains("setup")) {
            for (String ext : configExtensions) {
                if (lowerPath.endsWith(ext)) {
                    AlarmWithDetail("[SensitiveFile] 检测到配置文件：" + filePath);
                    return true;
                }
            }
        }
        
        // 检查敏感关键词
        for (String keyword : sensitiveKeywords) {
            if (lowerPath.contains(keyword)) {
                AlarmWithDetail("[SensitiveFile] 检测到敏感关键词文件：" + filePath);
                return true;
            }
        }
        
        return false;
    }

    /**
     * 判断是否为敏感目录
     * 用于检测目录列举行为（如冰蝎文件管理探测 Tomcat conf 目录）
     */
    private static boolean isSensitiveDirectory(String dirPath) {
        if (dirPath == null) return false;
        String lowerPath = dirPath.toLowerCase();
        
        // Web 容器敏感目录
        String[] sensitiveDirs = {
            "tomcat/conf",
            "tomcat\\conf",
            "tomcat/webapps",
            "tomcat\\webapps",
            "tomcat/logs",
            "tomcat\\logs",
            "catalina/conf",
            "catalina\\conf",
            "catalina_base/conf",
            "catalina_base\\conf",
            "webapps/web-inf",
            "webapps\\web-inf",
            "webapps/meta-inf",
            "webapps\\meta-inf"
        };
        
        // 系统敏感目录 (Linux/Windows)
        String[] systemDirs = {
            "/etc/",
            "/etc\\",
            "etc/",
            "etc\\",
            "windows/system32",
            "windows\\system32",
            "windows/winnt",
            "windows\\winnt",
            "programdata/",
            "programdata\\",
            "users/all users",
            "users\\all users",
            "users/default",
            "users\\default",
            ".ssh/",
            ".ssh\\",
            ".git/",
            ".git\\",
            "svn/",
            "svn\\",
            ".svn/",
            ".svn\\"
        };
        
        // 应用敏感目录
        String[] appDirs = {
            "classpath/",
            "classpath\\",
            "config/",
            "config\\",
            "configuration/",
            "configuration\\",
            "secrets/",
            "secrets\\",
            "keys/",
            "keys\\",
            "credentials/",
            "credentials\\"
        };
        
        for (String dir : sensitiveDirs) {
            if (lowerPath.contains(dir)) {
                return true;
            }
        }
        
        for (String dir : systemDirs) {
            if (lowerPath.contains(dir)) {
                return true;
            }
        }
        
        for (String dir : appDirs) {
            if (lowerPath.contains(dir)) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * 阻断异常操作
     */
    private static void block(String reason, StackTraceElement[] stack) {
        AlertLogger.block("[TemporalGuard] " + reason);
        
        StringBuilder stackTrace = new StringBuilder();
        for (StackTraceElement element : stack) {
            stackTrace.append("\tat ").append(element.toString()).append("\n");
        }
        AlertLogger.error("[TemporalGuard] 调用栈:\n" + stackTrace);
        
        throw new SecurityException("[TemporalGuard] 阻断异常调用: " + reason);
    }

    /**
     * 发出告警
     */
    private static void alarm(String reason, StackTraceElement[] stack) {
        AlertLogger.alarm("[TemporalGuard] " + reason);
    }

    /**
     * 带文件路径详情的告警
     */
    private static void AlarmWithDetail(String message) {
        AlertLogger.alarm(message);
    }

    /**
     * 记录线程事件
     */
    private static void recordThreadEvent(String method, StackTemporalEngine.CallEvent.EventType type) {
        if (type == StackTemporalEngine.CallEvent.EventType.ENTER) {
            onMethodEnter(method);
        } else {
            onMethodExit(method);
        }
    }
}
