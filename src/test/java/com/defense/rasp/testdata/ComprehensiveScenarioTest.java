package com.defense.rasp.testdata;

import com.defense.rasp.stackmodel.*;

/**
 * 综合场景测试：模拟真实环境数据，验证模型检测效果
 */
public class ComprehensiveScenarioTest {

    /** 正常Web请求调用链 */
    private static final String[][] NORMAL_WEB_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"org.springframework.web.servlet.DispatcherServlet.doDispatch"},
        {"com.example.controller.UserController.getUser"},
        {"com.example.service.UserService.findById"},
        {"com.example.repository.UserRepository.findById"},
        {"org.springframework.jdbc.core.JdbcTemplate.query"}
    };

    /** 正常配置加载调用链 */
    private static final String[][] NORMAL_CONFIG_CHAIN = {
        {"org.springframework.context.support.AbstractApplicationContext.refresh"},
        {"org.springframework.context.support.PropertySourcesPlaceholderConfigurer.postProcessBeanFactory"},
        {"org.springframework.core.io.support.PropertiesLoaderUtils.loadProperties"},
        {"java.io.FileInputStream.<init>"}
    };

    /** 正常文件上传调用链 */
    private static final String[][] NORMAL_FILE_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"org.springframework.web.servlet.DispatcherServlet.doDispatch"},
        {"com.example.controller.FileController.upload"},
        {"java.io.FileOutputStream.<init>"}
    };

    /** 反射攻击调用链 */
    private static final String[][] REFLECTION_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"com.example.controller.EvilController.readConfig"},
        {"java.lang.reflect.Method.invoke"},
        {"sun.reflect.DelegatingMethodAccessorImpl.invoke"},
        {"java.io.FileInputStream.<init>"}
    };

    /** 类加载器攻击调用链 */
    private static final String[][] CLASSLOADER_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"com.example.controller.MaliciousController.loadClass"},
        {"java.lang.ClassLoader.loadClass"},
        {"java.net.URLClassLoader.findClass"},
        {"java.lang.ClassLoader.defineClass"}
    };

    /** 反序列化攻击调用链 */
    private static final String[][] DESERIAL_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"com.example.controller.ApiController.deserialize"},
        {"java.io.ObjectInputStream.readObject"}
    };

    /** 敏感文件攻击调用链 */
    private static final String[][] SENSITIVE_FILE_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter"},
        {"com.example.controller.Stealer.readFile"},
        {"java.io.FileInputStream.<init>"}
    };

    /** 边界情况：深度反射 */
    private static final String[][] DEEP_REFLECT_BOUNDARY_CHAIN = {
        {"org.springframework.aop.framework.JdkDynamicAopProxy.invoke"},
        {"java.lang.reflect.Method.invoke"},
        {"java.lang.reflect.Method.invoke"},
        {"org.springframework.jdbc.core.JdbcTemplate.query"}
    };

    public static void main(String[] args) {
        System.out.println("╔══════════════════════════════════════════════════════════════╗");
        System.out.println("║          Stack Anomaly Detector 综合场景测试                  ║");
        System.out.println("╚══════════════════════════════════════════════════════════════╝\n");

        BaselineLearningEngine.resetLearning();
        System.out.println("[初始化] 学习状态已重置\n");

        // 阶段1：学习正常模式
        System.out.println("══════════════════════════════════════════════════════════════");
        System.out.println("  阶段1：基线学习（500次正常调用）");
        System.out.println("══════════════════════════════════════════════════════════════");
        
        learnNormalPatterns();

        System.out.println("\n[基线学习] 完成!");
        System.out.println("  - 指纹数量: " + BaselineLearningEngine.getLearnedFingerprintCount());
        System.out.println("  - 转移图节点: " + BaselineLearningEngine.getTransitionGraphSize());

        // 阶段2：测试正常流量
        System.out.println("\n══════════════════════════════════════════════════════════════");
        System.out.println("  阶段2：正常流量测试（100次）");
        System.out.println("══════════════════════════════════════════════════════════════");
        
        int normalAlarms = testNormalTraffic(100);
        
        System.out.println("\n[正常流量结果]");
        System.out.println("  - 误报数: " + normalAlarms + "/100");
        System.out.println("  - 误报率: " + String.format("%.1f%%", (double) normalAlarms));

        // 阶段3：测试异常流量
        System.out.println("\n══════════════════════════════════════════════════════════════");
        System.out.println("  阶段3：异常流量测试");
        System.out.println("══════════════════════════════════════════════════════════════");
        
        int[] results = new int[4];
        
        // 反射攻击
        System.out.print("\n  [反射攻击] 测试20次... ");
        int reflectDetected = 0;
        for (int i = 0; i < 20; i++) {
            int score = BaselineLearningEngine.forceDetectAnomaly(generateStack(REFLECTION_ATTACK_CHAIN), 
                    "/etc/application.properties");
            if (score >= 30) reflectDetected++;
        }
        results[0] = reflectDetected;
        System.out.println("检测 " + reflectDetected + "/20 (" + (reflectDetected * 100 / 20) + "%)");
        
        // 类加载器攻击
        System.out.print("  [类加载器攻击] 测试15次... ");
        int classloadDetected = 0;
        for (int i = 0; i < 15; i++) {
            int score = BaselineLearningEngine.forceDetectAnomaly(generateStack(CLASSLOADER_ATTACK_CHAIN), 
                    "/tmp/evil.class");
            if (score >= 30) classloadDetected++;
        }
        results[1] = classloadDetected;
        System.out.println("检测 " + classloadDetected + "/15 (" + (classloadDetected * 100 / 15) + "%)");
        
        // 反序列化攻击
        System.out.print("  [反序列化攻击] 测试15次... ");
        int deserializeDetected = 0;
        for (int i = 0; i < 15; i++) {
            int score = BaselineLearningEngine.forceDetectAnomaly(generateStack(DESERIAL_ATTACK_CHAIN), 
                    "/tmp/payload.ser");
            if (score >= 30) deserializeDetected++;
        }
        results[2] = deserializeDetected;
        System.out.println("检测 " + deserializeDetected + "/15 (" + (deserializeDetected * 100 / 15) + "%)");
        
        // 敏感文件攻击
        System.out.print("  [敏感文件攻击] 测试20次... ");
        int sensitiveDetected = 0;
        for (int i = 0; i < 20; i++) {
            int score = BaselineLearningEngine.forceDetectAnomaly(generateStack(SENSITIVE_FILE_ATTACK_CHAIN), 
                    "/root/.ssh/id_rsa");
            if (score >= 30) sensitiveDetected++;
        }
        results[3] = sensitiveDetected;
        System.out.println("检测 " + sensitiveDetected + "/20 (" + (sensitiveDetected * 100 / 20) + "%)");

        // 阶段4：边界情况
        System.out.println("\n══════════════════════════════════════════════════════════════");
        System.out.println("  阶段4：边界情况测试");
        System.out.println("══════════════════════════════════════════════════════════════");
        
        System.out.print("  [深度反射边界] 测试10次... ");
        int deepRefAlarms = 0;
        for (int i = 0; i < 10; i++) {
            int score = BaselineLearningEngine.forceDetectAnomaly(generateStack(DEEP_REFLECT_BOUNDARY_CHAIN), 
                    "config.xml");
            if (score >= 30) deepRefAlarms++;
        }
        System.out.println("告警 " + deepRefAlarms + "/10");

        // 总结
        System.out.println("\n══════════════════════════════════════════════════════════════");
        System.out.println("  测试总结");
        System.out.println("══════════════════════════════════════════════════════════════");
        
        int totalDetected = results[0] + results[1] + results[2] + results[3];
        int totalAttacks = 70;
        double detectionRate = (double) totalDetected / totalAttacks * 100;
        
        System.out.println("  异常检测率: " + String.format("%.1f%%", detectionRate));
        System.out.println("  误报率: " + String.format("%.1f%%", (double) normalAlarms));
        
        if (detectionRate >= 90 && normalAlarms <= 5) {
            System.out.println("  ✅ 模型检测效果优秀!");
        } else if (detectionRate >= 70) {
            System.out.println("  ⚠️ 模型检测效果良好");
        } else {
            System.out.println("  ❌ 模型需要优化");
        }

        System.out.println("\n测试完成!");
    }

    private static void learnNormalPatterns() {
        for (int i = 0; i < 500; i++) {
            StackTraceElement[] stack;
            int rand = (int) (Math.random() * 100);
            if (rand < 60) {
                stack = generateStack(NORMAL_WEB_CHAIN);
            } else if (rand < 80) {
                stack = generateStack(NORMAL_CONFIG_CHAIN);
            } else {
                stack = generateStack(NORMAL_FILE_CHAIN);
            }
            BaselineLearningEngine.learnNormalStack(stack, i < 100);
            if ((i + 1) % 100 == 0) {
                System.out.println("  进度: " + (i + 1) + "/500");
            }
        }
    }

    private static int testNormalTraffic(int count) {
        int alarms = 0;
        for (int i = 0; i < count; i++) {
            StackTraceElement[] stack;
            int rand = (int) (Math.random() * 100);
            if (rand < 60) {
                stack = generateStack(NORMAL_WEB_CHAIN);
            } else if (rand < 80) {
                stack = generateStack(NORMAL_CONFIG_CHAIN);
            } else {
                stack = generateStack(NORMAL_FILE_CHAIN);
            }
            int score = BaselineLearningEngine.detectAnomaly(stack, "normal.txt");
            if (score >= 30) {
                alarms++;
            }
        }
        return alarms;
    }

    private static StackTraceElement[] generateStack(String[][] template) {
        java.util.List<StackTraceElement> stack = new java.util.ArrayList<>();
        for (int i = template.length - 1; i >= 0; i--) {
            String method = template[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            stack.add(new StackTraceElement(className, methodName, className.substring(className.lastIndexOf('.') + 1) + ".java", 1));
        }
        return stack.toArray(new StackTraceElement[0]);
    }
}
