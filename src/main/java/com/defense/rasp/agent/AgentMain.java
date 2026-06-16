package com.defense.rasp.agent;

import com.defense.rasp.stackmodel.AlertLogger;
import com.defense.rasp.stackmodel.TemporalStackTransformer;
import java.lang.instrument.ClassDefinition;
import java.lang.instrument.Instrumentation;

/**
 * Java Agent 入口类
 * 通过 -javaagent 参数加载，实现字节码插桩
 */
public class AgentMain {

    private static final String[] TARGET_CLASSES = {
        // Servlet - Web 请求入口 (Tomcat 加载，可安全 Hook)
        "javax.servlet.http.HttpServlet",
        "javax.servlet.ServletContext"
    };

    /**
     * 延迟安装 RASP 安全管理器
     * SecurityManager 如果在 Tomcat 启动阶段激活，会干扰 webapp 类加载和部署流程
     * （JDK 8 中 checkPackageAccess/checkRead 调用极高频），导致 /examples 等内置应用 404
     * 解决方案：延迟 15 秒等待 Tomcat 启动完成后再安装
     */
    private static void installSecurityManagerDeferred() {
        Thread smThread = new Thread(() -> {
            try {
                // 等待 Tomcat 完全启动（默认 15 秒，可通过系统属性调整）
                int delay = Integer.parseInt(System.getProperty("rasp.sm.delay", "15"));
                System.out.println("[StackAnomalyDetector] SecurityManager 将在 " + delay + " 秒后安装（等待 Tomcat 就绪）");
                Thread.sleep(delay * 1000L);
                
                java.lang.SecurityManager current = System.getSecurityManager();
                com.defense.rasp.stackmodel.RaspSecurityManager raspSM = 
                        new com.defense.rasp.stackmodel.RaspSecurityManager(current);
                System.setSecurityManager(raspSM);
                System.out.println("[StackAnomalyDetector] RASP SecurityManager 已安装" + 
                        (current != null ? " (连接父级管理器)" : " (替换默认管理器)"));
            } catch (InterruptedException e) {
                System.out.println("[StackAnomalyDetector] SecurityManager 延迟安装被中断");
                Thread.currentThread().interrupt();
            } catch (SecurityException e) {
                System.out.println("[StackAnomalyDetector] SecurityManager 安装失败 (权限受限): " + e.getMessage());
            } catch (Exception e) {
                System.err.println("[StackAnomalyDetector] SecurityManager 安装异常: " + e.getMessage());
                e.printStackTrace();
            }
        }, "RaspSecurityManager-Installer");
        smThread.setDaemon(false);
        smThread.start();
    }

    /**
     * 立即安装 SecurityManager（仅在 JVM 参数 rasp.sm.immediate=true 时使用）
     * 适用于非 Tomcat 环境或已知不会干扰启动的场景
     */
    private static void installSecurityManagerImmediate() {
        try {
            java.lang.SecurityManager current = System.getSecurityManager();
            com.defense.rasp.stackmodel.RaspSecurityManager raspSM = 
                    new com.defense.rasp.stackmodel.RaspSecurityManager(current);
            System.setSecurityManager(raspSM);
            System.out.println("[StackAnomalyDetector] RASP SecurityManager 已安装(立即)" + 
                    (current != null ? " (连接父级管理器)" : " (替换默认管理器)"));
        } catch (SecurityException e) {
            System.out.println("[StackAnomalyDetector] SecurityManager 安装失败 (权限受限): " + e.getMessage());
        }
    }

    /**
     * Agent入口方法
     * @param agentArgs Agent参数
     * @param inst Instrumentation实例
     */
    public static void premain(String agentArgs, Instrumentation inst) {
        AgentConfig.parseArgs(agentArgs);
        
        System.out.println("[StackAnomalyDetector] Agent initialized with args: " + (agentArgs != null ? agentArgs : "none"));
        
        try {
            // Initialize Learning Engine first
            initializeLearningEngine();
            
            // 延迟安装 SecurityManager，避免干扰 Tomcat 启动
            if (Boolean.parseBoolean(System.getProperty("rasp.sm.immediate", "false"))) {
                installSecurityManagerImmediate();
            } else {
                installSecurityManagerDeferred();
            }
            
            TemporalStackTransformer transformer = new TemporalStackTransformer();
            
            inst.addTransformer(transformer, true);
            
            System.out.println("[StackAnomalyDetector] Bytecode transformer registered successfully");
            System.out.println("[StackAnomalyDetector] redefineClasses支持: " + inst.isRedefineClassesSupported());
            System.out.println("[StackAnomalyDetector] retransformClasses支持: " + inst.isRetransformClassesSupported());
            System.out.println("[StackAnomalyDetector] nativeMethodPrefix支持: " + inst.isNativeMethodPrefixSupported());
            
            if (inst.isRetransformClassesSupported()) {
                processLoadedClasses(inst, transformer);
            } else if (inst.isRedefineClassesSupported()) {
                processLoadedClasses(inst, transformer);
            } else {
                System.out.println("[StackAnomalyDetector] 当前环境不支持redefineClasses，仅监控后续加载的类");
            }
            
            listLoadedClasses(inst);
            
            System.out.println("[StackAnomalyDetector] Agent initialization complete");
        } catch (Exception e) {
            System.err.println("[StackAnomalyDetector] Agent initialization failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initializeLearningEngine() {
        try {
            com.defense.rasp.stackmodel.BaselineLearningEngine.setLearningDuration(
                    AgentConfig.getLearningDurationMs());
            Class.forName("com.defense.rasp.stackmodel.BaselineLearningEngine");
            System.out.println("[StackAnomalyDetector] 学习引擎初始化完成，学习时长: " + AgentConfig.getLearningDurationMs() + "ms");
        } catch (ClassNotFoundException e) {
            System.err.println("[StackAnomalyDetector] 学习引擎初始化失败: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("[StackAnomalyDetector] 学习引擎初始化异常: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void processLoadedClasses(Instrumentation inst, TemporalStackTransformer transformer) {
        int successCount = 0;
        int failCount = 0;
        int skipCount = 0;
        
        System.out.println("[StackAnomalyDetector] 开始处理已加载类...");
        
        for (String className : TARGET_CLASSES) {
            try {
                Class<?> clazz = Class.forName(className);
                
                if (inst.isModifiableClass(clazz)) {
                    if (inst.isRetransformClassesSupported()) {
                        inst.retransformClasses(clazz);
                        successCount++;
                        System.out.println("[StackAnomalyDetector] 已重新转换类: " + className);
                    } else {
                        byte[] originalBytes = getClassBytes(className);
                        if (originalBytes != null) {
                            byte[] transformedBytes = transformer.transform(
                                clazz.getClassLoader(),
                                className.replace('.', '/'),
                                clazz,
                                null,
                                originalBytes
                            );
                            
                            if (transformedBytes != null) {
                                ClassDefinition def = new ClassDefinition(clazz, transformedBytes);
                                inst.redefineClasses(def);
                                successCount++;
                                System.out.println("[StackAnomalyDetector] 已重新定义类: " + className);
                            } else {
                                skipCount++;
                                System.out.println("[StackAnomalyDetector] 类无需转换: " + className);
                            }
                        } else {
                            failCount++;
                            System.out.println("[StackAnomalyDetector] 无法获取类字节码: " + className);
                        }
                    }
                } else {
                    failCount++;
                    System.out.println("[StackAnomalyDetector] 类不可修改: " + className);
                }
            } catch (ClassNotFoundException e) {
                System.out.println("[StackAnomalyDetector] 类尚未加载，将在运行时插桩: " + className);
            } catch (Exception e) {
                failCount++;
                System.err.println("[StackAnomalyDetector] 处理类失败: " + className + ", 原因: " + e.getMessage());
                e.printStackTrace();
            }
        }
        
        System.out.println("[StackAnomalyDetector] 类处理完成 - 成功: " + successCount + ", 失败: " + failCount + ", 跳过: " + skipCount);
    }

    private static void listLoadedClasses(Instrumentation inst) {
        System.out.println("[StackAnomalyDetector] 已加载的 Servlet 相关类:");
        for (Class<?> clazz : inst.getAllLoadedClasses()) {
            String name = clazz.getName();
            if (name.contains("javax.servlet") || name.contains("org.apache.catalina")) {
                System.out.println("[StackAnomalyDetector]   " + name);
            }
        }
    }

    private static byte[] getClassBytes(String className) {
        java.io.InputStream is = null;
        java.util.jar.JarFile jarFile = null;
        try {
            String resourcePath = className.replace('.', '/') + ".class";
            
            is = ClassLoader.getSystemClassLoader().getResourceAsStream(resourcePath);
            
            if (is == null) {
                ClassLoader extClassLoader = null;
                try {
                    java.lang.reflect.Field extField = ClassLoader.class.getDeclaredField("extClassLoader");
                    extField.setAccessible(true);
                    extClassLoader = (ClassLoader) extField.get(null);
                } catch (Exception e) {
                }
                if (extClassLoader != null) {
                    is = extClassLoader.getResourceAsStream(resourcePath);
                }
            }
            
            if (is == null) {
                java.io.File file = new java.io.File(System.getProperty("java.home") + "/lib/rt.jar");
                if (file.exists()) {
                    jarFile = new java.util.jar.JarFile(file);
                    java.util.jar.JarEntry entry = jarFile.getJarEntry(resourcePath);
                    if (entry != null) {
                        is = jarFile.getInputStream(entry);
                    }
                }
            }
            
            if (is == null) {
                if (jarFile != null) {
                    try { jarFile.close(); } catch (Exception e) {}
                }
                return null;
            }
            
            java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
            byte[] buffer = new byte[4096];
            int len;
            while ((len = is.read(buffer)) != -1) {
                baos.write(buffer, 0, len);
            }
            byte[] bytes = baos.toByteArray();
            is.close();
            if (jarFile != null) {
                jarFile.close();
            }
            return bytes;
        } catch (Exception e) {
            if (is != null) {
                try { is.close(); } catch (Exception ex) {}
            }
            if (jarFile != null) {
                try { jarFile.close(); } catch (Exception ex) {}
            }
            return null;
        }
    }

    /**
     * 备用入口方法（某些JVM实现要求）
     */
    public static void premain(String agentArgs) {
        System.err.println("[StackAnomalyDetector] Agent loaded without Instrumentation support");
    }

    /**
     * agentmain 方法 - 支持运行时附加到正在运行的 JVM
     */
    public static void agentmain(String agentArgs, Instrumentation inst) {
        AgentConfig.parseArgs(agentArgs);
        
        System.out.println("[StackAnomalyDetector] Agent attached at runtime with args: " + (agentArgs != null ? agentArgs : "none"));
        
        try {
            // Initialize Learning Engine first
            initializeLearningEngine();
            
            // agentmain 是运行时附加，Tomcat 已启动，立即安装 SecurityManager
            installSecurityManagerImmediate();
            
            TemporalStackTransformer transformer = new TemporalStackTransformer();
            
            inst.addTransformer(transformer, true);
            
            System.out.println("[StackAnomalyDetector] Bytecode transformer registered successfully");
            System.out.println("[StackAnomalyDetector] redefineClasses支持: " + inst.isRedefineClassesSupported());
            System.out.println("[StackAnomalyDetector] retransformClasses支持: " + inst.isRetransformClassesSupported());
            
            initializeLearningEngine();
            
            if (inst.isRedefineClassesSupported()) {
                processLoadedClasses(inst, transformer);
            } else {
                System.out.println("[StackAnomalyDetector] 当前环境不支持redefineClasses，仅监控后续加载的类");
            }
            
            System.out.println("[StackAnomalyDetector] Agent attachment complete");
        } catch (Exception e) {
            System.err.println("[StackAnomalyDetector] Agent attachment failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * 备用 agentmain 方法
     */
    public static void agentmain(String agentArgs) {
        System.err.println("[StackAnomalyDetector] Agent attached without Instrumentation support");
    }
}