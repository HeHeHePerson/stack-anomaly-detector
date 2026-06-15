
package com.defense.rasp.testdata;

import java.util.*;

/**
 * 测试数据生成工具：生成模拟的Java堆栈信息
 */
public class StackDataGenerator {

    private static final Random RANDOM = new Random();

    /**
     * 正常的Web请求调用链模板
     */
    private static final String[][] NORMAL_WEB_CALL_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter", "servlet-api"},
        {"org.springframework.web.servlet.DispatcherServlet.doDispatch", "spring-core"},
        {"com.example.controller.UserController.getUser", "user-code"},
        {"com.example.service.UserService.findById", "user-code"},
        {"com.example.repository.UserRepository.findById", "user-code"},
        {"org.springframework.jdbc.core.JdbcTemplate.query", "spring-core"},
        {"java.sql.Connection.prepareStatement", "java-sql"}
    };

    /**
     * 正常的配置加载调用链模板
     */
    private static final String[][] NORMAL_CONFIG_CHAIN = {
        {"org.springframework.context.support.AbstractApplicationContext.refresh", "spring-core"},
        {"org.springframework.context.support.PropertySourcesPlaceholderConfigurer.postProcessBeanFactory", "spring-core"},
        {"org.springframework.core.io.support.PropertiesLoaderUtils.loadProperties", "spring-core"},
        {"java.io.FileInputStream.<init>", "java-io"}
    };

    /**
     * 反射攻击调用链模板
     */
    private static final String[][] REFLECTION_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter", "servlet-api"},
        {"com.example.controller.EvilController.attack", "user-code"},
        {"java.lang.reflect.Method.invoke", "java-reflect"},
        {"java.lang.reflect.Method.invoke", "java-reflect"},
        {"sun.reflect.DelegatingMethodAccessorImpl.invoke", "jdk-reflect"},
        {"java.io.FileInputStream.<init>", "java-io"}
    };

    /**
     * 直接IO攻击调用链模板（缺少中间层）
     */
    private static final String[][] DIRECT_IO_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter", "servlet-api"},
        {"java.io.FileInputStream.<init>", "java-io"}
    };

    /**
     * 类加载器攻击调用链模板
     */
    private static final String[][] CLASSLOADER_ATTACK_CHAIN = {
        {"org.apache.catalina.core.ApplicationFilterChain.doFilter", "servlet-api"},
        {"com.example.controller.EvilController.attack", "user-code"},
        {"java.lang.ClassLoader.getSystemClassLoader", "java-lang"},
        {"java.lang.ClassLoader.defineClass", "java-lang"}
    };

    /**
     * 生成随机的正常Web请求调用栈
     */
    public static StackTraceElement[] generateNormalWebStack() {
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = NORMAL_WEB_CALL_CHAIN.length - 1; i >= 0; i--) {
            String method = NORMAL_WEB_CALL_CHAIN[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成正常的配置加载调用栈
     */
    public static StackTraceElement[] generateNormalConfigStack() {
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = NORMAL_CONFIG_CHAIN.length - 1; i >= 0; i--) {
            String method = NORMAL_CONFIG_CHAIN[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成反射攻击调用栈
     */
    public static StackTraceElement[] generateReflectionAttackStack() {
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = REFLECTION_ATTACK_CHAIN.length - 1; i >= 0; i--) {
            String method = REFLECTION_ATTACK_CHAIN[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成直接IO攻击调用栈（Web直接到IO）
     */
    public static StackTraceElement[] generateDirectIOAttackStack() {
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = DIRECT_IO_ATTACK_CHAIN.length - 1; i >= 0; i--) {
            String method = DIRECT_IO_ATTACK_CHAIN[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成类加载器攻击调用栈
     */
    public static StackTraceElement[] generateClassLoaderAttackStack() {
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = CLASSLOADER_ATTACK_CHAIN.length - 1; i >= 0; i--) {
            String method = CLASSLOADER_ATTACK_CHAIN[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成随机混合调用栈
     */
    public static StackTraceElement[] generateMixedStack() {
        String[][] templates = {
            {"com.example.util.ConfigReader.load", "user-code"},
            {"com.example.service.ConfigService.getConfig", "user-code"},
            {"org.springframework.beans.factory.support.DefaultListableBeanFactory.preInstantiateSingletons", "spring-core"},
            {"org.springframework.context.support.AbstractApplicationContext.finishBeanFactoryInitialization", "spring-core"}
        };
        
        List<StackTraceElement> stack = new ArrayList<>();
        
        for (int i = templates.length - 1; i >= 0; i--) {
            String method = templates[i][0];
            String className = method.substring(0, method.lastIndexOf('.'));
            String methodName = method.substring(method.lastIndexOf('.') + 1);
            
            stack.add(new StackTraceElement(
                className,
                methodName,
                className.substring(className.lastIndexOf('.') + 1) + ".java",
                RANDOM.nextInt(100) + 1
            ));
        }
        
        return stack.toArray(new StackTraceElement[0]);
    }

    /**
     * 生成批量测试数据
     * @param count 生成数量
     * @param type 数据类型：NORMAL_WEB, NORMAL_CONFIG, REFLECTION_ATTACK, DIRECT_IO_ATTACK, CLASSLOADER_ATTACK, MIXED
     */
    public static List<StackTraceElement[]> generateBatchData(int count, String type) {
        List<StackTraceElement[]> data = new ArrayList<>();
        
        for (int i = 0; i < count; i++) {
            switch (type.toUpperCase()) {
                case "NORMAL_WEB":
                    data.add(generateNormalWebStack());
                    break;
                case "NORMAL_CONFIG":
                    data.add(generateNormalConfigStack());
                    break;
                case "REFLECTION_ATTACK":
                    data.add(generateReflectionAttackStack());
                    break;
                case "DIRECT_IO_ATTACK":
                    data.add(generateDirectIOAttackStack());
                    break;
                case "CLASSLOADER_ATTACK":
                    data.add(generateClassLoaderAttackStack());
                    break;
                case "MIXED":
                    data.add(generateMixedStack());
                    break;
                default:
                    data.add(generateNormalWebStack());
            }
        }
        
        return data;
    }

    /**
     * 打印调用栈信息
     */
    public static void printStack(StackTraceElement[] stack) {
        System.out.println("调用栈信息 (" + stack.length + " 层):");
        for (int i = 0; i < stack.length; i++) {
            System.out.printf("  [%d] %s.%s(%s:%d)%n", 
                i, 
                stack[i].getClassName(),
                stack[i].getMethodName(),
                stack[i].getFileName(),
                stack[i].getLineNumber());
        }
    }

    /**
     * 主方法：生成测试数据示例
     */
    public static void main(String[] args) {
        System.out.println("=== 测试数据生成示例 ===");
        
        System.out.println("\n1. 正常Web请求调用栈:");
        printStack(generateNormalWebStack());
        
        System.out.println("\n2. 正常配置加载调用栈:");
        printStack(generateNormalConfigStack());
        
        System.out.println("\n3. 反射攻击调用栈:");
        printStack(generateReflectionAttackStack());
        
        System.out.println("\n4. 直接IO攻击调用栈:");
        printStack(generateDirectIOAttackStack());
        
        System.out.println("\n5. 类加载器攻击调用栈:");
        printStack(generateClassLoaderAttackStack());
        
        System.out.println("\n=== 生成批量测试数据 ===");
        List<StackTraceElement[]> batchData = generateBatchData(10, "NORMAL_WEB");
        System.out.println("已生成 " + batchData.size() + " 条正常Web请求调用栈");
    }
}
