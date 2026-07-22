package com.defense.rasp.stackmodel;

import java.security.Permission;

/**
 * RASP 安全管理器 - 拦截文件 I/O、命令执行
 * 核心原则：检测逻辑异常绝不能阻断正常业务流
 * 使用 ThreadLocal 防止 AlertLogger 写日志触发递归 StackOverflow
 */
public class RaspSecurityManager extends java.lang.SecurityManager {

    private final java.lang.SecurityManager parent;
    
    /**
     * 防重入标志 - 检测逻辑内部写日志时会再次触发 checkWrite/checkRead，
     * 通过此标记跳过二次检测，避免 StackOverflowError
     */
    private static final ThreadLocal<Boolean> IN_DETECTION = ThreadLocal.withInitial(() -> false);

    public RaspSecurityManager(java.lang.SecurityManager parent) {
        this.parent = parent;
        AlertLogger.warn("[RaspSecurityManager] 初始化成功" + (parent != null ? "，已连接父级管理器" : ""));
    }

    @Override
    public void checkRead(String file) {
        if (IN_DETECTION.get()) return;
        try {
            IN_DETECTION.set(true);
            TemporalGuard.onFileRead(file);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
            // 检测逻辑异常，静默处理
        } finally {
            IN_DETECTION.remove();
        }
    }

    @Override
    public void checkRead(String file, Object context) {
        checkRead(file);
    }

    @Override
    public void checkWrite(String file) {
        if (IN_DETECTION.get()) return;
        try {
            IN_DETECTION.set(true);
            TemporalGuard.onFileWrite(file);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
        } finally {
            IN_DETECTION.remove();
        }
    }

    @Override
    public void checkDelete(String file) {
        if (IN_DETECTION.get()) return;
        try {
            IN_DETECTION.set(true);
            TemporalGuard.onFileDelete(file);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
        } finally {
            IN_DETECTION.remove();
        }
    }

    @Override
    public void checkExec(String cmd) {
        if (IN_DETECTION.get()) return;
        try {
            IN_DETECTION.set(true);
            TemporalGuard.onCommandExec(cmd);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
        } finally {
            IN_DETECTION.remove();
        }
    }

    @Override
    public void checkConnect(String host, int port) {
        if (IN_DETECTION.get()) return;
        if (isKnownServicePort(port)) return;
        String uri = TemporalGuard.getCurrentUri();
        if (uri == null) return;
        try {
            IN_DETECTION.set(true);
            TemporalGuard.onSuspiciousOutboundConnection(host, port);
        } catch (SecurityException e) {
            throw e;
        } catch (Throwable e) {
        } finally {
            IN_DETECTION.remove();
        }
    }

    private static boolean isKnownServicePort(int port) {
        switch (port) {
            case 3306:  case 5432:  case 6379:  case 11211:
            case 9200:  case 9300:  case 27017: case 5672:
            case 9092:  case 80:    case 443:   case 8080:
            case 8443:  case 53:    case 25:    case 587:
            case 1433:  case 1521:  case 2049:
                return true;
            default:
                return false;
        }
    }

    /**
     * 放行所有包访问检查，避免干扰 Tomcat WebappClassLoader 类加载
     * 此方法由 JVM 在类加载时直接调用，不经过 checkPermission
     */
    @Override
    public void checkPackageAccess(String pkg) {
        // 完全放行 - 包访问安全检查不影响文件/命令检测
    }

    /**
     * 放行包定义检查（类加载时 JVM 直接调用）
     */
    @Override
    public void checkPackageDefinition(String pkg) {
        // 完全放行
    }

    @Override
    public void checkPermission(Permission perm) {
        String permName = perm.getClass().getName();
        if ("java.util.PropertyPermission".equals(permName)) {
            return;
        }
        if ("java.lang.RuntimePermission".equals(permName)) {
            String name = perm.getName();
            if (name.startsWith("accessClassInPackage.") ||
                name.startsWith("defineClassInPackage.") ||
                name.equals("getProtectionDomain") ||
                name.equals("getClassLoader") ||
                name.equals("closeClassLoader") ||
                name.equals("getStackTrace") ||
                name.equals("modifyThread") ||
                name.equals("modifyThreadGroup") ||
                name.startsWith("accessDeclaredMembers")) {
                return;
            }
        }
        if ("java.net.NetPermission".equals(permName)) {
            return;
        }
        if ("java.net.SocketPermission".equals(permName)) {
            return;
        }
        if ("javax.net.ssl.SSLPermission".equals(permName)) {
            return;
        }
        if ("java.io.FilePermission".equals(permName)) {
            return;
        }
        if ("java.lang.reflect.ReflectPermission".equals(permName)) {
            return;
        }
        if ("java.security.SecurityPermission".equals(permName)) {
            return;
        }
        if (parent != null) {
            parent.checkPermission(perm);
        }
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        String permName = perm.getClass().getName();
        if ("java.util.PropertyPermission".equals(permName)) { return; }
        if ("java.lang.RuntimePermission".equals(permName)) {
            String name = perm.getName();
            if (name.startsWith("accessClassInPackage.") ||
                name.startsWith("defineClassInPackage.") ||
                name.equals("getProtectionDomain") ||
                name.equals("getClassLoader") ||
                name.equals("closeClassLoader") ||
                name.equals("getStackTrace") ||
                name.equals("modifyThread") ||
                name.equals("modifyThreadGroup") ||
                name.startsWith("accessDeclaredMembers")) {
                return;
            }
        }
        if ("java.net.NetPermission".equals(permName)) { return; }
        if ("java.net.SocketPermission".equals(permName)) { return; }
        if ("javax.net.ssl.SSLPermission".equals(permName)) { return; }
        if ("java.io.FilePermission".equals(permName)) { return; }
        if ("java.lang.reflect.ReflectPermission".equals(permName)) { return; }
        if ("java.security.SecurityPermission".equals(permName)) { return; }
        if (parent != null) {
            parent.checkPermission(perm, context);
        }
    }
}
