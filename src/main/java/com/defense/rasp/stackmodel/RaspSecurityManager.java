package com.defense.rasp.stackmodel;

import java.security.Permission;

/**
 * RASP 安全管理器 - 拦截文件 I/O、命令执行、文件删除
 * 核心原则：检测逻辑异常绝不能阻断正常业务流
 */
public class RaspSecurityManager extends java.lang.SecurityManager {

    private final java.lang.SecurityManager parent;

    public RaspSecurityManager(java.lang.SecurityManager parent) {
        this.parent = parent;
        AlertLogger.info("[RaspSecurityManager] 初始化成功" + (parent != null ? "，已连接父级管理器" : ""));
    }

    @Override
    public void checkRead(String file) {
        try {
            TemporalGuard.onFileRead(file);
        } catch (Exception e) {
            // 检测逻辑异常，静默处理，不阻断业务
        }
    }

    @Override
    public void checkRead(String file, Object context) {
        try {
            TemporalGuard.onFileRead(file);
        } catch (Exception e) {
            // 检测逻辑异常，静默处理
        }
    }

    @Override
    public void checkWrite(String file) {
        try {
            TemporalGuard.onFileWrite(file);
        } catch (Exception e) {
            // 检测逻辑异常，静默处理
        }
    }

    @Override
    public void checkDelete(String file) {
        try {
            TemporalGuard.onFileDelete(file);
        } catch (Exception e) {
            // 检测逻辑异常，静默处理
        }
    }

    @Override
    public void checkExec(String cmd) {
        try {
            TemporalGuard.onCommandExec(cmd);
        } catch (Exception e) {
            // 检测逻辑异常，静默处理
        }
    }

    @Override
    public void checkPermission(Permission perm) {
        String permName = perm.getClass().getName();
        // 放行属性权限
        if ("java.util.PropertyPermission".equals(permName)) {
            return;
        }
        // 放行类加载相关权限
        if ("java.lang.RuntimePermission".equals(permName)) {
            String name = perm.getName();
            if (name.startsWith("accessClassInPackage.") ||
                name.startsWith("defineClassInPackage.") ||
                name.equals("getProtectionDomain") ||
                name.equals("getClassLoader") ||
                name.equals("closeClassLoader") ||
                name.startsWith("accessDeclaredMembers")) {
                return;
            }
        }
        // 放行网络连接权限（WebSocket 等需要）
        if ("java.net.NetPermission".equals(permName)) {
            return;
        }
        if ("java.net.SocketPermission".equals(permName)) {
            return;
        }
        // SSL/TLS 权限
        if ("javax.net.ssl.SSLPermission".equals(permName)) {
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
                name.startsWith("accessDeclaredMembers")) {
                return;
            }
        }
        if ("java.net.NetPermission".equals(permName)) { return; }
        if ("java.net.SocketPermission".equals(permName)) { return; }
        if ("javax.net.ssl.SSLPermission".equals(permName)) { return; }
        if (parent != null) {
            parent.checkPermission(perm, context);
        }
    }
}
