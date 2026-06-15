package com.defense.rasp.stackmodel;

import java.security.Permission;

/**
 * RASP 安全管理器 - 拦截文件 IO、命令执行、文件删除
 * 默认放行非受控操作，避免破坏应用正常启动和运行
 */
public class RaspSecurityManager extends java.lang.SecurityManager {

    private final java.lang.SecurityManager parent;

    public RaspSecurityManager(java.lang.SecurityManager parent) {
        this.parent = parent;
        AlertLogger.info("[RaspSecurityManager] 初始化成功" + (parent != null ? "，已连接父级管理器" : ""));
    }

    @Override
    public void checkRead(String file) {
        TemporalGuard.onFileRead(file);
    }

    @Override
    public void checkRead(String file, Object context) {
        TemporalGuard.onFileRead(file);
    }

    @Override
    public void checkWrite(String file) {
        TemporalGuard.onFileWrite(file);
    }

    @Override
    public void checkDelete(String file) {
        TemporalGuard.onFileDelete(file);
    }

    @Override
    public void checkExec(String cmd) {
        TemporalGuard.onCommandExec(cmd);
    }

    @Override
    public void checkPermission(Permission perm) {
        String permName = perm.getClass().getName();
        if (permName.equals("java.util.PropertyPermission")) {
            return;
        }
        if (permName.equals("java.lang.RuntimePermission") &&
            (perm.getName().startsWith("accessClassInPackage.") ||
             perm.getName().startsWith("defineClassInPackage."))) {
            return;
        }
        if (parent != null) {
            parent.checkPermission(perm);
        }
    }

    @Override
    public void checkPermission(Permission perm, Object context) {
        String permName = perm.getClass().getName();
        if (permName.equals("java.util.PropertyPermission")) {
            return;
        }
        if (permName.equals("java.lang.RuntimePermission") &&
            (perm.getName().startsWith("accessClassInPackage.") ||
             perm.getName().startsWith("defineClassInPackage."))) {
            return;
        }
        if (parent != null) {
            parent.checkPermission(perm, context);
        }
    }
}
