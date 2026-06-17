package com.defense.rasp.stackmodel;

import org.objectweb.asm.*;
import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class TemporalStackTransformer implements ClassFileTransformer {

    private static final String GUARD_CLASS = "com/defense/rasp/stackmodel/TemporalGuard";

    @Override
    public byte[] transform(ClassLoader loader, String className,
                          Class<?> classBeingRedefined,
                          ProtectionDomain protectionDomain,
                          byte[] classfileBuffer) {

        if ("javax/servlet/http/HttpServlet".equals(className)) {
            AlertLogger.debug("[TemporalStackTransformer] 插桩 HttpServlet");
            return hookHttpServlet(classfileBuffer);
        }

        if ("javax/servlet/ServletContext".equals(className)) {
            AlertLogger.debug("[TemporalStackTransformer] 插桩 ServletContext");
            return hookServletContext(classfileBuffer);
        }
        
        // Bootstrap 类 (java.*) 不进行 ASM Hook
        // 文件 I/O → RaspSecurityManager.checkRead/Write/Delete
        // 命令执行 → RaspSecurityManager.checkExec

        return null;
    }
    
    private byte[] hookHttpServlet(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                if ("service".equals(name) && "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onHttpServlet", "(Ljava/lang/Object;)V", false);
                        }
                    };
                }
                return mv;
            }
        };
        cr.accept(cv, 0);
        return cw.toByteArray();
    }
    
    private byte[] hookServletContext(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                String reqStr = "(Ljava/lang/String;)";
                
                if (("getRealPath".equals(name) || "getResource".equals(name) || "getResourceAsStream".equals(name)) && 
                    descriptor.startsWith(reqStr)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onServletContextAccess", "(Ljava/lang/String;)V", false);
                        }
                    };
                }
                return mv;
            }
        };
        cr.accept(cv, 0);
        return cw.toByteArray();
    }
}
