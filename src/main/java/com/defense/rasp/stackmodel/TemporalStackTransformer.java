package com.defense.rasp.stackmodel;

import org.objectweb.asm.*;
import org.objectweb.asm.commons.AdviceAdapter;
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
            try {
                return hookHttpServlet(classfileBuffer);
            } catch (Throwable t) {
                System.err.println("[TemporalStackTransformer] HttpServlet 插桩失败: " + t.getMessage());
                t.printStackTrace();
                return null;
            }
        }

        if ("javax/servlet/ServletContext".equals(className)) {
            AlertLogger.debug("[TemporalStackTransformer] 插桩 ServletContext");
            try {
                return hookServletContext(classfileBuffer);
            } catch (Throwable t) {
                System.err.println("[TemporalStackTransformer] ServletContext 插桩失败: " + t.getMessage());
                t.printStackTrace();
                return null;
            }
        }
        
        return null;
    }
    
    private byte[] hookHttpServlet(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_FRAMES);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                if ("service".equals(name) && "(Ljavax/servlet/ServletRequest;Ljavax/servlet/ServletResponse;)V".equals(descriptor)) {
                    return new AdviceAdapter(Opcodes.ASM9, mv, access, name, descriptor) {
                        @Override
                        protected void onMethodEnter() {
                            // beforeService(req)
                            super.visitVarInsn(Opcodes.ALOAD, 1);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "beforeService", "(Ljava/lang/Object;)V", false);
                        }

                        @Override
                        protected void onMethodExit(int opcode) {
                            // afterService(req, res) — finally 语义
                            super.visitVarInsn(Opcodes.ALOAD, 1);
                            super.visitVarInsn(Opcodes.ALOAD, 2);
                            super.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "afterService", "(Ljava/lang/Object;Ljava/lang/Object;)V", false);
                        }
                    };
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
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
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }
}
