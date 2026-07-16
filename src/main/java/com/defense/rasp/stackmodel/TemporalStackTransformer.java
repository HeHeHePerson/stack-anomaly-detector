package com.defense.rasp.stackmodel;

import org.objectweb.asm.*;

import java.lang.instrument.ClassFileTransformer;
import java.security.ProtectionDomain;

public class TemporalStackTransformer implements ClassFileTransformer {

    private static final String GUARD_CLASS = "com/defense/rasp/stackmodel/TemporalGuard";
    private static final String BEFORE_DESC = "(Ljava/lang/Object;Ljava/lang/Object;)V";
    private static final String AFTER_DESC = "(Ljava/lang/Object;Ljava/lang/Object;)V";

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
                    return new TryFinallyMethodVisitor(Opcodes.ASM9, mv, access, name, descriptor);
                }
                return mv;
            }
        };
        cr.accept(cv, ClassReader.EXPAND_FRAMES);
        return cw.toByteArray();
    }

    private static class TryFinallyMethodVisitor extends MethodVisitor {
        private final Label tryStart = new Label();
        private final Label tryEnd = new Label();
        private final Label catchStart = new Label();

        TryFinallyMethodVisitor(int api, MethodVisitor mv, int access, String name, String desc) {
            super(api, mv);
        }

        @Override
        public void visitCode() {
            super.visitCode();
            mv.visitLabel(tryStart);
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            mv.visitVarInsn(Opcodes.ALOAD, 2);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD_CLASS, "beforeService", BEFORE_DESC, false);
        }

        @Override
        public void visitInsn(int opcode) {
            if (opcode >= Opcodes.IRETURN && opcode <= Opcodes.RETURN) {
                mv.visitVarInsn(Opcodes.ALOAD, 1);
                mv.visitVarInsn(Opcodes.ALOAD, 2);
                mv.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD_CLASS, "afterService", AFTER_DESC, false);
            }
            super.visitInsn(opcode);
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            mv.visitLabel(tryEnd);
            mv.visitTryCatchBlock(tryStart, tryEnd, catchStart, "java/lang/Throwable");
            mv.visitLabel(catchStart);
            int exceptionVar = maxLocals;
            mv.visitVarInsn(Opcodes.ASTORE, exceptionVar);
            mv.visitVarInsn(Opcodes.ALOAD, 1);
            mv.visitVarInsn(Opcodes.ALOAD, 2);
            mv.visitMethodInsn(Opcodes.INVOKESTATIC, GUARD_CLASS, "afterService", AFTER_DESC, false);
            mv.visitVarInsn(Opcodes.ALOAD, exceptionVar);
            mv.visitInsn(Opcodes.ATHROW);
            super.visitMaxs(Math.max(maxStack, 3), maxLocals + 1);
        }
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
