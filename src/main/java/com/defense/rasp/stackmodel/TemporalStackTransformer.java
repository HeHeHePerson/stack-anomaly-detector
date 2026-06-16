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

        // Servlet/Web 请求入口 (动态加载，可 Hook)
        if ("javax/servlet/ServletContext".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 ServletContext");
            return hookServletContext(classfileBuffer);
        }

        if ("javax/servlet/http/HttpServlet".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 HttpServlet");
            return hookHttpServlet(classfileBuffer);
        }

        // NIO 文件操作 (应用层动态加载)
        if ("java/nio/file/Files".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 Files (NIO.2)");
            return hookFiles(classfileBuffer);
        }

        if ("java/nio/channels/FileChannel".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 FileChannel");
            return hookFileChannel(classfileBuffer);
        }
        
        // 文件描述符 (动态加载时 Hook)
        if ("java/io/FileDescriptor".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 FileDescriptor (lowest-level I/O)");
            return hookFileDescriptor(classfileBuffer);
        }
        
        // --- 以下 Bootstrap 类已通过 RaspSecurityManager 覆盖，移除 ASM Hook 以避免 JVM 不稳定 ---
        // java.lang.reflect.Method, Runtime, ProcessBuilder 等均由 SecurityManager 拦截或不需要 Hook
        // --- 以下 Bootstrap 类已通过 RaspSecurityManager 覆盖，无需 ASM Hook ---
        // java.io.FileInputStream, FileReader, RandomAccessFile, File, 
        // UnixFileSystem, Win32FileSystem 均由 SecurityManager 拦截

        return null;
    }

    /**
     * Hook java.io.FileDescriptor.open()
     * FileChannel、RandomAccessFile 等底层读写最终入口
     */
    private byte[] hookFileDescriptor(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // FileDescriptor.open(String path, int mode) - 所有文件读取的最低层入口
                if ("open".equals(name) && descriptor.equals("(Ljava/lang/String;I)V")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileRead",
                                "(Ljava/lang/String;)V",
                                false);
                        }
                    };
                }
                
                return mv;
            }
        };
        cr.accept(cv, 0);
        return cw.toByteArray();
    }
    
    private byte[] hookFileChannel(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("open".equals(name) && descriptor.startsWith("(Ljava/nio/file/Path;")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitLdcInsn("FileChannel.open");
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileRead",
                                "(Ljava/lang/String;)V",
                                false);
                        }
                    };
                }
                return mv;
            }
        };
        cr.accept(cv, 0);
        return cw.toByteArray();
    }

    /**
     * Hook java.nio.file.Files 类 (JDK1.7+)
     */
    private byte[] hookFiles(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook Files.readAllBytes(Path)
                if ("readAllBytes".equals(name) && "(Ljava/nio/file/Path;)[B".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathRead", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }
                
                // Hook Files.newInputStream(Path)
                if ("newInputStream".equals(name) && "(Ljava/nio/file/Path;)Ljava/io/InputStream;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathRead", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }
                
                // Hook Files.newBufferedReader(Path)
                if ("newBufferedReader".equals(name) && "(Ljava/nio/file/Path;)Ljava/io/BufferedReader;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathRead", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }

                // Hook Files.write(Path, ...) - 拦截文件写入
                if ("write".equals(name) && descriptor.startsWith("(Ljava/nio/file/Path;")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathWrite", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }

                // Hook Files.copy(Path, ...) - 拦截文件复制/下载
                if ("copy".equals(name) && descriptor.startsWith("(Ljava/nio/file/Path;")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathRead", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }

                // Hook Files.delete(Path) - 拦截文件删除
                if ("delete".equals(name) && "(Ljava/nio/file/Path;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                GUARD_CLASS, "onPathDelete", "(Ljava/nio/file/Path;)V", false);
                        }
                    };
                }
                
                return mv;
            }
        };
        cr.accept(cv, 0);
        return cw.toByteArray();
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
                            // 直接传递 req 对象为 Object，避免 CHECKCAST 在 SecurityManager 下抛出 ClassCastException
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
                String getRealPath = "getRealPath";
                String getResource = "getResource";
                String getResourceAsStream = "getResourceAsStream";
                String reqStr = "(Ljava/lang/String;)";
                
                if ((getRealPath.equals(name) || getResource.equals(name) || getResourceAsStream.equals(name)) && 
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
    
    private byte[] hookRuntime(byte[] classfileBuffer) {
        // 已移除，由 SecurityManager.checkExec 覆盖
        return null;
    }

    private byte[] hookProcessBuilder(byte[] classfileBuffer) {
        // 已移除，由 SecurityManager.checkExec 覆盖
        return null;
    }
}
