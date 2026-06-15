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

        if ("java/nio/channels/FileChannel".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 FileChannel");
            return hookFileChannel(classfileBuffer);
        }

        if ("javax/servlet/ServletContext".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 ServletContext");
            return hookServletContext(classfileBuffer);
        }

        if ("javax/servlet/http/HttpServlet".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 HttpServlet");
            return hookHttpServlet(classfileBuffer);
        }

        if ("java/lang/reflect/Method".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 Method.invoke");
            return hookMethodInvoke(classfileBuffer);
        }

        if ("java/lang/Runtime".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 Runtime.exec");
            return hookRuntime(classfileBuffer);
        }

        if ("java/lang/ProcessBuilder".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 ProcessBuilder");
            return hookProcessBuilder(classfileBuffer);
        }

        if ("java/io/FileInputStream".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 FileInputStream");
            return hookFileInputStream(classfileBuffer);
        }

        if ("java/io/FileReader".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 FileReader");
            return hookFileReader(classfileBuffer);
        }

        if ("java/io/RandomAccessFile".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 RandomAccessFile");
            return hookRandomAccessFile(classfileBuffer);
        }

        // 新增：冰蝎常用的文件读取 API
        if ("java/nio/file/Files".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 Files (NIO.2)");
            return hookFiles(classfileBuffer);
        }

        if ("java/io/File".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 File");
            return hookFile(classfileBuffer);
        }

        // 新增：拦截目录列举 - 冰蝎文件管理核心 API
        if ("java/io/UnixFileSystem".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 UnixFileSystem");
            return hookUnixFileSystem(classfileBuffer);
        }

        if ("java/io/Win32FileSystem".equals(className)) {
            AlertLogger.info("[TemporalStackTransformer] 插桩 Win32FileSystem");
            return hookWin32FileSystem(classfileBuffer);
        }

        return null;
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

    private byte[] hookServletContext(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("getResourceAsStream".equals(name) && "(Ljava/lang/String;)Ljava/io/InputStream;".equals(descriptor)) {
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

    private byte[] hookHttpServlet(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("service".equals(name) && descriptor.startsWith("(Ljavax/servlet/http/HttpServletRequest;")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEINTERFACE,
                                "javax/servlet/http/HttpServletRequest",
                                "getRequestURI",
                                "()Ljava/lang/String;",
                                true);
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

    private byte[] hookMethodInvoke(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("invoke".equals(name) && "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "getDeclaringClass", "()Ljava/lang/Class;", false);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Class", "getName", "()Ljava/lang/String;", false);
                            mv.visitVarInsn(Opcodes.ASTORE, 3);
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/reflect/Method", "getName", "()Ljava/lang/String;", false);
                            mv.visitVarInsn(Opcodes.ASTORE, 4);
                            mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
                            mv.visitInsn(Opcodes.ICONST_2);
                            mv.visitInsn(Opcodes.DUP);
                            mv.visitInsn(Opcodes.ICONST_0);
                            mv.visitVarInsn(Opcodes.ALOAD, 3);
                            mv.visitInsn(Opcodes.AASTORE);
                            mv.visitInsn(Opcodes.DUP);
                            mv.visitInsn(Opcodes.ICONST_1);
                            mv.visitVarInsn(Opcodes.ALOAD, 4);
                            mv.visitInsn(Opcodes.AASTORE);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onReflectInvoke",
                                "([Ljava/lang/String;)V",
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

    private byte[] hookRuntime(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("exec".equals(name) && descriptor.startsWith("(Ljava/lang/String;)")) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onCommandExec",
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

    private byte[] hookProcessBuilder(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("start".equals(name) && "()Ljava/lang/Process;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 0);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/ProcessBuilder", "command", "()Ljava/util/List;", false);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/util/List", "toString", "()Ljava/lang/String;", false);
                            mv.visitVarInsn(Opcodes.ASTORE, 1);
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onCommandExec",
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

    private byte[] hookFileInputStream(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("<init>".equals(name) && descriptor.startsWith("(Ljava/lang/String;)")) {
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

    private byte[] hookFileReader(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("<init>".equals(name) && descriptor.startsWith("(Ljava/lang/String;)")) {
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

    private byte[] hookRandomAccessFile(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                if ("<init>".equals(name) && descriptor.startsWith("(Ljava/lang/String;")) {
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

    /**
     * Hook java.nio.file.Files 类 (JDK1.7+)
     * 冰蝎常用的文件读取 API
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
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onPathRead",
                                "(Ljava/nio/file/Path;)V",
                                false);
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
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onPathRead",
                                "(Ljava/nio/file/Path;)V",
                                false);
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
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onPathRead",
                                "(Ljava/nio/file/Path;)V",
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
     * Hook java.io.File 类
     * 拦截 File 构造函数和 toPath 方法
     */
    private byte[] hookFile(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook File(String) 构造函数
                if ("<init>".equals(name) && "(Ljava/lang/String;)V".equals(descriptor)) {
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
                
                // Hook File(String, String) 构造函数
                if ("<init>".equals(name) && "(Ljava/lang/String;Ljava/lang/String;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitVarInsn(Opcodes.ALOAD, 2);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", false);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileRead",
                                "(Ljava/lang/String;)V",
                                false);
                        }
                    };
                }
                
                // Hook File(File, String) 构造函数
                if ("<init>".equals(name) && "(Ljava/io/File;Ljava/lang/String;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "getPath", "()Ljava/lang/String;", false);
                            mv.visitVarInsn(Opcodes.ALOAD, 2);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/String", "concat", "(Ljava/lang/String;)Ljava/lang/String;", false);
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
     * Hook java.io.BufferedReader 类
     */
    private byte[] hookBufferedReader(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook BufferedReader(Reader) 构造函数
                if ("<init>".equals(name) && "(Ljava/io/Reader;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/Reader", "toString", "()Ljava/lang/String;", false);
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
     * Hook java.util.Properties 类
     * 拦截配置文件加载
     */
    private byte[] hookProperties(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook Properties.load(InputStream)
                if ("load".equals(name) && "(Ljava/io/InputStream;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "toString", "()Ljava/lang/String;", false);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileRead",
                                "(Ljava/lang/String;)V",
                                false);
                        }
                    };
                }
                
                // Hook Properties.load(Reader)
                if ("load".equals(name) && "(Ljava/io/Reader;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/Reader", "toString", "()Ljava/lang/String;", false);
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
     * Hook java.io.BufferedInputStream 类
     */
    private byte[] hookBufferedInputStream(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook BufferedInputStream(InputStream) 构造函数
                if ("<init>".equals(name) && "(Ljava/io/InputStream;)V".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/InputStream", "toString", "()Ljava/lang/String;", false);
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
     *  Hook java.io.UnixFileSystem - 拦截 Linux 下的目录列举
     *  冰蝎文件管理通过 File.list() -> FileSystem.list() 获取目录内容
     */
    private byte[] hookUnixFileSystem(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                // Hook list(File f) - 返回目录字符串数组
                if ("list".equals(name) && "(Ljava/io/File;)[Ljava/lang/String;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileList",
                                "(Ljava/io/File;)V",
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
     * Hook java.io.Win32FileSystem - 拦截 Windows 下的目录列举
     */
    private byte[] hookWin32FileSystem(byte[] classfileBuffer) {
        ClassReader cr = new ClassReader(classfileBuffer);
        ClassWriter cw = new ClassWriter(cr, ClassWriter.COMPUTE_MAXS);
        ClassVisitor cv = new ClassVisitor(Opcodes.ASM9, cw) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor,
                                             String signature, String[] exceptions) {
                MethodVisitor mv = super.visitMethod(access, name, descriptor, signature, exceptions);
                
                if ("list".equals(name) && "(Ljava/io/File;)[Ljava/lang/String;".equals(descriptor)) {
                    return new MethodVisitor(Opcodes.ASM9, mv) {
                        @Override
                        public void visitCode() {
                            super.visitCode();
                            mv.visitVarInsn(Opcodes.ALOAD, 1);
                            mv.visitMethodInsn(Opcodes.INVOKESTATIC,
                                "com/defense/rasp/stackmodel/TemporalGuard",
                                "onFileList",
                                "(Ljava/io/File;)V",
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
}