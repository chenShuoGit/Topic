package cs.ldfy.asm.juliet;

import org.objectweb.asm.*;

import static org.objectweb.asm.Opcodes.*;

/**
 * @Title: ClassAdapter
 * @Author chenshuo
 * @Package org.example.asm.execution.cve20163088
 * @Date 2024/6/19 15:49
 * @description: CVE-2016-3088相关类和方法进行ASM插桩
 */
public class ClassAdapter extends ClassVisitor {
    private String className;

    public ClassAdapter(ClassVisitor classVisitor) {
        super(ASM9, classVisitor);
    }

    @Override
    public void visit(int version, int access, String name, String signature, String superName, String[] interfaces) {
        this.className = name;
        // 修改类名
        super.visit(version, access, name, signature, superName, interfaces);
    }

    @Override
    public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
        MethodVisitor mv = null;
        // TODO 方法名改为JulietDot中的potentialFlaw.methodName
        if (name.equals("bad")) {
            mv = super.visitMethod(access, name, descriptor, signature, exceptions);
            mv = new MethodAdapterInitField(mv, "_sdgae_af_", className);
        }
        return mv != null ? mv : super.visitMethod(access, name, descriptor, signature, exceptions);
    }

    @Override
    public void visitEnd() {
        // 添加字段 注意这里是添加的是非静态字段，对于静态字段，
        FieldVisitor fv = cv.visitField(ACC_PRIVATE, "_sdgae_af_", Type.BOOLEAN_TYPE.getInternalName(), null, null);
        if (fv != null) {
            fv.visitEnd();
        }
        super.visitEnd();
    }

    private static class MethodAdapterInitField extends MethodVisitor {

        private String fieldName;
        private String father;

        public MethodAdapterInitField(MethodVisitor methodVisitor, String fieldName, String owner) {
            super(ASM9, methodVisitor);
            this.fieldName = fieldName;
            this.father = owner;
        }

        @Override
        public void visitCode() {
            super.visitCode();
            // 方法开始时，进行字段的初始化
            mv.visitVarInsn(ALOAD, 0);
            mv.visitInsn(ICONST_0);
            mv.visitFieldInsn(PUTFIELD, father, fieldName, Type.BOOLEAN_TYPE.getInternalName());
        }
        
        @Override
        public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
            if (opcode == INVOKEINTERFACE
                    && owner.equals("java/sql/Statement")
                    && name.equals("execute")
                    && descriptor.equals("(Ljava/lang/String;)Z")) {
                // 取出变量放入栈中
                mv.visitVarInsn(ALOAD, 0);
                mv.visitFieldInsn(GETFIELD, father, fieldName, Type.BOOLEAN_TYPE.getInternalName());
                Label label1 = new Label();
                // 从堆栈中弹出一个值
                mv.visitJumpInsn(IFEQ, label1);
                mv.visitTypeInsn(NEW, Type.getInternalName(RuntimeException.class));
                mv.visitInsn(DUP);
                mv.visitLdcInsn("infoinfoinfoinfoinfoinfoinfoinfoinfo");
                mv.visitMethodInsn(INVOKESPECIAL,
                        Type.getInternalName(RuntimeException.class),
                        "<init>",
                        "(Ljava/lang/String;)V",
                        false);
                mv.visitInsn(ATHROW);
                mv.visitLabel(label1);
            }
            super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
            if (opcode == INVOKEVIRTUAL
                    && owner.equals("java/io/BufferedReader")
                    && name.equals("readLine")
                    && descriptor.equals("()Ljava/lang/String;")) {
                mv.visitVarInsn(ALOAD, 0);
                mv.visitInsn(ICONST_1);
                mv.visitFieldInsn(PUTFIELD, father, fieldName, Type.BOOLEAN_TYPE.getInternalName());
            }
        }

        @Override
        public void visitMaxs(int maxStack, int maxLocals) {
            // 修改栈帧和局部变量表大小
            mv.visitMaxs(maxStack + 2, maxLocals+1);
        }

    }
}
