package org.example.model;

import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;

/**
 * @Author chenshuo
 * @Date 2024/9/22 17:17
 * @Description: 此类的实例存放Stmt和MethodSignature，其中Stmt代表敏感的MethodSignature所在的调用语句，MethodSignature代表这条语句所在的方法
 */
public class SensitiveStmtOfMethodSignature {

    // 敏感的MethodSignature所在的调用语句
    private Stmt stmt;
    // 敏感的MethodSignature所在的调用语句所在的方法
    private MethodSignature methodSignature;

    public Stmt getStmt() {
        return stmt;
    }

    public void setStmt(Stmt stmt) {
        this.stmt = stmt;
    }

    public MethodSignature getMethodSignature() {
        return methodSignature;
    }

    public void setMethodSignature(MethodSignature methodSignature) {
        this.methodSignature = methodSignature;
    }

    public SensitiveStmtOfMethodSignature(Stmt stmt, MethodSignature methodSignature) {
        this.stmt = stmt;
        this.methodSignature = methodSignature;
    }

    public SensitiveStmtOfMethodSignature() {
    }
}
