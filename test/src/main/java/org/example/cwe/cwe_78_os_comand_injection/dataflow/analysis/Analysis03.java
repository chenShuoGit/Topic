package org.example.cwe.cwe_78_os_comand_injection.dataflow.analysis;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.ibm.wala.util.io.FileUtil;
import org.apache.commons.io.FileUtils;
import org.example.juliet_java_2017_v1_3.CWEInfos;
import org.example.model.DetectResult;
import org.example.model.SensitiveStmtOfMethodSignature;
import org.example.util.CFGUtil;
import org.example.util.Graphviz;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.util.DotExporter;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

/**
 * @Author chenshuo
 * @Date 2024/10/10
 * @Description: 静态分析，尝试实现论文中的路径筛选
 */
public class Analysis03 {

    // 待分析的包路径
    public String classesPath;
    // 保存分析结果的路径
    public String targetPath;
    // 存储敏感Stmt的列表
    public List<MethodSignature> sensitiveStmtList = new ArrayList<>();
    // 存储敏感数据流的列表
    public List<MethodSignature> sensitiveDataFlowList = new ArrayList<>();
    // 待分析包下的所有的方法
    public List<MethodSignature> allMethodSignatureInCurrentPackage = new ArrayList<>();
    public Map<MethodSignature, StmtGraph<?>> allCFGInCurrentPackage = new HashMap<>();
    private DetectResult result = new DetectResult();
    private File resultFile;

    private MethodSignature currentSensitive;

    Analysis03(String classesPath, String targetPath, CWEInfos cweInfos) {
        this.classesPath = classesPath;
        this.targetPath = targetPath;
        this.sensitiveStmtList.addAll(cweInfos.getSensitiveStmt());
        this.sensitiveDataFlowList.addAll(cweInfos.getSensitiveDataFlow());
        this.resultFile = FileUtils.getFile(targetPath + "\\result.json");
        result.setClassPath(classesPath.replace("\\", "\\\\"));
        result.setCWEId(cweInfos.getId());
        result.setCWEName(cweInfos.getName());
        result.setData(new HashMap<>());
    }

    public void doAnalysis() {
        // 创建分析过程
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation(classesPath));
        JavaView view = new JavaView(inputLocations);
        for (MethodSignature ms : sensitiveStmtList) {
            this.currentSensitive = ms;
            List<SensitiveStmtOfMethodSignature> stmtOfSensitiveMethodSignatureList =
                    getStmtOfSensitiveMethodSignature(view, ms);
            for (SensitiveStmtOfMethodSignature obj : stmtOfSensitiveMethodSignatureList) {
                Stmt stmt = obj.getStmt();
                MethodSignature methodSignature = obj.getMethodSignature();
                Optional<JavaSootMethod> method = view.getMethod(methodSignature);
                if (method.isPresent()) {
                    JavaSootMethod sootMethod = method.get();
                    System.out.println("当前处理方法：" + sootMethod.getName());
                    recursiveAnalysis(methodSignature, stmt);
                }
            }
        }
        // 存储json文件
        System.out.println(result.toString());
        try {
            System.out.println("DetectResult.toJson(result) = " + DetectResult.toJson(result));
            FileUtil.writeFile(resultFile, DetectResult.toJson(result));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public void recursiveAnalysis(MethodSignature methodSignature, Stmt stmt) {
        StmtGraph<?> stmtGraph = allCFGInCurrentPackage.get(methodSignature);
        // 获取当前方法内关于stmt的数据流信息
        List<Stmt> dataFlowList = CFGUtil.getDataflowToList(stmtGraph, stmt);
        // 获取当前方法内的敏感路径
        List<List<Stmt>> allPaths = CFGUtil.findAllPaths(stmtGraph);
        List<List<Stmt>> sensitivePaths = CFGUtil.pathFilter(allPaths, stmt);
        List<Stmt> sensitiveStmtList = new ArrayList<>();
        for(List<Stmt> path : sensitivePaths) {
            // 在敏感路径中筛选出数据流Stmt
            sensitiveStmtList.clear();
            for (Stmt nowStmt : path) {
                if (dataFlowList.contains(nowStmt)) {
                    sensitiveStmtList.add(nowStmt);
                }
            }
            for (Stmt sensitiveStmt : sensitiveStmtList) {
                if (sensitiveStmt.isInvokableStmt()) {
                    InvokableStmt invoke = sensitiveStmt.asInvokableStmt();
                    Optional<AbstractInvokeExpr> invokeExpr1 = invoke.getInvokeExpr();
                    if (invokeExpr1.isPresent()) {
                        AbstractInvokeExpr abstractInvokeExpr = invokeExpr1.get();
                        MethodSignature methodSignature2 = abstractInvokeExpr.getMethodSignature();
                        // 判断是否符合约束-最初的敏感语句+当前的数据信息-->是否符合
                        if (sensitiveDataFlowList.contains(methodSignature2)) {
                            // 存储结果
                            if (!result.getData().containsKey(this.currentSensitive)) {
                                result.getData().put(this.currentSensitive, new HashMap<>());
                            }
                            Map<MethodSignature, List<List<Stmt>>> methodSignatureListMap = result.getData().get(this.currentSensitive);
                            if (!methodSignatureListMap.containsKey(methodSignature2)) {
                                methodSignatureListMap.put(methodSignature2, new ArrayList<>());
                            }
                            methodSignatureListMap.get(methodSignature2).add(path);
                            System.err.println("Injection Point In: " + sensitiveStmt);
                            System.err.println("Injection Point Path: " + path);
                        }
                        if (allMethodSignatureInCurrentPackage.contains(methodSignature2)) {
                            List<Stmt> returnStmtList = CFGUtil.getReturnStmtList(allCFGInCurrentPackage.get(methodSignature2));
                            for (Stmt returnStmt : returnStmtList) {
                                recursiveAnalysis(methodSignature2, returnStmt);
                            }
                        }
                    }
                }
            }
        }
    }


    /**
     * 在一个包内寻找目标MethodSignature所在的Stmt语句
     * @param view
     * @param sensitiveSignature
     * @return
     */
    public List<SensitiveStmtOfMethodSignature> getStmtOfSensitiveMethodSignature(JavaView view, MethodSignature sensitiveSignature) {
        List<JavaSootClass> classes = view.getClasses().collect(Collectors.toList());
        List<SensitiveStmtOfMethodSignature> resultList = new ArrayList<>();
        for (JavaSootClass item : classes) {
            String className = item.getName();
            Set<JavaSootMethod> methodSet = item.getMethods();
            for (JavaSootMethod method : methodSet) {
                String methodName = method.getName();
                if (method.isAbstract() || method.isNative()) {
                    System.out.println(methodName + " is abstract or native, without method body!");
                    continue;
                }
                StmtGraph<?> stmtGraph = method.getBody().getStmtGraph();

                // 缓存方法信息
                allCFGInCurrentPackage.put(method.getSignature(), stmtGraph);
                allMethodSignatureInCurrentPackage.add(method.getSignature());

                // 生成并存储方法的所有CFG
                String cfgDot = DotExporter.buildGraph(stmtGraph, false, null, null);
                Graphviz.dotToPng(cfgDot, targetPath, className + "." + methodName.replace("<", "_").replace(">", "_"));

                // 分析方法内是否包含目标敏感语句
                List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();
                for (int i = 0; i < blocksSorted.size(); ++i) {
                    List<Stmt> stmts = blocksSorted.get(i).getStmts();
                    for (Stmt stmt : stmts) {
                        if (stmt.isInvokableStmt()) {
                            InvokableStmt invokableStmt = stmt.asInvokableStmt();
                            Optional<AbstractInvokeExpr> invokeExpr = invokableStmt.getInvokeExpr();
                            if (invokeExpr.isPresent()) {
                                MethodSignature methodSignature = invokeExpr.get().getMethodSignature();
                                if (methodSignature.compareTo(sensitiveSignature) == 0) {
                                    System.out.println("find sensitive func! stmt:\n" + stmt);
                                    resultList.add(new SensitiveStmtOfMethodSignature(stmt, method.getSignature()));
                                }
                            }
                        }
                    }
                }
            }
        }
        return resultList;
    }


    public static void main(String[] args) {

        String classesPath =
                "C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\144554-v1.0.0\\target\\classes";
        String targetPath =
                "D:\\Project\\Java\\Topic\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\144554\\Analysis03";
        Analysis03 analysis01 = new Analysis03(classesPath, targetPath, CWEInfos.CWE_78);
        analysis01.doAnalysis();

    }

}
