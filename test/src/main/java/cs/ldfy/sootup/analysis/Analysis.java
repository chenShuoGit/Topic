package cs.ldfy.sootup.analysis;


import com.ibm.wala.util.io.FileUtil;
import cs.ldfy.cweinfos.juliet_java_2017_v1_3.CWEInfos;
import cs.ldfy.model.DetectResult;
import cs.ldfy.model.SensitiveStmtOfMethodSignature;
import cs.ldfy.util.CFGUtil;
import cs.ldfy.util.Graphviz;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.util.DotExporter;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.io.IOException;
import java.nio.file.Paths;
import java.util.*;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.stream.Collectors;


/**
 * @Author chenshuo
 * @Date 2024/10/10
 * @Description: 静态分析，尝试实现论文中的路径筛选
 */
@Slf4j
public class Analysis {

    // 源程序路径
    private final String classesPath;
    // 分析过程中产生的文件 dot/png/json 文件
    private final String targetPath;
    // 脆弱点列表
    private final List<MethodSignature> sensitiveStmtList = new ArrayList<>();
    // 脆弱数据流点列表
    private final List<MethodSignature> sensitiveDataFlowList = new ArrayList<>();
    // 源程序所有方法
    private List<JavaSootMethod> allSootMethodInCurrentPackage = new ArrayList<>();
    // 源程序所有方法及对应的CFG
    private final Map<MethodSignature, StmtGraph<?>> allCFGInCurrentPackage = new HashMap<>();

    // 分析结果
    @Getter
    private DetectResult result = new DetectResult();

    public Analysis(String classesPath, String targetPath, CWEInfos cweInfos) {
        this.classesPath = String.valueOf(Paths.get(classesPath));
        this.targetPath = String.valueOf(Paths.get(targetPath));
        this.sensitiveStmtList.addAll(cweInfos.getSensitiveStmt());
        this.sensitiveDataFlowList.addAll(cweInfos.getSensitiveDataFlow());
        this.result.setClassPath(this.classesPath);
        this.result.setCWEId(cweInfos.getId());
        this.result.setCWEName(cweInfos.getName());
        this.result.setData(new HashMap<>());
    }

    public void doAnalysis() {
        log.info("SootUp analysis start");

        // 创建源程序的分析视图 view
        JavaView view = new JavaView(new JavaClassPathAnalysisInputLocation(classesPath));

        // 缓存包内所有方法
        allSootMethodInCurrentPackage =
                view.getClasses()
                        .flatMap(sootClass -> sootClass.getMethods().stream())
                        .collect(Collectors.toList());

        // 在包内所有方法内搜索含有敏感语句的方法
        List<SensitiveStmtOfMethodSignature> stmtOfSensitiveMethodSignatureList =
                sensitiveStmtList.stream()
                        .flatMap(ms -> getStmtOfSensitiveMethodSignature(ms).stream())
                        .collect(Collectors.toList());

        stmtOfSensitiveMethodSignatureList.forEach(item -> {
            Stmt stmt = item.getStmt();
            MethodSignature sensitiveMethod = item.getSensitiveMethod();
            log.info("process method {}", sensitiveMethod.getDeclClassType() + "." + sensitiveMethod.getName());
            log.info("process stmt {}", stmt);
            recursiveAnalysis(sensitiveMethod, stmt);
        });

        // 存储json文件
        try {
            FileUtil.writeFile(Paths.get(targetPath, "result.json").toFile(), DetectResult.toJson(result));
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            log.info("SootUp analysis end");
        }
    }

    public void recursiveAnalysis(MethodSignature methodSignature, Stmt stmt) {

        // 从缓存中获取当前方法的Graph
        StmtGraph<?> stmtGraph = allCFGInCurrentPackage.get(methodSignature);

        // 获取当前方法内关于stmt的数据流信息
        List<Stmt> dataFlowList = CFGUtil.getDataflowToList(stmtGraph, stmt);

        // 获取当前方法内的所有执行路径
        List<List<Stmt>> allPaths = CFGUtil.findAllPaths(stmtGraph);
        // 筛选当前方法内的敏感执行路径
        List<List<Stmt>> sensitivePaths = CFGUtil.pathFilter(allPaths, stmt);

        // 临时列表，暂存一条执行路径中的一些与stmt相关联的数据流节点
        List<Stmt> sensitiveStmtList = new CopyOnWriteArrayList<>();

        sensitivePaths.forEach(path -> {
            // 清空临时列表
            sensitiveStmtList.clear();
            // 筛选出与stmt相关的数据流节点
            path.forEach(item -> {
                if (dataFlowList.contains(item)) {
                    sensitiveStmtList.add(item);
                }
            });
            // 对筛选出的数据流节点进行二次筛选
            sensitiveStmtList.forEach(sensitiveStmt -> {
                MethodSignature sensitiveMethodSignature = getMethodSignatureByStmt(sensitiveStmt);
                // 跳过无效节点
                if (sensitiveMethodSignature == null) {return;}
                // 判断是否符合约束-当前节点是否为CWEInfo中的敏感数据流节点
                if (sensitiveDataFlowList.contains(sensitiveMethodSignature)) {
                    // stmt为执行敏感节点的语句
                    MethodSignature methodSignatureByStmt = getMethodSignatureByStmt(stmt);
                    if (!result.getData().containsKey(methodSignatureByStmt)) {
                        result.getData().put(methodSignatureByStmt, new HashMap<>());
                    }
                    Map<MethodSignature, List<List<Stmt>>> methodSignatureListMap = result.getData().get(methodSignatureByStmt);
                    if (!methodSignatureListMap.containsKey(sensitiveMethodSignature)) {
                        methodSignatureListMap.put(sensitiveMethodSignature, new ArrayList<>());
                    }
                    // 添加路径
                    methodSignatureListMap.get(sensitiveMethodSignature).add(path);
                    log.info("injection point out: {}", sensitiveMethodSignature);
                    log.info("injection point path size: {}", path.size());
                    result.setSensitiveMethod(methodSignature);
                }
                // 递归执行.....
                if (isInPackage(sensitiveMethodSignature)) {
                    List<Stmt> returnStmtList = CFGUtil.getReturnStmtList(allCFGInCurrentPackage.get(sensitiveMethodSignature));
                    for (Stmt returnStmt : returnStmtList) {
                        recursiveAnalysis(sensitiveMethodSignature, returnStmt);
                    }
                }
            });
        });
    }

    private MethodSignature getMethodSignatureByStmt(Stmt stmt) {
        if (!stmt.isInvokableStmt()) {return null;}
        InvokableStmt invoke = stmt.asInvokableStmt();
        Optional<AbstractInvokeExpr> invokeExpr1 = invoke.getInvokeExpr();
        if (!invokeExpr1.isPresent()) {return null;}
        AbstractInvokeExpr abstractInvokeExpr = invokeExpr1.get();
        return abstractInvokeExpr.getMethodSignature();
    }

    private boolean isInPackage(MethodSignature methodSignature) {
        return allSootMethodInCurrentPackage.stream().anyMatch(m -> m.getSignature().compareTo(methodSignature) == 0);
    }


    /**
     * 在包内寻找目标MethodSignature所在的Stmt语句
     * @param sensitiveStmt 检索条件-敏感语句
     * @return 结果
     */
    public List<SensitiveStmtOfMethodSignature> getStmtOfSensitiveMethodSignature(MethodSignature sensitiveStmt) {
        log.info("search sensitive stmt {} in package start", sensitiveStmt);

        List<SensitiveStmtOfMethodSignature> resultList = new CopyOnWriteArrayList<>();

        allSootMethodInCurrentPackage.forEach(javaSootMethod -> {
            log.info("in method: {}", javaSootMethod.getDeclaringClassType().getFullyQualifiedName() + "." + javaSootMethod.getName());
            String className = javaSootMethod.getSignature().getDeclClassType().getFullyQualifiedName();
            String methodName = javaSootMethod.getName();
            if (javaSootMethod.isAbstract() || javaSootMethod.isNative()) {
                log.info("{} is abstract or native, without method body!", methodName);
                return;
            }

            // 缓存方法的Graph
            StmtGraph<?> stmtGraph = javaSootMethod.getBody().getStmtGraph();
            allCFGInCurrentPackage.put(javaSootMethod.getSignature(), stmtGraph);

            // 生成并存储方法的所有CFG
            String cfgDot = DotExporter.buildGraph(stmtGraph, false, null, null);
            Graphviz.dotToPng(cfgDot, targetPath, className + "." + methodName.replace("<", "_").replace(">", "_"));

            // 分析方法内是否包含目标敏感语句
            List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();

            blocksSorted.forEach(basicBlock -> {
                List<Stmt> stmts = basicBlock.getStmts();

                // 过滤非调用语句
                stmts.stream()
                        .filter(Stmt::isInvokableStmt)
                        .forEach(stmt -> {
                            // 过滤非调用语句
                            InvokableStmt invokableStmt = stmt.asInvokableStmt();
                            Optional<AbstractInvokeExpr> invokeExpr = invokableStmt.getInvokeExpr();
                            if (!invokeExpr.isPresent()) {
                                return;
                            }
                            MethodSignature methodSignature = invokeExpr.get().getMethodSignature();
                            // stmt == sensitiveStmt
                            if (methodSignature.compareTo(sensitiveStmt) == 0) {
                                log.info("sensitive stmt: {}", stmt);
                                resultList.add(new SensitiveStmtOfMethodSignature(javaSootMethod.getSignature(), methodSignature, stmt));
                            }
                        });

            });
        });

        log.info("search sensitive stmt {} in package end", sensitiveStmt);
        return resultList;
    }


    public static void main(String[] args) {

        String classesPath =
                "C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\146293-v1.0.0\\target\\classes";
        String targetPath =
                "D:\\Project\\Java\\Topic\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\146293\\Analysis03";
        Analysis analysis01 = new Analysis(classesPath, targetPath, CWEInfos.CWE_89);
        analysis01.doAnalysis();

    }

}
