package org.example.cwe.cwe_78_os_comand_injection.dataflow.analysis;


import org.example.model.SensitiveStmtOfMethodSignature;
import org.example.util.CFGUtil;
import org.example.util.Graphviz;
import sootup.analysis.intraprocedural.reachingdefs.ReachingDefs;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.PackageName;
import sootup.core.types.VoidType;
import sootup.core.util.DotExporter;
import sootup.core.util.tree.BuildTreeHelper;
import sootup.core.util.tree.TreeNode;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @Author chenshuo
 * @Date 2024/10/10
 * @Description: 静态分析，尝试实现论文中的路径筛选
 */
public class Analysis03 {

    public String classesPath;
    public String targetPath;
    public Deque<MethodSignature> sensitiveMethodDeque = new ArrayDeque<>();
    public List<MethodSignature> nextSensitiveMethodList = new ArrayList<>();
    public Map<MethodSignature, StmtGraph<?>> allCFGInNativePackage = new HashMap<>();

    Analysis03(String classesPath, String targetPath, List<MethodSignature> sensitiveMethodList) {
        this.classesPath = classesPath;
        this.targetPath = targetPath;
        sensitiveMethodList.forEach(method -> {
            this.sensitiveMethodDeque.push(method);
        });
    }

    public void doAnalysis() {
        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation(classesPath));
        JavaView view = new JavaView(inputLocations);
        while (!sensitiveMethodDeque.isEmpty()) {
            MethodSignature targetMethodSignature = sensitiveMethodDeque.pop();
        // 第一次类分析-目标MethodSignature所在的Stmt语句
            List<SensitiveStmtOfMethodSignature> stmtOfSensitiveMethodSignatureList =
                    getStmtOfSensitiveMethodSignature(view, targetMethodSignature);
            for (SensitiveStmtOfMethodSignature obj : stmtOfSensitiveMethodSignatureList) {
                Stmt stmt = obj.getStmt();
                MethodSignature methodSignature = obj.getMethodSignature();
                Optional<JavaSootMethod> method = view.getMethod(methodSignature);
                if (method.isPresent()) {
                    JavaSootMethod sootMethod = method.get();
                    System.out.println("当前处理方法：" + sootMethod.getName());
                    // 获取方法的控制流图
                    StmtGraph<?> stmtGraph = sootMethod.getBody().getStmtGraph();
                    // 获取路径-->全部的执行路径
                    List<List<Stmt>> allPaths = CFGUtil.findAllPaths(stmtGraph);
                    // 路径筛选-->获取具有敏感信息的路径
                    List<List<Stmt>> sensitivePaths = CFGUtil.pathFilter(allPaths, stmt);
                    System.out.println("敏感路径:");
                    sensitivePaths.forEach(System.out::println);
                    // 对敏感路径做数据流分析处理
                    System.out.println("列表结构表示数据流:");
                    CFGUtil.getDataflowToList(stmtGraph, stmt).forEach(stmt1 -> {
                        System.out.println("当前分析的stmt:" + stmt1);
                        if (stmt1.isInvokableStmt()) {
                            InvokableStmt invokableStmt = stmt1.asInvokableStmt();
                            invokableStmt.getInvokeExpr().ifPresent(System.out::println);
                        }
                    });
                    TreeNode<Stmt> dataflowToTree = CFGUtil.getDataflowToTree(stmtGraph, stmt);
                    System.out.println("树结构表示数据流:");
                    String treeDataFlow = DotExporter.buildDataFlowGraphByTreeNode(dataflowToTree);
                    System.out.println(treeDataFlow);
                    // 这里的想法是从总的数据流图中挑选出包含的，然后将这些包含的进行匹配，匹配到了就说明符合我们的约束
                    // TODO 写一个方法，在数据流信息的各个Stmt中，区分出所有的类型，目前初步可以分为以下几类：
                    //  1. 硬编码
                    //  2. 函数调用(java本地包内)
                    //  3. 函数调用(同一个类的另一个方法)
                    //  4. 函数调用(其它类型)

                    // TODO 写一个方法，获取anatherMethod这个方法的返回值的数据流信息

                    // TODO 确定数据流终止的条件(在跨函数条件下)
                    //  1. 不能是函数调用-->发现是函数调用，进行下一次数据流分析，敏感语句为return语句，循环分析知道

                    // TODO 找到完整的数据流向，判断数据是否通过了我们的约束，如HttpHeader等

                    // TODO 写一个递归方法，方法的参数为MethodSignature,Stmt,在这之前先把本包内的所有方法的CFG存储下来，作为分析用
                }
            }
        }
    }

    public void recursiveAnalysis(MethodSignature methodSignature, Stmt stmt) {
        StmtGraph<?> stmtGraph = allCFGInNativePackage.get(methodSignature);
        // 获取当前方法内关于stmt的数据流信息
        List<Stmt> dataList = CFGUtil.getDataflowToList(stmtGraph, stmt);
        // 获取当前方法内的敏感路径
        List<List<Stmt>> allPaths = CFGUtil.findAllPaths(stmtGraph);
        List<List<Stmt>> sensitivePaths = CFGUtil.pathFilter(allPaths, stmt);
        // 在敏感路径中筛选出数据流Stmt
        List<Stmt> sensitive
        sensitivePaths.forEach(path -> {
            path.forEach(nowStmt -> {
                if (dataList.contains(nowStmt)) {

                }
            });
        });
    }


    public void cutting(TreeNode<Stmt> tree) {
        if (Objects.nonNull(tree.getFirstChild())) {
            cutting(tree.getFirstChild());
        }
        if (Objects.nonNull(tree.getBrother())) {
            cutting(tree.getBrother());
        }
        Stmt stmt = tree.getData();
        try {
            InvokableStmt invokableStmt = stmt.asInvokableStmt();
            Optional<AbstractInvokeExpr> invokeExpr = invokableStmt.getInvokeExpr();
            if (invokeExpr.isPresent()) {
                MethodSignature nextMethodSignature = invokeExpr.get().getMethodSignature();
                if (nextMethodSignature.getDeclClassType().toString().startsWith("java.lang")) {
                    return;
                }
                // 除去java本地包内的方法
                this.nextSensitiveMethodList.add(nextMethodSignature);
            }
        } catch (ClassCastException e){
            System.out.println("stmt cannot be cast to InvokableStmt.class!!");
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
//            System.out.println("--------------------# 开始类分析：" + className + " #--------------------");
            // 进行方法分析
            Set<JavaSootMethod> methodSet = item.getMethods();
            for (JavaSootMethod method : methodSet) {
                String methodName = method.getName();
//                System.out.println("----------# 开始方法分析：" + methodName + " #----------");
                if (method.isAbstract() || method.isNative()) {
                    System.out.println(methodName + " is abstract or native, without method body!");
                    continue;
                }
                StmtGraph<?> stmtGraph = method.getBody().getStmtGraph();

                // 缓存所有方法的CFG信息
                allCFGInNativePackage.put(method.getSignature(), stmtGraph);

                // CFG
                String cfgDot = DotExporter.buildGraph(stmtGraph, false, null, null);
                Graphviz.dotToPng(cfgDot, targetPath, className + "." + methodName.replace("<", "_").replace(">", "_"));

                // 进行语句分析-数据流分析-针对execMethodSignature
                List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();
                for (int i = 0; i < blocksSorted.size(); ++i) {
//                    System.out.println("-----# " + "block: " + (i+1) + " #-----");
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
//                System.out.println("----------# 方法分析结束：" + methodName + " #----------");
            }
//            System.out.println("--------------------# 类分析结束：" + className + " #--------------------\n");
        }
        return resultList;
    }


    public static void main(String[] args) {

        String classesPath =
                "C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\144554-v1.0.0\\target\\classes";
        String targetPath =
                "D:\\Project\\Java\\Topic\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\dataflow\\Analysis03";
        MethodSignature sensitiveMethod = new MethodSignature(
                new JavaClassType("Runtime", new PackageName("java.lang")),
                "exec",
                Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                new JavaClassType("Process", new PackageName("java.lang"))
        );

        Analysis03 analysis01 = new Analysis03(classesPath, targetPath, Collections.singletonList(sensitiveMethod));
        analysis01.doAnalysis();

    }

}
