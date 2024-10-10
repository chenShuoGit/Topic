package org.example.cwe.cwe_78_os_comand_injection.dataflow;


import org.example.model.SensitiveStmtOfMethodSignature;
import sootup.core.util.tree.BuildTreeHelper;
import sootup.core.util.tree.TreeNode;
import org.example.util.Graphviz;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sootup.analysis.intraprocedural.reachingdefs.ReachingDefs;
import sootup.core.graph.*;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.common.expr.AbstractInvokeExpr;
import sootup.core.jimple.common.stmt.FallsThroughStmt;
import sootup.core.jimple.common.stmt.InvokableStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.util.DotExporter;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.views.JavaView;

import java.util.*;
import java.util.stream.Collectors;

/**
 * @Author chenshuo
 * @Date 2024/9/22 12:12
 * @Description: CWE-78 操作系统命令挟持 数据流 测试用例01
 */
public class TestCase01 {

    private final Logger log = LoggerFactory.getLogger(TestCase01.class);

    public String classesPath;
    public String targetPath;
    public List<MethodSignature> sensitiveMethodList;
    TestCase01(String classesPath, String targetPath, List<MethodSignature> sensitiveMethodList) {
        this.classesPath = classesPath;
        this.targetPath = targetPath;
        this.sensitiveMethodList = sensitiveMethodList;
    }

    public void doTest() {

        log.info("执行doTest......");

        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation(classesPath));
        JavaView view = new JavaView(inputLocations);

        // 这里是待分析的敏感函数的signature
        JavaIdentifierFactory javaIdentifierFactory = view.getIdentifierFactory();
        MethodSignature execMethodSignature = javaIdentifierFactory.getMethodSignature(
                javaIdentifierFactory.getClassType("java.lang.Runtime"),
                "exec",
                "java.lang.Process",
                Collections.singletonList("java.lang.String"));

        // 第一次类分析-目标MethodSignature所在的Stmt语句
        List<SensitiveStmtOfMethodSignature> stmtOfSensitiveMethodSignatureList =
                getStmtOfSensitiveMethodSignature(view, execMethodSignature);

        for (SensitiveStmtOfMethodSignature obj : stmtOfSensitiveMethodSignatureList) {
            Stmt stmt = obj.getStmt();
            MethodSignature methodSignature = obj.getMethodSignature();
            System.out.println("found sensitive stmt : " + stmt);
            System.out.println("found sensitive stmt in : " + methodSignature.getDeclClassType() + "." + methodSignature.getName());
            Optional<JavaSootMethod> method = view.getMethod(methodSignature);
            if (method.isPresent()) {
                JavaSootMethod sootMethod = method.get();
                StmtGraph<?> stmtGraph = sootMethod.getBody().getStmtGraph();
                // 前向数据流分析-由于stmtGraph是方法内的，因此这里只能是得到方法内部的数据流向.
                TreeNode<Stmt> dataflowTreeNode = getDataflowTreeNode(stmtGraph, stmt);

                // 数据流可视化
                String dataFlowDot = DotExporter.buildDataFlowGraphByTreeNode(dataflowTreeNode);
                System.out.println(dataFlowDot);


//                Stream<Value> uses = stmt.getUses();
//                uses.forEach(use -> {
//                    // TODO 这里思考一下，下面这个输出顺序是否和调用关系相关，比如 3 被 2 调用，所以 3 在 2 后面
//                    //  1 virtualinvoke $stack12.<java.lang.Runtime: java.lang.Process exec(java.lang.String)>($stack11)
//                    //  2 $stack11
//                    //  3 $stack12
//                    System.out.println(use);
//                    System.out.println(use.getType());
//                    System.out.println(use.getClass());
//                    System.out.println(use.getUses());
//                });
//                System.out.println("----------# 获取stmt的前向数据流("+ stmtList.size() +"条)- stmt: " + stmt + " #----------");
//                for (Stmt stmt1 : stmtList) {
//                    System.out.println(stmt1);
//                    System.out.println(reachingDefsMap.get(stmt1));
//                }
            }

//             只分析一个方法内的
//            break;
        }

        // 构造ICFG-CHA : 目前来看生成的ICFG没有满足预期
//        System.out.println("----------# " + "构造ICFG-CHA" + " #----------");
//        ClassHierarchyAnalysisAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
//        MethodSignature mainMethodSignature = view.getIdentifierFactory()
//                .getMethodSignature(
//                        javaIdentifierFactory.getClassType("testcases.CWE78_OS_Command_Injection.CWE78_OS_Command_Injection__connect_tcp_31"),
//                        "main",
//                        "void",
//                        Collections.singletonList("java.lang.String[]"));
//        CallGraph cha_cg = cha.initialize(Collections.singletonList(mainMethodSignature));
//        System.out.println("cha_cg:\n" + cha_cg);
//        List<JavaSootClass> collect = view.getClasses().collect(Collectors.toList());
//        Map<MethodSignature, StmtGraph<?>> map = new HashMap<>();
//        for (JavaSootClass sootClass : collect) {
//            Set<JavaSootMethod> methods = sootClass.getMethods();
//            for (JavaSootMethod method : methods) {
//                if (method.isNative() || method.isAbstract()) {
//                    continue;
//                }
//                MethodSignature signature = method.getSignature();
//                StmtGraph<?> stmtGraph = method.getBody().getStmtGraph();
//                map.put(signature, stmtGraph);
//            }
//        }
//        String icfgGraph = ICFGDotExporter.buildICFGGraph(map, view, cha_cg);
//        Graphviz.dotToPng(icfgGraph, "D:\\Project\\Java\\SootUp\\test\\src\\main\\resources\\", "icfg");


    }


    /**
     * 将生成的TreeNode转化成StmtGraph，这样可以直接使用DotExporter.buildGraph()将其转化成dot图
     * 行不通，提取出的数据流信息不具备方法语句之间的逻辑关系，不能通过MutableBasicBlockImpl生成
     * @param tree
     * @param graph
     */
    private void forwardTraversal(TreeNode<Stmt> tree, MutableBlockStmtGraph graph) {
        if (Objects.isNull(tree)) {
            return;
        }
        ArrayList<? extends BasicBlock<?>> blockList = new ArrayList<>(graph.getBlocks());
        if (blockList.isEmpty()) {
            return;
        }
        MutableBasicBlockImpl block = (MutableBasicBlockImpl) blockList.get(0);
        TreeNode<Stmt> firstChild = tree.getFirstChild();
        block.addStmt(firstChild.getData());
        graph.putEdge((FallsThroughStmt) firstChild.getData(), tree.getData());
        while (Objects.nonNull(firstChild.getBrother())) {
            TreeNode<Stmt> brother = firstChild.getBrother();
            MutableBasicBlock brotherBlock = new MutableBasicBlockImpl();
            brotherBlock.addStmt(brother.getData());
            graph.addBlock(brotherBlock.getStmts());
            graph.putEdge((FallsThroughStmt) brother.getData(), tree.getData());
        }
        forwardTraversal(tree.getFirstChild(), graph);
        forwardTraversal(tree.getBrother(), graph);
    }



    /**
     * 此方法输出对应语句(stmt)在方法(stmtGraph)内的数据流(使用二叉树表示)
     * @param stmtGraph 方法的stmtGraph
     * @param stmt 语句
     * @return 二叉树表示的数据流
     */
    public TreeNode<Stmt> getDataflowTreeNode(StmtGraph<?> stmtGraph, Stmt stmt) {
        ReachingDefs reachingDefs = new ReachingDefs(stmtGraph);
        Map<Stmt, List<Stmt>> reachingDefsMap = reachingDefs.getReachingDefs();
        List<Stmt> stmtList = reachingDefsMap.get(stmt);
        // 遍历查找调用链-使用二叉树结构来表示调用链
        TreeNode<Stmt> root = new TreeNode<>();
        BuildTreeHelper<Stmt> startEntry = new BuildTreeHelper<>(root, new AbstractMap.SimpleEntry<>(stmt, stmtList));
        Deque<BuildTreeHelper<Stmt>> workList = new ArrayDeque<>();
        workList.push(startEntry);
        while (!workList.isEmpty()) {
            BuildTreeHelper<Stmt> pop = workList.pop();
            TreeNode<Stmt> treeNode = pop.getTreeNode();
            Map.Entry<Stmt, List<Stmt>> stmtEntry = pop.getStmtEntry();
            treeNode.setData(stmtEntry.getKey());
            List<Stmt> value = stmtEntry.getValue();
            for (int i = 0; i < value.size(); i++) {
                BuildTreeHelper<Stmt> node = null;
                Stmt data = value.get(i);
                List<Stmt> dataList = reachingDefsMap.get(data);
                if (i == 0) {
                    TreeNode<Stmt> firstChild = new TreeNode<>();
                    firstChild.setData(data);
                    treeNode.setFirstChild(firstChild);
                    node = new BuildTreeHelper<>(firstChild, new AbstractMap.SimpleEntry<>(data, dataList));
                    workList.push(node);
                    continue;
                }
                TreeNode<Stmt> firstChild = treeNode.getFirstChild();
                TreeNode<Stmt> child = firstChild;
                while (!Objects.isNull(child.getBrother())) {
                    child = firstChild.getBrother();
                }
                TreeNode<Stmt> brother = new TreeNode<>(data);
                child.setBrother(brother);
                node = new BuildTreeHelper<>(brother, new AbstractMap.SimpleEntry<>(data, dataList));
                workList.push(node);
            }
        }
        return root;
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
            System.out.println("--------------------# 开始类分析：" + className + " #--------------------");
            // 进行方法分析
            Set<JavaSootMethod> methodSet = item.getMethods();
            for (JavaSootMethod method : methodSet) {
                String methodName = method.getName();
                System.out.println("----------# 开始方法分析：" + methodName + " #----------");
                if (method.isAbstract() || method.isNative()) {
                    System.out.println(methodName + " is abstract or native, without method body!");
                    continue;
                }
                StmtGraph<?> stmtGraph = method.getBody().getStmtGraph();

                // CFG
                String cfgDot = DotExporter.buildGraph(stmtGraph, false, null, null);
                Graphviz.dotToPng(cfgDot, targetPath, className + "." + methodName.replace("<", "_").replace(">", "_"));

                // 进行语句分析-数据流分析-针对execMethodSignature
                List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();
                for (int i = 0; i < blocksSorted.size(); ++i) {
                    System.out.println("-----# " + "block: " + (i+1) + " #-----");
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
                System.out.println("----------# 方法分析结束：" + methodName + " #----------");
            }
            System.out.println("--------------------# 类分析结束：" + className + " #--------------------\n");
        }
        return resultList;
    }

//    public void getForwardData/

    public static void main(String[] args) {
        // 测试用例字节码文件路径：（文件不存在就去对应的项目编译一下就好）
        // C:\Users\yeyan\Desktop\topic\漏洞分析\2017-11-02-juliet-java-v1-3\144554-v1.0.0\target\classes
        String classesPath = "C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\144554-v1.0.0\\target\\classes";
        String targetPath = "D:\\Project\\Java\\SootUp\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\dataflow\\TestCase01";
        TestCase01 test = new TestCase01(classesPath, targetPath, null);
        test.doTest();


    }

}
