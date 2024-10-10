package org.example;

import org.apache.commons.lang3.tuple.Pair;
import sootup.analysis.interprocedural.icfg.CGEdgeUtil;
import sootup.analysis.interprocedural.icfg.CalleeMethodSignature;
import sootup.analysis.intraprocedural.reachingdefs.ReachingDefs;
import sootup.callgraph.CallGraph;
import sootup.callgraph.ClassHierarchyAnalysisAlgorithm;
import sootup.callgraph.RapidTypeAnalysisAlgorithm;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.inputlocation.AnalysisInputLocation;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;
import sootup.core.types.VoidType;
import sootup.core.util.DotExporter;
import sootup.java.bytecode.frontend.inputlocation.JavaClassPathAnalysisInputLocation;
import sootup.java.core.JavaIdentifierFactory;
import sootup.java.core.JavaSootClass;
import sootup.java.core.JavaSootMethod;
import sootup.java.core.types.JavaClassType;
import sootup.java.core.views.JavaView;

import java.util.*;
import java.util.stream.Stream;

/**
 * @Author chenshuo
 * @Date 2024/9/20 7:46
 * @Description: 测试类
 */
public class Test {
    public static void main(String[] args) {

        List<AnalysisInputLocation> inputLocations = new ArrayList<>();
        inputLocations.add(new JavaClassPathAnalysisInputLocation("test/src/main/resources/activemq-fileserver"));
//        inputLocations.add(new JavaClassPathAnalysisInputLocation("test/src/main/resources/example01"));
        JavaView view = new JavaView(inputLocations);
        Stream<JavaSootClass> classes = view.getClasses();

        classes.forEach(item -> {
//            if (item.getName().equals("org.example.Example")) {
            if (item.getName().equals("org.apache.activemq.util.RestFilter")) {
                Set<JavaSootMethod> methods = item.getMethods();
                Optional<JavaSootMethod> method = methods.stream().filter(o -> o.getName().equals("doMove")).findFirst();
//                Optional<JavaSootMethod> method = methods.stream().filter(o -> o.getName().equals("doMove")).findFirst();
                if (method.isPresent()) {
                    JavaSootMethod sootMethod = method.get();
                    StmtGraph<?> stmtGraph = sootMethod.getBody().getStmtGraph();

                    // 控制流图
//                    String s = DotExporter.buildGraph(stmtGraph, false, null, null);
//                    System.out.println(s);


//                    List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();
//                    blocksSorted.forEach(block -> {
//                        block.getStmts().forEach( stmt -> {
//                            System.out.println("stmt: " + stmt.toString());
//                            System.out.println("stmt.getUses().count(): " + stmt.getUses().count());
//                            if (stmt.getUses().count() > 0) {
//                                stmt.getUses().forEach(use -> {
//                                    System.out.println("use: " + use.toString());
//                                });
//                            }
//                            System.out.println("stmt.getDef(): " + stmt.getDef());
//                        });
//                    });

                    // 数据流分析
                    ReachingDefs reachingDefs = new ReachingDefs(stmtGraph);
                    Map<Stmt, List<Stmt>> reachingDefsMap = reachingDefs.getReachingDefs();
                    Set<Map.Entry<Stmt, List<Stmt>>> entries = reachingDefsMap.entrySet();
                    for (Map.Entry entry : entries) {
                        System.out.println("stmt : " + entry.getKey());
                        System.out.println("reachingDefs : " + entry.getValue());
                    }

                }
            }
        });

        // TODO 这个MethodSignature失效了
        JavaClassType restFilterClassType = view.getIdentifierFactory().getClassType("org.apache.activemq.util.RestFilter");
        JavaClassType param1ClassType = view.getIdentifierFactory().getClassType("jakarta.servlet.http.HttpServletRequest");
        JavaClassType param2ClassType = view.getIdentifierFactory().getClassType("jakarta.servlet.http.HttpServletResponse");
        MethodSignature domoveMethodSignature = view.getIdentifierFactory()
                .getMethodSignature(
                        restFilterClassType,
                        JavaIdentifierFactory.getInstance()
                                .getMethodSubSignature(
                                        "doMove",
                                        VoidType.getInstance(),
                                        Arrays.asList(param1ClassType, param2ClassType))
                );


//        Optional<JavaSootMethod> method = view.getMethod(domoveMethodSignature);
//        if (method.isPresent()) {
//            JavaSootMethod sootMethod = method.get();
//            StmtGraph<?> stmtGraph = sootMethod.getBody().getStmtGraph();
//            List<? extends BasicBlock<?>> blocksSorted = stmtGraph.getBlocksSorted();
//            blocksSorted.forEach(item -> {
//                item.getStmts().forEach( stmt -> {
//                    System.out.println("stmt: " + stmt.toString());
//                    System.out.println("stmt.getUses(): " + stmt.getUses());
//                    System.out.println("stmt.getDef(): " + stmt.getDef());
//                });
//            });
//            ReachingDefs reachingDefs = new ReachingDefs(stmtGraph);
//            Map<Stmt, List<Stmt>> reachingDefsMap = reachingDefs.getReachingDefs();
//            Set<Map.Entry<Stmt, List<Stmt>>> entries = reachingDefsMap.entrySet();
//            for (Map.Entry entry : entries) {
//                System.out.println(entry.getKey());
//                System.out.println(entry.getValue());
//            }
//        } else {
//            System.out.println(domoveMethodSignature + "不存在！");
//        }

        // CHA
        ClassHierarchyAnalysisAlgorithm cha = new ClassHierarchyAnalysisAlgorithm(view);
        CallGraph cha_cg = cha.initialize(Collections.singletonList(domoveMethodSignature));
        System.out.println("cha_cg:\n" + cha_cg);

        // RTA
        RapidTypeAnalysisAlgorithm rta = new RapidTypeAnalysisAlgorithm(view);
        CallGraph rta_cg = rta.initialize(Collections.singletonList(domoveMethodSignature));
        System.out.println("rta_cg:\n" + rta_cg);

        // VTA
//        Set<Pair<MethodSignature, CalleeMethodSignature>> callEdges = CGEdgeUtil.getCallEdges(view, rta_cg);
//        callEdges.forEach(item -> {
//            System.out.println(item.toString());
//            System.out.println(item.getValue().getMethodSignature());
//        });

    }

}
