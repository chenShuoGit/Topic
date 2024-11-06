package cs.ldfy.util;

import sootup.analysis.intraprocedural.reachingdefs.ReachingDefs;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.jimple.common.stmt.JReturnStmt;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.util.tree.BuildTreeHelper;
import sootup.core.util.tree.TreeNode;

import java.util.*;

/**
 * @Author chenshuo
 * @Date 2024/10/10 21:40
 * @Description: 操作CFG的工具类
 */
public class CFGUtil {

    /**
     * 获取CFG中的所有执行路径
     * @param stmtGraph
     * @return
     */
    public static List<List<Stmt>> findAllPaths(StmtGraph<?> stmtGraph) {
        BasicBlock<?> root = stmtGraph.getStartingStmtBlock();
        List<List<Stmt>> allPaths = new ArrayList<>();
        List<Stmt> path = new ArrayList<>();
        path.addAll(root.getStmts());
        ArrayList<Integer> hashcodeList = new ArrayList<>();
        findPath(allPaths, root, path, hashcodeList);
        return allPaths;
    }
    private static void findPath(List<List<Stmt>> allPaths, BasicBlock<?> root, List<Stmt> path, ArrayList<Integer> hashcodeList) {
        if (root.getSuccessors().isEmpty()) {
            allPaths.add(path);
        } else {
            root.getSuccessors().forEach(successor -> {
                // 除去循环路径
                if (!hashcodeList.contains(successor.hashCode())) {
                    hashcodeList.add(successor.hashCode());
                    List<Stmt> newPath = new ArrayList<>(path);
                    newPath.addAll(successor.getStmts());
                    findPath(allPaths, successor, newPath, hashcodeList);
                }
            });
        }
    }

    /**
     * 路径筛选，保留存有stmt的路径
     * @param originalPaths
     * @param stmt
     * @return
     */
    public static List<List<Stmt>> pathFilter(List<List<Stmt>> originalPaths, Stmt stmt) {
        List<List<Stmt>> result = new ArrayList<>();
        originalPaths.forEach(path -> {
            if (path.contains(stmt)) {
                result.add(path);
            }
        });
        return result;
    }

    /**
     * 此方法输出对应语句(stmt)在方法(stmtGraph)内的数据流(使用二叉树表示)
     * @param stmtGraph 方法的stmtGraph
     * @param stmt 语句
     * @return 二叉树表示的数据流信息
     */
    public static TreeNode<Stmt> getDataflowToTree(StmtGraph<?> stmtGraph, Stmt stmt) {
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
            Stmt key = stmtEntry.getKey();
            treeNode.setData(key);
            List<Stmt> value = stmtEntry.getValue();
            for (int i = 0; i < value.size(); i++) {
                BuildTreeHelper<Stmt> node = null;
                Stmt data = value.get(i);
                List<Stmt> dataList = reachingDefsMap.get(data);
                if (Objects.isNull(treeNode.getFirstChild())) {
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
     * 此方法输出对应语句(stmt)在方法(stmtGraph)内的数据流(使用列表表示)
     * @param stmtGraph 方法的stmtGraph
     * @param stmt 语句
     * @return 列表表示的数据流信息
     */
    public static List<Stmt> getDataflowToList(StmtGraph<?> stmtGraph, Stmt stmt) {
        ArrayList<Stmt> result = new ArrayList<>();
        ReachingDefs reachingDefs = new ReachingDefs(stmtGraph);
        Map<Stmt, List<Stmt>> reachingDefsMap = reachingDefs.getReachingDefs();
        Deque<Stmt> workList = new ArrayDeque<>();
        workList.push(stmt);
        while (!workList.isEmpty()) {
            Stmt pop = workList.pop();
            result.add(pop);
            List<Stmt> stmts = reachingDefsMap.get(pop);
            workList.addAll(stmts);
        }
        return result;
    }

    /**
     * 得到CFG中所有的return语句
     * @param stmtGraph
     * @return
     */
    public static List<Stmt> getReturnStmtList(StmtGraph<?> stmtGraph) {
        List<Stmt> returnStmtList = new ArrayList<>();
        stmtGraph.getBlocks().forEach(block -> {
            block.getStmts().forEach(stmt -> {
                if (stmt instanceof JReturnStmt) {
                    returnStmtList.add(stmt);
                }
            });
        });
        return returnStmtList;
    }

}
