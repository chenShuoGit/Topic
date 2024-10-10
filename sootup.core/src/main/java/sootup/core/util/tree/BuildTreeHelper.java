package sootup.core.util.tree;

import sootup.core.jimple.common.stmt.Stmt;

import java.util.List;
import java.util.Map;

/**
 * @Author chenshuo
 * @Date 2024/9/23 21:13
 * @Description: 帮助构建二叉树的临时类
 */
public class BuildTreeHelper<E> {
    private TreeNode<E> treeNode;
    private Map.Entry<Stmt, List<Stmt>> stmtEntry;

    public BuildTreeHelper(TreeNode<E> treeNode, Map.Entry<Stmt, List<Stmt>> stmtEntry) {
        this.treeNode = treeNode;
        this.stmtEntry = stmtEntry;
    }

    public TreeNode<E> getTreeNode() {
        return treeNode;
    }

    public void setTreeNode(TreeNode<E> treeNode) {
        this.treeNode = treeNode;
    }

    public Map.Entry<Stmt, List<Stmt>> getStmtEntry() {
        return stmtEntry;
    }

    public void setStmtEntry(Map.Entry<Stmt, List<Stmt>> stmtEntry) {
        this.stmtEntry = stmtEntry;
    }
}
