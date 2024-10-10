package sootup.core.util.tree;

/**
 * @Author chenshuo
 * @Date 2024/9/23 20:50
 * @Description: 二叉树，用来表示数据流
 */
public class TreeNode<E> {
    private E data;
    private TreeNode<E> firstChild;
    private TreeNode<E> brother;

    public TreeNode(E stmt) {
        this.data = stmt;
        this.firstChild = null;
        this.brother = null;
    }

    public TreeNode() {
    }

    public E getData() {
        return data;
    }

    public void setData(E data) {
        this.data = data;
    }

    public TreeNode<E> getFirstChild() {
        return firstChild;
    }

    public void setFirstChild(TreeNode<E> firstChild) {
        this.firstChild = firstChild;
    }

    public TreeNode<E> getBrother() {
        return brother;
    }

    public void setBrother(TreeNode<E> brother) {
        this.brother = brother;
    }
}
