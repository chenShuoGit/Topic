package org.example.util;

import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

public class Graphviz {
    public static void dotToPng(String dot, String path, String fileName) {
        System.out.println("-----# Graphviz start #-----");
        String dotDirPath = path + "\\dot";
        String pngDirPath = path + "\\png";
        File dotDir = new File(dotDirPath);
        if (!dotDir.exists()) {
            dotDir.mkdirs();
        }
        File pngDir = new File(pngDirPath);
        if (!pngDir.exists()) {
            pngDir.mkdirs();
        }
        String dotFilePath = path + "\\dot" + "\\" + fileName + ".dot";
        String pngFilePath = path + "\\png" + "\\" + fileName + ".png";
        try {
            File dotFile = new File(dotFilePath);
            if (dotFile.exists()) {
                System.out.println("dot file already exists!");
                return;
            }
            // 存储dot文件
            FileUtils.writeByteArrayToFile(dotFile, dot.getBytes());
            // 执行命令行程序
            String command = "dot -Tpng -o " + pngFilePath + " " + dotFilePath;
            System.out.println("command: " + command);
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            throw new RuntimeException(e);
        } finally {
            System.out.println("-----# Graphviz end #-----");
        }
    }

    public static void main(String[] args) {
        dotToPng("digraph G {\n" +
                        "\tcompound=true\n" +
                        "\tlabelloc=b\n" +
                        "\tstyle=filled\n" +
                        "\tcolor=gray90\n" +
                        "\tnode [shape=box,style=filled,color=white]\n" +
                        "\tedge [fontsize=10,arrowsize=1.5,fontcolor=grey40]\n" +
                        "\tfontsize=10\n" +
                        "\n" +
                        "\tsubgraph cluster_20375222 { \n" +
                        "\t\tlabel = \"DataFlow\"\n" +
                        "\t\t31596604[label=\"request := @parameter0: javax.servlet.http.HttpServletRequest\"]\n" +
                        "\t\t27742284[label=\"destination = interfaceinvoke request.&lt;javax.servlet.http.HttpServletRequest: java.lang.String getHeader(java.lang.String)&gt;(&quot;Destination&quot;)\"]\n" +
                        "\t\t31596604 -> 27742284\n" +
                        "\t\t25300561[label=\"$stack9 = new java.net.URL\"]\n" +
                        "\t\t4443432[label=\"specialinvoke $stack9.&lt;java.net.URL: void &lt;init&gt;(java.lang.String)&gt;(destination)\"]\n" +
                        "\t\t25300561 -> 4443432\n" +
                        "\t\t27742284 -> 4443432\n" +
                        "\t}\n" +
                        "\n" +
                        "}",
                "D:\\Project\\Java\\SootUp\\test\\src\\main\\resources\\cwe\\active-mq\\dataflow\\Analysis02\\Graphviz",
                "domove");
    }

}
