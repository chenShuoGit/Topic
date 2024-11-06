package cs.ldfy.util;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

@Slf4j
public class Graphviz {
    public static void dotToPng(String dot, String path, String fileName) {
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
        String command = "";
        try {
            File dotFile = new File(dotFilePath);
            if (dotFile.exists()) {
                return;
            }
            // 存储dot文件
            FileUtils.writeByteArrayToFile(dotFile, dot.getBytes());
            // 执行命令行程序
            command = "dot -Tpng -o " + pngFilePath + " " + dotFilePath;
            Runtime.getRuntime().exec(command);
        } catch (IOException e) {
            log.error("Error executing command: {}, error: {}", command, e.getMessage());
        }
        log.info("create png/dot file for method: {}", fileName);
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
                        "\tsubgraph cluster_775081157 { \n" +
                        "\t\tlabel = \"DataFlow\"\n" +
                        "\t\t718187988[label=\"osCommand = &quot;/bin/ls &quot;\"]\n" +
                        "\t\t615438348[label=\"osCommand = &quot;c:\\\\WINDOWS\\\\SYSTEM32\\\\cmd.exe /c dir &quot;\"]\n" +
                        "\t\t664792509[label=\"$stack8 = new java.lang.StringBuilder\"]\n" +
                        "\t\t1965237677[label=\"$stack9 = virtualinvoke $stack8.&lt;java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)&gt;(osCommand)\"]\n" +
                        "\t\t664792509 -> 1965237677\n" +
                        "\t\t615438348 -> 1965237677\n" +
                        "\t\t718187988 -> 1965237677\n" +
                        "\t\t710708543[label=\"$stack10 = virtualinvoke $stack9.&lt;java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)&gt;(&quot;foo&quot;)\"]\n" +
                        "\t\t1965237677 -> 710708543\n" +
                        "\t\t2056031695[label=\"$stack11 = virtualinvoke $stack10.&lt;java.lang.StringBuilder: java.lang.String toString()&gt;()\"]\n" +
                        "\t\t710708543 -> 2056031695\n" +
                        "\t\t484589713[label=\"$stack12 = staticinvoke &lt;java.lang.Runtime: java.lang.Runtime getRuntime()&gt;()\"]\n" +
                        "\t\t16503286[label=\"process = virtualinvoke $stack12.&lt;java.lang.Runtime: java.lang.Process exec(java.lang.String)&gt;($stack11)\"]\n" +
                        "\t\t484589713 -> 16503286\n" +
                        "\t\t2056031695 -> 16503286\n" +
                        "\t}\n" +
                        "\n" +
                        "}",
                "D:\\Project\\Java\\Topic\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\dataflow\\Analysis03\\Graphviz",
                "goodG2B");
    }

}
