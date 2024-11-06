package cs.ldfy.asm.juliet;

import org.apache.commons.io.FileUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;
import org.objectweb.asm.util.TraceClassVisitor;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;

/**
 * @Title: Test
 * @Author chenshuo
 * @Package
 * @Date 2024/6/19 16:26
 * @description:
 */
public class HookTest {
    public static void main(String[] args) throws IOException {

        File file = FileUtils.getFile("C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\146289-v1.0.0\\target\\classes\\testcases\\CWE89_SQL_Injection\\s01\\CWE89_SQL_Injection__connect_tcp_execute_02.class");
        byte[] bytes = FileUtils.readFileToByteArray(file);

        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        String newClassName = file.getName();

        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);

        // 类追踪适配器<TraceClassVisitor>
        TraceClassVisitor traceClassVisitor = new TraceClassVisitor(cw, printWriter);

        // 类检查适配器<CheckClassAdapter>
        CheckClassAdapter checkClassAdapter = new CheckClassAdapter(traceClassVisitor);

        // 类修改适配器<ClassAdapter>
        ClassAdapter adapter = new ClassAdapter(checkClassAdapter);

        cr.accept(adapter, 0);

        // 输出TraceClassVisitor的值
//         System.out.println("类追踪：\n" + stringWriter);


        byte[] result = cw.toByteArray();
        File fileResult = FileUtils.getFile("D:\\Project\\Java\\Topic\\test\\src\\main\\java\\cs\\ldfy\\asm\\juliet\\" + newClassName);
        FileUtils.writeByteArrayToFile(fileResult, result);

    }
}
