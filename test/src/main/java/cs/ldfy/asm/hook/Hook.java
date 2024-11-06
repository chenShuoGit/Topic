package cs.ldfy.asm.hook;

import cs.ldfy.asm.juliet.ClassAdapter;
import cs.ldfy.asm.juliet.sqlinjection.SQLInjectionClassAdapter;
import cs.ldfy.model.DetectResult;
import org.apache.commons.io.FileUtils;
import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.util.CheckClassAdapter;
import org.objectweb.asm.util.TraceClassVisitor;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Paths;

/**
 * @Author chenshuo
 * @Date 2024/11/2 16:15
 * @Description: ASM插桩类
 */
public class Hook {
    private String classPath;
    private String targetPath;
    private DetectResult detectResult;
    private String message;

    public Hook(DetectResult detectResult, String targetPath, String message) {
        this.detectResult = detectResult;
        this.targetPath = targetPath;
        String[] split = String.valueOf(detectResult.getSensitiveMethod().getDeclClassType()).split("\\.");
        this.classPath = Paths.get(detectResult.getClassPath(), split) + ".class";
        this.message = message;
    }

    public void start() {
        File file = FileUtils.getFile(classPath);
        byte[] bytes;
        try {
            bytes = FileUtils.readFileToByteArray(file);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        String name = file.getName();

        ClassReader cr = new ClassReader(bytes);
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_FRAMES);


        StringWriter stringWriter = new StringWriter();
        PrintWriter printWriter = new PrintWriter(stringWriter);

        TraceClassVisitor traceClassVisitor = new TraceClassVisitor(cw, printWriter);
        CheckClassAdapter checkClassAdapter = new CheckClassAdapter(traceClassVisitor);

        // 类修改适配器<ClassAdapter>
        SQLInjectionClassAdapter adapter = new SQLInjectionClassAdapter(checkClassAdapter, detectResult, message);
        cr.accept(adapter, 0);

        byte[] result = cw.toByteArray();

        File fileResult = FileUtils.getFile(Paths.get(targetPath, name).toFile());
        try {
            FileUtils.writeByteArrayToFile(fileResult, result);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }

}
