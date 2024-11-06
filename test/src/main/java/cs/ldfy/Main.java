package cs.ldfy;

import cs.ldfy.asm.hook.Hook;
import cs.ldfy.cweinfos.juliet_java_2017_v1_3.CWEInfos;
import cs.ldfy.model.DetectResult;
import cs.ldfy.sootup.analysis.Analysis;
import cs.ldfy.util.ClassUtil;
import org.objectweb.asm.Type;
import sootup.core.signatures.MethodSignature;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @Author chenshuo
 * @Date 2024/11/2 13:53
 * @Description: 漏洞防御主类
 */
public class Main {

    public static void main(String[] args) {

        // sootUp分析
        String classesPath =
                "C:\\Users\\yeyan\\Desktop\\topic\\漏洞分析\\2017-11-02-juliet-java-v1-3\\146293-v1.0.0\\target\\classes";
        String targetPath =
                "D:\\Project\\Java\\Topic\\test\\src\\main\\resources\\cwe\\cwe_78_os_comand_injection\\146293\\Analysis03";
        Analysis analysis01 = new Analysis(classesPath, targetPath, CWEInfos.CWE_89);
        analysis01.doAnalysis();
        DetectResult sootUpDetectResult = analysis01.getResult();

        ArrayList<MethodSignature> methodSignatures = new ArrayList<>(sootUpDetectResult.getData().keySet());
        MethodSignature methodSignature = methodSignatures.get(0);

        Method method = ClassUtil.getMethodBySignature(methodSignature);

        // ASM插桩
        targetPath = "D:\\Project\\Java\\Topic\\test\\src\\main\\java\\cs\\ldfy";
        String msg = "message";
        Hook hook = new Hook(sootUpDetectResult, targetPath, msg);
        hook.start();

    }


}
