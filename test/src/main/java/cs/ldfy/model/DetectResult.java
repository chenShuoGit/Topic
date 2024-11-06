package cs.ldfy.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import sootup.core.jimple.common.stmt.Stmt;
import sootup.core.signatures.MethodSignature;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * @Author chenshuo
 * @Date 2024/10/14 10:27
 * @Description: 脆弱点检测结果
 */
@Data
@AllArgsConstructor
@NoArgsConstructor
public class DetectResult {

    // 源程序路径
    private String classPath;
    // CWE 信息
    private String CWEName;
    private int CWEId;
    // 脆弱方法 bad()
    private MethodSignature sensitiveMethod;

    // 检测结果 Map<脆弱点, Map<脆弱数据流点, List<脆弱执行路径>>>
    private Map<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> data;

//        "<java.lang.Runtime: java.lang.Process exec(java.lang.String)>": {
//        "<java.lang.System: java.lang.String getProperty(java.lang.String)>": [
//        [
//        "this := @this: testcases.CWE78_OS_Command_Injection.CWE78_OS_Command_Injection__Property_06",
//                "data = staticinvoke <java.lang.System: java.lang.String getProperty(java.lang.String)>(\"user.home\")",
//                "$stack4 = staticinvoke <java.lang.System: java.lang.String getProperty(java.lang.String)>(\"os.name\")",
//                "$stack5 = virtualinvoke $stack4.<java.lang.String: java.lang.String toLowerCase()>()",
//                "$stack6 = virtualinvoke $stack5.<java.lang.String: int indexOf(java.lang.String)>(\"win\")",
//                "if $stack6 < 0",
//                "osCommand = \"c:\\WINDOWS\\SYSTEM32\\cmd.exe /c dir \"",
//                "goto",
//                "$stack11 = staticinvoke <java.lang.Runtime: java.lang.Runtime getRuntime()>()",
//                "$stack7 = new java.lang.StringBuilder",
//                "specialinvoke $stack7.<java.lang.StringBuilder: void <init>()>()",
//                "$stack8 = virtualinvoke $stack7.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>(osCommand)",
//                "$stack9 = virtualinvoke $stack8.<java.lang.StringBuilder: java.lang.StringBuilder append(java.lang.String)>(data)",
//                "$stack10 = virtualinvoke $stack9.<java.lang.StringBuilder: java.lang.String toString()>()",
//                "process = virtualinvoke $stack11.<java.lang.Runtime: java.lang.Process exec(java.lang.String)>($stack10)",
//                "virtualinvoke process.<java.lang.Process: int waitFor()>()",
//                "return"
//        ],

        public static String toJson(DetectResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"classPath\":\"");
        sb.append(result.getClassPath() + "\",");
        sb.append("\"sensitiveMethod\":\"");
        sb.append(result.getSensitiveMethod() + "\",");
        sb.append("\"CWEName\":\"");
        sb.append(result.getCWEName() + "\",");
        sb.append("\"CWEId\":\"");
        sb.append(result.getCWEId() + "\",");
        sb.append("\"data\":");
        sb.append("{");
        Set<Map.Entry<MethodSignature, Map<MethodSignature, List<List<Stmt>>>>> entries =
                result.getData().entrySet();
        for (Map.Entry<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> entry : entries) {
            MethodSignature key = entry.getKey();
            Map<MethodSignature, List<List<Stmt>>> value = entry.getValue();
            sb.append("\"" + key.toString() + "\":{");
            for (Map.Entry<MethodSignature, List<List<Stmt>>> entry2 : value.entrySet()) {
                MethodSignature key2= entry2.getKey();
                List<List<Stmt>> value2 = entry2.getValue();
                sb.append("\"" + key2.toString() + "\":[");
                for (int i = 0; i < value2.size(); i++) {
                    sb.append("[");
                    for (int j = 0; j < value2.get(i).size(); j++) {
                        sb.append("\"" + value2.get(i).get(j).toString().replace("\"", "\\\"") + "\"");
                        if (j != value2.get(i).size()-1) {
                            sb.append(",");
                        }
                    }
                    sb.append("]");
                    if (i != value2.size()-1) {
                        sb.append(",");
                    }
                }
                sb.append("]");
            }
        }
        sb.append("}}}");
        return sb.toString();
    }

}
