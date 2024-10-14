package org.example.model;

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
public class DetectResult {

    private String classPath;
    private String CWEName;
    private int CWEId;

    private Map<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> data;

    public DetectResult() {
    }

    public DetectResult(String classPath, String CWEName, int CWEId, Map<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> data) {
        this.classPath = classPath;
        this.CWEName = CWEName;
        this.CWEId = CWEId;
        this.data = data;
    }

    public String getClassPath() {
        return classPath;
    }

    public void setClassPath(String classPath) {
        this.classPath = classPath;
    }

    public String getCWEName() {
        return CWEName;
    }

    public void setCWEName(String CWEName) {
        this.CWEName = CWEName;
    }

    public int getCWEId() {
        return CWEId;
    }

    public void setCWEId(int CWEId) {
        this.CWEId = CWEId;
    }

    public Map<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> getData() {
        return data;
    }

    public void setData(Map<MethodSignature, Map<MethodSignature, List<List<Stmt>>>> data) {
        this.data = data;
    }

    public static String toJson(DetectResult result) {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"classPath\":\"");
        sb.append(result.getClassPath() + "\",");
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
