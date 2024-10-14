package org.example.juliet_java_2017_v1_3;

import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.PackageName;
import sootup.core.types.VoidType;
import sootup.java.core.types.JavaClassType;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @Author chenshuo
 * @Date 2024/10/11 21:10
 * @Description: Juliet-java-2017-v1.3 漏洞信息
 */
public enum CWEInfos {
    CWE_78 ("OS Command Injection",
            78,
            Arrays.asList(
                    new MethodSignature(
                            new JavaClassType("Runtime", new PackageName("java.lang")),
                            "exec",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("Process", new PackageName("java.lang"))
                    )
            ),
            Arrays.asList(
                    new MethodSignature(
                            new JavaClassType("BufferedReader", new PackageName("java.io")),
                            "readLine",
                            Collections.emptyList(),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("PreparedStatement", new PackageName("java.sql")),
                            "executeQuery",
                            Collections.emptyList(),
                            new JavaClassType("ResultSet", new PackageName("java.sql"))
                    ),
                    new MethodSignature(
                            new JavaClassType("System", new PackageName("java.lang")),
                            "getenv",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("Cookie", new PackageName("javax.servlet.http")),
                            "getValue",
                            Collections.emptyList(),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("ServletRequest", new PackageName("javax.servlet")),
                            "getParameter",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("StringTokenizer", new PackageName("java.util")),
                            "nextToken",
                            Collections.emptyList(),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("Properties", new PackageName("java.util")),
                            "getProperty",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("String", new PackageName("java.lang"))
                    ),
                    new MethodSignature(
                            new JavaClassType("System", new PackageName("java.lang")),
                            "getProperty",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("String", new PackageName("java.lang"))
                    )
            )
    );
    public final String name;
    public final int id;
    public final List<MethodSignature> sensitiveStmt;

    public final List<MethodSignature> sensitiveDataFlow;

    CWEInfos(String name, int id, List<MethodSignature> sensitiveStmt, List<MethodSignature> sensitiveDataFlow) {
        this.name = name;
        this.id = id;
        this.sensitiveStmt = sensitiveStmt;
        this.sensitiveDataFlow = sensitiveDataFlow;
    }

    public int getId() {
        return id;
    }

    public String getName() {
        return name;
    }

    public List<MethodSignature> getSensitiveStmt() {
        return sensitiveStmt;
    }

    public List<MethodSignature> getSensitiveDataFlow() {
        return sensitiveDataFlow;
    }
}
