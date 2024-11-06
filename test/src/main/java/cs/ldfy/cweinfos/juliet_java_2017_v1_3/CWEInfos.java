package cs.ldfy.cweinfos.juliet_java_2017_v1_3;

import sootup.core.signatures.MethodSignature;
import sootup.core.signatures.PackageName;
import sootup.core.types.ArrayType;
import sootup.core.types.PrimitiveType;
import sootup.java.core.types.JavaClassType;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

/**
 * @Author chenshuo
 * @Date 2024/10/11 21:10
 * @Description: Juliet-java-2017-v1.3 漏洞信息
 */
public enum CWEInfos {
    CWE_78("OS Command Injection",
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
                            new JavaClassType("HttpServletRequest", new PackageName("javax.servlet.http")),
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
    ),
    CWE_134("Uncontrolled Format String",
            134,
            Arrays.asList(
                    new MethodSignature(
                            new JavaClassType("PrintStream", new PackageName("java.io")),
                            "printf",
                            Arrays.asList(
                                    new JavaClassType("String", new PackageName("java.lang")),
                                    new ArrayType(new JavaClassType("Object", new PackageName("java.lang")), 1)
                            ),
                            new JavaClassType("PrintStream", new PackageName("java.io"))
                    ),
                    new MethodSignature(
                            new JavaClassType("PrintStream", new PackageName("java.io")),
                            "format",
                            Arrays.asList(
                                    new JavaClassType("String", new PackageName("java.lang")),
                                    new ArrayType(new JavaClassType("Object", new PackageName("java.lang")), 1)
                            ),
                            new JavaClassType("PrintStream", new PackageName("java.io"))
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
                            new JavaClassType("HttpServletRequest", new PackageName("javax.servlet.http")),
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
    ),
    CWE_89("SQL Injection",
            89,
            Arrays.asList(
                    new MethodSignature(
                            new JavaClassType("Statement", new PackageName("java.sql")),
                            "execute",
                            Collections.singletonList(
                                    new JavaClassType("String", new PackageName("java.lang"))
                            ),
                            PrimitiveType.BooleanType.getInstance()
                    ),
                    new MethodSignature(
                            new JavaClassType("Statement", new PackageName("java.sql")),
                            "executeBatch",
                            Collections.emptyList(),
                            new ArrayType(PrimitiveType.IntType.getInstance(), 1)
                    ),
                    new MethodSignature(
                        new JavaClassType("Statement", new PackageName("java.sql")),
                            "executeQuery",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            new JavaClassType("ResultSet", new PackageName("java.sql"))
                    ),
                    new MethodSignature(
                            new JavaClassType("Statement", new PackageName("java.sql")),
                            "executeUpdate",
                            Collections.singletonList(new JavaClassType("String", new PackageName("java.lang"))),
                            PrimitiveType.IntType.getInstance()
                    ),
                    new MethodSignature(
                            new JavaClassType("PreparedStatement", new PackageName("java.sql")),
                            "execute",
                            Collections.emptyList(),
                            PrimitiveType.BooleanType.getInstance()
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
                    )
            )
    ),

    ;

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
