# SootUp 文档
#### 实现stmt接口的类
+ JThrowStmt
  + 抛出异常的语句
+ JSwitchStmt
  + switch语句
+ JReturnVoidStmt
  + 方法的结束语句，返回空
+ JReturnStmt
  + 方法的结束语句，返回一个值
+ JRetStmt
  + 表示已经弃用的 jvm ret 语句(已经弃用的字节码指令)
+ JNopStmt
  + 无任何操作的语句
+ JInvokeStmt
  + 方法调用语句
+ JIfStmt
  + 如果条件为真，则跳转到目标，否则继续执行下一个语句。第一个后继（索引=0）是 fallsthrough 语句，第二个后继（索引=1）是 rbanching 语句
+ JIdentityStmt
  + 定义语句
+ JGotoStmt
  + 无条件跳转到目标语句
+ JEnterMonitorStmt
  + 开始一个JVM monitor，即开始synchronization
+ JExitMonitorStmt
  + 结束一个JVM monitor，即结束synchronization
+ JBreakpointStmt
  + 应该是break语句
+ JAssignStmt
  + 赋值语句
+ interface BranchingStmt extends Stmt
  + 不一定会继续执行列表中的后续语句的语句
  + 实现此接口的类有 JGotoStmt JIfStmt JSwitchStmt
+ interface FallsThroughStmt extends Stmt
  + 和BranchingStmt类似
+ abstract class AbstractStmt implements Stmt
  + 继承自Stmt的抽象类，此处的大半部分类都实现了此类
#### AbstractStmt解析
+ public Stream<Value> getUses()
  + 返回此语句中使用的值列表。请注意，它们是按照通常的评估顺序返回的。
+ public Optional<LValue> getDef()
  + 返回此语句中定义的值列表。有些语言允许多种返回类型/分配，因此我们返回一个列表
+ public Stream<Value> getUsesAndDefs()
  + 上面两者的集合
+ public int getExpectedSuccessorCount()
  + 返回语句在 StmtGraph 中需要拥有的无异常后继的数量。
+ public boolean containsInvokeExpr()
  + 语句是否包括调用
+ public AbstractInvokeExpr getInvokeExpr()
  + 此方法只能用于包含通过 containsInvokeExpr() 检查的 InvokeExpr（JInvokeStmt；可能在 JAssignStmt 中）的 Stmts。
+ public boolean containsArrayRef()
  + 语句是否包括数组引用
+ public JArrayRef getArrayRef()
  + 此方法只能用于包含 ArrayRef 的 Stmts - 可使用 JAssignStmts。通过 containsArrayRef() 检查。
+ public boolean containsFieldRef()
  + 语句是否包括字段引用
+ public JFieldRef getFieldRef()
  + 此方法只能用于包含 FieldRef 的 Stmts - 可使用 JAssignStmts。通过 containsFieldRef() 检查。
+ public StmtPositionInfo getPositionInfo()
  + 获取语句的位置信息
+ public Stmt withNewUse(@Nonnull Value oldUse, @Nonnull Value newUse)
  + 这个应该是用于老版本的soot进行新版替换的
  + 返回具有 newUse 的新 Stmt，如果在 Stmt 中未找到 oldUse 或无法替换 oldUse，则使用当前 Stmt
#### Value解析
