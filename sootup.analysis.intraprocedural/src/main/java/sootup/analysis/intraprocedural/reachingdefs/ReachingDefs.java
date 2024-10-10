package sootup.analysis.intraprocedural.reachingdefs;

/*-
* #%L
* Soot - a J*va Optimization Framework
* %%
Copyright (C) 2024 Michael Youkeim, Stefan Schott and others
* %%
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU Lesser General Public License as
* published by the Free Software Foundation, either version 2.1 of the
* License, or (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Lesser Public License for more details.
*
* You should have received a copy of the GNU General Lesser Public
* License along with this program.  If not, see
* <http://www.gnu.org/licenses/lgpl-2.1.html>.
* #L%
*/

import java.util.*;
import java.util.stream.Stream;
import javax.annotation.Nonnull;
import sootup.analysis.intraprocedural.ForwardFlowAnalysis;
import sootup.core.graph.BasicBlock;
import sootup.core.graph.StmtGraph;
import sootup.core.jimple.basic.Value;
import sootup.core.jimple.common.stmt.JAssignStmt;
import sootup.core.jimple.common.stmt.Stmt;

public class ReachingDefs {
  private final Map<Stmt, List<Stmt>> reachingDefs;

  public ReachingDefs(StmtGraph<? extends BasicBlock<?>> graph) {
    this.reachingDefs = new HashMap<>();

    ReachingDefsAnalysis analysis = new ReachingDefsAnalysis(graph);

    for (Stmt stmt : graph.getStmts()) {
      // 该语句没有使用任何参数,跳过本次循环
      if (!stmt.getUses().findAny().isPresent()) continue;

      // getFlowBefore(stmt) : 获取stmt的前向流集合(从函数入口点至stmt之间的语句，跳转语句和初始化语句不在内)
      Set<VariableDefinition> inset = analysis.getFlowBefore(stmt);

//      // 测试-输出flowBefore
//      System.out.println("---------\nstmt : " + stmt);
//      inset.stream().filter(def -> def.getStmt().isPresent()).forEach(def -> System.out.println(def.getStmt()));

      reachingDefs.put(stmt, new ArrayList<>());

      for (VariableDefinition def : inset) {
        Value definedVar = def.getValue();
        Optional<Stmt> definingStmt = def.getStmt();

        stmt.getUses()
            .filter(
                usedVar ->
                    definedVar.equivTo(usedVar)
                        && definingStmt.isPresent()
                        && definingStmt.get() != stmt)
            .forEach(usedVar -> {
              // 确实是数据流分析，这里提取的是stmt中使用的数据的定义语句,在Jimple表示中，对一个数据进行处理后就变成另一个数据，可以根据这种特性进行数据溯源
//              // 测试-输出过滤后的一些语句，这里可能是数据流分析
//              System.out.println("---------\nstmt : " + stmt);
//              System.out.println(definingStmt.get());
              reachingDefs.get(stmt).add(definingStmt.get());
            });

      }
    }
  }

  public Map<Stmt, List<Stmt>> getReachingDefs() {
    return reachingDefs;
  }

  static class ReachingDefsAnalysis extends ForwardFlowAnalysis<Set<VariableDefinition>> {

    /** Construct the analysis from StmtGraph. */
    <B extends BasicBlock<B>> ReachingDefsAnalysis(StmtGraph<B> graph) {
      super(graph);
      execute();
    }

    @Nonnull
    @Override
    protected Set<VariableDefinition> newInitialFlow() {
      Set<VariableDefinition> initialValues = new HashSet<>();
      graph.getNodes().stream()
          .map(Stmt::getDef)
          .filter(Optional::isPresent)
          .map(Optional::get)
          .forEach(def -> initialValues.add(new VariableDefinition(def, null)));
      return initialValues;
    }

    @Override
    protected void merge(
        @Nonnull Set<VariableDefinition> in1,
        @Nonnull Set<VariableDefinition> in2,
        @Nonnull Set<VariableDefinition> out) {
      out.clear();
      out.addAll(in1);
      out.addAll(in2);
    }

    @Override
    protected void copy(
        @Nonnull Set<VariableDefinition> source, @Nonnull Set<VariableDefinition> dest) {
      dest.clear();
      dest.addAll(source);
    }

    @Override
    protected void flowThrough(
        @Nonnull Set<VariableDefinition> in, Stmt d, @Nonnull Set<VariableDefinition> out) {
      out.clear();
      out.addAll(in);
      kill(d).forEach(out::remove);
      gen(d).forEach(out::add);
    }

    private Stream<VariableDefinition> kill(Stmt d) {
      if (!(d instanceof JAssignStmt)) return Stream.empty();

      return d.getDef()
          .map(
              definedValue -> {
                List<VariableDefinition> output = new ArrayList<>();
                output.add(new VariableDefinition(definedValue, null));
                graph.getNodes().stream()
                    .filter(
                        stmt ->
                            stmt.getDef().isPresent() && stmt.getDef().get().equals(definedValue))
                    .forEach(stmt -> output.add(new VariableDefinition(definedValue, stmt)));
                return output.stream();
              })
          .orElseGet(Stream::empty);
    }

    private Stream<VariableDefinition> gen(Stmt d) {
      return d.getDef()
          .map(def -> Stream.of(new VariableDefinition(def, d)))
          .orElseGet(Stream::empty);
    }
  }
}
