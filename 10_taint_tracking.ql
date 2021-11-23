/**
 * @kind path-problem
 */

import cpp
import semmle.code.cpp.dataflow.TaintTracking
import DataFlow::PathGraph

class NetworkByteSwap extends Expr {
    NetworkByteSwap() {
      exists(MacroInvocation mi |
        mi.getMacroName().regexpMatch("ntoh(s|l|ll)") and
        this = mi.getExpr()
      )
    }
  }

class Config extends TaintTracking::Configuration {
  Config() { this = "NetworkToMemFuncLength" }

  override predicate isSource(DataFlow::Node source) {
    source.asExpr() instanceof NetworkByteSwap
    //源 是ntoh这些的表达式
  }
  override predicate isSink(DataFlow::Node sink) {
    // TODO
    //sink是 memcpy函数的控制大小的参数 void *memcpy(void *str1, const void *str2, size_t n)
    exists(FunctionCall fc |fc.getTarget().getName()="memcpy" and sink.asExpr()=fc.getArgument(2) )
  }
}

from Config cfg, DataFlow::PathNode source, DataFlow::PathNode sink
where cfg.hasFlowPath(source, sink)
select sink, source, sink, "Network byte swap flows to memcpy"