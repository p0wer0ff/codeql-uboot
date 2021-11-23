import cpp

class NetworkByteSwap extends Expr {
  NetworkByteSwap () {
    // TODO: replace <class> and <var>
    exists(MacroInvocation mi |
      mi.getMacro().getName().regexpMatch("ntoh(s|l|ll)") and
      this=mi.getExpr()
    )
  }
}

from NetworkByteSwap n
select n, "Network byte swap"