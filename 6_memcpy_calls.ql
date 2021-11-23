import cpp

from Function f ,FunctionCall fc
where fc.getTarget().getName()="memcpy"
select fc
