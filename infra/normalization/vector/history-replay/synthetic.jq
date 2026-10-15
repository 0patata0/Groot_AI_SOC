def row($id; $message):
  {MESSAGE:$message,_TRANSPORT:"kernel",__CURSOR:("synthetic-replay:"+$id),
   __REALTIME_TIMESTAMP:"1700000000000000",__MONOTONIC_TIMESTAMP:"1",_BOOT_ID:"00000000000000000000000000000000"};
def fields: "IN=eth0 OUT= SRC=198.51.100.7 DST=192.0.2.20 PROTO=TCP SPT=51000 DPT=443";
(["AGENT_BLOCK","FW_DROP_IN","FW_DROP_OUT","FW_DROP_FWD","FW_SHADOW_OUT","FW_SSH_RATE","SPOOF"][] | . as $prefix | row($prefix; $prefix+" "+fields)),
row("ordinary";"synthetic kernel startup control"),
row("duplicate";"FW_DROP_IN "+fields+" SRC=198.51.100.8"),
(row("nonkernel";"FW_DROP_IN "+fields) | ._TRANSPORT="stdout"),
row("bad_ip";"FW_DROP_IN IN=eth0 OUT= SRC=invalid DST=192.0.2.20 PROTO=TCP SPT=51000 DPT=443"),
row("protected";"FW_DROP_IN IN=eth0 OUT= SRC=211.170.162.111 DST=192.0.2.20 PROTO=TCP SPT=51000 DPT=443"),
(row("bad_timestamp";"FW_DROP_IN "+fields) | .__REALTIME_TIMESTAMP="invalid"),
row("unselected_prefix";"UNTRUSTED FW_DROP_IN "+fields)
