@0x9e7bb90f8aa091d7;

using Cxx = import "/capnp/c++.capnp";
$Cxx.namespace("iptrap");

struct Event {
  ts @0 :UInt64;
  ipSrc @1 :Text;
  dport @2 :UInt16;
  payload @3 :Data;
}
