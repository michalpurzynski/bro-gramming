# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
# Modifications and bugs by:
# Michal Purzynski mpurzynski@mozilla.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# Support for UDP, ICMP. This will only generate Intel matches when a connection is removed from Bro. Will not send local link IPv6 events to the Intel Framework because it generates false positives here.

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

const ip6_local: set[subnet] = set([fe80:0000::]/10, [ff02::]/16);

event Conn::log_conn(rec: Conn::Info)
{
if ( ( rec?$proto ) && ( rec$proto != tcp ) ) 
  {

  if ( ( rec$id$orig_h in ip6_local ) || ( rec$id$resp_h in ip6_local ) )
    return;

  # duration, start_time, addl, and hot are required fields although they are not used by Intel framework
  local dur: interval;
  local history: string;

  if ( rec?$duration )
    dur = rec$duration;
  else dur = 0secs;

  if ( rec?$history )
    history = rec$history;
  else history = "";

  local c = [$uid = rec$uid,$id = rec$id,$history = history,$duration = dur,$start_time = 0,$addl = "",$hot = 0];

  Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
  Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
  }
}
