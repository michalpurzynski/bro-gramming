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

event connection_state_remove(c: connection)  
{
        if ( c$conn?$proto && ( c$conn$proto != tcp || ( c$conn?$history && c$conn$proto == tcp && "h" !in c$conn$history ) ) ) {
                    Intel::seen([$host=c$id$orig_h, $conn=c, $where=Conn::IN_ORIG]);
                            Intel::seen([$host=c$id$resp_h, $conn=c, $where=Conn::IN_RESP]);
                                }
}
