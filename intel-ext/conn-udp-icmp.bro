# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
# Modifications and bugs by:
# Michal Purzynski mpurzynski@mozilla.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# Support for UDP, ICMP. This will only generate Intel matches when a connection is removed from Bro.
# Will not send local link IPv6 events to the Intel Framework because it generates false positives here.
# Also omit the non-established TCP connections.

@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

const ip6_local: set[subnet] = set([fe80:0000::]/10, [ff02::]/16);

event connection_state_remove(c: connection)  
{
    if ( ( c$conn?$proto ) && ( c$conn$proto != tcp ) ) {
        if ( ( c$id$orig_h in ip6_local ) || ( c$id$resp_h in ip6_local ) )
            return;

        Intel::seen([$indicator=cat(c$id$orig_h), $indicator_type=Intel::ADDR, $host=c$id$orig_h, $where=Conn::IN_ORIG, $conn=c]);
        Intel::seen([$indicator=cat(c$id$resp_h), $indicator_type=Intel::ADDR, $host=c$id$orig_h, $where=Conn::IN_RESP, $conn=c]);
    }
}
