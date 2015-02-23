# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
# Modifications and bugs by:
# Michal Purzynski mpurzynski@mozilla.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# Radius username and MAC address support for the Intel Framework

@load base/protocols/radius
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

module Intel;

export {
    redef enum Intel::Type += {
        PHY_ADDR
    };

    redef enum Intel::Where += {
        RADIUS::IN_SUCCESSFUL_AUTH,
        RADIUS::IN_FAILED_AUTH
    };
}

event RADIUS::log_radius(rec: RADIUS::Info)
{
    if ( rec?$username && rec?$result ) {

        if ( rec$result == "success" ) {
            Intel::seen([$indicator=rec$mac,
                        $indicator_type=Intel::PHY_ADDR,
                        $where=RADIUS::IN_SUCCESSFUL_AUTH]);
            Intel::seen([$indicator=rec$username,
                        $indicator_type=Intel::USER_NAME,
                        $where=RADIUS::IN_SUCCESSFUL_AUTH]);
        }

        if ( rec$result == "failed" ) {
            Intel::seen([$indicator=rec$mac,
                        $indicator_type=Intel::PHY_ADDR,
                        $where=RADIUS::IN_FAILED_AUTH]);
            Intel::seen([$indicator=rec$username,
                        $indicator_type=Intel::USER_NAME,
                        $where=RADIUS::IN_FAILED_AUTH]);
        }
    }
}

