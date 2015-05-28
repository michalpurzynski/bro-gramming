# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Script to detect connections to subnet given as a table index. Yields metadata.

module ConnBadSubnet;

type Idx: record {
        bad_subnet: subnet;
};

type Val: record {
        timestamp: time;
        description: string;
};

global bad_subnets: table[subnet] of Val = table();

event bro_init()
{
    Input::add_table([$source="/opt/bro/share/bro/intelzilla/bad_subnets.txt", $name="bad_subnets_list", $idx=Idx, $val=Val, $destination=bad_subnets, $mode=Input::REREAD]);
}

