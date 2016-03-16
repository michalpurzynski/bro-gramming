# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Script to read in a list of IP addresses that won't be logged to any log file
#

module LogFilter;

type Idx: record {
    drop_ip: addr;
};

type Val: record {
    description: string;
};

global drop_ip_from_log: table[addr] of Val = table();

event bro_init()
{
    Input::add_table([$source="/opt/bro/share/bro/brozilla/logfilter_ip.txt",
            $name="drop_ip_list",
            $idx=Idx,
            $val=Val,
            $destination=drop_ip_from_log,
            $mode=Input::REREAD]);
}
