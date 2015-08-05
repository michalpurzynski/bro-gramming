# A script to periodically log a known line that for some kind of a livecheck mechanism.
# If your SIEM does not see it for the last 5 minutes, Bro or some part of the logging pipeline might be dead.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/frameworks/notice

module MozillaAlive;

export {
    redef enum Notice::Type += {
        Bro_Is_Watching_You,
    };

    global wpad_dat_sum: set[string] &redef;
}

event MozillaAlive::check()
{
    local message = current_time() - network_time();

    NOTICE([$note=Bro_Is_Watching_You,
            $msg=fmt("Aliveness check succeeded"),
            $sub=fmt("falling behind by %s", cat(message))]);

    schedule 5mins { MozillaAlive::check() };
}

function start_liveness_check()
{
    schedule 5mins { MozillaAlive::check() };
}

event bro_init()
{
    start_liveness_check();
}

