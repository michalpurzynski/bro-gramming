# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2014
# the Initial Developer. All Rights Reserved.
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

