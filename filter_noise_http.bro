# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

event bro_init()
{
        Log::remove_default_filter(HTTP::LOG);
        Log::add_filter(HTTP::LOG, [$name = "http-noise",
                        $path_func(id: Log::ID, path: string, rec: HTTP::Info) = {
				return (rec?$user_agent && /User-Agent-I-Do-Not-Care-About/ in rec$user_agent) ? "http-noise" : "http";
                        }]);
}

