# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

event bro_init()
{
        Log::remove_default_filter(SSL::LOG);
        Log::add_filter(SSL::LOG, [$name = "ssl-noise",
                                    $pred(rec: SSL::Info) = {
                        if ((rec$id$orig_h in drop_ip_from_log) || (rec$id$resp_h in drop_ip_from_log))
                            return F;
                        else {
				if ((rec?$server_name) && (/your\.noisyservername\.org/ in rec$server_name))
					return F;
			}
			return T;
                        }
                        ]);
}
