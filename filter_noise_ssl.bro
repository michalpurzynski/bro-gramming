# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

const ignore_ports_resp: set[port] = {53/udp, 53/tcp, 123/udp, 137/udp, 161/udp, 514/udp, 514/tcp, 5355/udp, 5666/tcp, 8443/tcp} &redef;

event bro_init()
{
        Log::remove_default_filter(SSL::LOG);
        Log::add_filter(SSL::LOG, [$name = "ssl-noise",
                                    $pred(rec: SSL::Info) = {
                        if (rec$id$resp_p in ignore_ports_resp)
                            return F;
                        if ((rec$id$orig_h in drop_ip_from_log) || (rec$id$resp_h in drop_ip_from_log))
                            return F;
			if ((rec?$server_name) && (/alamakota\.domain\.org|alamakota2\.domain\.org|alamakota3\.domain\.org/ in rec$server_name))
			    return F;
                        return T;
                        }
                        ]);
}

