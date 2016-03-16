# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

const ignore_ports_resp: set[port] = {53/udp, 53/tcp, 123/udp, 137/udp, 161/udp, 5355/udp} &redef;

event bro_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name = "conn-noise",
                                    $pred(rec: Conn::Info) = {
                        local result = T;
                        if (/^RSTO|^S0$|^SH$|^SHR$/ in rec$conn_state)
                            result = F;
                        else {
                            if (rec$id$resp_p in ignore_ports_resp)
                                result = F;
                        }
                        if ((rec$id$orig_h in drop_ip_from_log) || (rec$id$resp_h in drop_ip_from_log))
                            result = F;
                        return result;
                        }
                        ]);
}

# If you have enough CPU power and just want to send them to a separate file, use this.
#event bro_init()
#{
#        Log::remove_default_filter(Conn::LOG);
#        Log::add_filter(Conn::LOG, [$name = "conn-noise",
#                        $path_func(id: Log::ID, path: string, rec: Conn::Info) = {
#
#                                return (rec$id$resp_p in ignore_ports_resp) ? "conn-noise" : "conn";
#                        }]);
#}
