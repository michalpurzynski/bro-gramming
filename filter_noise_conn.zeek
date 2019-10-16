# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

const ignore_ports_resp: set[port] = {53/udp, 53/tcp, 123/udp, 137/udp, 161/udp, 514/udp, 514/tcp, 5355/udp, 5666/tcp, 8443/tcp} &redef;
const ignore_services: set[string] = {"dns"} &redef;

event zeek_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name = "conn-noise",
                                    $pred(rec: Conn::Info) = {
                        #if (/^RSTO|^S0$|^SH$|^SHR$/ in rec$conn_state) {
                        #    return T;
                        #} else {
                        if (rec$id$resp_p in ignore_ports_resp) {
                                return F;
                        }
                        if (rec?$service && rec$service in ignore_services) {
                                return F;
                        }
                        if ((rec$id$orig_h in drop_ip_from_log) || (rec$id$resp_h in drop_ip_from_log))
                            return F;
                        return T;
                        }
                        ]);
}

# If you have enough CPU power and just want to send them to a separate file, use this.
#event zeek_init()
#{
#        Log::remove_default_filter(Conn::LOG);
#        Log::add_filter(Conn::LOG, [$name = "conn-noise",
#                        $path_func(id: Log::ID, path: string, rec: Conn::Info) = {
#
#                                return (rec$id$resp_p in ignore_ports_resp) ? "conn-noise" : "conn";
#                        }]);
#}
