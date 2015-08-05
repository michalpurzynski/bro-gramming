# Filter out communication on a set of given ports to a separate file.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

const ignore_ports_resp: set[port] = {53/udp, 53/tcp, 123/udp, 137/udp, 161/udp, 5355/udp} &redef;

event bro_init()
{
        Log::remove_default_filter(Conn::LOG);
        Log::add_filter(Conn::LOG, [$name = "conn-noise",
                        $path_func(id: Log::ID, path: string, rec: Conn::Info) = {
                                return (rec$id$resp_p in ignore_ports_resp) ? "conn-noise" : "conn";
                        }]);
}

