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
# Anthony Verez averez@mozilla.com

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module ApacheModStatus;

export {
    redef enum Notice::Type += {
        Apache_ModStatus,
    };

    const mozilla_internal_space: subnet = 10.0.0.0/8 &redef;
    const mozilla_public_space: subnet = 63.245.208.0/20 &redef;
    # From https://github.com/mozilla/nmap-differential-scan/blob/master/targets.txt
    const mozilla_pek1_office_space: subnet = 223.202.6.1/27 &redef;

    const ignore_host_resp: set[addr] = { } &redef;
    const ignore_host_orig: set[addr] = { } &redef;
}

event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # only conns we want
    local ports_ext: set[port] = { 80/tcp };
    local ports_int: set[port] = { 80/tcp, 81/tcp, 443/tcp };

    if (((c$id$resp_h in mozilla_internal_space) && (c$id$resp_p in ports_int)) || ((c$id$resp_h in mozilla_public_space) && (c$id$resp_p in ports_ext)) && (c$id$resp_h !in ignore_host_resp) && (c$id$orig_h !in ignore_host_orig)) {
        if (c$http?$cluster_client_ip && to_addr(c$http$cluster_client_ip) !in mozilla_pek1_office_space) {
            if(/.*\/server\-status.*/ in c$http$uri && c$http?$host) {
                    NOTICE([$note=Apache_ModStatus,
                            $msg=fmt("/server-status request (CVE-2014-0226): %s %s", c$http$host, c$http$uri),
                            $sub=fmt("from %s", c$http$cluster_client_ip),
                            $src=to_addr(c$http$cluster_client_ip),
                            $identifier=cat(c$http$cluster_client_ip,c$http$host),
                            $suppress_for=1day
                   ]);
            }
        }
    }
}
