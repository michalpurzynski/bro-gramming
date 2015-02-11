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
@load base/protocols/http

module MozillaUnusualHTTP;

export {
    redef enum Notice::Type += {
        Interesting_HTTP_Method_Success,
        Interesting_HTTP_Method_Fail,
    };

    redef enum HTTP::Tags += {
        HTTP_BAD_METHOD_OK,
        HTTP_BAD_METHOD_FAIL,
    };

    global whitelist_hosts_methods: table[addr, string] of set[subnet] = table() &redef;

    const suspicious_http_methods: set[string] = {
        "DELETE", "TRACE", "CONNECT",
        "PROPPATCH", "MKCOL", "SEARCH",
        "COPY", "MOVE", "LOCK", "UNLOCK",
        "POLL", "REPORT", "SUBSCRIBE", "BMOVE"
    } &redef;

    const monitor_ip_spaces: set[subnet] &redef;
    const monitor_ports: set[port] &redef;
    const ignore_hosts_orig: set[subnet] &redef;
    const ignore_hosts_resp: set[subnet] &redef;
}

event http_reply(c: connection, version: string, code: count, reason: string)
{

    local cluster_client_ip: addr;

    if ( ! c?$http )
        return;
    if ( ! c$http?$method )
        return;
    if ( c$id$resp_h !in monitor_ip_spaces )
        return;
    if ( c$id$resp_p !in monitor_ports )
        return;
    if ( c$id$resp_h in ignore_hosts_resp )
        return;
    if ( c$id$orig_h in ignore_hosts_orig )
        return;
    if ( ! c$http?$cluster_client_ip )
        cluster_client_ip = c$id$orig_h;
    else
        cluster_client_ip = to_addr(c$http$cluster_client_ip);
    if ( ( c$http?$cluster_client_ip ) && ( to_addr(c$http$cluster_client_ip) in ignore_hosts_orig ) )
        return;
    if ( c$http$method ! in suspicious_http_methods )
        return;

    if ( [c$id$resp_h, c$http$method] in whitelist_hosts_methods ) {
        if ( c$id$orig_h in whitelist_hosts_methods[c$id$resp_h, c$http$method] )
            return;
        if ( cluster_client_ip in whitelist_hosts_methods[c$id$resp_h, c$http$method] )
            return;
    } else {
        if ( c$http$status_code < 300 ) {
            add c$http$tags[HTTP_BAD_METHOD_OK];
            NOTICE([$note=Interesting_HTTP_Method_Success,
                $msg=fmt("%s successfully used method %s on %s host %s", cluster_client_ip, c$http$method, c$id$resp_h, c$http$host),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);
        } else {
            add c$http$tags[HTTP_BAD_METHOD_FAIL];
            NOTICE([$note=Interesting_HTTP_Method_Fail,
                $msg=fmt("%s failed to used method %s on %s host %s", cluster_client_ip, c$http$method, c$id$resp_h, c$http$host),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);
        }
    }
}

