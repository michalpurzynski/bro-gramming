# Script to detect HTTP bad user agents
#
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
@load base/protocols/http

module BadUA;

export {
    redef enum Notice::Type += {
        HTTP_Bad_UA
    };

    # Let's tag the http item
    redef enum HTTP::Tags += {
        HTTP_BADUA,
    };

    redef enum Log::ID += { LOG };

    const mozilla_internal_space: subnet = 10.0.0.0/8 &redef;
    const mozilla_public_space: subnet = 63.245.208.0/20 &redef;

    const ignore_host_resp: set[addr] = { } &redef;
    const ignore_host_orig: set[addr] = { } &redef;

    type Sig: record {
         regex: pattern;
         name: string;
    };

    type SigVec: vector of Sig;

    # Please add signatures at the END of this list and to preserve rule ids
    # (?i:javascriptt) for case-insensitive is not working atm, so we need to do it old school :S
    # see https://bro-tracker.atlassian.net/browse/BIT-26
    global sigs = SigVec(
        [$regex=/.*Apache-HttpClient\/4\.1\.1 \(java 1\.5\).*/,
         $name="apache-client"],
        [$regex=/.*Mozilla\/\\[0-9]+\\\.0.*/,
         $name="invalid-mozilla"],
        [$regex=/.*Safari\/\\[0-9]+\\\.0.*/,
         $name="invalid-safari"],
        [$regex=/.*Wget\/1\.12 \(darwin9\.8\.0\).*/,
         $name="wget"]
    );
}

# Make sure we have all the http info before looking for auth errors
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # only conns we want
    local ports_ext: set[port] = { 80/tcp };
    local ports_int: set[port] = { 80/tcp, 81/tcp, 443/tcp };

    if (((c$id$resp_h in mozilla_internal_space) && (c$id$resp_p in ports_int)) || ((c$id$resp_h in mozilla_public_space) && (c$id$resp_p in ports_ext)) && (c$id$resp_h !in ignore_host_resp) && (c$id$orig_h !in ignore_host_orig)) {
        if (c$http?$cluster_client_ip && c$http?$user_agent) {
            for(tid in sigs) {
                if(sigs[tid]$regex in c$http$user_agent) {

                    add c$http$tags[HTTP_BADUA];

                    NOTICE([$note=HTTP_Bad_UA,
                            $msg=fmt("Bad UA agent found: %s", c$http$user_agent),
                            $sub=fmt("from %s while accessing %s", c$http$cluster_client_ip, c$http$host),
                            $conn=c,
                            $identifier=cat(c$http$cluster_client_ip,c$http$host),
                            $suppress_for=1day
                   ]);
                }
            }
        }
    }
}

