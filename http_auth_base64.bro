# Script to detect Basic HTTP auth (using base64)
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
# Anthony Verez netantho@gmail.com

@load base/frameworks/notice
@load base/protocols/http

module AuthBasic;

export {
    redef enum Notice::Type += {
        Basic_Auth_Server,
        Basic_Auth_Client
    };

    const filter_port_resp: set[port] = { 80/tcp } &redef;

    const ignore_host_resp: set[addr] = { } &redef;
    const ignore_host_orig: set[addr] = { } &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ((c$id$resp_p in filter_port_resp) && (c$id$resp_h !in ignore_host_resp) && (c$id$orig_h !in ignore_host_orig)) {
        if (/WWW-Authenticate/ in name && /.*Basic.*/ in value) {
            NOTICE([$note=Basic_Auth_Server,
                   $msg="Server identified on which Basic Access Authentication is in use.",
                   $conn=c
                   $identifier=cat(c$id$resp_h,c$id$resp_p),
                   $suppress_for=1day
                   ]);
        }
        if (/Authorization/ in name && /.*Basic.*/ in value)
        {
            local parts = split1(decode_base64(sub_bytes(value, 7, |value|)), /:/);
            if (|parts| == 2)
              NOTICE([$note=Basic_Auth_Client,
                     $msg="Client using Basic Access Authentication.",
                     $sub=fmt("username: %s", parts[1]),
                     $conn=c
                     $identifier=cat(c$id$resp_h,c$id$resp_p),
                     $suppress_for=1day
                     ]);
        }
    }
}

