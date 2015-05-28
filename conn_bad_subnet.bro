# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Script to detect connections to subnet given as a table index. Yields metadata.

module ConnBadSubnet;

redef enum Notice::Type += {
    IN_ORIG,
    IN_RESP,
};

event new_connection(c: connection)
{
    if ( ! c?$id )
        return;
    if ( ! c$id?$orig_h )
        return;

    if ( c$id$orig_h in bad_subnets )
        NOTICE([$note=IN_ORIG,
                $msg=fmt("Suspicious IP %s known from %s attacks initated connection to our host %s ", cat(c$id$orig_h), bad_subnets[c$id$orig_h], cat(c$id$resp_h)),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);

    if ( c$id$resp_h in bad_subnets )
        NOTICE([$note=IN_RESP,
                $msg=fmt("Our host %s initiated connection to suspicious %s known from %s attacks", cat(c$id$orig_h), cat(c$id$resp_h), bad_subnets[c$id$resp_h]),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);
}

