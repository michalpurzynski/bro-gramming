# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
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

module MozillaDetectOpenProxies;

export {
    redef enum Notice::Type += {
        Possible_Open_Proxy,
        Possible_New_Proxy,
    };

    redef enum HTTP::Tags += {
        HTTP_PROXY_OPEN,
        HTTP_PROXY_NEW,
    };

    const whitelist_proxies_lb: set[addr] &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( Site::is_local_addr(c$id$orig_h) == T && c$id$orig_h ! in whitelist_proxies_lb )
        if ( name == "X-FORWARDED-FOR" ) {
            add c$http$tags[HTTP_PROXY_NEW];
            NOTICE([$note=Possible_New_Proxy,
                $msg=fmt("%s has sent outbound HTTP request with the X-FORWARDED-FOR header, looks like a proxy", c$id$orig_h),
                $uid=c$uid,
                $id=c$id,
                $identifier=cat(c$uid)]);
        }
}

