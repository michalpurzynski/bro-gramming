# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
# Julien Vehent jvehent@mozilla.com [:ulfr]
#
# Script that logs servers that do not support AES in the SSL ciphers that are
# announced in their SERVER HELLO

@load base/protocols/conn
@load base/protocols/ssl

module SSL;

redef enum Notice::Type += {
	SSL_NonAES_Server,
};

event ssl_server_handshake(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
{
    local hasAES:bool = F;
    if (/AES/ in SSL::cipher_desc[cipher]) {
        hasAES = T;
    }
    if ( !hasAES ) {
	if (c$id$resp_h in Site::local_nets) {
		NOTICE([$note=SSL_NonAES_Server,
			$msg=fmt("%s server negotiated non-AES cipher.", c$id$orig_h),
			$sub=SSL::cipher_desc[cipher],
			$uid=c$uid,
			$id=c$id,
			$identifier=cat(c$uid)]);
	}
    }
}
