# Script that logs clients that do not support AES in the SSL ciphers that are
# announced in their CLIENT HELLO
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Julien Vehent jvehent@mozilla.com [:ulfr]
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/conn
@load base/protocols/ssl

module SSL;

redef enum Notice::Type += {
	SSL_NonAES_Client,
};

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
{
    local hasAES:bool = F;
    for (cipher in ciphers) {
        if (/AES/ in SSL::cipher_desc[ciphers[cipher]]) {
            hasAES = T;
        }
    }
    if ( !hasAES ) {
	if (c$id$orig_h in Site::local_nets) {
		local cs = "";
		for (cipher in ciphers) {
			cs += SSL::cipher_desc[ciphers[cipher]] + ",";
		}
		NOTICE([$note=SSL_NonAES_Client,
			$msg=fmt("%s does not support AES cipher.", c$id$orig_h),
			$sub=cs,
			$uid=c$uid,
			$id=c$id,
			$identifier=cat(c$uid)]);
	}
    }
}
