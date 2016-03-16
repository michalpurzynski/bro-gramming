# Script that logs clients that do not support AES in the SSL ciphers that are
# announced in their CLIENT HELLO
# 
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
# 
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
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
# Julien Vehent jvehent@mozilla.com [:ulfr]
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

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
