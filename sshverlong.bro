# This scripts send an alert on SSH client or server longer than N chars. Used to detect some types of malware CnC communication, not longer in the wild.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

module SSH_VER_LONG;

redef enum Notice::Type += {
        ClientVersionStringLong,
	ServerVersionStringLong,
};

event ssh_client_version(c: connection, version: string)
        {
	if (|version| > 40)
		NOTICE([$note=ClientVersionStringLong,
                        $msg=fmt("%s seems to use a very long SSH client version.", c$id$orig_h),
                        $sub=version,
                        $uid=c$uid,
                        $id=c$id,
                        $identifier=cat(c$uid)]);
        }

event ssh_server_version(c: connection, version: string)
        {
	if (|version| > 40)
		NOTICE([$note=ServerVersionStringLong,
                        $msg=fmt("%s seems to use a very long SSH server version.", c$id$orig_h),
                        $sub=version,
                        $uid=c$uid,
                        $id=c$id,
                        $identifier=cat(c$uid)]);
	}
