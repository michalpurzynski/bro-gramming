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
