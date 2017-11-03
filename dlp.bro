module ConnAnomaly;

redef enum Notice::Type += {
    ConnLong,
    ConnBig,
    ConnBigUp,
    ConnBigDown,
};

export {
    const max_duration: interval = 3600sec &redef;
    const size_threshold = 1024*1024*100 &redef;
    
    global ConnAnomaly::whitelist_connlong_policy: hook(wlconn: conn_id);
    global ConnAnomaly::whitelist_connbigup_policy: hook(wlconn: conn_id);
    global ConnAnomaly::whitelist_connbigdown_policy: hook(wlconn: conn_id);
}

# global wl_dlp_table: table[subnet] of table[subnet] of port = table() &synchronized;
hook whitelist_connbig_policy(wlconn: conn_id)
{
    if (wlconn$orig_h in wl_dlp_table) {
        if (wlconn$resp_h in wl_dlp_table[wlconn$orig_h])
            if (wlconn$resp_p in wl_dlp_table[wlconn$orig_h][wlconn$resp_h]) {
                break;
            }
    }
}

#hook whitelist_connbigup_policy(wlconn: conn_id)
#{
#    if (wlconn$orig_h in wl_dlp_table) {
#        if (wlconn$resp_h in wl_dlp_table[wlconn$orig_h]$wl_dst)
#            if (wlconn$resp_p == wl_dlp_table[wlconn$orig_h]$wl_port) {
#                break;
#            }
#    }
#}
#
#hook whitelist_connbigdown_policy(wlconn: conn_id)
#{
#    if (wlconn$orig_h in wl_dlp_table) {
#        if (wlconn$resp_h in wl_dlp_table[wlconn$orig_h]$wl_dst)
#            if (wlconn$resp_p == wl_dlp_table[wlconn$orig_h]$wl_port) {
#                break;
#            }
#    }
#}

event ConnThreshold::bytes_threshold_crossed(c: connection, threshold: count, is_orig: bool)
{
    if ( ( c$orig$num_bytes_ip >= size_threshold || c$resp$num_bytes_ip >= size_threshold) && ( hook whitelist_connbig_policy(c$id) )) {
        #add c["bigconn"];
        NOTICE([
            $note=ConnBig,
            $msg=fmt("%s received/sent more than %d bytes over a single connection", c$id$orig_h, threshold),
            $uid=c$uid,
            $id=c$id,
            $identifier=c$uid + cat(c$orig$num_bytes_ip) + cat(c$resp$num_bytes_ip),
            $conn = c,
            $suppress_for=0sec
        ]);

        ConnThreshold::set_bytes_threshold(c, threshold*2, F);
        ConnThreshold::set_bytes_threshold(c, threshold*2, T);
    }
}

event connection_established(c: connection) &priority=-3
{
    ConnThreshold::set_bytes_threshold(c, size_threshold, T);
    ConnThreshold::set_bytes_threshold(c, size_threshold, F);
}

#event Conn::log_conn(rec: Conn::Info)
#{
#    if ( ( rec?$duration ) && ( rec$duration > max_duration ) && ( hook whitelist_connlong_policy(rec$id) ) )
#        NOTICE([$note=ConnLong,
#                $msg=fmt("%s had a connection opened for %s minutes", rec$id$orig_h, rec$duration/60sec),
#                $uid=rec$uid,
#                $id=rec$id,
#                $identifier=cat(rec$uid)
#        ]);
#}

