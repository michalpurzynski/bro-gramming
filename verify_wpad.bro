# A script to detect unknown WPAD advertisements. Known WPAD are whitelisted using known hosts serving wpad.dat files with a precomputed checksum.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# TODO: application/x-ns-proxy-autoconfig
# "site-local" option 252 ("auto-proxy-config")
# maybe check for HTTP download from DNS answers only
# proxy.pac

@load policy/frameworks/files/hash-all-files
@load base/frameworks/notice
@load base/protocols/http
@load base/protocols/dns

module MozillaVerifyWPAD;

export {
    redef enum Notice::Type += {
        New_WPAD_In_DNS,
        New_WPAD_In_HTTP,
    };

    global whitelist_hosts: set[string] &redef;
    global wpad_dat_sum: set[string] &redef;
}

event file_hash(f: fa_file, kind: string, hash: string)
{
    local is_whitelisted: bool;
    local error_code: int;
    local lastconn: connection;

    for ( cid in f$conns ) {
        if ( ! f$conns[cid]?$http )
            return;
        if ( ! f$conns[cid]$http?$method )
            return;
        lastconn = f$conns[cid];
        if ( f$conns[cid]$http$method != "GET" )
            return;
        else {
            if ( /^\/wpad\.dat/ ! in f$conns[cid]$http$uri ) {
                return;
            }
        }
    }

    for ( cid in f$conns ) {
        if ( cat(cid$resp_h) in whitelist_hosts ) {
            is_whitelisted = T;
            error_code = 0;
        } else {
            is_whitelisted = F;
            error_code = 1;
            break;
        }
    }

    if ( is_whitelisted == T ) {
        if ( hash ! in wpad_dat_sum )
            error_code = 2;
    }

    local message: string;
    if ( error_code == 0 )
        return;
    else if ( error_code == 1 )
        message = "Unknown HTTP server";
    else if ( error_code == 2 )
        message = "WPAD checksum fail";
    else
        message = "Something went wrong";

    NOTICE([$note=New_WPAD_In_HTTP,
            $msg=fmt("Unauthorized WPAD detected"),
            $sub=message,
            $uid=lastconn$uid,
            $id=lastconn$id,
            $identifier=cat(lastconn$uid)]);
}

event DNS::log_dns(rec: DNS::Info)
{
    local is_whitelisted: bool;

    if ( ! rec?$qtype_name )
        return;
    if ( ! rec?$query )
        return;
    if ( ! rec?$answers )
        return;

    if ( /CNAME|^A|AAAA/ ! in rec$qtype_name )
        return;
    # put your domain name in here
    if ( /^wpad\..*mozilla\.(net|org|com)/ ! in rec$query )
        return;

    for ( vecidx in rec$answers ) {
        if ( rec$answers[vecidx] in whitelist_hosts )
            is_whitelisted = T;
        else {
            is_whitelisted = F;
            break;
        }
    }

    if ( is_whitelisted == T )
        return;
    else {
        NOTICE([$note=New_WPAD_In_DNS,
                $msg=fmt("Unauthorized WPAD detected"),
                $sub=fmt("Host %s sends WPAD answers with unknown proxies", cat(rec$id$resp_h)),
                $uid=rec$uid,
                $id=rec$id,
                $identifier=cat(rec$uid)]);
    }
}

