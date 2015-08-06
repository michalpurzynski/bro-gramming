# Script to detect bugzilla login bruteforcing. A nice example how to parse HTML traffic in Bro.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

# Suggestion: Same as auth_bruteforcing.bro

module BugzBruteforcing;

export {
    redef enum Notice::Type += {
        ## Indicates that a host performing HTTP requests leading to
        ## excessive HTTP auth errors was detected.
        HTTP_BugzBruteforcing_Attacker,
        ## Indicates that a host was seen to respond excessive HTTP
        ## auth errors. This is tracked by IP address as opposed to
        ## hostname.
        HTTP_BugzBruteforcing_Victim,
    };

    const ports_int: set[port] = { 80/tcp, 443/tcp } &redef;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                time        &log;
        uid:               string      &log;
        id:                conn_id     &log &optional;
        cluster_client_ip: string      &log &optional;
        status_code:       count       &log &optional;
        host:              string      &log &optional;
        uri:               string      &log &optional;
        username:          string      &log &optional;
        auth_success:      bool        &log &optional;
    };

    const auth_errors_threshold: double = 5.0 &redef;
    const auth_errors_interval = 1min &redef;
}

event bro_init()
{
    Log::create_stream(BugzBruteforcing::LOG, [$columns=Info]);

    # HTTP auth errors for requests FROM the same host
    local r1: SumStats::Reducer = [$stream="bugz.auth_errors.attacker", $apply=set(SumStats::SUM)];
    SumStats::create([$name="bugz-http-errors-attackers",
                      $epoch=auth_errors_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["bugz.auth_errors.attacker"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=HTTP_BugzBruteforcing_Attacker,
                                  $msg=fmt("HTTP auth bruteforcing from attacker %s", key$host),
                                  $sub=fmt("%.0f auth failed in %s", result["bugz.auth_errors.attacker"]$sum, auth_errors_interval),
                                  $src=key$host,
                                  $n=to_count(fmt("%.0f", result["bugz.auth_errors.attacker"]$sum))
                          ]);
                      }]);

    # HTTP errors for requests TO the same host
    local r2: SumStats::Reducer = [$stream="bugz.auth_errors.victim", $apply=set(SumStats::SUM)];
    SumStats::create([$name="bugz-http-errors-victims",
                      $epoch=auth_errors_interval,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["bugz.auth_errors.victim"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=HTTP_BugzBruteforcing_Victim,
                                  $msg=fmt("HTTP auth bruteforcing to victim %s", key$str),
                                  $sub=fmt("%s auth failed in %s", result["bugz.auth_errors.victim"]$sum, auth_errors_interval),
#                                  $src=key$str,
                                  $n=to_count(fmt("%.0f", result["bugz.auth_errors.victim"]$sum))
                          ]);
                      }]);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) {
#	if (!Site::is_local_addr(c$id$resp_h))
#		return;
	if (c$id$resp_p !in ports_int)
		return;
	if (!c$http?$method || c$http$method != "POST")
		return;
	if (/(index|show_bug)\.cgi/ !in c$http$uri)
		return;

	local meta_table: string = sub_bytes(data, 250, 260);
	if (/Invalid\ Username\ Or\ Password/ in meta_table) {
		SumStats::observe("bugz.auth_errors.attacker", [$host=to_addr(c$http$cluster_client_ip)], SumStats::Observation($num=1));
                SumStats::observe("bugz.auth_errors.victim", [$str=c$http$host], SumStats::Observation($num=1));
	}

}

