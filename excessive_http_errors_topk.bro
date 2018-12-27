# Script to detect excessive HTTP errors from the same source IP
# Inspired by policy/protocols/http/detect-sqli.bro
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Bro IDS team (detect-sqli inspiration)
# Anthony Verez averez@mozilla.com
# Michal Purzynski mpurzynski@mozilla.com

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module MozillaHTTPErrors;

export {
    redef enum Notice::Type += {
        ## Indicates that a host performing HTTP requests leading to
	## excessive HTTP errors was detected.
        Excessive_HTTP_Errors_Attacker,
        ## Indicates that a host was seen to respond excessive HTTP
        ## errors. This is tracked by IP address as opposed to
        ## hostname.
        Excessive_HTTP_Errors_Victim,
    };

    # Let's tag the http item
    redef enum HTTP::Tags += {
        ## HTTP status code >= 400, describing a HTTP error
        HTTP_ERROR,
    };

    ## Interval at which to watch for the
    ## :bro:id:`HTTP::excessive_http_errors_threshold` variable to be
    ## crossed. At the end of each interval the counter is reset.
    const excessive_http_errors_interval = 15mins &redef;
    const report_threshold_attacker = 50 &redef;
    const report_threshold_victim = 100 &redef;
    const suppress_attacker = 15mins &redef;
    const suppress_victim = 15mins &redef;

    const topk_attacker_howmuch = 30 &redef;
    const topk_attacker_size = 1000 &redef;

    const topk_victim_howmuch = 30 &redef;
    const topk_victim_size = 1000 &redef;

    const monitor_ip_spaces: set[subnet] &redef;
    const monitor_ports: set[port] &redef;
    const ignore_hosts_orig: set[subnet] &redef;
    const ignore_hosts_resp: set[subnet] &redef;
    const ignore_user_agents: pattern &redef;
    const ignore_referrers: pattern &redef;
    const ignore_host_fields: pattern &redef;
}

event bro_init()
{
    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an actual attack and how to respond when
    # thresholds are crossed.

    # HTTP errors for requests FROM the same host
    local r1: SumStats::Reducer = [$stream="http.excessive_errors.attacker", $apply=set(SumStats::TOPK), $topk_size=topk_attacker_size];
    SumStats::create([$name="excessive-http-errors-attackers",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r1),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                          if ("http.excessive_errors.attacker" in result) {
                              local r = result["http.excessive_errors.attacker"];
                              local s: vector of SumStats::Observation;
                              s = topk_get_top(r$topk, topk_attacker_howmuch);

                              for (attacker in s) {
			        local errors = topk_count(r$topk, s[attacker]);
				if (errors > report_threshold_attacker) {
                                  NOTICE([$note=Excessive_HTTP_Errors_Attacker,
                                      $msg=fmt("Excessive HTTP errors for requests from %s", s[attacker]$str),
                                      $sub=fmt("%d in %s, eps: %d", errors, excessive_http_errors_interval, topk_epsilon(r$topk, s[attacker])),
                                      $src=to_addr(s[attacker]$str),
                                      $identifier=s[attacker]$str,
                                      $suppress_for=suppress_attacker
                                 ]);
                               }
                              }
                          }
                      }]);

    # HTTP errors for requests TO the same host
    local r2: SumStats::Reducer = [$stream="http.excessive_errors.victim", $apply=set(SumStats::TOPK), $topk_size=topk_victim_size];
    SumStats::create([$name="excessive-http-errors-victims",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                      {
                          if ("http.excessive_errors.victim" in result) {
                              local r = result["http.excessive_errors.victim"];
                              local s: vector of SumStats::Observation;
                              s = topk_get_top(r$topk, topk_victim_howmuch);

                              for (victim in s) {
				local errors = topk_count(r$topk, s[victim]);
                                if (errors > report_threshold_victim) {
                                  NOTICE([$note=Excessive_HTTP_Errors_Victim,
                                      $msg=fmt("Excessive HTTP errors for requests to %s", s[victim]$str),
                                      $sub=fmt("%d in %s, eps: %d", victim, excessive_http_errors_interval, topk_epsilon(r$topk, s[victim])),
                                      $src=to_addr(s[victim]$str),
                                      $identifier=s[victim]$str,
                                      $suppress_for=suppress_victim
                                 ]);
				}
                              }
                          }
                      }]);
}



event http_reply(c: connection, version: string, code: count,
                 reason: string) &priority=3
{
    if ( c$id$resp_h !in monitor_ip_spaces )
        return;
    if ( c$id$resp_p !in monitor_ports )
        return;
    if ( c$id$resp_h in ignore_hosts_resp )
        return;
    if ( c$id$orig_h in ignore_hosts_orig )
        return;
    if ( ! c?$http )
        return;
    if ( ( c$http?$cluster_client_ip ) && ( to_addr(c$http$cluster_client_ip) in ignore_hosts_orig ) )
        return;
    if ( ( c$http?$user_agent ) && ( ignore_user_agents in c$http$user_agent ) )
        return;
    if ( ( c$http?$referrer ) && ( ignore_referrers in c$http$referrer ) )
        return;
    if ( ( c$http?$host ) && ( ignore_host_fields in c$http$host ) )
        return;
    if ( code >= 400 ) {
                add c$http$tags[HTTP_ERROR];
                SumStats::observe("http.excessive_errors.victim", [],
                                  [$str=fmt("%s", c$id$resp_h)]);
                if ( ( c?$http ) && ( c$http?$cluster_client_ip ) )
                    SumStats::observe("http.excessive_errors.attacker", [],
                                    [$str=fmt("%s", c$http$cluster_client_ip)]);
    }
}

