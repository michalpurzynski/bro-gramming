# Script to detect HTTP auth bruteforcing
# write http auth stuff in http_auth.log for forensics
# Inspired by policy/protocols/http/detect-sqli.bro
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
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
# Anthony Verez averez@mozilla.com
# Michal Purzynski mpurzynski@mozilla.com

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module AuthBruteforcing;

export {
    redef enum Notice::Type += {
        ## Indicates that a host performing HTTP requests leading to
	## excessive HTTP auth errors was detected.
        HTTP_AuthBruteforcing_Attacker,
        ## Indicates that a host was seen to respond excessive HTTP
        ## auth errors. This is tracked by IP address as opposed to
        ## hostname.
        HTTP_AuthBruteforcing_Victim,
    };

    # Let's tag the http item
    redef enum HTTP::Tags += {
        ## HTTP status code 401, describing a HTTP auth error
        HTTP_AUTH_ERROR,
        ## HTTP describing a successful HTTP auth
        HTTP_AUTH_SUCCESS,
    };

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

    global log_auth: event(rec: Info);

    ## Defines the threshold that determines if a auth bruteforcing attack
    ## is ongoing based on the number of requests that appear to be
    ## attacks.
    const auth_errors_threshold: double = 50.0 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`AuthBruteforcing::auth_errors_requests_threshold` variable to be crossed.
    ## At the end of each interval the counter is reset.
    const auth_errors_interval = 5min &redef;

    ## Interval at which to watch for the
    ## :bro:id:`AuthBruteforcing::excessive_auth_errors_threshold` variable to be
    ## crossed. At the end of each interval the counter is reset.
    const excessive_auth_errors_interval = 1min &redef;

    const internal_space: subnet = 10.0.0.0/8 &redef;
    const public_space: subnet = 63.245.208.0/20 &redef;

    const ignore_host_resp: set[addr] = { } &redef;
    const ignore_host_orig: set[addr] = { } &redef;
}

event bro_init() &priority=3
{
    # Create auth_bruteforcing.log
    Log::create_stream(AuthBruteforcing::LOG, [$columns=Info, $ev=log_auth]);

    # HTTP auth errors for requests FROM the same host
    local r1: SumStats::Reducer = [$stream="http.auth_errors.attacker", $apply=set(SumStats::SUM)];
    SumStats::create([$name="auth-http-errors-attackers",
                      $epoch=auth_errors_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["http.auth_errors.attacker"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=HTTP_AuthBruteforcing_Attacker,
                                  $msg=fmt("HTTP auth bruteforcing from attacker %s", key$host),
                                  $sub=fmt("%.0f auth failed in %s", result["http.auth_errors.attacker"]$sum, auth_errors_interval),
                                  $src=key$host,
                                  $n=to_count(fmt("%.0f", result["http.auth_errors.attacker"]$sum))
                          ]);
                      }]);

    # HTTP errors for requests TO the same host
    local r2: SumStats::Reducer = [$stream="http.auth_errors.victim", $apply=set(SumStats::SUM)];
    SumStats::create([$name="auth-http-errors-victims",
                      $epoch=auth_errors_interval,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["http.auth_errors.victim"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=HTTP_AuthBruteforcing_Victim,
                                  $msg=fmt("HTTP auth bruteforcing to victim %s", key$host),
                                  $sub=fmt("%.0f auth failed in %s", result["http.auth_errors.victim"]$sum, auth_errors_interval),
                                  $src=key$host,
                                  $n=to_count(fmt("%.0f", result["http.auth_errors.victim"]$sum))
                          ]);
                      }]);
}

# Make sure we have all the http info before looking for auth errors
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # only conns we want
    local ports_ext: set[port] = { 80/tcp };
    local ports_int: set[port] = { 80/tcp, 81/tcp, 443/tcp };

    if (c$id$resp_h in ignore_host_resp)
        return;
    if (c$id$orig_h in ignore_host_orig)
	    return;

    if (((c$id$resp_h in internal_space) && (c$id$resp_p in ports_int)) || ((c$id$resp_h in public_space) && (c$id$resp_p in ports_ext))) {

            if (c$http?$username && c$http?$status_code) {
                local auth_success : bool = T;
                if (c$http$status_code == 401) {
                    auth_success = F;
                    add c$http$tags[HTTP_AUTH_ERROR];
                }
                else if (c$http$status_code < 400) {
                    auth_success = T;
                    add c$http$tags[HTTP_AUTH_SUCCESS];
                }
                if(!auth_success) {
                    SumStats::observe("http.auth_errors.attacker",
                                      [$host=to_addr(c$http$cluster_client_ip)],
                                      []);
                    if ( c?$conn )
                        SumStats::observe("http.auth_errors.victim",
                                          [$host=c$conn$id$resp_h],
                                          []);
                }
            }
        }
}

