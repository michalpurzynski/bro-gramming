# Script to detect Unix command injection attempts
# inspired by detect_sqli for sumstats part
# creates a unix_command.log file with all attacks detected for forensics
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

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module UnixCommand;

export {
    # unix_command.log
    # Let's tag our items

    redef enum HTTP::Tags += {
        ## Unix command detected with arcsight signatures
        UNIX_COMMAND_SIG_ARCSIGHT,
    };

    type Tags: enum {
        ## Unix command detected with arcsight signatures
        SIG_ARCSIGHT,
    } &redef;

    redef enum Log::ID += { LOG };

    type Info: record {
        ts:                time        &log;
        uid:               string      &log;
        id:                conn_id     &log;
        cluster_client_ip: string      &log &optional;
        status_code:       count       &log &optional;
        host:              string      &log &optional;
        uri:               string      &log &optional;
        sig_id:            string      &log &optional;
        tags:              set[Tags]   &log &optional;
    };

    global log_unix: event(rec: Info);

    # Sumstats and alerts in notice
    redef enum Notice::Type += {
        ## Indicates that a host performing Unix Command injection
        ## attacks was detected.
        UnixCommand_Attacker,
        ## Indicates that a host was seen to have Unix Command injection
        ## attacks against it.  This is tracked by IP address as opposed to
        ## hostname.
        UnixCommand_Victim,
    };

    ## Defines the threshold that determines if a unix command injection
    ## attack is ongoing based on the number of requests that appear to be
    ## unix command injection attacks.
    const unix_requests_threshold: double = 2.0 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`UnixCommand::unix_requests_threshold` variable to be crossed.
    ## At the end of each interval the counter is reset.
    const unix_requests_interval = 1min &redef;

    const mozilla_internal_space: subnet = 10.0.0.0/8 &redef;
    const mozilla_public_space: subnet = 63.245.208.0/20 &redef;
    # From https://github.com/mozilla/nmap-differential-scan/blob/master/targets.txt
    const mozilla_pek1_office_space: subnet = 223.202.6.1/27 &redef;

    const ignore_host_resp: set[addr] = { } &redef;
    const ignore_host_orig: set[addr] = { } &redef;

    type Sig: record {
         regex: pattern;
         name: string;
    };

    type SigVec: vector of Sig;

    # Please add signatures at the END of this list and to preserve rule ids
    # (?i:javascriptt) for case-insensitive is not working atm, so we need to do it old school :S
    # see https://bro-tracker.atlassian.net/browse/BIT-26
    global sigs = SigVec(
        [$regex=/.*\.\.\/\.\.\/.*/,
         $name="unix_arcsight-1"],
        [$regex=/.*\/etc\/shadow.*/,
         $name="unix_arcsight-2"],
        [$regex=/.*\/etc\/passwd.*/,
         $name="unix_arcsight-3"]
    );
}

#function subn_norm(key: SumStats::Key): SumStats::Key {
#        return [$str=cat(mask_addr(key$host, 24))];
#}

event bro_init() &priority=5
{
    # Create unix_command.log
    Log::create_stream(UnixCommand::LOG, [$columns=Info, $ev=log_unix]);

    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an actual attack and how to respond when
    # thresholds are crossed.
#    local r1: SumStats::Reducer = [$stream="http.unix.attacker", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="unix-attackers",
#                      $epoch=unix_requests_interval,
#                      $reducers=set(r1),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.unix.attacker"]$sum;
#                      },
#                      $threshold=unix_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=UnixCommand_Attacker,
#                                  $msg=fmt("Unix command attack from attack subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.unix.attacker"]$sum, unix_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.unix.attacker"]$sum))
#                          ]);
#                      }]);
#    local r2: SumStats::Reducer = [$stream="http.unix.victim", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="unix-victims",
#                      $epoch=unix_requests_interval,
#                      $reducers=set(r2),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.unix.victim"]$sum;
#                      },
#                      $threshold=unix_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=UnixCommand_Victim,
#                                  $msg=fmt("Unix command attack to victim subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.unix.victim"]$sum, unix_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.unix.victim"]$sum))
#                          ]);
#                      }]);
}

# Make sure we have all the http info before looking for unix commands
event http_message_done(c: connection, is_orig: bool, stat: http_message_stat)
{
    # only conns we want
    local ports_ext: set[port] = { 80/tcp };
    local ports_int: set[port] = { 80/tcp, 81/tcp, 443/tcp };

    if (((c$id$resp_h in mozilla_internal_space) && (c$id$resp_p in ports_int)) || ((c$id$resp_h in mozilla_public_space) && (c$id$resp_p in ports_ext)) && (c$id$resp_h !in ignore_host_resp) && (c$id$orig_h !in ignore_host_orig)) {
        if (c$http?$cluster_client_ip && to_addr(c$http$cluster_client_ip) !in mozilla_pek1_office_space) {
            for(tid in sigs) {
                if(sigs[tid]$regex in c$http$uri) {
                    local tags: set[Tags];

                    add tags[SIG_ARCSIGHT];
                    add c$http$tags[UNIX_COMMAND_SIG_ARCSIGHT];

                    local rec: UnixCommand::Info = [
                        $ts=network_time(),
                        $uid=c$uid,
                        $id=c$id,
                        $cluster_client_ip=c$http$cluster_client_ip,
                        $status_code=c$http$status_code,
                        $host=c$http$host,
                        $uri=c$http$uri,
                        $sig_id=sigs[tid]$name,
                        $tags=tags
                    ];

                    Log::write(UnixCommand::LOG, rec);

#                    SumStats::observe("http.unix.attacker",
#                                      [$host=to_addr(c$http$cluster_client_ip)],
#                                      []);
#                    SumStats::observe("http.unix.victim",
#                                      [$host=c$conn$id$resp_h],
#                                      []);
                    break;
                }
            }
        }
    }
}

