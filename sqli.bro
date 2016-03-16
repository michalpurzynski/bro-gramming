# Script to detect SQLi attempts
# inspired by detect_sqli for sumstats part
# creates a sqli.log file with all attacks detected for forensics
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

module SQLi;

export {
    # sqli.log
    # Let's tag our items

    redef enum HTTP::Tags += {
        ## SQLi detected with Bro signatures
        SQLI_SIG_BRO,
    };

    type Tags: enum {
        ## SQLi detected with Bro signatures
        SIG_BRO,
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

    global log_sqli: event(rec: Info);

    # Sumstats and alerts in notice
    redef enum Notice::Type += {
        ## Indicates that a host performing SQLi attacks was
        ## detected.
        SQLi_Attacker,
        ## Indicates that a host was seen to have SQLi attacks
        ## against it. This is tracked by IP address as opposed to
        ## hostname.
        SQLi_Victim,
    };

    ## Defines the threshold that determines if a SQLi attack
    ## is ongoing based on the number of requests that appear to be SQLi
    ## attacks.
    const sqli_requests_threshold: double = 2.0 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`SQLi::sqli_requests_threshold` variable to be crossed.
    ## At the end of each interval the counter is reset.
    const sqli_requests_interval = 1min &redef;

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
        [$regex=/.*[\?&][^[:blank:]\x00-\x37\|]+?=[\-[:alnum:]%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+.*?([hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+.*/,
         $name="bro-1"],
        [$regex=/.*[\?&][^[:blank:]\x00-\x37\|]+?=[\-0-9%]+([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]?([[:blank:]\x00-\x37]|\/\*.*?\*\/|\)?;)+([xX]?[oO][rR]|[nN]?[aA][nN][dD])([[:blank:]\x00-\x37]|\/\*.*?\*\/)+['"]?(([^a-zA-Z&]+)?=|[eE][xX][iI][sS][tT][sS]).*/,
         $name="bro-2"],
        [$regex=/.*[\?&][^[:blank:]\x00-\x37]+?=[\-0-9%]*([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/)*(-|=|\+|\|\|)([[:blank:]\x00-\x37]|\/\*.*?\*\/)*([0-9]|\(?[cC][oO][nN][vV][eE][rR][tT]|[cC][aA][sS][tT]).*/,
         $name="bro-3"],
        [$regex=/.*[\?&][^[:blank:]\x00-\x37\|]+?=([[:blank:]\x00-\x37]|\/\*.*?\*\/)*['"]([[:blank:]\x00-\x37]|\/\*.*?\*\/|;)*([xX]?[oO][rR]|[nN]?[aA][nN][dD]|[hH][aA][vV][iI][nN][gG]|[uU][nN][iI][oO][nN]|[eE][xX][eE][cC]|[sS][eE][lL][eE][cC][tT]|[dD][eE][lL][eE][tT][eE]|[dD][rR][oO][pP]|[dD][eE][cC][lL][aA][rR][eE]|[cC][rR][eE][aA][tT][eE]|[rR][eE][gG][eE][xX][pP]|[iI][nN][sS][eE][rR][tT])([[:blank:]\x00-\x37]|\/\*.*?\*\/|[\[(])+[a-zA-Z&]{2,}.*/,
         $name="bro-4"],
        [$regex=/.*[\?&][^[:blank:]\x00-\x37]+?=[^\.]*?([cC][hH][aA][rR]|[aA][sS][cC][iI][iI]|[sS][uU][bB][sS][tT][rR][iI][nN][gG]|[tT][rR][uU][nN][cC][aA][tT][eE]|[vV][eE][rR][sS][iI][oO][nN]|[lL][eE][nN][gG][tT][hH])\(.*/,
         $name="bro-5"],
        [$regex=/.*\/\*![[:digit:]]{5}.*?\*\/.*/,
         $name="bro-6"]
    );
}

function subn_norm(key: SumStats::Key): SumStats::Key {
        return [$str=cat(mask_addr(key$host, 24))];
}

event bro_init() &priority=5
{
    # Create sqli.log
    Log::create_stream(SQLi::LOG, [$columns=Info, $ev=log_sqli]);

    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an actual attack and how to respond when
    # thresholds are crossed.
#    local r1: SumStats::Reducer = [$stream="http.sqli.attacker", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="sqli-attackers",
#                      $epoch=sqli_requests_interval,
#                      $reducers=set(r1),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.sqli.attacker"]$sum;
#                      },
#                      $threshold=sqli_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=SQLi_Attacker,
#                                  $msg=fmt("SQLi attack from attacker subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.sqli.attacker"]$sum, sqli_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.sqli.attacker"]$sum))
#                          ]);
#                      }]);
#    local r2: SumStats::Reducer = [$stream="http.sqli.victim", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="sqli-victims",
#                      $epoch=sqli_requests_interval,
#                      $reducers=set(r2),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.sqli.victim"]$sum;
#                      },
#                      $threshold=sqli_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=SQLi_Victim,
#                                  $msg=fmt("SQLi attack to victim subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.sqli.victim"]$sum, sqli_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.sqli.victim"]$sum))
#                          ]);
#                      }]);
}

# Make sure we have all the http info before looking for SQLi
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

                    add tags[SIG_BRO];
                    add c$http$tags[SQLI_SIG_BRO];

                    local rec: SQLi::Info = [
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

                    Log::write(SQLi::LOG, rec);

#                    SumStats::observe("http.sqli.attacker",
#                                      [$host=to_addr(c$http$cluster_client_ip)],
#                                      []);
#                    SumStats::observe("http.sqli.victim",
#                                      [$host=c$conn$id$resp_h],
#                                      []);
                    break;
                }
            }
        }
    }
}

