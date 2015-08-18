# Script to detect XSS attempts
# inspired by detect_sqli for sumstats part
# creates a xss.log file with all attacks detected for forensics
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
# Anthony Verez netantho@gmail.com

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module XSS;

export {
    # xss.log
    # Let's tag our items

    redef enum HTTP::Tags += {
        ## XSS detected with arcsight signatures
        XSS_SIG_ARCSIGHT,
    };

    type Tags: enum {
        ## XSS detected with arcsight signatures
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

    global log_xss: event(rec: Info);

    # Sumstats and alerts in notice
    redef enum Notice::Type += {
        ## Indicates that a host performing XSS attacks was
        ## detected.
        XSS_Attacker,
        ## Indicates that a host was seen to have XSS attacks
        ## against it.  This is tracked by IP address as opposed to
        ## hostname.
        XSS_Victim,
    };

    ## Defines the threshold that determines if a XSS attack
    ## is ongoing based on the number of requests that appear to be XSS
    ## attacks.
    const xss_requests_threshold: double = 2.0 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`XSS::xss_requests_threshold` variable to be crossed.
    ## At the end of each interval the counter is reset.
    const xss_requests_interval = 1min &redef;

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
        [$regex=/.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]:[aA][lL][eE][rR][tT].*/,
         $name="xss_arcsight-1"],
        [$regex=/.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]:[pP][rR][oO][mM][pP][tT].*/,
         $name="xss_arcsight-2"],
        [$regex=/.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]\.[aA][lL][eE][rR][tT].*/,
         $name="xss_arcsight-3"],
        [$regex=/.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]\.[pP][rR][oO][mM][pP][tT].*/,
         $name="xss_arcsight-4"],
        [$regex=/.*[jJ][aA][vV][aA][sS][cC][rR][iI][pP][tT]:[wW][iI][nN][dD][oO][wW].*/,
         $name="xss_arcsight-5"],
        [$regex=/.*<[sS][cC][rR][iI][pP][tT]>.*/,
         $name="xss_arcsight-6"],
        [$regex=/.*<\/[sS][cC][rR][iI][pP][tT]>.*/,
         $name="xss_arcsight-7"],
        [$regex=/.*<[iI][fF][rR][aA][mM][eE]>.*/,
         $name="xss_arcsight-8"],
        [$regex=/.*<\/[iI][fF][rR][aA][mM][eE]>.*/,
         $name="xss_arcsight-9"],
        [$regex=/.*[oO][nN][mM][oO][uU][sS][eE][oO][vV][eE][rR].*/,
         $name="xss_arcsight-10"],
        [$regex=/.*[vV][bB][sS][cC][rR][iI][pP][tT]>.*/,
         $name="xss_arcsight-11"],
        [$regex=/.*\/[pP][rR][eE][sS][sS][iI][oO][nN]\(.*/,
         $name="xss_arcsight-12"]
    );
}

#function subn_norm(key: SumStats::Key): SumStats::Key {
#        return [$str=cat(mask_addr(key$host, 24))];
#}

event bro_init() &priority=5
{
    # Create xss.log
    Log::create_stream(XSS::LOG, [$columns=Info, $ev=log_xss]);

    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an actual attack and how to respond when
    # thresholds are crossed.
#    local r1: SumStats::Reducer = [$stream="http.xss.attacker", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="xss-attackers",
#                      $epoch=xss_requests_interval,
#                      $reducers=set(r1),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.xss.attacker"]$sum;
#                      },
#                      $threshold=xss_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=XSS_Attacker,
#                                  $msg=fmt("XSS attack from attacker subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.xss.attacker"]$sum, xss_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.xss.attacker"]$sum))
#                          ]);
#                      }]);
#    local r2: SumStats::Reducer = [$stream="http.xss.victim", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
#    SumStats::create([$name="xss-victims",
#                      $epoch=xss_requests_interval,
#                      $reducers=set(r2),
#                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
#                          return result["http.xss.victim"]$sum;
#                      },
#                      $threshold=xss_requests_threshold,
#                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
#                          NOTICE([$note=XSS_Victim,
#                                  $msg=fmt("XSS attack to victim subnet %s", key$str),
#                                  $sub=fmt("%.0f requests in %s", result["http.xss.victim"]$sum, xss_requests_interval),
#                                  $n=to_count(fmt("%.0f", result["http.xss.victim"]$sum))
#                          ]);
#                      }]);
}

# Make sure we have all the http info before looking for XSS
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
                    add c$http$tags[XSS_SIG_ARCSIGHT];

                    local rec: XSS::Info = [
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

                    Log::write(XSS::LOG, rec);

 #                   SumStats::observe("http.xss.attacker",
 #                                     [$host=to_addr(c$http$cluster_client_ip)],
 #                                     []);
 #                   SumStats::observe("http.xss.victim",
 #                                     [$host=c$conn$id$resp_h],
 #                                     []);
                    break;
                }
            }
        }
    }
}

