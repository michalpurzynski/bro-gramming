# Script to detect excessive HTTP error ratios from the same source IP or to
# the same internal web server
# Inspired by policy/protocols/http/detect-sqli.bro
#
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
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
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.

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

    ## Defines the minimum number of hits from a client IP address
    ## to generate an alert
    const excessive_http_errors_attacker_hits_min: count = 2 &redef;

    ## Defines the minimum number of hits to an internal web server
    ## to generate an alert
    const excessive_http_errors_victim_hits_min: count = 2 &redef;

    ## Defines the threshold that determines the percentage limit
    ## of bad http replies / good http replies for which we want
    ## alerts
    const excessive_http_errors_per_threshold: double = 0.3 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`HTTP::excessive_http_errors_threshold` variable to be
    ## crossed. At the end of each interval the counter is reset.
    const excessive_http_errors_interval = 1min &redef;

    ## Collecting samples will add extra data to the alert
    ## by collecting some sample error paths and error codes. 
    ## Disable sample collection by setting this value to 0.
    const collect_http_error_samples = 2 &redef;

    const mozilla_internal_space = 10.0.0.0/8 &redef;
    const mozilla_public_space = 63.245.208.0/20 &redef;
}


function format_http_error_samples(samples: vector of SumStats::Observation): string
{
    local ret = "Samples: ";
    for ( i in samples )
        ret += samples[i]$str + ", ";
    return ret;
}

event bro_init() &priority=3
{
    # Add filters to the metrics so that the metrics framework knows how to
    # determine when it looks like an actual attack and how to respond when
    # thresholds are crossed.

    # HTTP errors for requests FROM the same host
    local r1g: SumStats::Reducer = [$stream="http.excessive_errors.attacker_goodhits", $apply=set(SumStats::SUM)];
    local r1b: SumStats::Reducer = [$stream="http.excessive_errors.attacker_badhits", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_http_error_samples];
    SumStats::create([$name="excessive-http-errors-attackers",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r1g, r1b),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local goodhits = result["http.excessive_errors.attacker_goodhits"]$sum;
                          local badhits = result["http.excessive_errors.attacker_badhits"]$sum;
                          # The threshold is the ratio if we have enough hits
                          if (goodhits == 0) {
                              return 0.;
                          }
                          if (goodhits + badhits < excessive_http_errors_attacker_hits_min) {
                              return 0.;
                          }
                          return badhits / goodhits;
                      },
                      $threshold=excessive_http_errors_per_threshold,
                      # Action when the threshold is crossed
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local r_badhits = result["http.excessive_errors.attacker_badhits"];
                          local percentage = result["http.excessive_errors.attacker_badhits"]$sum / result["http.excessive_errors.attacker_goodhits"]$sum;
                          NOTICE([$note=Excessive_HTTP_Errors_Attacker,
                                  $msg=fmt("%f HTTP errors for requests from %s", percentage, key$host),
                                  # Uniformely distributed samples on unique (code + host + uri) set that gave HTTP errors
                                  $sub=format_http_error_samples(r_badhits$samples),
                                  $src=key$host
                                 ]);
                      }]);

    # HTTP errors for requests TO the same host
    local r2g: SumStats::Reducer = [$stream="http.excessive_errors.victim_goodhits", $apply=set(SumStats::SUM)];
    local r2b: SumStats::Reducer = [$stream="http.excessive_errors.victim_badhits", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_http_error_samples];
    SumStats::create([$name="excessive-http-errors-victims",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r2g, r2b),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local goodhits = result["http.excessive_errors.victim_goodhits"]$sum;
                          local badhits = result["http.excessive_errors.victim_badhits"]$sum;
                          # The threshold is the ratio if we have enough hits
                          if (goodhits == 0) {
                              return 0.;
                          }
                          if (goodhits + badhits < excessive_http_errors_victim_hits_min) {
                              return 0.;
                          }
                          return badhits / goodhits;
                      },
                      $threshold=excessive_http_errors_per_threshold,
                      # Action when the threshold is crossed
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local r_badhits = result["http.excessive_errors.attacker_badhits"];
                          local percentage = result["http.excessive_errors.victim_badhits"]$sum / result["http.excessive_errors.attacker_goodhits"]$sum;
                          NOTICE([$note=Excessive_HTTP_Errors_Attacker,
                                  $msg=fmt("%f HTTP errors for requests to %s", percentage, key$host),
                                  # Uniformely distributed samples on unique (code + host + uri) set that gave HTTP errors
                                  $sub=format_http_error_samples(r_badhits$samples),
                                  $src=key$host
                                 ]);
                      }]);
}

event http_reply(c: connection, version: string, code: count,
                 reason: string) &priority=3
{
    # only conns we want
    local ports_ext: set[port] = { 80 };
    local ports_int: set[port] = { 80, 81, 443 };
    if ((c$id$resp_h in mozilla_public_space && c$id$resp_p in ports_ext)
        || (c$id$resp_h in mozilla_internal_space && c$id$resp_p in ports_int)) { 
        if (code >= 400) {
            add c$http$tags[HTTP_ERROR];

            SumStats::observe("http.excessive_errors.attacker_badhits", [$host=c$id$orig_h],
                              [$str=fmt("%d %s%s", code, c$http$host, c$http$uri)]);
            SumStats::observe("http.excessive_errors.victim_badhits",   [$host=c$id$resp_h],
                              [$str=fmt("%d %s%s", code, c$http$host, c$http$uri)]);
        }
        else if (code < 400) {
            SumStats::observe("http.excessive_errors.attacker_goodhits", [$host=c$id$orig_h], []);
            SumStats::observe("http.excessive_errors.victim_goodhits",   [$host=c$id$resp_h], []);
        }
    }
}

