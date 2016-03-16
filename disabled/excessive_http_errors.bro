# Script to detect excessive HTTP errors from the same source IP
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

    ## Defines the threshold that determines if someone is generating
    ## too many HTTP errors
    const excessive_http_errors_threshold: double = 3.0 &redef;

    ## Interval at which to watch for the
    ## :bro:id:`HTTP::excessive_http_errors_threshold` variable to be
    ## crossed. At the end of each interval the counter is reset.
    const excessive_http_errors_interval = 1min &redef;

    ## Collecting samples will add extra data to the alert
    ## by collecting some sample error paths and error codes. 
    ## Disable sample collection by setting this value to 0.
    const collect_http_error_samples = 2 &redef;

    ## Mozilla public IP space
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
    local r1: SumStats::Reducer = [$stream="http.excessive_errors.attacker", $apply=set(SumStats::SUM, SumStats::UNIQUE, SumStats::SAMPLE), $num_samples=collect_http_error_samples];
    SumStats::create([$name="excessive-http-errors-attackers",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          # The threshold is the number of occurrences
                          return result["http.excessive_errors.attacker"]$sum;
                      },
                      $threshold=excessive_http_errors_threshold,
                      # Action when the threshold is crossed
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local r = result["http.excessive_errors.attacker"];
                          NOTICE([$note=Excessive_HTTP_Errors_Attacker,
                                  $msg=fmt("Excessive HTTP errors for requests from %s", key$host),
                                  # Uniformely distributed samples on unique (code + host + uri) set that gave HTTP errors
                                  $sub=format_http_error_samples(r$samples),
                                  $src=key$host
                                 ]);
                      }]);

    # HTTP errors for requests TO the same host
    local r2: SumStats::Reducer = [$stream="http.excessive_errors.victim", $apply=set(SumStats::SUM, SumStats::SAMPLE), $num_samples=collect_http_error_samples];
    SumStats::create([$name="excessive-http-errors-victims",
                      $epoch=excessive_http_errors_interval,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                      {
                          # The threshold is the number of occurrences
                          return result["http.excessive_errors.victim"]$sum;
                      },
                      $threshold=excessive_http_errors_threshold,
                      # Action when the threshold is crossed
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                      {
                          local r = result["http.excessive_errors.victim"];
                          NOTICE([$note=Excessive_HTTP_Errors_Victim,
                                  $msg=fmt("Excessive HTTP errors for request to %s", key$host),
                                  $sub=format_http_error_samples(r$samples),
                                  $src=key$host
                                 ]);
                      }]);
}

event http_reply(c: connection, version: string, code: count,
                 reason: string) &priority=3
{
    if (code >= 400 && Site::is_local_addr(c$id$resp_h)) {
        add c$http$tags[HTTP_ERROR];

        SumStats::observe("http.excessive_errors.attacker", [$host=c$id$orig_h],
                          [$str=fmt("%d %s%s", code, c$http$host, c$http$uri)]);
        SumStats::observe("http.excessive_errors.victim",   [$host=c$id$resp_h],
                          [$str=fmt("%d %s%s", code, c$http$host, c$http$uri)]);
    }
}

