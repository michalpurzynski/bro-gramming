# Script to detect Radius auth bruteforcing
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module MozillaRadiusErrors;

export {
    redef enum Notice::Type += {
        Auth_Bruteforcing_User,
        Auth_Bruteforcing_MAC,
    };

    const auth_errors_threshold: double = 3.0 &redef;
    const auth_errors_interval = 1min &redef;
}

event bro_init()
{
    local r1: SumStats::Reducer = [$stream="radius.auth_errors.user", $apply=set(SumStats::SUM)];
    local r2: SumStats::Reducer = [$stream="radius.auth_errors.mac", $apply=set(SumStats::SUM)];
    SumStats::create([$name="radius-auth-errors-users",
                      $epoch=auth_errors_interval,
                      $reducers=set(r1),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["radius.auth_errors.user"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=Radius_Auth_Bruteforcing_User,
                                  $msg=fmt("Radius auth bruteforcing for user %s", key$str),
                                  $sub=fmt("%.0f auth failed in %s", result["radius.auth_errors.user"]$sum, auth_errors_interval),
                                  $n=to_count(fmt("%.0f", result["radius.auth_errors.user"]$sum))
                          ]);
                      }]);
    SumStats::create([$name="radius-auth-errors-macs",
                      $epoch=auth_errors_interval,
                      $reducers=set(r2),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) = {
                          return result["radius.auth_errors.mac"]$sum;
                      },
                      $threshold=auth_errors_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
                          NOTICE([$note=Radius_Auth_Bruteforcing_MAC,
                                  $msg=fmt("Radius auth bruteforcing for MAC %s", key$str),
                                  $sub=fmt("%.0f auth failed in %s", result["radius.auth_errors.mac"]$sum, auth_errors_interval),
                                  $n=to_count(fmt("%.0f", result["radius.auth_errors.mac"]$sum))
                          ]);
                      }]);
}

event RADIUS::log_radius(rec: RADIUS::Info)
{
    if ( rec$result != "success" ) {
        if ( |rec$username| > 1 )
            SumStats::observe("radius.auth_errors.user",
                            [$str=rec$username],
                            SumStats::Observation($num=1));
        if ( |rec$connect_info| > 1 )
            SumStats::observe("radius.auth_errors.mac",
                            [$str=rec$connect_info],
                            SumStats::Observation($num=1));
    }
}

