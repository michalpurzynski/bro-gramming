# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

event zeek_init()
{
        Log::remove_default_filter(DNS::LOG);
        Log::add_filter(DNS::LOG, [$name = "dns-noise",
                        $path_func(id: Log::ID, path: string, rec: DNS::Info) = {
                                return (rec?$query && /.mozilla.(org|net|com)$|.newrelic.com$|.github.(io|com)$|.allizom.org$|.local$|^localhost_prl$/ in rec$query) ? "dns-noise" : "dns";
                        }]);
}

