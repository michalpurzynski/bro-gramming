# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Redirect intel hits from the usual noise generators like DNS caching servers to a separate log file.

module Intel;

export {
    const ignore_intel_src: set[addr] &redef;
}

event bro_init()
{
        Log::remove_default_filter(Intel::LOG);
        Log::add_filter(Intel::LOG, [$name = "intel-noise",
                        $path_func(id: Log::ID, path: string, rec: Intel::Info) = {
                                return (rec?$id && rec$id?$orig_h && rec$id$orig_h in ignore_intel_src) ? "intel-noise" : "intel";
                        }]);
}

