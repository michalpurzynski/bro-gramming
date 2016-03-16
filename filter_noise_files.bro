# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

event bro_init()
{
        Log::remove_default_filter(Files::LOG);
        Log::add_filter(Files::LOG, [$name = "files-noise",
                                    $pred(rec: Files::Info) = {
					local result = T;
					for (tx_host in rec$tx_hosts) {
						if (Site::is_local_addr(tx_host) == T) {
                            if ((rec?$mime_type) && (/^application\/pkix-cert$/ in rec$mime_type))
                                result = F;
                        }
                        else
                            result = T;
					}
                    return result;
                                    }
                        ]);
}

