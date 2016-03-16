# For MYSQL log only connections form outside to internal network and from internal network to outside.
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
        Log::remove_default_filter(mysql::LOG);
        Log::add_filter(mysql::LOG, [$name = "mysql-noise", 
                                    $pred(rec: MySQL::Info) = {
                        if ((Site::is_local_addr(rec$id$orig_h) == F) || (Site::is_local_addr(rec$id$resp_h)) == F)
                            return T;
                        else
                            return F;
                        }]);
}
