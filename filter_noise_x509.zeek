# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Johanna Amann, Bro/ICSI - johanna@icir.org
# Michal Purzynski mpurzynski@mozilla.com
#

module LogFilter;

redef record X509::Info += {
	local_cert: bool &default=F;
};

event file_state_remove(f: fa_file) &priority=6
	{
	if ( ! f$info?$x509 )
		return;

	for ( i in f$info$tx_hosts )
		{
		if ( Site::is_local_addr(i) )
			f$info$x509$local_cert = T;
		}
	}

function no_local_certs(rec: X509::Info): bool
  {
  return ! rec$local_cert;
  }

event zeek_init () &priority=-5
	{
	local f = Log::get_filter(X509::LOG, "default");
	Log::remove_filter(X509::LOG, "default");
	f$pred=no_local_certs;
	Log::add_filter(X509::LOG, f);
	}

#event zeek_init()
#{
#        Log::remove_default_filter(X509::LOG);
#        Log::add_filter(X509::LOG, [$name = "X509-noise",
#                                    $pred(rec: X509::Info) = {
#                                        if ((rec$certificate?$cn) && (/mozilla\.(com|org|net)$/ in rec$certificate$cn))
#                        return F;
#                                    }
#                        ]);
#}
