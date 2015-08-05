# This script calculates the ratio of each ciphersuites proposed by your clients.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/ssl
@load ./counttable

module SSLCiphers;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:             time &log &default=network_time();
		resp_h:         addr &log;
		cipher:         string &log;
		percent:        double &log;
		connections:    count &log;
	};

	## The frequency of logging the stats collected by this script.
	const epoch_interval = 60mins &redef;
}

event bro_init()
	{
	Log::create_stream(LOG, [$columns=Info]);

	local r1: SumStats::Reducer = [$stream="ciphers.conns",  $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="ciphers.ciphers",  $apply=set(SumStats::COUNTTABLE)];

	SumStats::create([$name="ciphers",
			$epoch=epoch_interval,
			$reducers=set(r1,r2),
			$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
				{
				# both of these always have to be in the result set
				if ( "ciphers.conns" !in result )
					return;
				if ( "ciphers.ciphers" !in result )
					return;

				local hits = result["ciphers.conns"]$sum;
				local ciphers = result["ciphers.ciphers"]$counttable;

				for ( cipher in ciphers )
					{
					local line: Info = [$resp_h=key$host, $cipher=cipher, $connections=ciphers[cipher], $percent=(ciphers[cipher]+0.0)/hits];
					Log::write(LOG,line);
					}

				}
			]);
    }

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
	{
	if (!Site::is_local_addr(c$id$resp_h))
		return;

	SumStats::observe("ciphers.conns", [$host=c$id$resp_h], []);

	local cipher_str = SSL::cipher_desc[cipher];
	SumStats::observe("ciphers.ciphers", [$host=c$id$resp_h], [$str=cipher_str]);
}

