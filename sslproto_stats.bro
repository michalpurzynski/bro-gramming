# A script to periodically log a summary of SSL/TLS version used by the servers in your network.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/ssl

module SSLProtoStat;

export {
    redef enum Log::ID += { LOG1 };
    redef enum Log::ID += { LOG2 };

    type Info_C: record {
        ## Timestamp when the log line was finished and written.
        ts:		time &log;
        ## Time interval that the log line covers.
        ts_delta:	interval &log;
	resp_h:		addr &log;
	tls12:		double &log;
	tls11:		double &log;
	tls10:		double &log;
	ssl3:		double &log;
	ssl2:		double &log;
    };

    type Info_S: record {
        ## Timestamp when the log line was finished and written.
        ts:             time &log;
        ## Time interval that the log line covers.
        ts_delta:       interval &log;
        resp_h:         addr &log;
        tls12:          double &log;
        tls11:          double &log;
        tls10:          double &log;
        ssl3:           double &log;
        ssl2:           double &log;
    };

    ## The frequency of logging the stats collected by this script.
    const break_interval = 15mins &redef;

    ## Monitored hosts for weak SSL ciphers
    const cert_tracking = ALL_HOSTS &redef;
}

event bro_init()
    {
	Log::create_stream(SSLProtoStat::LOG1, [$columns=Info_C]);
	Log::create_stream(SSLProtoStat::LOG2, [$columns=Info_S]);

	local cr1: SumStats::Reducer = [$stream="ssl_proto_stat.ssl_hits",  $apply=set(SumStats::SUM)];
	local cr2: SumStats::Reducer = [$stream="ssl_proto_stat.tls12_hits",  $apply=set(SumStats::SUM)];
	local cr3: SumStats::Reducer = [$stream="ssl_proto_stat.tls11_hits",  $apply=set(SumStats::SUM)];
        local cr4: SumStats::Reducer = [$stream="ssl_proto_stat.tls10_hits",  $apply=set(SumStats::SUM)];
        local cr5: SumStats::Reducer = [$stream="ssl_proto_stat.ssl3_hits",  $apply=set(SumStats::SUM)];
        local cr6: SumStats::Reducer = [$stream="ssl_proto_stat.ssl2_hits",  $apply=set(SumStats::SUM)];

        local sr1: SumStats::Reducer = [$stream="ssl_proto_negotiated.ssl_hits",  $apply=set(SumStats::SUM)];
	local sr2: SumStats::Reducer = [$stream="ssl_proto_negotiated.tls12_hits",  $apply=set(SumStats::SUM)];
        local sr3: SumStats::Reducer = [$stream="ssl_proto_negotiated.tls11_hits",  $apply=set(SumStats::SUM)];
        local sr4: SumStats::Reducer = [$stream="ssl_proto_negotiated.tls10_hits",  $apply=set(SumStats::SUM)];
        local sr5: SumStats::Reducer = [$stream="ssl_proto_negotiated.ssl3_hits",  $apply=set(SumStats::SUM)];
        local sr6: SumStats::Reducer = [$stream="ssl_proto_negotiated.ssl2_hits",  $apply=set(SumStats::SUM)];

	SumStats::create([$name="ssl_proto_stat.ssl_hits",
			$epoch=break_interval,
			$reducers=set(cr1,cr2,cr3,cr4,cr5,cr6),
			$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
				{
					local l: Info_C;

					l$resp_h = key$host;
					l$ts = network_time();
					l$ts_delta = break_interval;
					if ("ssl_proto_stat.tls12_hits" in result)
						l$tls12 = result["ssl_proto_stat.tls12_hits"]$sum/result["ssl_proto_stat.ssl_hits"]$sum;
                                        if ("ssl_proto_stat.tls11_hits" in result)
						l$tls11 = result["ssl_proto_stat.tls11_hits"]$sum/result["ssl_proto_stat.ssl_hits"]$sum;
                                        if ("ssl_proto_stat.tls10_hits" in result)
                                        	l$tls10 = result["ssl_proto_stat.tls10_hits"]$sum/result["ssl_proto_stat.ssl_hits"]$sum;
                                        if ("ssl_proto_stat.ssl3_hits" in result)
                                        	l$ssl3 = result["ssl_proto_stat.ssl3_hits"]$sum/result["ssl_proto_stat.ssl_hits"]$sum;
                                        if ("ssl_proto_stat.ssl2_hits" in result)
						l$ssl2 = result["ssl_proto_stat.ssl2_hits"]$sum/result["ssl_proto_stat.ssl_hits"]$sum;

					Log::write(LOG1,l);
				}
			]);

        SumStats::create([$name="ssl_proto_negotiated.ssl_hits",
                        $epoch=break_interval,
                        $reducers=set(sr1,sr2,sr3,sr4,sr5,sr6),
                        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                        local l: Info_S;

                                        l$resp_h = key$host;
                                        l$ts = network_time();
                                        l$ts_delta = break_interval;
                                        if ("ssl_proto_negotiated.tls12_hits" in result)
                                                l$tls12 = result["ssl_proto_negotiated.tls12_hits"]$sum/result["ssl_proto_negotiated.ssl_hits"]$sum;
                                        if ("ssl_proto_negotiated.tls11_hits" in result)
                                                l$tls11 = result["ssl_proto_negotiated.tls11_hits"]$sum/result["ssl_proto_negotiated.ssl_hits"]$sum;
                                        if ("ssl_proto_negotiated.tls10_hits" in result)
                                                l$tls10 = result["ssl_proto_negotiated.tls10_hits"]$sum/result["ssl_proto_negotiated.ssl_hits"]$sum;
                                        if ("ssl_proto_negotiated.ssl3_hits" in result)
                                                l$ssl3 = result["ssl_proto_negotiated.ssl3_hits"]$sum/result["ssl_proto_negotiated.ssl_hits"]$sum;
                                        if ("ssl_proto_negotiated.ssl2_hits" in result) 
                                                l$ssl2 = result["ssl_proto_negotiated.ssl2_hits"]$sum/result["ssl_proto_negotiated.ssl_hits"]$sum;

                                        Log::write(LOG2,l);
                                }
                        ]);

    }

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
{
	if (Site::is_local_addr(c$id$orig_h))
		return;

	SumStats::observe("ssl_proto_stat.ssl_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));

		if (/TLSv12/ in SSL::version_strings[version])
			SumStats::observe("ssl_proto_stat.tls12_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
		if (/TLSv11/ in SSL::version_strings[version])
			SumStats::observe("ssl_proto_stat.tls11_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
		if (/TLSv10/ in SSL::version_strings[version])
			SumStats::observe("ssl_proto_stat.tls10_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
		if (/SSLv3/ in SSL::version_strings[version])
			SumStats::observe("ssl_proto_stat.sslv3_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
                if (/SSLv2/ in SSL::version_strings[version])
                        SumStats::observe("ssl_proto_stat.sslv2_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
{
	SumStats::observe("ssl_proto_negotiated.ssl_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));

	if (/TLSv12/ in SSL::version_strings[version])
		SumStats::observe("ssl_proto_negotiated.tls12_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/TLSv11/ in SSL::version_strings[version])
		SumStats::observe("ssl_proto_negotiated.tls11_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/TLSv10/ in SSL::version_strings[version])
		SumStats::observe("ssl_proto_negotiated.tls10_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/SSLv3/ in SSL::version_strings[version])
		SumStats::observe("ssl_proto_negotiated.ssl3_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
        if (/SSLv2/ in SSL::version_strings[version])
                SumStats::observe("ssl_proto_negotiated.ssl2_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
}
