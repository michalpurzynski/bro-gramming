# Script to calculate the statistics about the SSL/TLS ciphersuites used in your network.
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/ssl

module SSLCipherStat;

export {
    redef enum Log::ID += { LOG1 };
    redef enum Log::ID += { LOG2 };

    type Info_C: record {
        ## Timestamp when the log line was finished and written.
        ts:		time &log;
        ## Time interval that the log line covers.
        ts_delta:	interval &log;
	resp_h:		addr &log;
	ecdhe_c:	double &log;
	dhe_c:		double &log;
	dh_c:		double &log;
	aes_c:		double &log;
	ecdhe_s:	double &log;
        dhe_s:          double &log;
        dh_s:           double &log;
        aes_s:          double &log;
    };

    type Info_S: record {
        ## Timestamp when the log line was finished and written.
        ts:             time &log;
        ## Time interval that the log line covers.
        ts_delta:       interval &log;
        resp_h:         addr &log;
        ecdhe:        double &log;
        dhe:          double &log;
        dh:           double &log;
        aes:          double &log;
    };

    ## The frequency of logging the stats collected by this script.
    const break_interval = 15mins &redef;

    ## Monitored hosts for weak SSL ciphers
    const cert_tracking = ALL_HOSTS &redef;
}

redef record SSL::Info += {
    ## Ciphers available for the client
    weak_cipher:    bool   &log &optional;
};

event bro_init()
    {
	Log::create_stream(SSLCipherStat::LOG1, [$columns=Info_C]);
	Log::create_stream(SSLCipherStat::LOG2, [$columns=Info_S]);

	local cr1: SumStats::Reducer = [$stream="ssl_cipher_stat.ssl_hits",  $apply=set(SumStats::SUM)];
	local cr2: SumStats::Reducer = [$stream="ssl_cipher_stat.cipher_hits",  $apply=set(SumStats::SUM)];
	local cr3: SumStats::Reducer = [$stream="ssl_cipher_stat.ecdhe_hits",  $apply=set(SumStats::SUM)];
        local cr4: SumStats::Reducer = [$stream="ssl_cipher_stat.dhe_hits",  $apply=set(SumStats::SUM)];
        local cr5: SumStats::Reducer = [$stream="ssl_cipher_stat.dh_hits",  $apply=set(SumStats::SUM)];
        local cr6: SumStats::Reducer = [$stream="ssl_cipher_stat.aes_hits",  $apply=set(SumStats::SUM)];
	local cr7: SumStats::Reducer = [$stream="ssl_cipher_stat.client_dh",  $apply=set(SumStats::SUM)];
	local cr8: SumStats::Reducer = [$stream="ssl_cipher_stat.client_dhe",  $apply=set(SumStats::SUM)];
	local cr9: SumStats::Reducer = [$stream="ssl_cipher_stat.client_ecdhe",  $apply=set(SumStats::SUM)];
	local cr10: SumStats::Reducer = [$stream="ssl_cipher_stat.client_aes",  $apply=set(SumStats::SUM)];

        local sr1: SumStats::Reducer = [$stream="ssl_cipher_negotiated.ssl_hits",  $apply=set(SumStats::SUM)];
	local sr2: SumStats::Reducer = [$stream="ssl_cipher_negotiated.ecdhe_hits",  $apply=set(SumStats::SUM)];
        local sr3: SumStats::Reducer = [$stream="ssl_cipher_negotiated.dhe_hits",  $apply=set(SumStats::SUM)];
        local sr4: SumStats::Reducer = [$stream="ssl_cipher_negotiated.dh_hits",  $apply=set(SumStats::SUM)];
        local sr5: SumStats::Reducer = [$stream="ssl_cipher_negotiated.aes_hits",  $apply=set(SumStats::SUM)];

	SumStats::create([$name="ssl_cipher_stat.ssl_hits",
			$epoch=break_interval,
			$reducers=set(cr1,cr2,cr3,cr4,cr5,cr6,cr7,cr8,cr9,cr10),
			$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
				{
					local l: Info_C;

					l$resp_h = key$host;
					l$ts = network_time();
					l$ts_delta = break_interval;
					if ("ssl_cipher_stat.ecdhe_hits" in result)
						l$ecdhe_c = result["ssl_cipher_stat.ecdhe_hits"]$sum/result["ssl_cipher_stat.cipher_hits"]$sum;
                                        if ("ssl_cipher_stat.dhe_hits" in result)
						l$dhe_c = result["ssl_cipher_stat.dhe_hits"]$sum/result["ssl_cipher_stat.cipher_hits"]$sum;
                                        if ("ssl_cipher_stat.dh_hits" in result)
                                        	l$dh_c = result["ssl_cipher_stat.dh_hits"]$sum/result["ssl_cipher_stat.cipher_hits"]$sum;
                                        if ("ssl_cipher_stat.aes_hits" in result)
                                        	l$aes_c = result["ssl_cipher_stat.aes_hits"]$sum/result["ssl_cipher_stat.cipher_hits"]$sum;
                                        if ("ssl_cipher_stat.ecdhe_hits" in result)
						l$ecdhe_s = result["ssl_cipher_stat.client_ecdhe"]$sum/result["ssl_cipher_stat.ssl_hits"]$sum;
                                        if ("ssl_cipher_stat.dhe_hits" in result)
                                        	l$dhe_s = result["ssl_cipher_stat.client_dhe"]$sum/result["ssl_cipher_stat.ssl_hits"]$sum;
                                        if ("ssl_cipher_stat.dh_hits" in result)
                                        	l$dh_s = result["ssl_cipher_stat.client_dh"]$sum/result["ssl_cipher_stat.ssl_hits"]$sum;
                                        if ("ssl_cipher_stat.aes_hits" in result)
                                        	l$aes_s = result["ssl_cipher_stat.client_aes"]$sum/result["ssl_cipher_stat.ssl_hits"]$sum;

					Log::write(LOG1,l);
				}
			]);

        SumStats::create([$name="ssl_cipher_negotiated.ssl_hits",
                        $epoch=break_interval,
                        $reducers=set(sr1,sr2,sr3,sr4,sr5),
                        $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                                {
                                        local l: Info_S;

                                        l$resp_h = key$host;
                                        l$ts = network_time();
                                        l$ts_delta = break_interval;
                                        if ("ssl_cipher_negotiated.ecdhe_hits" in result)
                                                l$ecdhe = result["ssl_cipher_negotiated.ecdhe_hits"]$sum/result["ssl_cipher_negotiated.ssl_hits"]$sum;
                                        if ("ssl_cipher_negotiated.dhe_hits" in result)
                                                l$dhe = result["ssl_cipher_negotiated.dhe_hits"]$sum/result["ssl_cipher_negotiated.ssl_hits"]$sum;
                                        if ("ssl_cipher_negotiated.dh_hits" in result)
                                                l$dh = result["ssl_cipher_negotiated.dh_hits"]$sum/result["ssl_cipher_negotiated.ssl_hits"]$sum;
                                        if ("ssl_cipher_negotiated.aes_hits" in result) {
                                                l$aes = result["ssl_cipher_negotiated.aes_hits"]$sum/result["ssl_cipher_negotiated.ssl_hits"]$sum;
					}

                                        Log::write(LOG2,l);
                                }
                        ]);

    }

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: index_vec)
{
	if (Site::is_local_addr(c$id$orig_h))
		return;

	local dh_ok = F;
	local dhe_ok = F;
	local ecdhe_ok = F;
	local aes_ok = F;

	SumStats::observe("ssl_cipher_stat.ssl_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));

	for (cipher in ciphers) {
		SumStats::observe("ssl_cipher_stat.cipher_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
		if (/_ECDHE_/ in SSL::cipher_desc[ciphers[cipher]]) {
			SumStats::observe("ssl_cipher_stat.ecdhe_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
			ecdhe_ok = T;
		}
		if (/_DHE_/ in SSL::cipher_desc[ciphers[cipher]]) {
			SumStats::observe("ssl_cipher_stat.dhe_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
			dhe_ok = T;
		}
		if (/_DH_/ in SSL::cipher_desc[ciphers[cipher]]) {
			SumStats::observe("ssl_cipher_stat.dh_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
			dh_ok = T;
		}
		if (/_AES_/ in SSL::cipher_desc[ciphers[cipher]]) {
			SumStats::observe("ssl_cipher_stat.aes_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
			aes_ok = T;
		}
	}

	if (dh_ok = T)
		SumStats::observe("ssl_cipher_stat.client_dh", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (dhe_ok = T)
		SumStats::observe("ssl_cipher_stat.client_dhe", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (ecdhe_ok = T)
		SumStats::observe("ssl_cipher_stat.client_ecdhe", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (aes_ok = T)
		SumStats::observe("ssl_cipher_stat.client_aes", [$host=c$id$resp_h], SumStats::Observation($num=1));

}

event ssl_server_hello(c: connection, version: count, possible_ts: time, server_random: string, session_id: string, cipher: count, comp_method: count)
{
	local dh_ok = F;
        local dhe_ok = F;
        local ecdhe_ok = F;
        local aes_ok = F;

	SumStats::observe("ssl_cipher_negotiated.ssl_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));

	if (/_AES_/ in SSL::cipher_desc[cipher])
		SumStats::observe("ssl_cipher_negotiated.aes_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/_DHE_/ in SSL::cipher_desc[cipher])
		SumStats::observe("ssl_cipher_negotiated.dhe_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/_ECDHE_/ in SSL::cipher_desc[cipher])
		SumStats::observe("ssl_cipher_negotiated.ecdhe_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
	if (/_DH_/ in SSL::cipher_desc[cipher])
		SumStats::observe("ssl_cipher_negotiated.dh_hits", [$host=c$id$resp_h], SumStats::Observation($num=1));
}
