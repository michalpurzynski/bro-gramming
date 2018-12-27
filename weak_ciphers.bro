#! SslWeakCiphers give percentage of SSL weak ciphers used (< 2048 bits key except for ECDHE)
#! Depends on protocols/ssl/client_ciphers.bro
# Original author lost in the battle - either Johanna Amann, Bro/ICSI - johanna@icir.org or Michal Purzynski

@load base/protocols/ssl

module SslWeakCiphers;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp when the log line was finished and written.
        ts:                         time        &log;
        ## Time interval that the log line covers.
        ts_delta:                   interval    &log;
        ## Percentage of weak SSL ciphers used
        percent_weak_ciphers:       double      &log;
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

event bro_init() &priority=3
    {
    Log::create_stream(SslWeakCiphers::LOG, [$columns=Info]);

    local r1: SumStats::Reducer = [$stream="ssl_weak_ciphers.weak_hits",  $apply=set(SumStats::UNIQUE)];
    local r2: SumStats::Reducer = [$stream="ssl_weak_ciphers.ssl_hits",  $apply=set(SumStats::UNIQUE)];
    SumStats::create([$name="ssl_weak_ciphers-metrics",
                      $epoch=break_interval,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local l: Info;
                        l$ts                        = network_time();
                        l$ts_delta                  = break_interval;
			if ("ssl_weak_ciphers.weak_hits" in result && "ssl_weak_ciphers.ssl_hits" in result)
	                        l$percent_weak_ciphers = result["ssl_weak_ciphers.weak_hits"]$num * 100 / result["ssl_weak_ciphers.ssl_hits"]$num;
			else
				l$percent_weak_ciphers = 0;
                        Log::write(LOG, l);
                        }]);
    }

event ssl_established(c: connection)
    {
    # Only look at monitored hosts
    if (addr_matches_host(c$id$resp_h, cert_tracking))
        {
        local strong_key = F;
        c$ssl$weak_cipher = F;
        SumStats::observe("ssl_weak_ciphers.ssl_hits", [], []);
        # If the cipher key used is weak
        if ( !(/256/ in c$ssl$cipher) && !(/ECDHE/ in c$ssl$cipher) )
            {
            # Does the client browser support 256 bytes SSL/TLS cipher key?
            local client_browser_weak = F;
            for(cipher in c$ssl$available_ciphers_client)
                {
                if(/256/ in cipher || /ECDHE/ in cipher)
                    {
                    client_browser_weak = T;
                    break;
                    }
                }
            # If the server does not support strong SSL/TLS cipher but client does
            if (!client_browser_weak)
                {
                SumStats::observe("ssl_weak_ciphers.weak_hits", [], []);
                c$ssl$weak_cipher = T;
                }
            }
        }
    }

