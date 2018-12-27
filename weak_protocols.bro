#! SslWeakProtocols give percentage of SSL weak protocols used (<= SSL2)
# Original author lost in the battle - either Johanna Amann, Bro/ICSI - johanna@icir.org or Michal Purzynski

@load base/protocols/ssl
@load base/frameworks/sumstats

module SslWeakProtocols;

export {
    redef enum Log::ID += { LOG };

    type Info: record {
        ## Timestamp when the log line was finished and written.
        ts:                         time        &log;
        ## Time interval that the log line covers.
        ts_delta:                   interval    &log;
        ## Percentage of weak SSL protocols used
        percent_weak_protocols:     double      &log;
    };

    ## The frequency of logging the stats collected by this script.
    const break_interval = 15mins &redef;

    ## Monitored hosts for weak SSL protocols
    const cert_tracking = ALL_HOSTS &redef;
}

event bro_init() &priority=3
    {
    Log::create_stream(SslWeakProtocols::LOG, [$columns=Info]);

    local r1: SumStats::Reducer = [$stream="ssl_weak_protocols.weak_hits",  $apply=set(SumStats::UNIQUE)];
    local r2: SumStats::Reducer = [$stream="ssl_weak_protocols.ssl_hits",  $apply=set(SumStats::UNIQUE)];
    SumStats::create([$name="ssl_weak_protocols-metrics",
                      $epoch=break_interval,
                      $reducers=set(r1,r2),
                      $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) =
                        {
                        local l: Info;
                        l$ts                        = network_time();
                        l$ts_delta                  = break_interval;
			if ("ssl_weak_protocols.ssl_hits" in result && "ssl_weak_protocols.weak_hits" in result)
	                        l$percent_weak_protocols = result["ssl_weak_protocols.weak_hits"]$num * 100 / result["ssl_weak_protocols.ssl_hits"]$num;
			else
				l$percent_weak_protocols = 0;
                        Log::write(LOG, l);
                        }]);
    }

event ssl_established(c: connection)
    {
    # Only look at monitored hosts
    if (addr_matches_host(c$id$resp_h, cert_tracking))
        {
        SumStats::observe("ssl_weak_protocols.ssl_hits", [], []);
        # If the protocol used is weak
        if ( /SSLv2/ in c$ssl$version )
            {
            SumStats::observe("ssl_weak_protocols.weak_hits", [], []);
            }
        }
    }

