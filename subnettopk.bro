module Subnet;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		net: string &log;
		inbytes: double &log;
		outbytes: double &log;
	};

	global log_subnet: event( rec: Info );
}

function subn_norm(key: SumStats::Key): SumStats::Key {
	return [$str=cat(mask_addr(key$host, 24))];
}

event bro_init() {

	local r1: SumStats::Reducer = [$stream="inbytes", $apply=set(SumStats::SUM), $normalize_key=subn_norm];
	local r2: SumStats::Reducer = [$stream="outbytes", $apply=set(SumStats::SUM), $normalize_key=subn_norm];

	SumStats::create([
		$name="subnet-measurement",
		$epoch=60mins,
		$reducers=set(r1, r2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
				local out: Subnet::Info;
				out$ts = ts;
				out$inbytes = result["inbytes"]$sum;
				out$outbytes = result["outbytes"]$sum;
				out$net = key$str;
				Log::write(Subnet::LOG, out);
			}
		]);

	Log::create_stream(Subnet::LOG, [$columns=Info, $ev=log_subnet]);
	Log::set_buf(Subnet::LOG, F);
}


event connection_state_remove(c: connection) {
	if ( c$conn$proto == tcp && c$conn$conn_state == "SF" ) {
		if ( Site::is_local_addr(c$id$resp_h) ) {
			SumStats::observe("outbytes", [$host=c$id$resp_h], [$num=c$conn$orig_bytes]);
			SumStats::observe("inbytes", [$host=c$id$resp_h], [$num=c$conn$resp_bytes]);
		} else if ( Site::is_local_addr(c$id$orig_h) ) {
			SumStats::observe("outbytes", [$host=c$id$orig_h], [$num=c$conn$orig_bytes]);
			SumStats::observe("inbytes", [$host=c$id$orig_h], [$num=c$conn$resp_bytes]);
		}
	}
}

