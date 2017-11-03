module RelEngVPC;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts: time &log;
		host: addr &log;
		inbytes: double &log;
		outbytes: double &log;
	};

	global log_rsubnet: event( rec: Info );
}

event bro_init() {

	local r1: SumStats::Reducer = [$stream="inbytes", $apply=set(SumStats::SUM)];
	local r2: SumStats::Reducer = [$stream="outbytes", $apply=set(SumStats::SUM)];

	SumStats::create([
		$name="rsubnet-measurement",
		$epoch=10mins,
		$reducers=set(r1, r2),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
				local out: RelEngVPC::Info;
				out$ts = ts;
				out$inbytes = result["inbytes"]$sum;
				out$outbytes = result["outbytes"]$sum;
				out$host = key$host;
				Log::write(RelEngVPC::LOG, out);
			}
		]);

	Log::create_stream(RelEngVPC::LOG, [$columns=Info, $ev=log_rsubnet]);
	Log::set_buf(RelEngVPC::LOG, F);
}


event connection_state_remove(c: connection) {

const relengvpc1: subnet = 10.132.0.0/16 &redef;
const relengvpc2: subnet = 10.134.0.0/16 &redef;
if ((c$id$resp_h in relengvpc1) || (c$id$resp_h in relengvpc2) || (c$id$orig_h in relengvpc1) || (c$id$orig_h in relengvpc2)) {
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
}

