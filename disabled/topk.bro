module Topk;

export {
	redef enum Log::ID += { LOG, LOG10 };

	type Info: record {
		ts: time &log;
		iv: interval &log;
		sources: vector of string &log;
		sources_counts: vector of count &log;
		sources_epsilons: vector of count &log;
		sources_num: count &log;
	};

	global log_topk: event( rec: Info );
}

global topk_howmuch = 10;
global topk_size = 1000;


event bro_init() {

	local r1_conn_source: SumStats::Reducer = [$stream="conn_source", $apply=set(SumStats::TOPK), $topk_size=topk_size];

	SumStats::create([
		$name="topk-measure-hour",
		$epoch=5mins,
		$reducers=set(r1_conn_source),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
			local out: Topk::Info;
			out$ts = ts;
			out$iv= 5 mins;
			print key;
			print result;

			if ( "conn_source" in result ) {
				local top_sources_strs: vector of SumStats::Observation;
				top_sources_strs = topk_get_top(result["conn_source"]$topk, topk_howmuch);
				for ( str in top_sources_strs ) {
					out$sources[|out$sources|] = top_sources_strs[str]$str;
					out$sources_counts[|out$sources_counts|] = topk_count(result["conn_source"]$topk, top_sources_strs[str]);
					out$sources_epsilons[|out$sources_epsilons|] = topk_epsilon(result["conn_source"]$topk, top_sources_strs[str]);
				}
				out$sources_num = topk_sum(result["conn_source"]$topk);
			}

			Log::write(Topk::LOG, out);
		}]);
	
	Log::create_stream(Topk::LOG, [$columns=Info, $ev=log_topk]);
	#Log::set_buf(Topk::LOG, F);
}

event connection_state_remove(c: connection) {
	#if ( Site::is_private_addr(c$id$resp_h) || Site::is_local_addr(c$id$resp_h) ) {
	#	return;
	#}

	if ( c$conn$proto == tcp && c$conn$conn_state == "SF" ) {
		SumStats::observe("conn_source", [$str="nocat"], [$str=cat(c$id$orig_h)]);
	}
}

