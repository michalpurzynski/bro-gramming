# Log
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

module RelengVpc;

export {
	redef enum Log::ID += { LOG1, LOG2 };

	type Info: record {
		ts: time &log;
		host: string &log;
		inbytes: double &log;
		outbytes: double &log;
	};

	global log_rsubnet: event( rec: Info );
}

event bro_init() {

	local r11: SumStats::Reducer = [$stream="inbytes1", $apply=set(SumStats::SUM)];
	local r21: SumStats::Reducer = [$stream="outbytes1", $apply=set(SumStats::SUM)];

	SumStats::create([
		$name="rsubnet-measurement",
		$epoch=10mins,
		$reducers=set(r11, r21),
		$epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
				local out1: RelengVpc::Info;
				out1$ts = ts;
				out1$inbytes = result["inbytes1"]$sum;
				out1$outbytes = result["outbytes1"]$sum;
				out1$host = key$str;
				Log::write(RelengVpc::LOG1, out1);
			}
		]);

	Log::create_stream(RelengVpc::LOG1, [$columns=Info, $ev=log_rsubnet]);
	Log::set_buf(RelengVpc::LOG1, F);

        local r12: SumStats::Reducer = [$stream="inbytes2", $apply=set(SumStats::SUM)];
        local r22: SumStats::Reducer = [$stream="outbytes2", $apply=set(SumStats::SUM)];

        SumStats::create([
                $name="rsubnet-measurement2",
                $epoch=10mins,
                $reducers=set(r12, r22),
                $epoch_result(ts: time, key: SumStats::Key, result: SumStats::Result) = {
                                local out2: RelengVpc::Info;
                                out2$ts = ts;
                                out2$inbytes = result["inbytes2"]$sum;
                                out2$outbytes = result["outbytes2"]$sum;
                                out2$host = key$str;
                                Log::write(RelengVpc::LOG2, out2);
                        }
                ]);

        Log::create_stream(RelengVpc::LOG2, [$columns=Info, $ev=log_rsubnet]);
        Log::set_buf(RelengVpc::LOG2, F);

}


event connection_state_remove(c: connection) {

const relengvpc1: subnet = 10.132.0.0/16 &redef;
const relengvpc2: subnet = 10.134.0.0/16 &redef;

if ((c$id$resp_h in relengvpc1) || (c$id$resp_h in relengvpc2) || (c$id$orig_h in relengvpc1) || (c$id$orig_h in relengvpc2)) {
	if ( c$conn$proto == tcp && c$conn$conn_state == "SF" ) {
			local key1: string;
			key1 = fmt("%s-%s", c$id$resp_h,c$id$resp_p);
			SumStats::observe("inbytes1", [$str=key1], [$num=c$conn$orig_bytes]);
			SumStats::observe("outbytes1", [$str=key1], [$num=c$conn$resp_bytes]);
			local key2: string;
                        key2 = fmt("%s-%s-%s", c$id$orig_h,c$id$resp_h,c$id$resp_p);
                        SumStats::observe("inbytes2", [$str=key2], [$num=c$conn$orig_bytes]);
                        SumStats::observe("outbytes2", [$str=key2], [$num=c$conn$resp_bytes]);
	}
}
}

