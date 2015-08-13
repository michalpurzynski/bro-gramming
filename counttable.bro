# This script provives a COUNTTABLE type for sumstats. This type is basically like
# SUM, with the difference that you have to provide a $str in the observation, and
# the SUM is calculated independently for each $str.
#
# This makes it optimal to sum up small number of keys per host like, for example,
# all the TLS ciphers you saw in use for hosts on the local host.
#
# Do not try to use this with a big number of different $str values, especially
# in a cluster setup. It will probably lead to excessive resource use.
#
# Questions -> johanna@icir.org

@load base/frameworks/sumstats

module SumStats;

export {
	redef enum Calculation += { COUNTTABLE };

	redef record ResultVal += {
		counttable: table[string] of count &optional;
	};
}

function add_ct_entry(mytable: table[string] of count, str: string, num: count)
	{
	if ( str !in mytable )
		mytable[str] = 0;

	mytable[str] += num;
	}

hook register_observe_plugins()
	{
	register_observe_plugin(COUNTTABLE, function(r: Reducer, val: double, obs: Observation, rv: ResultVal)
		{
		if ( ! obs?$str )
			{
			Reporter::error("COUNTTABLE sumstats plugin needs str in observation");
			return;
			}

		local increment = 1;
		if ( obs?$num )
			increment = obs$num;

		if ( ! rv?$counttable )
			rv$counttable = table();

		add_ct_entry(rv$counttable, obs$str, increment);
		});
	}

hook compose_resultvals_hook(result: ResultVal, rv1: ResultVal, rv2: ResultVal)
	{
	if ( ! (rv1?$counttable || rv2?$counttable ) )
		return;

	if ( !rv1?$counttable )
		{
		result$counttable = copy(rv2$counttable);
		return;
		}

	if ( !rv2?$counttable )
		{
		result$counttable = copy(rv1$counttable);
		return;
		}

	result$counttable = copy(rv1$counttable);

	for ( i in rv2$counttable )
		add_ct_entry(result$counttable, i, rv2$counttable[i]);
	}

