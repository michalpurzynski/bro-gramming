##! When we get an intel hit for a DNS query, store the IP answer(s) and 
##! generate a notice if anyone connects to one of those IPs.

@load policy/frameworks/intel/seen/where-locations

module Broala;

export {
	redef enum Notice::Type += {
		## A connection was seen to an IP associated with a domain name from the Intel framework
		Connection_to_Intel_Domain
	};
 
	global dns_intel_match: event(s: Intel::Seen, items: set[Intel::Item]);
}
 
type DNS_Query: record {
	## The connection of the DNS query
	conn: connection;
	## The query itself
	query: string;
	## The TTL
	ttl  : interval;
	## The intelligence item(s) associated with this
	intel: set[Intel::Item];
};
 
global get_ttl: function(t: table[addr] of DNS_Query, idx: any): interval;
global intel_dns_watchlist: table[addr] of DNS_Query &create_expire=0secs &expire_func=get_ttl;
 
redef record Intel::Seen += {
	## The associated DNS answer IP
	dns_ip:  addr &optional;
	## The associated DNS answer TTL
	dns_ttl: interval &optional;
};
 
function get_ttl(t: table[addr] of DNS_Query, idx: any): interval
	{
	if ( t[idx]$ttl < 5min ) return 5min;
	return t[idx]$ttl;
	}
 
function dns_do_seen(c: connection, ans: dns_answer, a: addr)
	{
	# Pulling this out to avoid repeating code.
	if ( c$dns?$query )
		{
		Intel::seen([$indicator=c$dns$query, $indicator_type=Intel::DOMAIN, $conn=c, $where=DNS::IN_RESPONSE, 
		     	     $dns_ip=a, $dns_ttl=ans$TTL]);
		# The query in the reply can be different; consider both if different
		if ( c$dns$query != ans$query )
			Intel::seen([$indicator=ans$query, $indicator_type=Intel::DOMAIN, $conn=c, $where=DNS::IN_RESPONSE,
	 		     	     $dns_ip=a, $dns_ttl=ans$TTL]);
		}
	else
		{
		Intel::seen([$indicator=ans$query, $indicator_type=Intel::DOMAIN, $conn=c, $where=DNS::IN_RESPONSE,
 		     	     $dns_ip=a, $dns_ttl=ans$TTL]);
		}
	}
 
event dns_A_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	dns_do_seen(c, ans, a);
	}
 
event dns_AAAA_reply(c: connection, msg: dns_msg, ans: dns_answer, a: addr)
	{
	dns_do_seen(c, ans, a);
	}
 
event Intel::match(s: Intel::Seen, items: set[Intel::Item])
	{
	# This is handled by the manager. Send it to the worker.
	event Broala::dns_intel_match(s, items);
	}
 
event dns_intel_match(s: Intel::Seen, items: set[Intel::Item])
	{
	if ( s$where != DNS::IN_RESPONSE ) return;
	if ( s?$conn && s?$dns_ip && s$dns_ip !in intel_dns_watchlist )
		intel_dns_watchlist[s$dns_ip] = [$conn=s$conn, $query=s$indicator, $ttl=s$dns_ttl, $intel=items];
	}	
 
event connection_state_remove(c: connection)
	{
	if ( c$id$resp_h in intel_dns_watchlist )
		{
		local d = intel_dns_watchlist[c$id$resp_h];
 
		# Let's create a comma-seperated string of the intel sources that this domain was from
		local sources: table[count] of string = table();
		for ( i in d$intel )
			sources[|sources|+1] = i$meta$source;
 
		NOTICE([$note=Connection_to_Intel_Domain,
		        $msg=fmt("Connection to IP associated with Intel Domain '%s'", d$query),
		        $sub=join_string_array(",", sources), $conn=c, $suppress_for=30mins,
		        $identifier=cat(c$id$orig_h, d$query)]);
		}
	}
 
redef Cluster::manager2worker_events += /Broala::dns_intel_match/;
