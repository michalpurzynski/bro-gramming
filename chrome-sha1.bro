# This script identifies certificates on the local network which will be
# impacted by the Chrome SHA-1 sunset changes. For more details, please
# see http://googleonlinesecurity.blogspot.com/2014/09/gradually-sunsetting-sha-1.html
#
# Questions -> johanna@icir.org

@load base/protocols/ssl
@load base/frameworks/notice

module Chrome;

export {
	redef enum Notice::Type += {
		## Indicates that the certificate of a host will be impacted by the google
		## SHA-1 sunset changes.
		SHA1_Sunset
	};
}

global recently_checked_certs: set[string] = set();

event ssl_established(c: connection)
	{
	if (!Site::is_local_addr(c$id$resp_h))
		return;

	# If there aren't any certs we can't validate the chain.
	if ( ! c$ssl?$cert_chain || |c$ssl$cert_chain| == 0 ||
	     ! c$ssl$cert_chain[0]?$x509 )
		return;

	local chain_id = "";
	local chain: vector of opaque of x509 = vector();
	local chain_hashes: table[string] of string;

	for ( i in c$ssl$cert_chain )
		{
		chain_id = cat(chain_id, c$ssl$cert_chain[i]$sha1);
		if ( c$ssl$cert_chain[i]?$x509 )
			{
			chain[i] = c$ssl$cert_chain[i]$x509$handle;
			chain_hashes[c$ssl$cert_chain[i]$sha1] = c$ssl$cert_chain[i]$fuid;
			}
		}

	if ( chain_id in recently_checked_certs )
		return;

	add recently_checked_certs[chain_id];

	# This only applies to certificates with an expiry after 2016-01-01.
	local cutoff: time = double_to_time(1451606400.0);

	if ( c$ssl$cert_chain[0]$x509$certificate$not_valid_after < cutoff )
		return;

	local result = x509_verify(chain, SSL::root_certs);

	# If we cannot validate, we cannot tell anything in any case...
	if ( result$result_string != "ok" )
		return;

	local vchain = result$chain_certs;
	for ( i in vchain )
		{
		local cert = x509_parse(vchain[i]);

		if ( cert$subject == cert$issuer )
			# skip the root, it is allowed to use whatever hash algorithm it wants to.
			next;

		if ( /^sha1With/ in cert$sig_alg )
			{
			local msg: string = "An intermediate CA certificate in the chain uses SHA-1. Chrome will consider this unsafe in the future.";
			if ( i == 0 )
				msg = "The host certificate uses SHA-1. Chrome will consider this unsafe in the future.";

			local n: Notice::Info = [$note=SHA1_Sunset,
				$msg=msg,
				$sub=fmt("Subject: %s, Issuer: %s, Signature algorithm: %s", cert$subject, cert$issuer, cert$sig_alg),
				$conn=c, $n=int_to_count(i),
				$identifier=cat(c$id$resp_h,c$id$resp_p,i),
				$suppress_for=7 days
			];

			local cert_hash = sha1_hash(x509_get_certificate_string(vchain[i]));
			if ( cert_hash in chain_hashes )
				n$fuid = chain_hashes[cert_hash];

			NOTICE(n);
			}
		}

	}
