event bro_init()
{
        Log::remove_default_filter(X509::LOG);
        Log::add_filter(X509::LOG, [$name = "X509-noise",
                                    $pred(rec: X509::Info) = {
                                        if ((rec$certificate?$cn) && (/mozilla\.(com|org|net)$/ in rec$certificate$cn))
						return F;
					else
						return T;
                                    }
                        ]);
}

