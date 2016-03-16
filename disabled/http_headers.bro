##! Extract and include the header names used for each request in the HTTP
##! logging stream.  The headers in the logging stream will be stored in the
##! same order which they were seen on the wire.

@load base/protocols/http/main

module HTTP;

export {
	redef record Info += {
		## The vector of HTTP header names sent by the client.  No
		## header values are included here, just the header names.
		client_header:  vector of string &log &optional;
		
		## The vector of HTTP header names sent by the server.  No
		## header values are included here, just the header names.
		server_header:  vector of string &log &optional;
	};
	
	## A boolean value to determine if client header names are to be logged.
	const log_client_header = T &redef;
	
	## A boolean value to determine if server header names are to be logged.
	const log_server_header = T &redef;
}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! is_orig || ! c?$http )
		return;
	
	if ( log_client_header )
		{
		if ( ! c$http?$client_header )
			c$http$client_header = vector();
		c$http$client_header[|c$http$client_header|] = fmt("%s=%s", name, value);
		}
		
	if ( log_server_header )
		{
		if ( ! c$http?$server_header )
			c$http$server_header = vector();
		c$http$server_header[|c$http$server_header|] = fmt("%s=%s", name, value);
		}
	}
