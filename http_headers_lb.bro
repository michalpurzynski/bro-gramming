# Script to extract value of various HTTP headers provided by load balancers
# and add it to the HTTP log stream
# Inspired by policy/protocols/http/header-names.bro
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Initial Developer of the Original Code is
# Mozilla Corporation
# Portions created by the Initial Developer are Copyright (C) 2014
# the Initial Developer. All Rights Reserved.
#
# Contributor(s):
# Anthony Verez averez@mozilla.com
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/http/main

module MozillaHTTPHeaders;

export {
	redef record Intel::Info += {
		## True client IP address added by our ZLBs
		cluster_client_ip: string &log &optional;
	};

	redef record Intel::Seen += {
		## Log value of the X-CLUSTER-CLIENT-IP
		## True client IP address added by our ZLBs
		cluster_client_ip: string &log &optional;
	};

	redef record HTTP::Info += {
		## Log value of the X-CLUSTER-CLIENT-IP
		## True client IP address added by our ZLBs
		cluster_client_ip: string &log &optional;
		## Log which backend server handled the connection.
		## Might be useful to know where to look for more logs or which server might be under the load
		backend_server: string &log &optional;
	};

	redef enum Intel::Where += {
		HTTP::IN_X_CLUSTER_CLIENT_IP_HEADER,
		HTTP::IN_X_BACKEND_SERVER_HEADER,
	};
	
	## A boolean value to determine if you log the value of X-CLUSTER-CLIENT-IP headers
	const log_cluster_client_ip = T &redef;
	## A boolean value to determine if you log the value of X-BACKEND-SERVER headers
	const log_backend_server = T &redef;
}

event Intel::match(s: Intel::Seen, items: set[Intel::Item])
{
    if ( ( s?$conn ) && ( s$conn?$http ) && ( s$conn$http?$cluster_client_ip ) )
        s$cluster_client_ip = s$conn$http$cluster_client_ip;
}

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	if (!c?$http)
		return;

	if (name == "X-CLUSTER-CLIENT-IP" ) {
		#if (is_valid_ip(value)) {
			c$http$cluster_client_ip = value;
			Intel::seen([$host=to_addr(value),
					$indicator_type=Intel::ADDR,
					$conn=c,
					$where=HTTP::IN_X_CLUSTER_CLIENT_IP_HEADER]);
		#}
	}
	if (name == "X-BACKEND-SERVER") {
			c$http$backend_server = value;
			# this has no right to be true. EVER.
#			 Intel::seen([$host=to_addr(value),
#				 $indicator_type=Intel::DOMAIN,
#				 $conn=c,
#				 $where=HTTP::IN_X_BACKEND_SERVER_HEADER]);
	}
}

