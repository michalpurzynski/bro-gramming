# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Script to read in a list of IP addresses that will be whitelisted from scan detection (ignore as a source of a scan).
#

module Scan;

global whitelist_scan_port: set[port] = {5223/udp, 5223/tcp, 7000/udp, 7000/tcp, 4001/tcp, 3283/tcp, 11375/tcp, 4242/tcp, 13040/tcp, 6850/tcp, 10380/tcp } &redef;

hook scan_policy(scanner: addr, victim: addr, scanned_port: port)
{
        # MozDef will decide what to alert on
	#if ( ( scanner ! in 10.0.0.0/8 ) || ( scanner in whitelist_scan_ip ) || ( scanned_port in whitelist_scan_port) )
	if ( ( scanner in whitelist_scan_ip ) || ( scanned_port in whitelist_scan_port) )
		break;
}

