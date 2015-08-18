# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com
#
# Script to detect not authorized DHCP servers. Bro needs to see DHCP traffic of course. Will not work when servers and clients are in the same Vlan, unless you mirror that traffic.

@load base/protocols/dhcp/utils

module UnauthorizedDHCP;

redef enum Notice::Type += {
    ServerOffer,
	ServerAck,
	ServerRoutersInOffer,
	ServerRoutersInAck,
};

export {
	global trusted_dhcpd: set[addr] = { } &redef;
	global trusted_gw: set[addr] = { } &redef;
}

event dhcp_offer(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
	local clientip: addr;
	if (serv_addr !in trusted_dhcpd) {
		if ( DHCP::reverse_ip(msg$yiaddr) != 0.0.0.0 )
                	clientip = DHCP::reverse_ip(msg$yiaddr);
        	else
                	clientip = c$id$orig_h;
		NOTICE([$note=ServerOffer,
                        $msg=fmt("%s is sending unauthorized DHCP offers", serv_addr),
                        $sub=cat(DHCP::reverse_ip(msg$yiaddr)),
			            $uid=c$uid,
                        $id=c$id,
                        $identifier=serv_addr,
                        $suppress_for=1day,
                        $identifier=cat(c$uid)]);
	}
	if (|router| > 1 || (|router| == 1) && router[1] !in trusted_gw )
	{
                local rtr: count;
		local routers: string = "";
                for (rtr in router) {
                        routers += cat(router[rtr]) + ",";
                }
                NOTICE([$note=ServerRoutersInOffer,
                        $msg=fmt("%s is sending suspicious DHCP router list - %s", serv_addr, routers),
                        $sub=cat(serv_addr),
                        $uid=c$uid,
                        $id=c$id,
                        $identifier=serv_addr,
                        $suppress_for=1day,
                        $identifier=cat(c$uid)]);
	}
}
event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
{
        local clientip: addr;
        if (serv_addr !in trusted_dhcpd) {
                if ( DHCP::reverse_ip(msg$yiaddr) != 0.0.0.0 )
                        clientip = DHCP::reverse_ip(msg$yiaddr);
                else
                        clientip = c$id$orig_h;
                NOTICE([$note=ServerAck,
                        $msg=fmt("%s is sending unauthorized DHCP ack", serv_addr),
                        $sub=cat(DHCP::reverse_ip(msg$yiaddr)),
                        $uid=c$uid,
                        $id=c$id,
                        $identifier=serv_addr,
                        $suppress_for=1day,
                        $identifier=cat(c$uid)]);
        }
}

