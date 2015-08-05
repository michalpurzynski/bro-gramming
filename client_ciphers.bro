# Add list of SSL/TLS cipher suites supported by clients to ssl log file
#
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.
#
# Contributor(s):
# Michal Purzynski mpurzynski@mozilla.com

@load base/protocols/ssl

redef record SSL::Info += {
    ## Ciphers available for the client
    available_ciphers_client:   set[string]   &log &default=string_set();
};

event ssl_client_hello(c: connection, version: count, possible_ts: time, session_id: string, ciphers: count_set)
    {
        for(cipher in ciphers)
        {
            add c$ssl$available_ciphers_client[SSL::cipher_desc[cipher]];
        }
    }

