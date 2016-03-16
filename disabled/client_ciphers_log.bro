#! Add list of SSL/TLS cipher suites supported by clients to ssl log file

@load base/protocols/ssl

redef record SSL::Info += {
    ## Ciphers available for the client
    available_ciphers_client:   set[string]   &log &default=string_set();
};

event ssl_client_hello(c: connection, version: count, possible_ts: time, client_random: string, session_id: string, ciphers: count_set)
    {
        for(cipher in ciphers)
        {
            add c$ssl$available_ciphers_client[SSL::cipher_desc[cipher]];
        }
    }

