#! Add field pfs (perfect forward secrecy) to ssl log file
#! Attackers in possession of a private ssl/tls key want be able
#! to decrypt old communications if perfect forward secrecy is used.
#! We consider we have perfect forward secrecy if we use DHE
#! (Diffie-Hellman) or ECDHE (Elliptic-curve Diffie-Hellman)

@load base/protocols/ssl

module PerfectForwardSecrecy;

export {
    ## Monitored hosts for PFS
    const cert_tracking = ALL_HOSTS &redef;
}

redef record SSL::Info += {
    ## Perfect Forward Secrecy
    pfs:    bool &log &optional;
};

event ssl_established(c: connection)
    {
    if (addr_matches_host(c$id$resp_h, cert_tracking))
        {
        c$ssl$pfs = F;
        if ( (/_DHE_/ in c$ssl$cipher) || (/_ECDHE_/ in c$ssl$cipher) )
            {
            c$ssl$pfs = T;
            }
        }
    }

