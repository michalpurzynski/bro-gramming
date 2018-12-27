# Copyright (c) 2015 CrowdStrike 2014
# josh.liburdi@crowdstrike.com
# Modifications and bugs by:
# Michal Purzynski mpurzynski@mozilla.com
#
# This file has been initially imported from https://github.com/CrowdStrike/NetworkDetection/tree/master/bro-scripts/intel-extensions/seen
#
# SSL Issuer and Subject field support for the Intel Framework

@load base/protocols/ssl
@load base/frameworks/intel
@load policy/frameworks/intel/seen/where-locations

module Intel;

export {
    redef enum Intel::Type += {
        CERT_ISSUER,
        CERT_SUBJECT,
        CERT_SERIAL
    };

    redef enum Intel::Where += {
        SSL::IN_SERVER_CERT,
        SSL::IN_CLIENT_CERT
    };
}

event ssl_established(c: connection)
{
    if ( ! c?$ssl )
        return;

    if ( ( c$ssl?$issuer ) && ( c$ssl?$subject ) ) {
        Intel::seen([$indicator=c$ssl$issuer,
                    $indicator_type=Intel::CERT_ISSUER,
                    $conn=c,
                    $where=SSL::IN_SERVER_CERT
                ]);
        Intel::seen([$indicator=c$ssl$subject,
                    $indicator_type=Intel::CERT_SUBJECT,
                    $conn=c,
                    $where=SSL::IN_SERVER_CERT
                ]);
    }

    if ( ( c$ssl?$issuer ) && ( c$ssl?$client_subject ) ) {
        Intel::seen([$indicator=c$ssl$issuer,
                    $indicator_type=Intel::CERT_ISSUER,
                    $conn=c,
                    $where=SSL::IN_CLIENT_CERT
                ]);
        Intel::seen([$indicator=c$ssl$client_subject,
                    $indicator_type=Intel::CERT_SUBJECT,
                    $conn=c,
                    $where=SSL::IN_CLIENT_CERT
                ]);
    }
}

event x509_certificate(f: fa_file, cert_ref: opaque of x509, cert: X509::Certificate)
{
    Intel::seen([$indicator=cert$serial, $indicator_type=Intel::CERT_SERIAL, $f=f, $where=X509::IN_CERT]);
   if ( ! cert?$serial )
       return;

   Intel::seen([$indicator=cert$serial, $indicator_type=Intel::CERT_SERIAL, $f=f, $where=X509::IN_CERT]);
}

event file_hash(f: fa_file, kind: string, hash: string)
{
   if ( ! f?$info || ! f$info?$x509 || kind != "sha1" )
       return;

   Intel::seen([$indicator=hash,
                $indicator_type=Intel::CERT_HASH,
                $f=f,
                $where=X509::IN_CERT]);
 }
