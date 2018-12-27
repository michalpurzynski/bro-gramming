bro-gramming
============

Bro IDS programs collection.

Special and a big thank you for the guidance, ideas and code snippets to:
Seth Hall, Bro/ICSI, Broala
Justin Azoff, Bro/NCSA
Johanna Amann, Bro/ICSI
And the rest of the Bro/Zeek Team
Anthony Verez

auth_bruteforcing - detect HTTP bruteforcing (Base64)
bugzilla_bruteforce - an example how to parse raw HTTP data to implement an application level bruteforcing detection
chrome-sha1 - warn on certificates issued before a certain timestamp and with SHA1
cipher_stats - generates a periodic statistics of cipher suites used in your network. Useful to measure an impact when disabling yet another vulnerable ciphersuite
conn-add-country - add the country code to each connection record
conn-peer - for each connection record add the full worker name that processed that connection. Useful for troubleshooting packet loss.
conn_bad_subnet - an early attempt to implement the Intelligence-like framework but for subnets
conn_bad_subnet_input - a parser for the above code's config file (i.e. what to watch for)
counttable - Johanna Amann's script to count the number of times $str has been seen, to be used with the SUMSTAT framework (see the ciper_stats script how to use that)
detect-bruteforcing-ext - SSH bruteforcing detection on the wire
detect_open_proxies - whitelist all known proxies, detect servers behaving like proxies you do not know about
dhcpr - whitelist known DHCP servers, alert on unknown servers that look like they are sending DHCP answers
dlp - a naive attempt to implement a DLP-like functionality, complete with whitelisting support
excessive_http_errors_topk - a SUMSTATS script that's been highly successful detecting abusers of web services. Tune it to your liking.
extract-interesting-files - an example script answering a popular question 'how to extract files of a certain MIME type'
filter_input - a parser for the filter_noise_conn script. IP addresses for which traffic should not be logged can be put there
filter_noise_conn - an example how to prevent some connections from logging
filter_noise_dns - an example how to prevent some DNS queries from logging
filter_noise_files - an example how to prevent some MIME types from logging (avoids the X509 certificates double-logging)
filter_noise_http - an example how to prevent some HTTP transactions from logging
filter_noise_intel - filter out noisy connections from the intel.log
filter_noise_mysql - a filter that prevents ANY form of MySQL logging other than one crossing the private-public boundry
filter_noise_ssl - filter out some SSL transactions and do not log them
filter_noise_x509 - filter out some X509 certificates from log
find_non_aes_clients - alert on SSL communication from clients using weak ciphersuite. Detects obsolete clients initating weak connections from your network
find_non_aes_clients - alert on SSL communication from servers using weak ciphersuite. Detects weak ciphersuites negotiated by your servers
heartbleed_mozillaca - an old example kept here to show how to alert based on certificate's data, including the time when the certificate was issued. Useful for detecting certificates from a compromised CA.
http_auth_base64 - there is no place for HTTP+Base64 authentication and this scripts alerts on such traffic
http_headers_lb - an example how to find a custom HTTP header in your traffic (here - from the load-balancer), add it to logs and use content in the Intel framework
intel-dns - a script written by the Corelight team, that alerts on an actual connection to an IP associated with a domain that had had an Intel hit
intel-ext - a collection of scripts extending the Intel framework, sources from Crowdstrike and modified for Mozilla
livecheck - a small script that logs how much the logger process falls behind the connection processing, useful for troubleshooting
perfect_forward_secrecy - adds the 'pfs' field to the SSL record if the connection uses PFS
radius_bruteforcing - a small script to detect Radius auth bruteforcing
sqli - a script to detect SQLi attempts
sshverlong - detect a suspiciously long SSH client/server version string
ssl-ciphers - written by Johanna Amann, this script calculates the percentage of the use of the different TLS cipher suites for each host in the local network
ssl-log-ext1 - Add list of SSL/TLS cipher suites supported by clients to ssl log file - written by Johanna Amann
ssl-log-ext - Add list of SSL/TLS cipher suites supported by clients to ssl log file - written by Johanna Amann
sslproto_stats - yet another script creating a breakdown by SSL protocols seen on the wire
subnettopk - a script that has been proven useful in the DDoS combat. Creates a log file with statistics about connections and bytes send/received per subnet
unix_commands - a script to detect Unix command injection attempts
unusual_http_methods - a script to detect the most unusual HTTP methods used, useful for tunneling detection, scanner detection, etc
validate-certs-cache-intermediates - perform full certificate chain validation for SSL certificates. Also caches all intermediate certificates encountered so far and use them for future validations - Johanna Amann
verify_wpad - alert on unknown (or all) WPAD queries and answers
weak-keys-mozilla - generate notices when SSL/TLS connections use certificates or DH parameters that have potentially unsafe key lengths
weak_ciphers - SslWeakCiphers give percentage of SSL weak ciphers used (< 2048 bits key except for ECDHE)
weak_protocols - SslWeakProtocols give percentage of SSL weak protocols used (<= SSL2)
whitelist_scan_detection - script to read in a list of IP addresses that will be whitelisted from scan detection (ignore as a source of a scan).
whitelist_scan_detection_input - script to read in a list of IP addresses that will be whitelisted from scan detection (ignore as a source of a scan).
