# DNS over TLS resolver

DNS over TLS is one way to send DNS queries over an encrypted connection (compared to traditional DNS being sent in plain text and can easily be tracked by anybody on the network). I'd call it easier and maybe faster alternative to DNSSEC protocol.
This code was made as a proof of concept and I'm plannnig on using it as a replacement of gethostbyname in all my ongoing projects.

This code relys on CloudFlare's DNS over TLS implementation. Quad9 dns tested to be working as well. Unsecured DNS requests over TCP also supported giving you an option to abandon outdated DNS comm over UDP.
DNS Query and Answer packets are parsed as described in [RFC1035](https://tools.ietf.org/html/rfc1035)

Tested DNS Servers:
Cloudflare DNS: boths IPv4(1.1.1.1) and IPv6 versions. Secure and unsecure requests
Quad9: boths IPv4(9.9.9.9) and IPv6 versions. Secure and unsecure requests
Google: IPv4(8.8.8.8) unsecured requests
OpenNIC: IPv4(172.104.136.243) unsecured requests

More privacy oriented, non-tracking DNS servers can be found [here](https://dnsprivacy.org/wiki/display/DP/DNS+Privacy+Test+Servers)

Sample output:
```sh
$ ./resolver 
Certificate Subject: /C=US/ST=CA/L=San Francisco/O=Cloudflare, Inc./CN=*.cloudflare-dns.com
Certificate Issuer: /C=US/O=DigiCert Inc/CN=DigiCert ECC Secure Server CA
Certificate Pub: 04B2450B31AC5063CE21E67C34231AC5C1534596977A3187BBE0EA1D95F5FF2504CA75F0F63FB5DF51E95BC93DADB403057320923E74BE8E4B1BE26886446E62BB
atomminer.com   299     A       104.27.172.23
atomminer.com   299     A       104.27.173.23
```

Do you trust your ISP? I don't....


This code is put out for all to use for free to support net neutrality and privacy. I'd really like to see someone using this code in a commercial implementation. 
