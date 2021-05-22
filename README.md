# ipxer
IP Address and Domain Exploration Tool

This code runs [ipxer.com](https://ipxer.com).

ipxer is a simple web API which provides JSON responses for common public DNS queries, IP information from [Team Cymru](http://www.team-cymru.com/community-services.html), IP geolocation data from [MaxMind](https://www.maxmind.com/en/home) GeoLite2 City, and IP threat intelligence from [Alien Labs Open Threat Exchange](https://cybersecurity.att.com/open-threat-exchange) and [IBM X-Force Exchange](https://exchange.xforce.ibmcloud.com/). A simple front-end is provided to facilitate quick exploration of information.

Sometimes interesting things can be found: https://ipxer.com/dns.google.

### API
Domains: `/api/{a,aaaa,mx,ns,txt}/{example.com}`

IPs: `/api/{ipv4,ptr}/{8.8.8.8}`

Alien Labs Open Exchange (OTX) IP Reputation: `/api/ipv4/otx/{8.8.8.8}`

IBM X-Force Exchange IP Reputation: `/api/ipv4/xforce/{8.8.8.8}`
