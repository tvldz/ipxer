# ipxer
IP Address and Domain Exploration Tool

This code runs [ipxer.com](https://ipxer.com).

ipxer is a simple web API which provides JSON responses for common public DNS queries, IP information from [Team Cymru](http://www.team-cymru.com/community-services.html), IP geolocation data from [MaxMind](https://www.maxmind.com/en/home) GeoLite2 City, and IP threat intelligence from Open Threat Exchange (OTX). A simple front-end is provided to facilitate quick exploration of information.

Sometimes interesting things can be found: https://ipxer.com/google-public-dns-a.google.com.

### API
Domains: `/api/{a,aaaa,mx,ns,txt}/{example.com}`

IPs: `/api/{ipv4,ptr}/{8.8.8.8}`

Open Threat Exchange (OTX) Reputation: `/api/ipv4/otx/{8.8.8.8}`
