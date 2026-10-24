# Module and Tool Catalog

This catalog is generated from [`core/tools_manifest.yaml`](../core/tools_manifest.yaml). Run `python docs/scripts/generate_modules.py` after editing the manifest, or add `--check` in CI to verify it is current.

Ultrecon is a reconnaissance and inventory tool, not an exploitation framework. Active components require `--active --authorize` and a separate confirmation. Optional free-tier sources remain off unless explicitly enabled and configured with their own API key.

## P01 — Passive OSINT & org recon

Certificate transparency, public DNS archives and org metadata.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **BGPView** (`bgpview`) | http_api | oss | manual_note | — | [https://bgpview.io](https://bgpview.io) | — |
| **Censys (free credit only)** (`censys`) | http_api | free_tier | manual_note | — | [https://search.censys.io](https://search.censys.io) | Off by default. Key: `CENSYS_API_ID`. Reference only. Not wired into the pipeline; paid tiers are out of scope. |
| **CertSpotter** (`certspotter`) | http_api | free_tier | manual_note | — | [https://sslmate.com/certspotter/](https://sslmate.com/certspotter/) | Off by default. Key: `CERTSPOTTER_API_KEY`.  |
| **Common Crawl index** (`commoncrawl`) | http_api | oss | manual_note | — | [https://commoncrawl.org](https://commoncrawl.org) | — |
| **crt.sh** (`crtsh`) | http_api | oss | manual_note | — | [https://crt.sh](https://crt.sh) | — |
| **GitHub Code Search** (`github-code-search`) | http_api | free_tier | manual_note | — | [https://github.com/search](https://github.com/search) | Off by default. Key: `GITHUB_TOKEN`.  |
| **HackerTarget API** (`hackertarget`) | http_api | free_tier | manual_note | — | [https://hackertarget.com](https://hackertarget.com) | Strict rate limits; the client sends a single request per domain. |
| **Hurricane Electric BGP Toolkit** (`bgp-he`) | http_api | manual_only | manual_note | — | [https://bgp.he.net](https://bgp.he.net) | Off by default. Browser-oriented; use BGPView/RIPEstat for automation. |
| **RapidDNS** (`rapiddns`) | http_api | oss | manual_note | — | [https://rapiddns.io](https://rapiddns.io) | — |
| **RIPEstat** (`ripestat`) | http_api | oss | manual_note | — | [https://stat.ripe.net](https://stat.ripe.net) | — |
| **Shodan (free credit only)** (`shodan`) | http_api | free_tier | manual_note | — | [https://www.shodan.io](https://www.shodan.io) | Off by default. Key: `SHODAN_API_KEY`. Reference only. Not wired into the pipeline; paid tiers are out of scope. |
| **urlscan.io** (`urlscan`) | http_api | free_tier | manual_note | — | [https://urlscan.io](https://urlscan.io) | Off by default. Key: `URLSCAN_API_KEY`.  |
| **VirusTotal** (`virustotal`) | http_api | free_tier | manual_note | — | [https://www.virustotal.com](https://www.virustotal.com) | Off by default. Key: `VIRUSTOTAL_API_KEY`.  |
| **dig (BIND)** (`dig`) | os_utility | oss | apt_fallback | `dig` · `dig -v` | [https://bind9.readthedocs.io/](https://bind9.readthedocs.io/) | — |
| **host** (`host`) | os_utility | oss | apt_fallback | `host` · `host -V` | [https://bind9.readthedocs.io/](https://bind9.readthedocs.io/) | — |
| **nslookup** (`nslookup`) | os_utility | oss | apt_fallback | `nslookup` · `nslookup -version` | [https://bind9.readthedocs.io/](https://bind9.readthedocs.io/) | — |
| **whois** (`whois`) | os_utility | oss | apt_fallback | `whois` · `whois --version` | [https://github.com/rfc1036/whois](https://github.com/rfc1036/whois) | — |
| **Recon-ng** (`recon-ng`) | tool | oss | pipx | `recon-ng` · `recon-ng -h` | [https://github.com/lanmaster53/recon-ng](https://github.com/lanmaster53/recon-ng) | — |
| **sn0int** (`sn0int`) | tool | oss | apt_fallback | `sn0int` · `sn0int --version` | [https://github.com/kpcyrd/sn0int](https://github.com/kpcyrd/sn0int) | Not available in every distro; falls back to a manual cargo/git install note. |
| **SpiderFoot (OSS edition)** (`spiderfoot`) | tool | oss | git | `sf.py` · `sf.py -h` | [https://github.com/smicallef/spiderfoot](https://github.com/smicallef/spiderfoot) | Large Python app; auto-install is disabled by default in config. |
| **theHarvester** (`theharvester`) | tool | oss | pipx | `theHarvester` · `theHarvester -h` | [https://github.com/laramies/theHarvester](https://github.com/laramies/theHarvester) | — |

## P02 — Subdomain enumeration

Passive providers plus gated brute-force, permutation and takeover checks.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **can-i-take-over-xyz** (`can-i-take-over-xyz`) | http_api | oss | manual_note | — | [https://github.com/EdOverflow/can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz) | Off by default. Data reference for interpreting takeover fingerprints; nuclei -tags takeover is wired. |
| **altdns** (`altdns`) | tool | oss | pipx | `altdns` · `altdns -h` | [https://github.com/infosec-au/altdns](https://github.com/infosec-au/altdns) | Active; authorization required.  |
| **Alterx** (`alterx`) | tool | oss | go | `alterx` · `alterx -version` | [https://github.com/projectdiscovery/alterx](https://github.com/projectdiscovery/alterx) | Active; authorization required.  |
| **Assetfinder** (`assetfinder`) | tool | oss | go | `assetfinder` · `assetfinder --help` | [https://github.com/tomnomnom/assetfinder](https://github.com/tomnomnom/assetfinder) | — |
| **BBOT** (`bbot`) | tool | oss | pipx | `bbot` · `bbot --help` | [https://github.com/blacklanternsecurity/bbot](https://github.com/blacklanternsecurity/bbot) | — |
| **Chaos** (`chaos`) | tool | free_tier | go | `chaos` · `chaos -version` | [https://github.com/projectdiscovery/chaos-client](https://github.com/projectdiscovery/chaos-client) | Off by default. Key: `CHAOS_KEY`.  |
| **CTFR** (`ctfr`) | tool | oss | pipx | `ctfr` · `ctfr -h` | [https://github.com/UnaPibaGeek/ctfr](https://github.com/UnaPibaGeek/ctfr) | — |
| **dnsenum** (`dnsenum`) | tool | oss | apt_fallback | `dnsenum` · `dnsenum --help` | [https://github.com/fwaeytens/dnsenum](https://github.com/fwaeytens/dnsenum) | Active; authorization required.  |
| **dnsgen** (`dnsgen`) | tool | oss | pipx | `dnsgen` · `dnsgen --help` | [https://github.com/ProjectAnte/dnsgen](https://github.com/ProjectAnte/dnsgen) | Active; authorization required.  |
| **dnsReaper** (`dnsreaper`) | tool | oss | git | `dnsReaper.py` · `dnsReaper.py --help` | [https://github.com/punk-security/dnsReaper](https://github.com/punk-security/dnsReaper) | Active; authorization required.  |
| **dnsrecon** (`dnsrecon`) | tool | oss | pipx | `dnsrecon` · `dnsrecon --version` | [https://github.com/darkoperator/dnsrecon](https://github.com/darkoperator/dnsrecon) | Active; authorization required.  |
| **dnsx** (`dnsx`) | tool | oss | go | `dnsx` · `dnsx -version` | [https://github.com/projectdiscovery/dnsx](https://github.com/projectdiscovery/dnsx) | Active; authorization required.  |
| **dsieve** (`dsieve`) | tool | oss | go | `dsieve` · `dsieve -h` | [https://github.com/trickest/dsieve](https://github.com/trickest/dsieve) | Active; authorization required.  |
| **Fierce** (`fierce`) | tool | oss | pipx | `fierce` · `fierce --help` | [https://github.com/mschwager/fierce](https://github.com/mschwager/fierce) | Active; authorization required.  |
| **Findomain** (`findomain`) | tool | oss | git | `findomain` · `findomain --version` | [https://github.com/Findomain/Findomain](https://github.com/Findomain/Findomain) | — |
| **github-subdomains** (`github-subdomains`) | tool | free_tier | go | `github-subdomains` · `github-subdomains -h` | [https://github.com/gwen001/github-subdomains](https://github.com/gwen001/github-subdomains) | Off by default. Key: `GITHUB_TOKEN`.  |
| **Gotator** (`gotator`) | tool | oss | go | `gotator` · `gotator -h` | [https://github.com/Josue87/gotator](https://github.com/Josue87/gotator) | Active; authorization required.  |
| **MassDNS** (`massdns`) | tool | oss | git | `massdns` · `massdns --version` | [https://github.com/blechschmidt/massdns](https://github.com/blechschmidt/massdns) | Active; authorization required.  |
| **OneForAll** (`oneforall`) | tool | oss | git | `oneforall.py` · `oneforall.py --help` | [https://github.com/shmilylty/OneForAll](https://github.com/shmilylty/OneForAll) | — |
| **OWASP Amass** (`amass`) | tool | oss | go | `amass` · `amass -version` | [https://github.com/owasp-amass/amass](https://github.com/owasp-amass/amass) | Only passive mode is invoked by p02. |
| **PureDNS** (`puredns`) | tool | oss | go | `puredns` · `puredns --version` | [https://github.com/d3mondev/puredns](https://github.com/d3mondev/puredns) | Active; authorization required.  |
| **reconFTW** (`reconftw`) | tool | oss | git | `reconftw` · `reconftw --help` | [https://github.com/six2dez/reconftw](https://github.com/six2dez/reconftw) | Off by default. Installs a large external toolchain; intentionally not auto-installed. |
| **shuffledns** (`shuffledns`) | tool | oss | go | `shuffledns` · `shuffledns -version` | [https://github.com/projectdiscovery/shuffledns](https://github.com/projectdiscovery/shuffledns) | Active; authorization required.  |
| **Subfinder** (`subfinder`) | tool | oss | go | `subfinder` · `subfinder -version` | [https://github.com/projectdiscovery/subfinder](https://github.com/projectdiscovery/subfinder) | — |
| **Subjack** (`subjack`) | tool | oss | go | `subjack` · `subjack -h` | [https://github.com/haccer/subjack](https://github.com/haccer/subjack) | Active; authorization required.  |
| **Sublist3r** (`sublist3r`) | tool | oss | pipx | `sublist3r` · `sublist3r -h` | [https://github.com/aboul3la/Sublist3r](https://github.com/aboul3la/Sublist3r) | — |
| **Subzy** (`subzy`) | tool | oss | go | `subzy` · `subzy -h` | [https://github.com/PentestPad/subzy](https://github.com/PentestPad/subzy) | Active; authorization required.  |

## P03 — ASN / IP / network mapping

Map domains to ASNs, prefixes and reverse-DNS hostnames.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **asnmap** (`asnmap`) | tool | oss | go | `asnmap` · `asnmap -version` | [https://github.com/projectdiscovery/asnmap](https://github.com/projectdiscovery/asnmap) | — |
| **hakip2host** (`hakip2host`) | tool | oss | go | `hakip2host` · `hakip2host -h` | [https://github.com/hakluke/hakip2host](https://github.com/hakluke/hakip2host) | — |
| **mapcidr** (`mapcidr`) | tool | oss | go | `mapcidr` · `mapcidr -version` | [https://github.com/projectdiscovery/mapcidr](https://github.com/projectdiscovery/mapcidr) | — |

## P04 — Ports & services

Rate-limited port and service discovery (active only).

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **FingerprintX** (`fingerprintx`) | tool | oss | go | `fingerprintx` · `fingerprintx --help` | [https://github.com/praetorian-inc/fingerprintx](https://github.com/praetorian-inc/fingerprintx) | Active; authorization required.  |
| **Masscan** (`masscan`) | tool | oss | git | `masscan` · `masscan --version` | [https://github.com/robertdavidgraham/masscan](https://github.com/robertdavidgraham/masscan) | Active; authorization required.  |
| **Naabu** (`naabu`) | tool | oss | go | `naabu` · `naabu -version` | [https://github.com/projectdiscovery/naabu](https://github.com/projectdiscovery/naabu) | Active; authorization required.  |
| **Nmap** (`nmap`) | tool | oss | apt_fallback | `nmap` · `nmap --version` | [https://nmap.org](https://nmap.org) | Active; authorization required.  |
| **RustScan** (`rustscan`) | tool | oss | git | `rustscan` · `rustscan --version` | [https://github.com/RustScan/RustScan](https://github.com/RustScan/RustScan) | Active; authorization required.  |
| **SSLyze** (`sslyze`) | tool | oss | pipx | `sslyze` · `sslyze --version` | [https://github.com/nabla-c0d3/sslyze](https://github.com/nabla-c0d3/sslyze) | Active; authorization required.  |
| **testssl.sh** (`testssl`) | tool | oss | git | `testssl.sh` · `testssl.sh --version` | [https://github.com/testssl/testssl.sh](https://github.com/testssl/testssl.sh) | Active; authorization required.  |
| **tlsx** (`tlsx`) | tool | oss | go | `tlsx` · `tlsx -version` | [https://github.com/projectdiscovery/tlsx](https://github.com/projectdiscovery/tlsx) | Active; authorization required.  |

## P05 — HTTP probing & tech fingerprint

Probe live web hosts, status, titles, servers and technologies.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **cdncheck** (`cdncheck`) | tool | oss | go | `cdncheck` · `cdncheck -version` | [https://github.com/projectdiscovery/cdncheck](https://github.com/projectdiscovery/cdncheck) | — |
| **httprobe** (`httprobe`) | tool | oss | go | `httprobe` · `httprobe -h` | [https://github.com/tomnomnom/httprobe](https://github.com/tomnomnom/httprobe) | — |
| **httpx** (`httpx`) | tool | oss | go | `httpx` · `httpx -version` | [https://github.com/projectdiscovery/httpx](https://github.com/projectdiscovery/httpx) | — |
| **Retire.js** (`retirejs`) | tool | oss | npm | `retire` · `retire --version` | [https://github.com/RetireJS/retire.js](https://github.com/RetireJS/retire.js) | — |
| **wafw00f** (`wafw00f`) | tool | oss | pipx | `wafw00f` · `wafw00f --version` | [https://github.com/EnableSecurity/wafw00f](https://github.com/EnableSecurity/wafw00f) | — |
| **webanalyze** (`webanalyze`) | tool | oss | go | `webanalyze` · `webanalyze --version` | [https://github.com/rverton/webanalyze](https://github.com/rverton/webanalyze) | — |
| **WhatWeb** (`whatweb`) | tool | oss | apt_fallback | `whatweb` · `whatweb --version` | [https://github.com/urbanadventurer/WhatWeb](https://github.com/urbanadventurer/WhatWeb) | — |

## P06 — Virtual hosts & app discovery

Screenshots and gated vhost fuzzing for discovered web hosts.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **GoWitness** (`gowitness`) | tool | oss | go | `gowitness` · `gowitness version` | [https://github.com/sensepost/gowitness](https://github.com/sensepost/gowitness) | Active; authorization required.  |

## P07 — Crawling & endpoint discovery

Crawl sites and public URL archives into normalized endpoints.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **awk (gawk)** (`awk`) | os_utility | oss | apt_fallback | `awk` · `awk --version` | [https://www.gnu.org/software/gawk/](https://www.gnu.org/software/gawk/) | — |
| **GNU parallel** (`parallel`) | os_utility | oss | apt_fallback | `parallel` · `parallel --version` | [https://www.gnu.org/software/parallel/](https://www.gnu.org/software/parallel/) | — |
| **jq** (`jq`) | os_utility | oss | apt_fallback | `jq` · `jq --version` | [https://github.com/jqlang/jq](https://github.com/jqlang/jq) | — |
| **sed** (`sed`) | os_utility | oss | apt_fallback | `sed` · `sed --version` | [https://www.gnu.org/software/sed/](https://www.gnu.org/software/sed/) | — |
| **sort (coreutils)** (`sort`) | os_utility | oss | apt_fallback | `sort` · `sort --version` | [https://www.gnu.org/software/coreutils/](https://www.gnu.org/software/coreutils/) | — |
| **uniq (coreutils)** (`uniq`) | os_utility | oss | apt_fallback | `uniq` · `uniq --version` | [https://www.gnu.org/software/coreutils/](https://www.gnu.org/software/coreutils/) | — |
| **anew** (`anew`) | tool | oss | go | `anew` · `anew -h` | [https://github.com/tomnomnom/anew](https://github.com/tomnomnom/anew) | — |
| **Cariddi** (`cariddi`) | tool | oss | go | `cariddi` · `cariddi -version` | [https://github.com/edoardottt/cariddi](https://github.com/edoardottt/cariddi) | — |
| **GAU** (`gau`) | tool | oss | go | `gau` · `gau --version` | [https://github.com/lc/gau](https://github.com/lc/gau) | — |
| **gf** (`gf`) | tool | oss | go | `gf` · `gf -h` | [https://github.com/tomnomnom/gf](https://github.com/tomnomnom/gf) | — |
| **GoSpider** (`gospider`) | tool | oss | go | `gospider` · `gospider --version` | [https://github.com/jaeles-project/gospider](https://github.com/jaeles-project/gospider) | — |
| **gron** (`gron`) | tool | oss | go | `gron` · `gron --version` | [https://github.com/tomnomnom/gron](https://github.com/tomnomnom/gron) | — |
| **Hakrawler** (`hakrawler`) | tool | oss | go | `hakrawler` · `hakrawler -h` | [https://github.com/hakluke/hakrawler](https://github.com/hakluke/hakrawler) | — |
| **Katana** (`katana`) | tool | oss | go | `katana` · `katana -version` | [https://github.com/projectdiscovery/katana](https://github.com/projectdiscovery/katana) | — |
| **qsreplace** (`qsreplace`) | tool | oss | go | `qsreplace` · `qsreplace -h` | [https://github.com/tomnomnom/qsreplace](https://github.com/tomnomnom/qsreplace) | — |
| **unfurl** (`unfurl`) | tool | oss | go | `unfurl` · `unfurl -h` | [https://github.com/tomnomnom/unfurl](https://github.com/tomnomnom/unfurl) | — |
| **URLFinder** (`urlfinder`) | tool | oss | go | `urlfinder` · `urlfinder -h` | [https://github.com/praetorian-inc/urlfinder](https://github.com/praetorian-inc/urlfinder) | — |
| **uro** (`uro`) | tool | oss | pipx | `uro` · `uro --version` | [https://github.com/s0md3v/uro](https://github.com/s0md3v/uro) | — |
| **waybackurls** (`waybackurls`) | tool | oss | go | `waybackurls` · `waybackurls -h` | [https://github.com/tomnomnom/waybackurls](https://github.com/tomnomnom/waybackurls) | — |
| **Waymore** (`waymore`) | tool | oss | pipx | `waymore` · `waymore --help` | [https://github.com/xnl-h4ck3r/waymore](https://github.com/xnl-h4ck3r/waymore) | — |

## P08 — Content discovery

Wordlist-based path discovery (active only).

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **CeWL** (`cewl`) | tool | oss | apt_fallback | `cewl` · `cewl --version` | [https://github.com/digininja/CeWL](https://github.com/digininja/CeWL) | Active; authorization required.  |
| **Dirsearch** (`dirsearch`) | tool | oss | pipx | `dirsearch` · `dirsearch --version` | [https://github.com/maurosoria/dirsearch](https://github.com/maurosoria/dirsearch) | Active; authorization required.  |
| **Feroxbuster** (`feroxbuster`) | tool | oss | git | `feroxbuster` · `feroxbuster --version` | [https://github.com/epi052/feroxbuster](https://github.com/epi052/feroxbuster) | Active; authorization required.  |
| **ffuf** (`ffuf`) | tool | oss | go | `ffuf` · `ffuf -V` | [https://github.com/ffuf/ffuf](https://github.com/ffuf/ffuf) | Active; authorization required.  |
| **Gobuster** (`gobuster`) | tool | oss | go | `gobuster` · `gobuster version` | [https://github.com/OJ/gobuster](https://github.com/OJ/gobuster) | Active; authorization required.  |
| **Wfuzz** (`wfuzz`) | tool | oss | pipx | `wfuzz` · `wfuzz --version` | [https://github.com/xmendez/wfuzz](https://github.com/xmendez/wfuzz) | Active; authorization required.  |
| **Assetnote Wordlists** (`assetnote-wordlists`) | wordlist | oss | git | — | [https://github.com/assetnote/wordlists](https://github.com/assetnote/wordlists) | Off by default.  |
| **FuzzDB** (`fuzzdb`) | wordlist | oss | git | — | [https://github.com/fuzzdb-project/fuzzdb](https://github.com/fuzzdb-project/fuzzdb) | Off by default.  |
| **RobotsDisallowed** (`robotsdisallowed`) | wordlist | oss | git | — | [https://github.com/danielmiessler/RobotsDisallowed](https://github.com/danielmiessler/RobotsDisallowed) | Off by default.  |
| **SecLists** (`seclists`) | wordlist | oss | git | — | [https://github.com/danielmiessler/SecLists](https://github.com/danielmiessler/SecLists) | — |

## P09 — JavaScript recon

Enumerate JS, mine routes and flag secret-like strings.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **getJS** (`getjs`) | tool | oss | go | `getJS` · `getJS -h` | [https://github.com/003random/getJS](https://github.com/003random/getJS) | — |
| **Jsluice** (`jsluice`) | tool | oss | go | `jsluice` · `jsluice --help` | [https://github.com/BishopFox/jsluice](https://github.com/BishopFox/jsluice) | — |
| **LinkFinder** (`linkfinder`) | tool | oss | pipx | `linkfinder` · `linkfinder -h` | [https://github.com/GerbenJavado/LinkFinder](https://github.com/GerbenJavado/LinkFinder) | — |
| **SecretFinder** (`secretfinder`) | tool | oss | pipx | `SecretFinder.py` · `SecretFinder.py -h` | [https://github.com/m4ll0k/SecretFinder](https://github.com/m4ll0k/SecretFinder) | Upstream does not publish a console entry point; built-in secret scanning is the fallback. |
| **Sourcemapper** (`sourcemapper`) | tool | oss | go | `sourcemapper` · `sourcemapper -h` | [https://github.com/denandz/sourcemapper](https://github.com/denandz/sourcemapper) | — |
| **subjs** (`subjs`) | tool | oss | go | `subjs` · `subjs -h` | [https://github.com/lc/subjs](https://github.com/lc/subjs) | — |
| **xnLinkFinder** (`xnlinkfinder`) | tool | oss | pipx | `xnLinkFinder` · `xnLinkFinder -h` | [https://github.com/xnl-h4ck3r/xnLinkFinder](https://github.com/xnl-h4ck3r/xnLinkFinder) | — |

## P10 — Hidden parameters & routes

Extract parameters and discover hidden routes, with gated fuzzing.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Arjun** (`arjun`) | tool | oss | pipx | `arjun` · `arjun --version` | [https://github.com/s0md3v/Arjun](https://github.com/s0md3v/Arjun) | Active; authorization required.  |
| **Kiterunner** (`kiterunner`) | tool | oss | go | `kr` · `kr version` | [https://github.com/assetnote/kiterunner](https://github.com/assetnote/kiterunner) | Active; authorization required.  |
| **mitmproxy** (`mitmproxy`) | tool | oss | pipx | `mitmproxy` · `mitmproxy --version` | [https://mitmproxy.org](https://mitmproxy.org) | — |
| **OWASP Noir** (`noir`) | tool | oss | go | `noir` · `noir --version` | [https://github.com/owasp-noir/noir](https://github.com/owasp-noir/noir) | — |
| **OWASP ZAP** (`zap`) | tool | oss | apt_fallback | `zap.sh` · `zap.sh -version` | [https://www.zaproxy.org](https://www.zaproxy.org) | Active; authorization required. Used in headless/API mode only; active scan profiles are gated by --active. |
| **ParamSpider** (`paramspider`) | tool | oss | pipx | `paramspider` · `paramspider -h` | [https://github.com/devanshbatham/ParamSpider](https://github.com/devanshbatham/ParamSpider) | — |
| **x8** (`x8`) | tool | oss | git | `x8` · `x8 --version` | [https://github.com/Sh1Yo/x8](https://github.com/Sh1Yo/x8) | Active; authorization required.  |

## P11 — REST API recon

Find OpenAPI/Swagger specs and enumerate API operations.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Built-in OpenAPI/Swagger probe** (`builtin-openapi`) | http_api | oss | manual_note | — | [https://github.com/fx-sys/Ultrecon](https://github.com/fx-sys/Ultrecon) | — |
| **Swagger Editor/UI** (`swagger-ui`) | http_api | oss | manual_note | — | [https://github.com/swagger-api/swagger-ui](https://github.com/swagger-api/swagger-ui) | Off by default. Run locally via Docker/npm; not a scanning CLI and not auto-installed. |
| **oasdiff** (`oasdiff`) | tool | oss | go | `oasdiff` · `oasdiff --version` | [https://github.com/oasdiff/oasdiff](https://github.com/oasdiff/oasdiff) | — |
| **RESTler** (`restler`) | tool | oss | git | `restler` · `restler --help` | [https://github.com/microsoft/restler-fuzzer](https://github.com/microsoft/restler-fuzzer) | Active; authorization required. Python/.NET build toolchain; install manually and wire only for authorized tests. |
| **Schemathesis** (`schemathesis`) | tool | oss | pipx | `schemathesis` · `schemathesis --version` | [https://github.com/schemathesis/schemathesis](https://github.com/schemathesis/schemathesis) | Active; authorization required.  |
| **Spectral** (`spectral`) | tool | oss | npm | `spectral` · `spectral --version` | [https://github.com/stoplightio/spectral](https://github.com/stoplightio/spectral) | — |

## P12 — GraphQL recon

Detect GraphQL endpoints and (with authorization) introspect.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Built-in GraphQL detector** (`builtin-graphql`) | http_api | oss | manual_note | — | [https://github.com/fx-sys/Ultrecon](https://github.com/fx-sys/Ultrecon) | — |
| **Clairvoyance** (`clairvoyance`) | tool | oss | pipx | `clairvoyance` · `clairvoyance --help` | [https://github.com/nikitastupin/clairvoyance](https://github.com/nikitastupin/clairvoyance) | Active; authorization required.  |
| **get-graphql-schema** (`get-graphql-schema`) | tool | oss | npm | `get-graphql-schema` · `get-graphql-schema --version` | [https://github.com/prisma-labs/get-graphql-schema](https://github.com/prisma-labs/get-graphql-schema) | Active; authorization required.  |
| **graphql-cop** (`graphql-cop`) | tool | oss | pipx | `graphql-cop` · `graphql-cop --help` | [https://github.com/dolevf/graphql-cop](https://github.com/dolevf/graphql-cop) | Active; authorization required.  |
| **graphql-path-enum** (`graphql-path-enum`) | tool | oss | go | `graphql-path-enum` · `graphql-path-enum -h` | [https://github.com/Escape-Technologies/graphql-path-enum](https://github.com/Escape-Technologies/graphql-path-enum) | Active; authorization required.  |
| **GraphQLmap** (`graphqlmap`) | tool | oss | pipx | `graphqlmap` · `graphqlmap --help` | [https://github.com/swisskyrepo/GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) | Active; authorization required.  |

## P13 — gRPC / SOAP / WebSocket recon

Inventory non-REST API surface across other web protocols.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Built-in protocol inventory** (`builtin-other-protocols`) | http_api | oss | manual_note | — | [https://github.com/fx-sys/Ultrecon](https://github.com/fx-sys/Ultrecon) | — |
| **SoapUI OSS edition** (`soapui`) | http_api | manual_only | manual_note | — | [https://www.soapui.org](https://www.soapui.org) | Off by default.  |
| **grpcui** (`grpcui`) | tool | oss | go | `grpcui` · `grpcui -version` | [https://github.com/fullstorydev/grpcui](https://github.com/fullstorydev/grpcui) | Active; authorization required.  |
| **grpcurl** (`grpcurl`) | tool | oss | go | `grpcurl` · `grpcurl -version` | [https://github.com/fullstorydev/grpcurl](https://github.com/fullstorydev/grpcurl) | Active; authorization required.  |
| **websocat** (`websocat`) | tool | oss | git | `websocat` · `websocat --version` | [https://github.com/vi/websocat](https://github.com/vi/websocat) | Active; authorization required.  |
| **wscat** (`wscat`) | tool | oss | npm | `wscat` · `wscat --version` | [https://github.com/websockets/wscat](https://github.com/websockets/wscat) | Active; authorization required.  |

## P14 — Cloud assets

Import explicit in-scope inventory for an operator-designated account; no cloud API or asset probes are made.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **cloud_enum** (`cloud-enum`) | tool | oss | pipx | `cloud_enum` · `cloud_enum -h` | [https://github.com/initstring/cloud_enum](https://github.com/initstring/cloud_enum) | Active; authorization required.  |
| **Cloudlist** (`cloudlist`) | tool | oss | go | `cloudlist` · `cloudlist -version` | [https://github.com/projectdiscovery/cloudlist](https://github.com/projectdiscovery/cloudlist) | — |
| **CloudSplaining** (`cloudsplaining`) | tool | oss | pipx | `cloudsplaining` · `cloudsplaining --version` | [https://github.com/salesforce/cloudsplaining](https://github.com/salesforce/cloudsplaining) | — |
| **Prowler** (`prowler`) | tool | oss | pipx | `prowler` · `prowler --version` | [https://github.com/prowler-cloud/prowler](https://github.com/prowler-cloud/prowler) | — |
| **S3Scanner** (`s3scanner`) | tool | oss | go | `s3scanner` · `s3scanner --version` | [https://github.com/sa7mon/S3Scanner](https://github.com/sa7mon/S3Scanner) | Active; authorization required.  |
| **ScoutSuite** (`scoutsuite`) | tool | oss | pipx | `scoutsuite` · `scoutsuite --version` | [https://github.com/nccgroup/ScoutSuite](https://github.com/nccgroup/ScoutSuite) | — |

## P15 — Git & secret exposure

Check for exposed VCS metadata and scan client code for secrets.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Built-in git exposure check** (`builtin-git-exposure`) | http_api | oss | manual_note | — | [https://github.com/fx-sys/Ultrecon](https://github.com/fx-sys/Ultrecon) | — |
| **detect-secrets** (`detect-secrets`) | tool | oss | pipx | `detect-secrets` · `detect-secrets --version` | [https://github.com/Yelp/detect-secrets](https://github.com/Yelp/detect-secrets) | — |
| **GitDorker** (`gitdorker`) | tool | oss | pipx | `GitDorker` · `GitDorker -h` | [https://github.com/obheda12/GitDorker](https://github.com/obheda12/GitDorker) | — |
| **Gitleaks** (`gitleaks`) | tool | oss | go | `gitleaks` · `gitleaks version` | [https://github.com/gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | — |
| **Nosey Parker** (`noseyparker`) | tool | oss | git | `noseyparker` · `noseyparker --version` | [https://github.com/praetorian-inc/noseyparker](https://github.com/praetorian-inc/noseyparker) | — |
| **Semgrep** (`semgrep`) | tool | oss | pipx | `semgrep` · `semgrep --version` | [https://semgrep.dev](https://semgrep.dev) | — |
| **TruffleHog** (`trufflehog`) | tool | oss | go | `trufflehog` · `trufflehog --version` | [https://github.com/trufflesecurity/trufflehog](https://github.com/trufflesecurity/trufflehog) | — |

## P16 — CMS & framework fingerprint

Identify CMS/framework versions and known metadata endpoints.

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **CMSeeK** (`cmseek`) | tool | oss | pipx | `cmseek` · `cmseek --help` | [https://github.com/Tuhinshubhra/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK) | — |
| **droopescan** (`droopescan`) | tool | oss | pipx | `droopescan` · `droopescan --help` | [https://github.com/SamJoan/droopescan](https://github.com/SamJoan/droopescan) | — |
| **JoomScan** (`joomscan`) | tool | oss | git | `joomscan.pl` · `joomscan.pl --help` | [https://github.com/OWASP/joomscan](https://github.com/OWASP/joomscan) | — |
| **WPScan** (`wpscan`) | tool | free_tier | gem | `wpscan` · `wpscan --version` | [https://github.com/wpscanteam/wpscan](https://github.com/wpscanteam/wpscan) | Key: `WPSCAN_API_TOKEN`. The scanner itself is free; the vulnerability database token is optional. |

## P17 — Vulnerability verification

Template-based verification with free tools (active only).

| Tool / source | Type | Access | Install | Binary / check | Source | Notes |
|---|---|---|---|---|---|---|
| **Nikto** (`nikto`) | tool | oss | apt_fallback | `nikto` · `nikto -Version` | [https://github.com/sullo/nikto](https://github.com/sullo/nikto) | Active; authorization required.  |
| **Nuclei** (`nuclei`) | tool | oss | go | `nuclei` · `nuclei -version` | [https://github.com/projectdiscovery/nuclei](https://github.com/projectdiscovery/nuclei) | Active; authorization required. Community templates only; -tags takeover is also used by p02. |

## Stable report schema

JSON reports use schema version `1.0`. The top-level object contains `schema_version`, `tool`, `generated_at`, `run`, `scope`, `stats`, `tables`, and `tool_runs`. `stats` contains per-table `counts`, `total_findings`, and `tool_runs`. `tables` is keyed by the normalized tables below; row-level `extra` values are decoded as JSON when possible.

| Table | Purpose |
|---|---|
| `subdomains` | Discovered in-scope hostnames and provenance. |
| `ips` | IP addresses and network/ASN metadata. |
| `ports_services` | Port and service observations. |
| `http_hosts` | HTTP status, title, server, technologies, and URLs. |
| `endpoints` | Discovered web/API paths and endpoint metadata. |
| `js_files` | JavaScript resources and extracted analysis metadata. |
| `parameters` | Query and route parameter names. |
| `api_specs` | OpenAPI/Swagger documents and parsed operations. |
| `graphql_findings` | GraphQL endpoint and safe schema observations. |
| `cloud_assets` | Cloud assets constrained to explicitly configured own-account inventory. |
| `secrets_findings` | Redacted secret-like values and their source locations. |
| `cms_fingerprints` | CMS/framework identification and version hints. |
| `vuln_findings` | Non-destructive template-verification observations. |

Every normalized finding carries `source_tool` and `discovered_at`; the report also includes run scope, selected phases, authorization state, aggregate counts, and tool execution records. Consumers should use `schema_version` when validating compatibility.
