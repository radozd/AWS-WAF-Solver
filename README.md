<div align="center">

<br>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&duration=3000&pause=1000&color=A855F7&center=true&vCenter=true&width=500&lines=AWS+WAF+Solver">
  <source media="(prefers-color-scheme: light)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&duration=3000&pause=1000&color=7C3AED&center=true&vCenter=true&width=500&lines=AWS+WAF+Solver">
  <img alt="AWS WAF Solver" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&weight=700&size=28&duration=3000&pause=1000&color=A855F7&center=true&vCenter=true&width=500&lines=AWS+WAF+Solver">
</picture>

<br>

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=14&duration=4000&pause=2000&color=6B7280&center=true&vCenter=true&width=600&lines=pure+go+%7C+no+browser+%7C+no+hardcoded+keys+%7C+universal">
  <source media="(prefers-color-scheme: light)" srcset="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=14&duration=4000&pause=2000&color=9CA3AF&center=true&vCenter=true&width=600&lines=pure+go+%7C+no+browser+%7C+no+hardcoded+keys+%7C+universal">
  <img alt="tagline" src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=14&duration=4000&pause=2000&color=6B7280&center=true&vCenter=true&width=600&lines=pure+go+%7C+no+browser+%7C+no+hardcoded+keys+%7C+universal">
</picture>

<br><br>

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://golang.org)
[![Node](https://img.shields.io/badge/Node-18+-339933?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org)
[![License](https://img.shields.io/badge/MIT-blue?style=for-the-badge)](LICENSE)

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

</div>

<br>

### what is this

solves AWS WAF challenge tokens through pure HTTP requests with a Chrome TLS fingerprint.
dynamically extracts encryption parameters from each site's obfuscated `challenge.js` at runtime.
nothing hardcoded. works on any site behind AWS WAF.

```
  aws-waf-solver v1.0.0

  >> target  :: https://account.booking.com/sign-in

  -- fetching target page --
  ++ script  :: https://d8c14d4960ca.edge.sdk.awswaf.com/.../challenge.js

  -- extracting crypto config --
  ++ crypto  :: id=Zoey key=32B ver=2.4.0 types=1

  -- solving challenge --
  >> inner   :: NetworkBandwidth
  ++ solved  :: 0s

  -- posting solution --
  >> status  :: 200
  ++ token received directly
  ++ bypass complete -- token verified
```

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

<br>

### how it works

```
target url
    |
    v
1. fetch page html --> extract *.awswaf.com script url
    |
    v
2. download challenge.js (~1.3MB obfuscated)
    |
    v
3. node.js vm sandbox --> extract aes key, identifier, type mappings
    |
    v
4. parse challenge inputs (b64 input, hmac, region, difficulty)
    |
    v
5. build browser signals (navigator, screen, gpu, canvas, tz)
    |
    v
6. encrypt signals with aes-256-gcm
    |
    v
7. solve proof-of-work
    |-- NetworkBandwidth : zeroed buffer (1KB-10MB)
    |-- Scrypt hashcash  : find nonce with N leading zero bits
    |-- SHA2 hashcash    : find nonce with N leading zero bits
    |
    v
8. post solution + encrypted signals
    |
    v
aws-waf-token
```

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

<br>

### install

```bash
git clone https://github.com/kareeen133/AWS-WAF-Solver.git
cd AWS-WAF-Solver
go mod tidy
go build -o awswaf.exe .
```

needs go 1.21+ and node.js 18+

<br>

### usage

```bash
./awswaf.exe -url "https://example.com/protected-page"

./awswaf.exe -url "https://example.com" -proxy "1.2.3.4:8080:user:pass"

./awswaf.exe -url "https://example.com" -proxy-file proxies.txt -retries 5
```

```
flag          default                                    description
-url          https://account.booking.com/sign-in        target url
-proxy        none                                       host:port:user:pass
-proxy-file   none                                       proxy list, rotates per attempt
-retries      3                                          max solve attempts
```

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

<br>

### architecture

```
main.go             cli, retry loop, logging
solver.go           challenge extraction, signals, aes-256-gcm, pow solving
transport.go        tls-client (chrome 131), cookie jar, header ordering
extract_config.js   deobfuscate challenge.js via node.js vm sandbox
```

```
tls-client           chrome 131 tls fingerprint (ja3/ja4)
fhttp                http/2 with custom header ordering
brotli               brotli decompression
x/crypto/scrypt      scrypt pow solver
```

<br>

### signals

```
navigator       useragent, platform, hardwareconcurrency, devicememory, webdriver=false
screen          width, height, colordepth, pixeldepth
window          innerwidth, innerheight, devicepixelratio
gpu             vendor, renderer (nvidia/intel/amd), extensions
canvas          fingerprint hash
math            17 constant fingerprints
timezone        offset + iana name
fonts           count + hash
plugins         count + hash
stealth         webdriver, phantom, selenium, domautomation checks
battery         charging state + level
```

encrypted with aes-256-gcm, formatted as `base64(nonce)::tagHex::ciphertextHex`

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

<br>

### tested on

```
booking.com       working
food.grab.com     working
binance.com       working
```

<br>

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=12,14,20&height=1&section=header" width="100%">

<br>

<div align="center">

built by **[kareeen133](https://github.com/kareeen133)**

dc: **seb.ian (seb)**

<br>

<sub>for educational and authorized security research purposes only</sub>

<br>

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=12,14,20&height=80&section=footer" width="100%">

</div>
