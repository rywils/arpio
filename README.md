## arpio

(Linux + MacOS)
Fast, minimal LAN discovery using ARP and mDNS.
Single binary.

---

### Features

* Active ARP discovery (Linux + macOS)
* Passive ARP listening
* mDNS hostname discovery
* Live watch mode
* JSON output
* Auto interface detection or manual override
* Vendor enrichment via OUI database files (with fallback)
* Safer scan behavior (skips self/network/broadcast targets)
* Timeout-safe packet collection in active and passive modes

---

Build
```bash
go build
```

> ARP requires elevated privileges.

--- 

### Usage
Active scan
```bash
sudo ./arpio scan
```

Passive scan (listen only)
```bash
sudo ./arpio scan --passive
```
JSON output
```bash
sudo ./arpio scan --json
```
Select interface
```bash
sudo ./arpio scan --iface en0
```
Disable mDNS
```bash
sudo ./arpio scan --mdns=false
```

Set scan timeout
```bash
sudo ./arpio scan --timeout 5s
```

---

Watch mode (live table)
```bash
sudo ./arpio watch
sudo ./arpio watch --iface en0 --interval 2s
```

Passive watch:
```bash
sudo ./arpio watch --passive
```

Disable mDNS in watch mode
```bash
sudo ./arpio watch --mdns=false
```

---

### Output fields

* `IP` - IPv4 address discovered by ARP
* `MAC` - hardware address
* `VENDOR` - resolved from OUI prefix if available
* `HOSTNAME` - inferred from mDNS A/AAAA responses when enabled

---

Notes

* Linux uses native ARP sockets
* macOS uses pcap for ARP capture and injection
* Results depend on network activity and privileges
* Vendor lookup prefers external OUI data when available:
  * `ARPIO_OUI_DB` (explicit file path)
  * `/usr/share/arp-scan/ieee-oui.txt`
  * `/usr/share/ieee-data/oui.txt`
  * `/usr/share/misc/oui.txt`
  * `~/.local/share/arpio/oui.txt` and `~/.config/arpio/oui.txt`
* Falls back to built-in OUI prefixes when no file is available
* Supported OUI line formats:
  * `XX-XX-XX   (base 16)   Vendor Name`
  * `XX-XX-XX,Vendor Name` or `XX:XX:XX,Vendor Name`

---

### Development

Run local verification:

```bash
go test ./...
go build ./...
go vet ./...
```

CI runs the same checks on push and pull request.

---

License

MIT

---
