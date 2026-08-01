# 📦 [项目说明](README.md) | [Project](README.en.md) | [اطلاعات پروژه](README.fa.md)

> Repository: https://github.com/livingfree2023/nokey

Many popular "one-click" scripts nowadays have become ~~bloated~~ feature-rich, ~~lost their original purpose~~ very advanced.

So I decided to package my own DIY experience into a **truly** one-click script and share it.

This modified script is even more aggressive than standard one-clicks—so what should I call it? Zero-click? Well, you do still have to press Enter… but if scripts that require 101 keystrokes still call themselves "one-click," I’ll shamelessly call mine "**NoKey**."

No domain required. Perfect for both seasoned users who love tinkering and total beginners who want a hassle-free setup.

Run a single command, sit back, and wait. No chatter, no fuss—super fast. Ready to race any other script 🚀 Speed is my specialty.

> In testing, even a modest 1vCPU/1GB RAM VPS completed setup in under 20 seconds. Ideal for busy users.
> Also verified to run on an Alpine pod with only 64MB RAM.

---

# ⚙️ Features (without passing any parameters, it goes from a fresh machine to installing BBR + FQ)

1. Skips unnecessary `apt` updates automatically  
2. Skips redundant `geodata` updates  
3. Generates UUID/KeyPair using official commands  
4. Auto-detects a random free port  
5. Adapts across multiple Linux distributions  
6. Downloads prebuilt Xray binaries directly (amd64/arm64)  
7. Accepts parameters for protocol stack, UUID, SNI, port  
8. Shows help with `--help`  
9. Outputs only minimal steps—detailed logs saved to a file  
10. Generates QR codes  
11. `--realm` mode — installs Realm relay proxy alongside Xray (`--remote` required, `--listen` optional)
12. `--realm-only` mode — installs Realm relay proxy only (without Xray)
13. Auto-probes a feasible REALITY target SNI (mirrors 3x-ui's REALITY Target Scanner; verifies TLS 1.3 + HTTP/2)
14. More features coming soon...

---

# 📦 Why binaries are downloaded from this repo

`nokey.sh` downloads `xray_amd64/xray_arm64/realm_amd64/realm_arm64/geoip.dat/geosite.dat` from this repository's Releases instead of pulling and extracting official ZIP packages during install.

Why:

1. Lower CPU and RAM usage during install, which improves success rate on tiny instances (especially Alpine low-memory pods).
2. Fewer external dependencies and a shorter install path.
3. More controlled install inputs instead of executing a heavier install chain on the target host.

These release assets are generated/synced by GitHub Actions. See: [`./.github/workflows/blank.yml`](.github/workflows/blank.yml).

---

# 🧑‍🍳 How to Use (as root)

```bash
curl -fsSL -o /usr/local/bin/nokey https://raw.githubusercontent.com/livingfree2023/nokey/refs/heads/main/nokey.sh && chmod +x /usr/local/bin/nokey && nokey
```

---

# 🔍 Dry-run (preview without changing system)

```bash
nokey --dry-run
```

---

# 🔁 Realm relay proxy

### Scenario 1 — Install Xray + Realm (both)
```bash
# Install Xray and Realm, forward local 443 to 1.2.3.4:443
nokey --realm --remote 1.2.3.4:443

# With custom listen address
nokey --realm --remote 1.2.3.4:443 --listen 0.0.0.0:8080

# Over IPv6
nokey --netstack=6 --realm --remote [2001:db8::1]:443
```

### Scenario 2 — Install Xray only (default, no flags needed)
```bash
nokey
```

### Scenario 3 — Install Realm only (without Xray)
```bash
nokey --realm-only --remote 1.2.3.4:443
```

---

# 🧹 Uninstall

```bash
nokey --remove              # uninstall Xray (also Realm if installed)
nokey --realm-only --remove  # uninstall Realm only
```

---

# ⭐ Please give it a star :)

Mistakes are inevitable—feedback is welcome!

_Forked from https://github.com/crazypeace/ — thanks to the original author._

---

If you’d like, I can help you write a localized README that switches between this translation and the original using links or folders. Just say the word!
