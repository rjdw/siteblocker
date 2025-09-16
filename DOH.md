Short answer: yes, it’s **usually safe** to block popular DNS-over-HTTPS/DoT endpoints. It won’t break normal web browsing, because you’re only blocking **DNS traffic to those specific providers** (on ports 443/853), not HTTPS to the rest of the internet. The main side effects are:

* If a browser/app tries to use **DoH/DoT** to those providers, it’ll fail and (usually) **fall back to system DNS**.
* If you **intentionally** use one of those services (e.g., NextDNS app, Cloudflare’s 1.1.1.1/WARP), that app’s DNS will be blocked—by design.
* Visiting those endpoints directly (e.g., [https://dns.google/dns-query](https://dns.google/dns-query)) won’t work—not something most people do daily.

If that sounds acceptable (it is for most people), go ahead and add `doh.txt`. If you prefer a lighter touch, see the alternatives below.

---

## What exactly gets blocked?

With the anchor I gave you:

```pf
table <dohblock> persist
block drop out quick proto { tcp, udp } to <dohblock> port { 443, 853 }
```

* Only connections to **the IPs in `<dohblock>`** on **ports 443 or 853** are dropped.
* Normal HTTPS traffic to other IPs is unaffected.
* Regular system DNS (UDP/TCP **53** to your router/ISP DNS) is **not** affected by `<dohblock>`.

So day-to-day browsing works; you just lose the ability to bypass your block via those DoH/DoT providers.

---

## Add the DoH list (safe starter set)

1. Create the list:

```bash
sudo tee /var/db/siteblocker/doh.txt >/dev/null <<'EOF'
dns.google
cloudflare-dns.com
mozilla.cloudflare-dns.com
security.cloudflare-dns.com
one.one.one.one
dns.nextdns.io
dns.quad9.net
doh.opendns.com
dns.adguard.com
dns.mullvad.net
EOF
```

2. Reapply:

```bash
sudo launchctl kickstart -k system/com.siteblocker.daemon
# or: sudo /usr/local/sbin/site-blocker.sh --auto
```

3. Verify:

```bash
sudo pfctl -t dohblock -T show | head   # should list some IPs
# quick test (should hang or fail):
curl -I https://dns.google/dns-query
```

The “pfctl: Use of -f option…” and “No ALTQ support” messages are normal on macOS.

---

## Minimal-impact alternative (even safer)

If you’re nervous about blocking specific providers, you can instead **block encrypted DNS globally** and allow only classic DNS to your router:

1. Find your router’s IP (default gateway):

```bash
route -n get default | awk '/gateway/ {print $2}'
```

Assume it prints `192.168.1.1` (use whatever you see).

2. Add two rules to the **pf anchor** (these don’t exist yet; you can add them just below the existing lines in `/etc/pf.anchors/siteblocker`):

```pf
# Allow classic DNS only to your router
pass out quick proto { tcp, udp } to 192.168.1.1 port 53
# Block all other DNS (prevents direct-to-ISP or random DNS)
block drop out quick proto { tcp, udp } to any port 53

# Block all DoT everywhere (port 853), regardless of provider
block drop out quick proto { tcp, udp } to any port 853
```

3. Reload pf:

```bash
sudo pfctl -f /etc/pf.conf
```

This approach:

* keeps your DNS going only to your router (or whatever resolver you specify),
* blocks all **DoT** everywhere,
* doesn’t care about a list of DoH IPs (you can skip `doh.txt` if you like),
* and won’t touch normal HTTPS.

You can **combine** this with the DoH list for extra coverage (DoH runs over HTTPS/443 to specific IPs).

---

## Browser-only alternative (no pf changes)

* **Chrome/Chromium/Edge:** Settings → Privacy & security → **Use secure DNS** → **Off** (or set to your router’s resolver).
* **Firefox:** Settings → Network Settings → DNS over HTTPS → **Off** (or “Use OS resolver”). In strict (mode 3), Firefox won’t fall back—so you want it off.

This won’t stop other apps from using DoH/DoT, but it’s the least invasive.

---

## Pick a mode

* **Max protection:** Add `doh.txt` **and** block all port 853 + only allow port 53 to your router.
* **Medium:** Add `doh.txt` only (what we outlined originally).
* **Light:** Turn off DoH in browsers, skip pf DoH rules.

For most users, **Medium** is perfect: no noticeable browsing impact, and it closes the most common bypass path.

Want me to patch your script to **auto-sanitize** `doh.txt` and `domains.txt` lines (strip schemes/paths), and to optionally insert the “allow router DNS + block others” rules automatically?

