a hardened, **self-healing** website blocker for macOS:

* DNS denial (`/etc/hosts` + `/etc/resolver`)
* **pf** firewall IP blocking (incl. common DNS-over-HTTPS endpoints)
* A **root LaunchDaemon** that **reapplies** the block at boot, hourly, and whenever protected files change
* **Immutable flags** (`chflags uchg`) to make manual edits annoying

You’ll set it up once; after that, it’ll keep re-asserting itself.

---

# 0) Heads-up (important)

* **Turn off iCloud Private Relay** and any VPN you might use to bypass local filtering. (System Settings → Apple ID → iCloud → Private Relay → Off.)
* You’ll need **sudo** (an admin account).
* All paths assume Monterey. `/etc` here is `/private/etc` under the hood—use `/etc` as shown.

---

# 1) Create the working directory and domain lists

```bash
sudo mkdir -p /var/db/siteblocker
sudo chmod 700 /var/db/siteblocker
```

## Domains to block (edit later any time)

```bash
sudo tee /var/db/siteblocker/domains.txt >/dev/null <<'EOF'
# One domain or subdomain per line (comments allowed with #)
youtube.com
www.youtube.com
m.youtube.com
youtu.be
ytimg.com
i.ytimg.com
yt3.ggpht.com
googlevideo.com
s.youtube.com
youtubei.googleapis.com
EOF
```

## Common DNS-over-HTTPS endpoints (optional but recommended)

```bash
sudo tee /var/db/siteblocker/doh.txt >/dev/null <<'EOF'
# Big DoH providers (not exhaustive). Blocking their IPs helps stop browser DoH bypass.
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

---

# 2) Install the blocker script

```bash
sudo tee /usr/local/sbin/site-blocker.sh >/dev/null <<'EOF'
#!/bin/bash
set -euo pipefail

# -------- Config / Paths --------
STATE_DIR="/var/db/siteblocker"
DOMAINS_FILE="$STATE_DIR/domains.txt"
DOH_FILE="$STATE_DIR/doh.txt"

HOSTS="/etc/hosts"
PF_CONF="/etc/pf.conf"
PF_ANCHOR="/etc/pf.anchors/siteblocker"
PF_IPSET_BLOCK="$STATE_DIR/siteblocker.ipset"
PF_IPSET_DOH="$STATE_DIR/doh.ipset"

LAUNCHD_PLIST="/Library/LaunchDaemons/com.siteblocker.daemon.plist"

RESOLVER_DIR="/etc/resolver"   # per-domain DNS stubs
RESOLVER_NS="127.0.0.1"        # send those domains nowhere

LOG="$STATE_DIR/run.log"
DATE() { date "+%Y-%m-%d %H:%M:%S"; }

# Use public DNS for resolution when computing firewall IPs
DIG_BIN="/usr/bin/dig"
DNS_UPSTREAM="1.1.1.1"  # Cloudflare (plain DNS:53), adjust if you prefer

# Markers for hosts & pf.conf
HOSTS_BEGIN="# --- SITE-BLOCKER BEGIN ---"
HOSTS_END="# --- SITE-BLOCKER END ---"
PF_BEGIN="# --- SITEBLOCKER BEGIN ---"
PF_END="# --- SITEBLOCKER END ---"

# -------- Helpers --------
log() { echo "[$(DATE)] $*" | tee -a "$LOG" >&2; }

require_root() {
  if [[ $EUID -ne 0 ]]; then
    echo "Run as root (sudo)" >&2; exit 1
  fi
}

ensure_file_backup() {
  local f="$1"
  [[ -f "$f" ]] || return 0
  local bak="${f}.siteblocker.bak.$(date +%Y%m%d%H%M%S)"
  cp "$f" "$bak"
  log "Backed up $f -> $bak"
}

toggle_immutable() {
  # $1=on|off $2=file_or_dir
  local mode="$1" target="$2"
  if [[ "$mode" == "off" ]]; then
    chflags -R nouchg "$target" 2>/dev/null || true
  else
    chflags -R uchg "$target" 2>/dev/null || true
  fi
}

flush_dns() {
  /usr/bin/dscacheutil -flushcache || true
  /usr/bin/killall -HUP mDNSResponder || true
}

base_exists() {
  [[ -s "$1" ]] || { echo ""; return 1; }
}

# Resolve A/AAAA for a hostname using explicit upstream (pre-DNS-stub phase)
resolve_ips() {
  local host="$1"
  "$DIG_BIN" +short A    "$host" @"$DNS_UPSTREAM" | sed 's/\s\+$//' || true
  "$DIG_BIN" +short AAAA "$host" @"$DNS_UPSTREAM" | sed 's/\s\+$//' || true
}

# -------- Steps --------
write_hosts_block() {
  toggle_immutable off "$HOSTS"
  ensure_file_backup "$HOSTS"
  local tmp
  tmp="$(mktemp)"

  # Remove prior block
  awk -v b="$HOSTS_BEGIN" -v e="$HOSTS_END" '
    $0==b {skip=1; next}
    $0==e {skip=0; next}
    skip!=1 {print}
  ' "$HOSTS" > "$tmp"

  {
    cat "$tmp"
    echo
    echo "$HOSTS_BEGIN"
    while IFS= read -r d; do
      [[ -z "$d" || "$d" =~ ^# ]] && continue
      printf "0.0.0.0\t%s\n" "$d"
      # Optionally also map IPv6 to ::1 (commented by default)
      # printf "::1\t%s\n" "$d"
    done < "$DOMAINS_FILE"
    echo "$HOSTS_END"
  } > "${HOSTS}.new"

  mv "${HOSTS}.new" "$HOSTS"
  rm -f "$tmp"
  toggle_immutable on "$HOSTS"
  log "hosts block updated"
}

write_resolver_stubs() {
  mkdir -p "$RESOLVER_DIR"
  # Clean existing siteblocker stubs (we tag ours via first line comment)
  # We won't delete non-siteblocker files.
  for f in "$RESOLVER_DIR"/*; do
    [[ -f "$f" ]] || continue
    if head -1 "$f" 2>/dev/null | grep -q "SITEBLOCKER-STUB"; then
      toggle_immutable off "$f"
      rm -f "$f"
    fi
  done

  # Create new stubs for each domain line (exact match)
  while IFS= read -r d; do
    [[ -z "$d" || "$d" =~ ^# ]] && continue
    local f="$RESOLVER_DIR/$d"
    printf "# SITEBLOCKER-STUB\nnameserver %s\n" "$RESOLVER_NS" > "$f"
    chmod 644 "$f"
    chown root:wheel "$f"
    toggle_immutable on "$f"
  done < "$DOMAINS_FILE"

  log "resolver stubs updated in $RESOLVER_DIR"
}

ensure_pf_anchor() {
  # Static rules; we fill tables dynamically
  if [[ ! -f "$PF_ANCHOR" ]]; then
    cat > "$PF_ANCHOR" <<'ANCHOR'
table <siteblocker> persist
table <dohblock> persist

# Drop outbound traffic to blocked destinations
block drop out quick to <siteblocker>

# Block common encrypted DNS paths (DoH/DoT)
block drop out quick proto { tcp, udp } to <dohblock> port { 443, 853 }
ANCHOR
    chmod 644 "$PF_ANCHOR"
    chown root:wheel "$PF_ANCHOR"
  fi
}

ensure_pf_include() {
  # Ensure pf.conf includes our anchor, once
  if ! grep -q "$PF_BEGIN" "$PF_CONF"; then
    toggle_immutable off "$PF_CONF"
    ensure_file_backup "$PF_CONF"
    {
      echo "$PF_BEGIN"
      echo "anchor \"siteblocker\""
      echo "load anchor \"siteblocker\" from \"$PF_ANCHOR\""
      echo "$PF_END"
    } >> "$PF_CONF"
    toggle_immutable on "$PF_CONF" || true  # optional; comment out if you don't want pf.conf immutable
    log "pf.conf updated to include anchor"
  fi
}

rebuild_pf_tables() {
  # Build IP sets from domains + doh endpoints (resolve before DNS stubs bite)
  : > "$PF_IPSET_BLOCK"
  while IFS= read -r d; do
    [[ -z "$d" || "$d" =~ ^# ]] && continue
    resolve_ips "$d" >> "$PF_IPSET_BLOCK" || true
  done < "$DOMAINS_FILE"
  sort -u "$PF_IPSET_BLOCK" -o "$PF_IPSET_BLOCK"

  : > "$PF_IPSET_DOH"
  if [[ -f "$DOH_FILE" ]]; then
    while IFS= read -r d; do
      [[ -z "$d" || "$d" =~ ^# ]] && continue
      resolve_ips "$d" >> "$PF_IPSET_DOH" || true
    done < "$DOH_FILE"
    sort -u "$PF_IPSET_DOH" -o "$PF_IPSET_DOH"
  fi

  # Enable pf, (re)load config, then replace tables
  /sbin/pfctl -E >/dev/null 2>&1 || true
  /sbin/pfctl -f "$PF_CONF" >/dev/null

  if [[ -s "$PF_IPSET_BLOCK" ]]; then
    /sbin/pfctl -t siteblocker -T replace -f "$PF_IPSET_BLOCK" >/dev/null
  else
    /sbin/pfctl -t siteblocker -T kill >/dev/null 2>&1 || true
  fi

  if [[ -s "$PF_IPSET_DOH" ]]; then
    /sbin/pfctl -t dohblock -T replace -f "$PF_IPSET_DOH" >/dev/null
  else
    /sbin/pfctl -t dohblock -T kill >/dev/null 2>&1 || true
  fi

  log "pf tables refreshed: $(wc -l < "$PF_IPSET_BLOCK") site IPs; $(wc -l < "$PF_IPSET_DOH" 2>/dev/null || echo 0) DoH IPs"
}

self_heal() {
  # Reassert everything
  ensure_pf_anchor
  ensure_pf_include
  rebuild_pf_tables
  write_hosts_block
  write_resolver_stubs
  flush_dns
}

case "${1:-apply}" in
  apply|--auto)
    require_root
    mkdir -p "$STATE_DIR"
    touch "$LOG"
    self_heal
    ;;
  show)
    echo "Blocked domains:"
    grep -v '^#' "$DOMAINS_FILE" | sed '/^$/d'
    echo
    echo "pf enabled?"; /sbin/pfctl -s info | head -n 2
    echo
    echo "siteblocker table:"; /sbin/pfctl -t siteblocker -T show || true
    ;;
  *)
    echo "Usage: $0 [apply|show]" >&2; exit 2 ;;
esac
EOF

sudo chmod 755 /usr/local/sbin/site-blocker.sh
sudo chown root:wheel /usr/local/sbin/site-blocker.sh
```

---

# 3) Install the LaunchDaemon (root, self-healing, file watchers)

```bash
sudo tee /Library/LaunchDaemons/com.siteblocker.daemon.plist >/dev/null <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key> <string>com.siteblocker.daemon</string>

    <key>ProgramArguments</key>
    <array>
      <string>/bin/bash</string>
      <string>/usr/local/sbin/site-blocker.sh</string>
      <string>--auto</string>
    </array>

    <!-- Reapply at boot -->
    <key>RunAtLoad</key> <true/>

    <!-- Reapply hourly -->
    <key>StartInterval</key> <integer>3600</integer>

    <!-- Restart if it dies -->
    <key>KeepAlive</key>
    <dict>
      <key>SuccessfulExit</key><false/>
    </dict>

    <!-- Reapply immediately if any of these change -->
    <key>WatchPaths</key>
    <array>
      <string>/etc/hosts</string>
      <string>/etc/resolver</string>
      <string>/etc/pf.conf</string>
      <string>/etc/pf.anchors/siteblocker</string>
      <string>/var/db/siteblocker/domains.txt</string>
      <string>/var/db/siteblocker/doh.txt</string>
    </array>

    <key>StandardOutPath</key> <string>/var/log/siteblocker.log</string>
    <key>StandardErrorPath</key> <string>/var/log/siteblocker.err</string>
  </dict>
</plist>
EOF

sudo chmod 644 /Library/LaunchDaemons/com.siteblocker.daemon.plist
sudo chown root:wheel /Library/LaunchDaemons/com.siteblocker.daemon.plist
```

**Load + start it now (and at every boot):**

```bash
sudo launchctl bootstrap system /Library/LaunchDaemons/com.siteblocker.daemon.plist
sudo launchctl enable system/com.siteblocker.daemon
sudo launchctl kickstart -k system/com.siteblocker.daemon
```

---

# 4) Make key files **immutable** (tamper-resistance)

The daemon can still update files because it clears and re-sets the flag in code. Manual edits become annoying unless you know to remove the flag first.

```bash
# hosts and our resolver stubs
sudo chflags uchg /etc/hosts
# mark our resolver stubs (created with a SITEBLOCKER-STUB header) immutable:
# (If you just installed, they're already flagged by the script. Run again to be sure.)
for f in /etc/resolver/*; do
  head -1 "$f" 2>/dev/null | grep -q 'SITEBLOCKER-STUB' && sudo chflags uchg "$f"
done

# pf anchor & plist
sudo chflags uchg /etc/pf.anchors/siteblocker
sudo chflags uchg /Library/LaunchDaemons/com.siteblocker.daemon.plist
```

*(Optional, more aggressive)*
You can also flag `/etc/pf.conf` immutable, but macOS rarely touches it; if you do:

```bash
sudo chflags uchg /etc/pf.conf
```

(If you ever need to edit it, run `sudo chflags nouchg /etc/pf.conf` first.)

---

# 5) Test

```bash
ping -c 1 youtube.com     # should fail to resolve or hit 0.0.0.0
scutil --dns | grep 'resolver\|nameserver' -n   # sanity check
sudo pfctl -sr | grep siteblocker               # pf rules loaded?
sudo pfctl -t siteblocker -T show | head        # IPs populated?
```

Try a browser: youtube should not load (DoH blocked, DNS stubs active, pf drops).

---

# 6) Day-to-day use

* **Add or remove sites:** edit `/var/db/siteblocker/domains.txt` (one per line), then:

  ```bash
  sudo launchctl kickstart -k system/com.siteblocker.daemon
  ```

  (The `WatchPaths` also auto-runs it when the file changes.)

* **Check logs:**
  `sudo tail -n 50 /var/log/siteblocker.log /var/log/siteblocker.err`

* **Status quick look:**
  `sudo /usr/local/sbin/site-blocker.sh show`

---

# 7) Uninstall (clean exit)

1. **Disable the LaunchDaemon**

```bash
sudo launchctl bootout system /Library/LaunchDaemons/com.siteblocker.daemon.plist || true
sudo launchctl disable system/com.siteblocker.daemon || true
```

2. **Remove immutable flags**

```bash
sudo chflags nouchg /etc/hosts /etc/pf.anchors/siteblocker /Library/LaunchDaemons/com.siteblocker.daemon.plist || true
for f in /etc/resolver/*; do
  head -1 "$f" 2>/dev/null | grep -q 'SITEBLOCKER-STUB' && sudo chflags nouchg "$f"
done
# (If you flagged /etc/pf.conf:)
# sudo chflags nouchg /etc/pf.conf
```

3. **Delete files and restore configs**

```bash
# Delete our resolver stubs
for f in /etc/resolver/*; do
  head -1 "$f" 2>/dev/null | grep -q 'SITEBLOCKER-STUB' && sudo rm -f "$f"
done

# Remove hosts block (restore from backup created earlier if you like)
sudo /usr/bin/awk -v b="# --- SITE-BLOCKER BEGIN ---" -v e="# --- SITE-BLOCKER END ---" '
  $0==b {skip=1; next}
  $0==e {skip=0; next}
  skip!=1 {print}
' /etc/hosts | sudo tee /etc/hosts.tmp >/dev/null
sudo mv /etc/hosts.tmp /etc/hosts

# Remove pf anchor include from pf.conf
sudo awk -v b="# --- SITEBLOCKER BEGIN ---" -v e="# --- SITEBLOCKER END ---" '
  $0==b {skip=1; next}
  $0==e {skip=0; next}
  skip!=1 {print}
' /etc/pf.conf | sudo tee /etc/pf.conf.tmp >/dev/null
sudo mv /etc/pf.conf.tmp /etc/pf.conf

# Reload pf with a clean config and kill our tables
sudo pfctl -f /etc/pf.conf
sudo pfctl -t siteblocker -T kill || true
sudo pfctl -t dohblock -T kill || true

# Remove artifacts
sudo rm -f /etc/pf.anchors/siteblocker
sudo rm -f /Library/LaunchDaemons/com.siteblocker.daemon.plist
sudo rm -f /usr/local/sbin/site-blocker.sh
sudo rm -rf /var/db/siteblocker
sudo rm -f /var/log/siteblocker.log /var/log/siteblocker.err || true

# Flush DNS
sudo dscacheutil -flushcache
sudo killall -HUP mDNSResponder || true
```

Reboot (or just continue) — you’re back to normal.

---

## Why this is genuinely annoying to undo

* You’d have to know **multiple mechanisms** were used (hosts, resolver stubs, pf IP tables).
* You must **unload a root LaunchDaemon** and remove immutable flags in the right order — otherwise the daemon auto-repairs your edits within seconds.
* Even if DNS is restored, **pf** quietly drops traffic to the target IPs (and to common DoH providers) so browser tricks don’t help.
* Each file is owned by **root\:wheel** and **immutable** (`uchg`), so casual GUI or `nano` edits fail until you clear flags intentionally.

---
