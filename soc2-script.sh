#!/bin/bash
# soc2-audit.sh - 2026-10-14 - Combined IDS + recon + SOC2 pentest, dated output
#
# Authorized testing only. Edit the CONFIG block before running.

set -u

# ---------------- CONFIG ----------------
IFACE="eth0"
NETWORK="10.1.10.0/24"
DNS_SERVER="10.1.10.201"
WEB_TARGET="http://10.1.10.200"       # set to the web host to test
IDS_DURATION=30                       # seconds to run IDS capture
USERS_FILE="users.txt"                # for Hydra
PASS_FILE="passwords.txt"             # for Hydra
HASH_FILE="hashes.txt"                # for John
WORDLIST="/usr/share/wordlists/rockyou.txt"
HANDSHAKE="handshake.cap"             # for Aircrack
BSSID=""                              # target BSSID for Aircrack, blank = skip
RUN_IDS=true                          # IDS capture is noisy; toggle off if not needed
RUN_ATTACKS=true                      # Hydra/Responder/CrackMap/Aircrack; toggle off for recon-only
# ----------------------------------------

[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

DATE_DIR="/root/scans/$(date +%Y-%m-%d)/run_$(date +%H%M%S)"   # absolute: ZAP cd's into its own dir
mkdir -p "$DATE_DIR"
REPORT="$DATE_DIR/report.html"
exec > >(tee -a "$DATE_DIR/console.txt") 2>&1

echo "SOC2 audit -> $DATE_DIR"

# Run a tool only if it is installed; otherwise note it and move on
have() { command -v "$1" >/dev/null 2>&1; }
skip() { echo "[skip] $1 not installed"; echo "<h2>$2</h2><pre>$1 not installed</pre>" >> "$REPORT"; }

# Append a tool's output file as an HTML section
section() { echo "<h2>$1</h2><pre>$(tr -d '\000' < "$2" 2>/dev/null)</pre>" >> "$REPORT"; }

# ---------------- REPORT HEADER ----------------
cat > "$REPORT" <<EOF
<html><head><title>SOC2 Audit Report</title>
<style>body{font-family:Arial,sans-serif;margin:20px}
h1{color:#036}h2{border-bottom:2px solid #036;padding-bottom:5px}
pre{background:#f4f4f4;padding:10px;border-radius:5px;overflow:auto}</style>
</head><body>
<h1>SOC2 Audit Report</h1><p>Target: $NETWORK — Generated $(date)</p>
EOF

# ---------------- IDS CAPTURE ----------------
run_ids() {
  echo "IDS capture on $IFACE for ${IDS_DURATION}s..."
  have snort    && snort -A fast -c /etc/snort/snort.conf -l "$DATE_DIR" -i "$IFACE" >/dev/null 2>&1 &
  have suricata && suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --runmode=autofp -l "$DATE_DIR" >/dev/null 2>&1 &
  have zeek     && ( cd "$DATE_DIR" && zeek -C -i "$IFACE" >/dev/null 2>&1 ) &
  sleep "$IDS_DURATION"
  pkill -x snort suricata zeek 2>/dev/null
  echo "<h2>IDS Capture</h2><pre>Logs saved in $DATE_DIR</pre>" >> "$REPORT"
}

# ---------------- RECON ----------------
run_recon() {
  if have nmap; then
    echo "Nmap discovery + service scan..."
    nmap -sn --dns-servers "$DNS_SERVER" "$NETWORK" -oG - | awk '/Up$/{print $2}' > "$DATE_DIR/live_hosts.txt"
    nmap -sV -oN "$DATE_DIR/nmap.txt" -iL "$DATE_DIR/live_hosts.txt"
    section "Nmap Scan" "$DATE_DIR/nmap.txt"
  else skip nmap "Nmap Scan"; fi

  if have masscan; then
    echo "Masscan full-port sweep..."
    masscan -p1-65535 --rate 10000 "$NETWORK" -oL "$DATE_DIR/masscan.txt"
    section "Masscan" "$DATE_DIR/masscan.txt"
  else skip masscan "Masscan"; fi

  if have nikto; then
    echo "Nikto web scan on $WEB_TARGET..."
    nikto -h "$WEB_TARGET" -output "$DATE_DIR/nikto.txt"
    section "Nikto Web Scan" "$DATE_DIR/nikto.txt"
  else skip nikto "Nikto Web Scan"; fi

  if have zaproxy; then
    echo "OWASP ZAP quick scan..."
    zaproxy -cmd -quickurl "$WEB_TARGET" -quickout "$DATE_DIR/zap.html" > "$DATE_DIR/zap.txt" 2>&1
    echo "<h2>OWASP ZAP</h2><p>See <a href='zap.html'>full report</a>.</p>" >> "$REPORT"
  else skip zaproxy "OWASP ZAP"; fi
}

# ---------------- ATTACK / CREDENTIAL ----------------
run_attacks() {
  if have responder; then
    echo "Responder (background)..."
    responder -I "$IFACE" -w -f -d > "$DATE_DIR/responder.txt" 2>&1 &
    RESP_PID=$!
  fi
  if have crackmapexec; then
    echo "CrackMapExec SMB enum..."
    crackmapexec smb "$NETWORK" > "$DATE_DIR/crackmap.txt" 2>&1
    section "CrackMapExec" "$DATE_DIR/crackmap.txt"
  else skip crackmapexec "CrackMapExec"; fi

  if have hydra && [ -f "$USERS_FILE" ] && [ -f "$PASS_FILE" ]; then
    echo "Hydra SSH brute-force..."
    hydra -L "$USERS_FILE" -P "$PASS_FILE" "ssh://$NETWORK" -o "$DATE_DIR/hydra.txt" 2>&1
    section "Hydra" "$DATE_DIR/hydra.txt"
  else skip hydra "Hydra"; fi

  if have john && [ -f "$HASH_FILE" ]; then
    echo "John cracking hashes..."
    john "$HASH_FILE" --format=NT --wordlist="$WORDLIST" > "$DATE_DIR/john.txt" 2>&1
    section "John the Ripper" "$DATE_DIR/john.txt"
  else skip john "John the Ripper"; fi

  if have aircrack-ng && [ -n "$BSSID" ] && [ -f "$HANDSHAKE" ]; then
    echo "Aircrack-ng on handshake..."
    aircrack-ng -w "$WORDLIST" -b "$BSSID" "$HANDSHAKE" > "$DATE_DIR/aircrack.txt" 2>&1
    section "Aircrack-ng" "$DATE_DIR/aircrack.txt"
  else skip aircrack-ng "Aircrack-ng"; fi

  [ -n "${RESP_PID:-}" ] && { kill "$RESP_PID" 2>/dev/null; section "Responder" "$DATE_DIR/responder.txt"; }
}

# ---------------- HARDENING ----------------
run_hardening() {
  if have lynis; then
    echo "Lynis audit..."
    lynis audit system --quick > "$DATE_DIR/lynis.txt" 2>&1
    section "Lynis Hardening Audit" "$DATE_DIR/lynis.txt"
  else skip lynis "Lynis Hardening Audit"; fi

  if have openvas; then
    echo "OpenVAS scan..."
    have greenbone-feed-sync && greenbone-feed-sync >/dev/null 2>&1
    openvas --target="$NETWORK" --output="$DATE_DIR/openvas.html" 2>&1
    echo "<h2>OpenVAS</h2><p>See <a href='openvas.html'>full report</a>.</p>" >> "$REPORT"
  else skip openvas "OpenVAS"; fi
}

# ---------------- RUN ----------------
$RUN_IDS && run_ids
run_recon
$RUN_ATTACKS && run_attacks
run_hardening

echo "</body></html>" >> "$REPORT"
echo "Done. Report: $REPORT"
