#!/bin/bash
# soc2-audit.sh - 2026-10-14 - Combined IDS + recon + SOC2 pentest, parallel + dated output
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
RUN_ATTACKS=true                      # Hydra/Responder/NetExec/Aircrack; toggle off for recon-only
# ----------------------------------------

[ "$EUID" -ne 0 ] && { echo "Run as root"; exit 1; }

DATE_DIR="/root/scans/$(date +%Y-%m-%d)/run_$(date +%H%M%S)"   # absolute: ZAP cd's into its own dir
mkdir -p "$DATE_DIR"
REPORT="$DATE_DIR/report.html"
exec > >(tee -a "$DATE_DIR/console.txt") 2>&1

CORES=$(nproc)                         # auto-tune parallelism to vCPU count
echo "SOC2 audit -> $DATE_DIR ($CORES cores)"

have() { command -v "$1" >/dev/null 2>&1; }

# Each tool writes ONLY to its own file (no shared writes) so they can run in parallel.
# ---------------- TOOL JOBS ----------------
job_ids() {
  echo "[start] IDS capture (${IDS_DURATION}s)"
  have snort    && snort -A fast -c /etc/snort/snort.conf -l "$DATE_DIR" -i "$IFACE" >/dev/null 2>&1 &
  have suricata && suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --runmode=autofp -l "$DATE_DIR" >/dev/null 2>&1 &
  have zeek     && ( cd "$DATE_DIR" && zeek -C -i "$IFACE" >/dev/null 2>&1 ) &
  sleep "$IDS_DURATION"
  pkill -x snort suricata zeek 2>/dev/null
  echo "[done] IDS capture"
}

job_nmap() {
  have nmap || return
  echo "[start] nmap"
  nmap -sn --dns-servers "$DNS_SERVER" "$NETWORK" -oG - | awk '/Up$/{print $2}' > "$DATE_DIR/live_hosts.txt"
  # LAN-tuned: T4 timing, no rDNS, fewer retries, top 9000 ports, rate floor
  nmap -sV -T4 -n --max-retries 2 --min-rate 1000 --top-ports 9000 \
    -oN "$DATE_DIR/nmap.txt" -iL "$DATE_DIR/live_hosts.txt" >/dev/null 2>&1
  echo "[done] nmap"
}

job_masscan() {
  have masscan || return
  echo "[start] masscan"
  masscan -p1-65535 --rate 10000 "$NETWORK" -oL "$DATE_DIR/masscan.txt" >/dev/null 2>&1
  echo "[done] masscan"
}

job_nikto() {
  have nikto || return
  echo "[start] nikto"
  nikto -h "$WEB_TARGET" -output "$DATE_DIR/nikto.txt" >/dev/null 2>&1
  echo "[done] nikto"
}

job_zap() {
  have zaproxy || return
  echo "[start] zap"
  zaproxy -cmd -quickurl "$WEB_TARGET" -quickout "$DATE_DIR/zap.html" > "$DATE_DIR/zap.txt" 2>&1
  echo "[done] zap"
}

job_netexec() {
  have nxc || return
  echo "[start] netexec"
  nxc smb "$NETWORK" > "$DATE_DIR/netexec.txt" 2>&1
  echo "[done] netexec"
}

job_hydra() {
  { have hydra && [ -f "$USERS_FILE" ] && [ -f "$PASS_FILE" ]; } || return
  echo "[start] hydra"
  hydra -L "$USERS_FILE" -P "$PASS_FILE" "ssh://$NETWORK" -o "$DATE_DIR/hydra.txt" >/dev/null 2>&1
  echo "[done] hydra"
}

job_john() {
  { have john && [ -f "$HASH_FILE" ]; } || return
  echo "[start] john (fork=$1)"
  john "$HASH_FILE" --format=NT --fork="$1" --wordlist="$WORDLIST" > "$DATE_DIR/john.txt" 2>&1
  echo "[done] john"
}

job_aircrack() {
  { have aircrack-ng && [ -n "$BSSID" ] && [ -f "$HANDSHAKE" ]; } || return
  echo "[start] aircrack"
  aircrack-ng -w "$WORDLIST" -b "$BSSID" "$HANDSHAKE" > "$DATE_DIR/aircrack.txt" 2>&1
  echo "[done] aircrack"
}



# ---------------- RUN IN PARALLEL (2 WAVES) ----------------
# Wave 1: fast recon + light audits. IDS + Responder capture the scan traffic.
echo "=== Wave 1: recon ==="
if $RUN_ATTACKS && have responder; then
  echo "[start] responder (background)"
  responder -I "$IFACE" -w -d > "$DATE_DIR/responder.txt" 2>&1 &
  RESP_PID=$!
fi

$RUN_IDS && job_ids &
job_nmap &
job_masscan &
job_nikto &
job_zap &
job_netexec &

wait   # all of Wave 1 must finish first

# Stop Responder before the heavy wave
[ -n "${RESP_PID:-}" ] && kill "$RESP_PID" 2>/dev/null

# Wave 2: heavy / long-running jobs (credential cracking)
# john and aircrack are CPU-bound; give john half the cores, aircrack uses the rest.
echo "=== Wave 2: heavy scans ==="
JOHN_FORK=$(( CORES / 2 )); [ "$JOHN_FORK" -lt 1 ] && JOHN_FORK=1
if $RUN_ATTACKS; then
  job_hydra &
  job_john "$JOHN_FORK" &
  job_aircrack &
fi

wait   # all of Wave 2 must finish

echo "All jobs finished. Building report..."

# ---------------- BUILD REPORT (serial, fixed order) ----------------
cat > "$REPORT" <<EOF
<html><head><title>SOC2 Audit Report</title>
<style>body{font-family:Arial,sans-serif;margin:20px}
h1{color:#036}h2{border-bottom:2px solid #036;padding-bottom:5px}
pre{background:#f4f4f4;padding:10px;border-radius:5px;overflow:auto}</style>
</head><body>
<h1>SOC2 Audit Report</h1><p>Target: $NETWORK — Generated $(date)</p>
EOF

# Add a text section if its file exists, else note it was skipped
section() {
  if [ -s "$2" ]; then
    echo "<h2>$1</h2><pre>$(tr -d '\000' < "$2")</pre>" >> "$REPORT"
  else
    echo "<h2>$1</h2><pre>not run or no output</pre>" >> "$REPORT"
  fi
}
# Link to a standalone HTML report if it exists
link() {
  if [ -s "$2" ]; then echo "<h2>$1</h2><p>See <a href='$(basename "$2")'>full report</a>.</p>" >> "$REPORT"
  else echo "<h2>$1</h2><pre>not run</pre>" >> "$REPORT"; fi
}

$RUN_IDS && echo "<h2>IDS Capture</h2><pre>Logs saved in $DATE_DIR</pre>" >> "$REPORT"
section "Nmap Scan"          "$DATE_DIR/nmap.txt"
section "Masscan"            "$DATE_DIR/masscan.txt"
section "Nikto Web Scan"     "$DATE_DIR/nikto.txt"
link    "OWASP ZAP"          "$DATE_DIR/zap.html"
section "NetExec (SMB)"      "$DATE_DIR/netexec.txt"
section "Hydra"              "$DATE_DIR/hydra.txt"
section "John the Ripper"    "$DATE_DIR/john.txt"
section "Aircrack-ng"        "$DATE_DIR/aircrack.txt"
section "Responder"          "$DATE_DIR/responder.txt"

echo "</body></html>" >> "$REPORT"
echo "Done. Report: $REPORT"
