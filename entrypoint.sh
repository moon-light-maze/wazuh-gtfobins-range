#!/bin/bash
set -e

echo "[ENTRYPOINT] Starting Wazuh agent container initialization..."

# Replace MANAGER_IP in ossec.conf
if [ -n "$MANAGER_IP" ]; then
    echo "[ENTRYPOINT] Setting MANAGER_IP to $MANAGER_IP"
    sed -i "s|<address>MANAGER_IP</address>|<address>${MANAGER_IP}</address>|g" /var/ossec/etc/ossec.conf
    # Also set manager IP in client.keys
    sed -i "s|MANAGER_IP|${MANAGER_IP}|g" /var/ossec/etc/client.keys 2>/dev/null || true
fi

# Configure log monitoring (auth.log, syslog).
#
# Architectural notes on the idempotency check:
#   - The previous version grep'd for "/var/log/auth.log" which is too
#     loose; combined with sed's "insert before every </ossec_config>",
#     it ended up with duplicated <localfile> blocks across container
#     recreates. The fix here uses a unique marker ("GTFOBINS-EVAL-LF")
#     that only appears when WE wrote the blocks, and inserts only at
#     the LAST </ossec_config> via awk.
echo "[ENTRYPOINT] Configuring log monitoring for sudo + Sysmon detection..."
if grep -q "GTFOBINS-EVAL-LF" /var/ossec/etc/ossec.conf 2>/dev/null; then
    echo "[ENTRYPOINT] Log monitoring already configured (marker found)"
else
    echo "[ENTRYPOINT] Adding auth.log + syslog monitoring..."
    LOCALFILE_BLOCK=$(cat <<'BLOCK'

  <!-- GTFOBINS-EVAL-LF: do not remove this marker; it makes the entrypoint idempotent -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>
BLOCK
)
    # Insert before the LAST </ossec_config>, not every occurrence.
    awk -v block="$LOCALFILE_BLOCK" '
        /<\/ossec_config>/ { last_close = NR }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                if (i == last_close) print block
                print lines[i]
            }
        }
    ' /var/ossec/etc/ossec.conf > /tmp/ossec.conf.new && mv /tmp/ossec.conf.new /var/ossec/etc/ossec.conf
    echo "[ENTRYPOINT] Log monitoring added (auth.log + syslog)"
fi

# Add a realtime FIM watch on /tmp + /usr/bin + /usr/sbin so binary-rename
# evasions (cp /usr/bin/find /tmp/f) trip a high-severity alert on the
# write itself. The agent's default <syscheck> already lists these paths
# but with no realtime — the periodic scan fires every 12h, far outside
# our 20-second eval window. Adding a SECOND <syscheck> block with
# realtime="yes" merges with the default config; Wazuh keeps both sets
# of directories.
echo "[ENTRYPOINT] Configuring realtime FIM on /tmp + /usr/bin + /usr/sbin..."
if grep -q "GTFOBINS-EVAL-FIM" /var/ossec/etc/ossec.conf 2>/dev/null; then
    echo "[ENTRYPOINT] Realtime FIM already configured (marker found)"
else
    SYSCHECK_BLOCK=$(cat <<'BLOCK'

  <!-- GTFOBINS-EVAL-FIM: do not remove this marker; it makes the entrypoint idempotent.
       /tmp + /var/tmp + /dev/shm are the standard payload-drop paths.
       /home is added because the eval's most successful evasion (multi-step
       SUID via /home/testuser/) used it as a non-watched escape hatch.
       /usr/bin + /usr/sbin catch any malicious binary written to system bin
       paths. Common churn paths (.bash_history, .viminfo, .cache/) are
       excluded so legit shell activity doesn't generate FIM noise. -->
  <syscheck>
    <directories realtime="yes" check_all="yes" report_changes="yes">/tmp</directories>
    <directories realtime="yes" check_all="yes">/var/tmp</directories>
    <directories realtime="yes" check_all="yes">/dev/shm</directories>
    <directories realtime="yes" check_all="yes">/home</directories>
    <directories realtime="yes" check_all="yes">/usr/bin</directories>
    <directories realtime="yes" check_all="yes">/usr/sbin</directories>
    <ignore type="sregex">\.bash_history$|\.viminfo$|/\.cache/</ignore>
  </syscheck>
BLOCK
)
    awk -v block="$SYSCHECK_BLOCK" '
        /<\/ossec_config>/ { last_close = NR }
        { lines[NR] = $0 }
        END {
            for (i = 1; i <= NR; i++) {
                if (i == last_close) print block
                print lines[i]
            }
        }
    ' /var/ossec/etc/ossec.conf > /tmp/ossec.conf.new && mv /tmp/ossec.conf.new /var/ossec/etc/ossec.conf
    echo "[ENTRYPOINT] Realtime FIM watches added"
fi

# Wait for Wazuh manager to be reachable
echo "[ENTRYPOINT] Waiting for Wazuh manager at ${MANAGER_IP}:1514..."
max_attempts=30
attempt=1

while [ $attempt -le $max_attempts ]; do
    if nc -z ${MANAGER_IP} 1514; then
        echo "[ENTRYPOINT] Wazuh manager is reachable!"
        break
    fi
    echo "[ENTRYPOINT] Attempt $attempt/$max_attempts: Wazuh manager not ready, sleeping 5s..."
    sleep 5
    attempt=$((attempt + 1))
done

if [ $attempt -gt $max_attempts ]; then
    echo "[ENTRYPOINT] Warning: Could not connect to Wazuh manager after $max_attempts attempts. Starting agent anyway..."
fi

# Set up sudo permissions for testing GTFOBins
echo "[ENTRYPOINT] Configuring sudo permissions for testing..."
if ! grep -q "testuser ALL=(ALL) NOPASSWD:" /etc/sudoers; then
    echo 'testuser ALL=(ALL) NOPASSWD: ALL' >> /etc/sudoers
    echo "[ENTRYPOINT] Sudo permissions configured for testuser"
else
    echo "[ENTRYPOINT] Sudo permissions already configured"
fi

# Start Sysmon-for-Linux. The Microsoft package's systemd unit isn't usable
# in our slim base (no systemd as PID 1), but the binary itself runs fine —
# it just prints two harmless "systemctl: not found" lines from its install
# hooks before forking into a daemon. Two pieces are needed:
#
#   1. tracefs mounted at /sys/kernel/tracing — Sysmon's BPF programs attach
#      to tracepoints (sched/sched_process_exit etc) and need to read the
#      tracepoint id from tracefs. Docker Desktop's LinuxKit VM has tracefs
#      compiled in but doesn't expose it inside containers; with
#      privileged: true we can mount it ourselves.
#   2. `sysmon -i <config> -service` — what the systemd unit normally runs.
#      Copies binary/config to /opt/sysmon/ and forks into a daemon that
#      writes events to /var/log/syslog (which Wazuh is already monitoring).
echo "[ENTRYPOINT] Mounting tracefs for Sysmon eBPF tracepoints..."
if mountpoint -q /sys/kernel/tracing; then
    echo "[ENTRYPOINT] tracefs already mounted"
else
    if mount -t tracefs nodev /sys/kernel/tracing 2>&1; then
        echo "[ENTRYPOINT] tracefs mounted at /sys/kernel/tracing"
    else
        echo "[ENTRYPOINT] WARNING: tracefs mount failed — Sysmon BPF will not attach"
    fi
fi

# Sysmon launch is two-step:
#   (a) `/usr/bin/sysmon -accepteula -i <config>` — copies binary + eBPF .o
#       files + config to /opt/sysmon/. Without `-service` it does the install
#       half only; the systemctl invocations at the end fail harmlessly with
#       "systemctl: not found". Doing this synchronously (without `-service`)
#       avoids a race where `-service` mode can fork before /opt/sysmon is
#       fully populated.
#   (b) `/opt/sysmon/sysmon -i /opt/sysmon/config.xml -service` — what the
#       Microsoft-shipped systemd unit normally runs. Forks into a daemon
#       that loads the eBPF program and writes events to /var/log/syslog.
echo "[ENTRYPOINT] Installing Sysmon (copy binary + config to /opt/sysmon)..."
/usr/bin/sysmon -accepteula -i /sysmon-config.xml > /var/log/sysmon.out 2>&1 || true

echo "[ENTRYPOINT] Starting Sysmon-for-Linux daemon..."
nohup /opt/sysmon/sysmon -i /opt/sysmon/config.xml -service >> /var/log/sysmon.out 2>&1 &
disown
sleep 4
if pgrep -x sysmon > /dev/null; then
    echo "[ENTRYPOINT] Sysmon running (PIDs: $(pgrep -x sysmon | tr '\n' ' '))"
else
    echo "[ENTRYPOINT] WARNING: Sysmon failed to start — last 15 lines of /var/log/sysmon.out:"
    tail -15 /var/log/sysmon.out 2>&1
fi

# Sysmon (above) is the sole process-event source. We previously also
# started auditd, but on Docker Desktop the kernel rejects auditd's
# `set-enable` netlink message (`type=DAEMON_ABORT op=set-enable
# res=failed`) even with privileged + seccomp:unconfined + AUDIT_*
# caps. Sysmon's eBPF telemetry covers the same ground (every execve,
# file access on watched paths, process tree with hashes), so auditd
# is not needed here.

# Start rsyslog for sudo command logging (try multiple methods)
echo "[ENTRYPOINT] Starting rsyslog for sudo and Sysmon logging..."
rsyslogd || service rsyslog start || echo "[ENTRYPOINT] Warning: Could not start rsyslog"

# Test sudo command logging
echo "[ENTRYPOINT] Testing sudo command logging..."
logger -p auth.info "SUDO_CMD: root /root test sudo logging"
sleep 2
if [ -f /var/log/auth.log ] && grep -q "test sudo logging" /var/log/auth.log; then
    echo "[ENTRYPOINT] Sudo command logging is working correctly"
else
    echo "[ENTRYPOINT] Warning: Sudo command logging may not be working properly"
    echo "[ENTRYPOINT] Creating auth.log manually..."
    touch /var/log/auth.log
    chmod 644 /var/log/auth.log
fi

# Validate ossec.conf before starting agent
echo "[ENTRYPOINT] Validating Wazuh configuration..."
if /var/ossec/bin/wazuh-control status 2>&1 | grep -q "Configuration error"; then
    echo "[ENTRYPOINT] ERROR: Configuration validation failed"
    echo "[ENTRYPOINT] Showing last 10 lines of ossec.conf:"
    tail -10 /var/ossec/etc/ossec.conf
    exit 1
fi

# Start Wazuh agent
echo "[ENTRYPOINT] Starting Wazuh agent..."
/var/ossec/bin/wazuh-control start

# Wait for agent to initialize
sleep 5

# Show agent status
echo "[ENTRYPOINT] Agent status:"
/var/ossec/bin/wazuh-control status

# Verify auth.log monitoring is configured
echo "[ENTRYPOINT] Checking auth.log monitoring configuration..."
if grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    echo "[ENTRYPOINT] Auth.log monitoring is configured and active"
else
    echo "[ENTRYPOINT] WARNING: Auth.log monitoring not found in configuration"
fi

echo "[ENTRYPOINT] Agent started successfully. Ready for GTFOBins testing with Sysmon detection."
echo "[ENTRYPOINT] Sysmon status: $(pgrep -x sysmon > /dev/null && echo 'running' || echo 'not running')"
echo "[ENTRYPOINT] Sudo commands will be logged to: /var/log/auth.log"
echo "[ENTRYPOINT] Sysmon events will be logged to: /var/log/syslog"
echo "[ENTRYPOINT] Wazuh will process both logs for GTFOBins detection"
echo "[ENTRYPOINT] rsyslog status: $(pgrep rsyslogd > /dev/null && echo 'running' || echo 'not running')"

# Keep container alive and show agent logs
tail -f /var/ossec/logs/ossec.log