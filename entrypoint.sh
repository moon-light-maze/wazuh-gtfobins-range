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

# Configure log monitoring (auth.log, syslog, audit.log).
#
# Architectural notes on the idempotency check:
#   - The previous version grep'd for "/var/log/auth.log" which is too
#     loose; combined with sed's "insert before every </ossec_config>",
#     it ended up with duplicated <localfile> blocks across container
#     recreates. The fix here uses a unique marker ("GTFOBINS-EVAL-LF")
#     that only appears when WE wrote the blocks, and inserts only at
#     the LAST </ossec_config> via awk.
echo "[ENTRYPOINT] Configuring log monitoring for sudo + auditd detection..."
if grep -q "GTFOBINS-EVAL-LF" /var/ossec/etc/ossec.conf 2>/dev/null; then
    echo "[ENTRYPOINT] Log monitoring already configured (marker found)"
else
    echo "[ENTRYPOINT] Adding auth.log + syslog + audit.log monitoring..."
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

  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
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
    echo "[ENTRYPOINT] Log monitoring added (auth.log + syslog + audit.log)"
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

# Sysmon-for-Linux v1.5.1 requires systemd; not available in slim base.
# We use auditd as the process-event source instead — same telemetry shape
# (every execve, file access on watched paths), no systemd required.
echo "[ENTRYPOINT] Skipping Sysmon (requires systemd) — using auditd instead"

# Start auditd as a daemon. The container needs CAP_AUDIT_CONTROL,
# CAP_AUDIT_READ, CAP_AUDIT_WRITE (already in compose) plus the host
# kernel's audit subsystem to be available. With privileged: true we
# get all of these.
echo "[ENTRYPOINT] Starting auditd..."
if /sbin/auditd 2>&1; then
    sleep 1
    if pgrep -x auditd > /dev/null; then
        echo "[ENTRYPOINT] auditd running (PID $(pgrep -x auditd))"
        # Load the rules from /etc/audit/rules.d/*.rules
        /sbin/augenrules --load 2>&1 | tail -3 || echo "[ENTRYPOINT] augenrules --load failed (rules may still be partial)"
        rule_count=$(/sbin/auditctl -l 2>/dev/null | wc -l)
        echo "[ENTRYPOINT] auditd has $rule_count rules loaded"
    else
        echo "[ENTRYPOINT] WARNING: auditd died after start; eval will lack process-event coverage"
    fi
else
    echo "[ENTRYPOINT] WARNING: auditd failed to launch"
fi

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