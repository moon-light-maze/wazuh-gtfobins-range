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

# Configure auth.log and syslog monitoring for sudo and Sysmon detection
echo "[ENTRYPOINT] Configuring log monitoring for sudo and Sysmon detection..."
if ! grep -q "/var/log/auth.log" /var/ossec/etc/ossec.conf; then
    echo "[ENTRYPOINT] Adding auth.log and syslog monitoring..."
    sed -i '/<\/ossec_config>/i\
\
  <!-- Auth log monitoring for sudo detection -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/auth.log</location>\
  </localfile>\
\
  <!-- Syslog monitoring for Sysmon events -->\
  <localfile>\
    <log_format>syslog</log_format>\
    <location>/var/log/syslog</location>\
  </localfile>' /var/ossec/etc/ossec.conf
    echo "[ENTRYPOINT] Auth.log and syslog monitoring added successfully"
else
    echo "[ENTRYPOINT] Log monitoring already configured"
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

# Install and start Sysmon for Linux. The Microsoft package's -i flag
# tries to register a systemd unit, but debian:bookworm-slim has no
# systemd inside the container — systemctl is missing. We let the install
# attempt fail non-fatally and continue so the Wazuh agent + auth.log +
# auditd path still works. The eval loses Sysmon process-event telemetry
# but Wazuh's correlation rules over auth.log/syslog still cover a
# meaningful chunk of GTFOBins activity.
echo "[ENTRYPOINT] Installing Sysmon for Linux configuration..."
if [ -f /sysmon-config.xml ]; then
    if sysmon -accepteula -i /sysmon-config.xml 2>&1; then
        echo "[ENTRYPOINT] Sysmon for Linux installed with GTFOBins detection config"
    else
        echo "[ENTRYPOINT] WARNING: Sysmon install failed (no systemd in container) — continuing without Sysmon telemetry"
    fi
else
    sysmon -accepteula -i 2>&1 || echo "[ENTRYPOINT] WARNING: Sysmon install failed"
fi

# Verify Sysmon is running (informational only — not a hard requirement)
if pgrep -x sysmon > /dev/null; then
    echo "[ENTRYPOINT] Sysmon is running (PID: $(pgrep -x sysmon))"
else
    echo "[ENTRYPOINT] Sysmon not running — eval will rely on Wazuh auth.log/auditd/SOCFortress rules only"
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