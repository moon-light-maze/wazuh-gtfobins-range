#!/bin/bash
# Setup script to copy SOCFortress rules and decoders to Wazuh manager
set -e

echo "[SETUP] Copying SOCFortress rules and decoders to Wazuh manager..."

# Resolve the Wazuh manager container by compose service label rather than
# guessing the project-prefixed name.
WAZUH_MGR=$(docker ps --filter "label=com.docker.compose.service=wazuh.manager" --format "{{.Names}}" | head -1)
if [ -z "$WAZUH_MGR" ]; then
    echo "[ERROR] No running container for compose service 'wazuh.manager'."
    echo "        Run 'docker-compose up -d' first, then re-run this script."
    exit 1
fi
echo "[SETUP] Using Wazuh manager container: $WAZUH_MGR"

# Wait for manager to be fully started
sleep 10

# Copy Linux Sysmon decoder
echo "[SETUP] Installing Sysmon for Linux decoder..."
docker exec $WAZUH_MGR cp /socfortress_rules/decoder-linux-sysmon.xml /var/ossec/etc/decoders/

# Copy Sysmon for Linux rules
echo "[SETUP] Installing Sysmon for Linux detection rules..."
docker exec $WAZUH_MGR cp /socfortress_rules/200150-sysmon_for_linux_rules.xml /var/ossec/etc/rules/

# Copy auditd rules (for additional coverage)
echo "[SETUP] Installing auditd detection rules..."
docker exec $WAZUH_MGR cp /socfortress_rules/200110-auditd.xml /var/ossec/etc/rules/
docker exec $WAZUH_MGR cp /socfortress_rules/auditd_decoders.xml /var/ossec/etc/decoders/

# Set proper ownership
echo "[SETUP] Setting proper ownership on rules and decoders..."
docker exec $WAZUH_MGR chown wazuh:wazuh /var/ossec/etc/rules/*.xml
docker exec $WAZUH_MGR chown wazuh:wazuh /var/ossec/etc/decoders/*.xml

# Restart Wazuh manager to load new rules
echo "[SETUP] Restarting Wazuh manager to load new rules..."
docker exec $WAZUH_MGR /var/ossec/bin/wazuh-control restart

# Wait for restart
sleep 15

# Verify rules are loaded
echo "[SETUP] Verifying Sysmon rules are loaded..."
docker exec $WAZUH_MGR grep -c "sysmon-linux" /var/ossec/etc/decoders/decoder-linux-sysmon.xml

echo "[SETUP] SOCFortress rules installation complete!"
echo "[SETUP] Sysmon for Linux detection is now active on all target containers."
