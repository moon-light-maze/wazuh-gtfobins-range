#!/bin/bash
# Setup script to copy SOCFortress rules and decoders to Wazuh manager

echo "[SETUP] Copying SOCFortress rules and decoders to Wazuh manager..."

# Wait for manager to be fully started
sleep 10

# Copy Linux Sysmon decoder
echo "[SETUP] Installing Sysmon for Linux decoder..."
docker exec wazuh-inspect-range-wazuh.manager-1 cp /socfortress_rules/decoder-linux-sysmon.xml /var/ossec/etc/decoders/

# Copy Sysmon for Linux rules
echo "[SETUP] Installing Sysmon for Linux detection rules..."
docker exec wazuh-inspect-range-wazuh.manager-1 cp /socfortress_rules/200150-sysmon_for_linux_rules.xml /var/ossec/etc/rules/

# Copy auditd rules (for additional coverage)
echo "[SETUP] Installing auditd detection rules..."
docker exec wazuh-inspect-range-wazuh.manager-1 cp /socfortress_rules/200110-auditd.xml /var/ossec/etc/rules/
docker exec wazuh-inspect-range-wazuh.manager-1 cp /socfortress_rules/auditd_decoders.xml /var/ossec/etc/decoders/

# Set proper ownership
echo "[SETUP] Setting proper ownership on rules and decoders..."
docker exec wazuh-inspect-range-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/*.xml
docker exec wazuh-inspect-range-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/decoders/*.xml

# Restart Wazuh manager to load new rules
echo "[SETUP] Restarting Wazuh manager to load new rules..."
docker exec wazuh-inspect-range-wazuh.manager-1 /var/ossec/bin/wazuh-control restart

# Wait for restart
sleep 15

# Verify rules are loaded
echo "[SETUP] Verifying Sysmon rules are loaded..."
docker exec wazuh-inspect-range-wazuh.manager-1 grep -c "sysmon-linux" /var/ossec/etc/decoders/decoder-linux-sysmon.xml

echo "[SETUP] SOCFortress rules installation complete!"
echo "[SETUP] Sysmon for Linux detection is now active on all target containers."
