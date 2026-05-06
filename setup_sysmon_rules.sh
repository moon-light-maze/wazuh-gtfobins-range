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

# Copy our custom GTFOBins detection rules (children of 200151 that fire at
# level 10 with technique-specific descriptions). These are what give the
# eval its signal — without them, the only firing rules are the SOCFortress
# level-3 catch-alls which mark every command as detected.
echo "[SETUP] Installing custom GTFOBins detection rules..."
# Filename is 200160 so it sorts AFTER 200150-sysmon_for_linux_rules.xml
# (parent 200151 must exist when our children load) and BEFORE
# 200200-osquery.xml (a slot collision). Rule IDs themselves are
# 100200-100213 (private, no conflict with SOCFortress catalog).
docker exec $WAZUH_MGR cp /socfortress_rules/200160-gtfobins_detection_rules.xml /var/ossec/etc/rules/

# Install the GTFOBins CDB allowlist used by rule 100213 (sudo executed
# unapproved binary). The manager auto-compiles to .cdb on restart; we
# also need to register the list under <ruleset> in ossec.conf so the
# rule's lookup="not_match_key" reference resolves.
echo "[SETUP] Installing GTFOBins approved-sudo-binaries CDB allowlist..."
docker exec $WAZUH_MGR cp /socfortress_rules/cdblists/gtfobins-approved-sudo-binaries /var/ossec/etc/lists/
docker exec $WAZUH_MGR sh -c '
  CONF=/var/ossec/etc/ossec.conf
  if ! grep -q "etc/lists/gtfobins-approved-sudo-binaries" "$CONF"; then
    # Insert our <list> entry just before </ruleset> (the LAST one).
    awk "
      /<\/ruleset>/ { last_close = NR }
      { lines[NR] = \$0 }
      END {
        for (i = 1; i <= NR; i++) {
          if (i == last_close) print \"    <list>etc/lists/gtfobins-approved-sudo-binaries</list>\"
          print lines[i]
        }
      }
    " "$CONF" > /tmp/ossec.conf.new && mv /tmp/ossec.conf.new "$CONF"
    chown wazuh:wazuh "$CONF"
    echo "[SETUP] Registered CDB list in ossec.conf <ruleset>"
  else
    echo "[SETUP] CDB list already registered in ossec.conf"
  fi
'

# auditd rules deliberately omitted — auditd doesn't run in this stack
# (Docker Desktop kernel rejects auditd's set-enable). Sysmon covers the
# same ground via eBPF.

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
