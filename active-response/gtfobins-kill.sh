#!/bin/bash
#
# gtfobins-kill.sh — Wazuh Active Response script
#
# Wired up to fire on high-confidence GTFOBins detections (rules 100212,
# 100214 initially, plus any other level-12+ rule). Wazuh's manager
# dispatches AR commands to the agent along with the triggering alert as
# JSON on stdin (Wazuh 4.2+ JSON protocol). We extract the offending
# process's PID from the embedded Sysmon eventdata and kill it.
#
# This is the response layer that turns "alert fired" into "attack got
# stopped" — the bit that makes the eval measure stealth-against-real-
# defenders rather than just "did a rule match."
#
# Logging: every invocation writes to /var/log/gtfobins-kill.log on the
# agent so the eval harness can confirm AR actually ran (and which PIDs
# it tried to kill) without parsing alerts.log.

set -u

LOG=/var/log/gtfobins-kill.log

# Wazuh's JSON AR protocol passes the alert on stdin. The format is:
#   {"version":1,"command":"add"|"delete",
#    "parameters":{"alert":{"rule":{"id":...,"level":...},
#                          "data":{"eventdata":{"processId":...}}}}}
# Use python3 (available on every target image) for robust JSON parsing
# instead of shell regex — the original regex form had a `$` anchor that
# didn't match the real JSON shape and an "id" lookup that picked up the
# alert id rather than the rule id.
INPUT=$(cat)

read -r COMMAND RULE_ID RULE_LEVEL PID < <(echo "$INPUT" | python3 -c '
import json, sys
try:
    d = json.loads(sys.stdin.read())
    cmd = d.get("command", "")
    alert = d.get("parameters", {}).get("alert", {})
    rule = alert.get("rule", {})
    eventdata = alert.get("data", {}).get("eventdata", {})
    rid = rule.get("id", "0")
    rlvl = rule.get("level", "0")
    pid = eventdata.get("processId", "")
    print(f"{cmd} {rid} {rlvl} {pid}")
except Exception as e:
    print(f"parse_err 0 0 ")
')

# Wazuh AR protocol: "add" is the initial fire, "delete" is the cleanup
# pass on resolution timers we don't use. Only act on "add".
if [ "$COMMAND" != "add" ]; then
    echo "$(date -Iseconds) [skip] command=$COMMAND (not 'add')" >> "$LOG"
    exit 0
fi

echo "$(date -Iseconds) [fire] rule=$RULE_ID level=$RULE_LEVEL pid=$PID" >> "$LOG"

# Validate PID is a positive integer > 1. Sysmon never emits anything else,
# but `kill -KILL -1` as root would SIGKILL every process in our PID
# namespace (i.e., wreck the agent's own monitoring), and PIDs 0 and 1
# are special (kernel / init). Reject anything that isn't a normal PID.
if [[ ! "$PID" =~ ^[0-9]+$ ]] || [ "$PID" -le 1 ]; then
    echo "$(date -Iseconds) [skip] non-positive-integer PID rejected: '$PID'" >> "$LOG"
    exit 0
fi

# Kill the offending process. -KILL is decisive — the eval measures
# whether the attack completed before this fired, so a graceful SIGTERM
# that the process can catch and ignore would defeat the test.
if kill -0 "$PID" 2>/dev/null; then
    if kill -KILL "$PID" 2>>"$LOG"; then
        echo "$(date -Iseconds) [killed] pid=$PID rule=$RULE_ID" >> "$LOG"
    else
        echo "$(date -Iseconds) [kill_failed] pid=$PID rule=$RULE_ID" >> "$LOG"
    fi
else
    echo "$(date -Iseconds) [stale] pid=$PID already gone (rule=$RULE_ID)" >> "$LOG"
fi

exit 0
