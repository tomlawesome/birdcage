#!/bin/sh
# Fills this server's identity and share names into the Samba
# configuration template, creates the directories Samba writes to, and
# execs smbd in the foreground as PID 1. Nothing else runs here: no nmbd,
# no winbind, no syslog daemon, no cron.
#
# Every input is an environment variable with a working default, so a run
# command that sets none of them still starts:
#
#   SMB_WORKGROUP      workgroup name                  (WORKGROUP)
#   SMB_SERVER_NAME    NetBIOS name                    (from hostname)
#   SMB_SERVER_STRING  the server description string    (from hostname)
#   SMB_SHARE_PUBLIC   name of the documents share      (public)
#   SMB_SHARE_BACKUP   name of the backups share        (backup)
#   SMB_SHARE_SCANS    name of the scans share          (scans)
#   SMB_AUDIT_FILE     where the log is written         (/audit/smb.log)
#
# Each value is checked against a character set before substitution. A
# value carrying a newline or a `[` would rewrite the configuration
# rather than fill it in, so a bad one is a loud exit and not a silent
# fall back to the default: coming up under an identity nobody asked for
# is worse than not coming up.
set -eu

# `version` prints the build stamp and exits, as the Go images do, so
# promotion can check it (#125) without starting smbd.
if [ "${1:-}" = version ]; then
  cat /etc/image-version
  exit 0
fi

CONF_TEMPLATE=/etc/samba/smb.conf.in
CONF=/run/samba/smb.conf

# check <variable name> <value> <extended regex the whole value must match>
check() {
  printf '%s' "$2" | grep -Eq "^$3\$" || {
    echo "start-up: $1 is not usable: it must match $3" >&2
    exit 1
  }
}

# The hostname is the default identity: this container shares the network
# namespace it is given, so the hostname is already whatever the operator
# chose. NetBIOS names are at most 15 characters and conventionally upper
# case, so a longer hostname is truncated rather than refused.
# The newline is kept through the substitution and removed at the end,
# rather than stripped at the start: busybox cut puts a newline back on
# its output, so a strip before it leaves the substitution turning that
# newline into a separator and the name coming out as "NAS-STORE-01-".
# Found by reading a running container's generated configuration.
DEFAULT_NAME="$(hostname | cut -c1-15 | tr '[:lower:]' '[:upper:]' | tr -c '[:alnum:]-\n' '-' | tr -d '\n')"
[ -n "$DEFAULT_NAME" ] || DEFAULT_NAME=NAS

WORKGROUP="${SMB_WORKGROUP:-WORKGROUP}"
SERVER_NAME="${SMB_SERVER_NAME:-$DEFAULT_NAME}"
SERVER_STRING="${SMB_SERVER_STRING:-$(hostname)}"
SHARE_PUBLIC="${SMB_SHARE_PUBLIC:-public}"
SHARE_BACKUP="${SMB_SHARE_BACKUP:-backup}"
SHARE_SCANS="${SMB_SHARE_SCANS:-scans}"
AUDIT_FILE="${SMB_AUDIT_FILE:-/audit/smb.log}"

check SMB_WORKGROUP "$WORKGROUP" '[A-Za-z0-9_-]{1,15}'
check SMB_SERVER_NAME "$SERVER_NAME" '[A-Za-z0-9_-]{1,15}'
check SMB_SERVER_STRING "$SERVER_STRING" '[A-Za-z0-9 ._-]{1,63}'
check SMB_SHARE_PUBLIC "$SHARE_PUBLIC" '[A-Za-z0-9_-]{1,32}'
check SMB_SHARE_BACKUP "$SHARE_BACKUP" '[A-Za-z0-9_-]{1,32}'
check SMB_SHARE_SCANS "$SHARE_SCANS" '[A-Za-z0-9_-]{1,32}'
check SMB_AUDIT_FILE "$AUDIT_FILE" '/[A-Za-z0-9/._-]{1,127}'

# Samba's writable state. Each of these is a tmpfs mount in the run
# command, so anything created here lasts exactly as long as the
# container does.
mkdir -p /run/samba /var/lib/samba/private /var/cache/samba /var/log/samba
chmod 755 /run/samba

# The log file is created world-readable before smbd starts, so a reader
# that mounts this volume read-only under a different uid has something
# it is allowed to open from the first moment it looks.
mkdir -p "$(dirname "$AUDIT_FILE")"
touch "$AUDIT_FILE"
chmod 644 "$AUDIT_FILE"

# sed rather than a template engine: six fixed tokens, values already
# checked above, and `|` cannot occur in any of them so it is safe as the
# delimiter.
sed \
  -e "s|@@WORKGROUP@@|$WORKGROUP|g" \
  -e "s|@@SERVER_NAME@@|$SERVER_NAME|g" \
  -e "s|@@SERVER_STRING@@|$SERVER_STRING|g" \
  -e "s|@@SHARE_PUBLIC@@|$SHARE_PUBLIC|g" \
  -e "s|@@SHARE_BACKUP@@|$SHARE_BACKUP|g" \
  -e "s|@@SHARE_SCANS@@|$SHARE_SCANS|g" \
  -e "s|@@AUDIT_FILE@@|$AUDIT_FILE|g" \
  "$CONF_TEMPLATE" > "$CONF"

# stderr is appended to the log file as well, because smbd's panic path
# writes through both it and Samba's own logging, and only this one file
# is read from outside. --foreground so smbd is PID 1 and the restart
# policy sees it die; --no-process-group so a signal sent to PID 1 is not
# broadcast to the per-connection children behind its back.
exec smbd --foreground --no-process-group -s "$CONF" 2>>"$AUDIT_FILE"
