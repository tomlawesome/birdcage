#!/bin/sh
# entrypoint.sh -- brings up rsyslogd (which vfs_full_audit's syslog(3)
# calls need somewhere to land, see smb.conf's comment) and then execs
# smbd in the foreground as PID 1.
#
# /samba-audit is the volume shared with the canary container
# (scripts/e2e/smb-stack.sh); the audit file is touched and made
# world-readable here, before smbd ever starts, so OpenCanary's
# FileSystemWatcher has something it is allowed to open from the moment
# it starts polling -- it copes with the file appearing later, but there
# is no reason to make it.
set -eu

mkdir -p /run/samba /var/log/samba
chmod 755 /run/samba

mkdir -p /srv/share
chmod 777 /srv/share

mkdir -p /samba-audit
touch /samba-audit/samba-audit.log
chmod 644 /samba-audit/samba-audit.log
chmod 755 /samba-audit

# Daemonises itself (no -n): it needs to keep running after this script
# execs smbd as PID 1, and --init in the container's run command reaps
# it if it forks again.
rsyslogd

# /dev/log is what smbd's syslog(3) calls need; rsyslogd creates it
# asynchronously, so wait rather than racing it.
i=0
while [ ! -S /dev/log ]; do
  i=$((i + 1))
  [ "$i" -le 50 ] || { echo "entrypoint: /dev/log never appeared" >&2; exit 1; }
  sleep 0.1
done

exec smbd --foreground --no-process-group --debug-stdout -s /etc/samba/smb.conf
