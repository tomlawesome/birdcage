# shellcheck shell=sh
# totp.sh -- an RFC 6238 authenticator-app code (HMAC-SHA1, 30-second
# steps, six digits: what gauntlet's TOTP enrolment hands out), in plain
# POSIX sh, for the sign-in journeys (#8). Sourced, never run.
#
# It runs inside the e2e helper container (scripts/e2e/stack.sh: alpine
# with busybox) and on any workstation, so it uses only sh builtins,
# awk arithmetic (no gawk bit operations) and sha1sum. HMAC is spelt out
# rather than handed to `openssl dgst -hmac`, which takes the key as a
# command-line argument: the key never appears in a process listing.
#
#   . scripts/e2e/totp.sh
#   totp_code "$base32_secret" "$(( $(date +%s) / 30 ))"
#
# Tested against RFC 6238's own SHA-1 vectors by scripts/e2e/totp.test.sh.

# _totp_b32hex reads a base32 secret on stdin (RFC 4648, either case,
# padding and spaces ignored) and prints it as lower-case hex.
_totp_b32hex() {
  tr -d '= \n' | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' | awk '
    BEGIN { alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; buf = 0; bits = 0; bad = 0 }
    {
      for (i = 1; i <= length($0); i++) {
        v = index(alphabet, substr($0, i, 1)) - 1
        if (v < 0) { bad = 1; exit }
        buf = buf * 32 + v; bits += 5
        if (bits >= 8) { bits -= 8; p = 2 ^ bits; b = int(buf / p); buf -= b * p; printf "%02x", b }
      }
    }
    END { if (bad) exit 1; printf "\n" }'
}

# _totp_block reads three lines on stdin -- the key as hex, a pad byte
# (decimal), a message as hex -- and prints, as printf octal escapes,
# the key zero-filled to SHA-1's 64-byte block and XORed with the pad,
# followed by the message: HMAC's (K ^ pad) || m.
_totp_block() {
  awk '
    function hexval(s,   i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
    function xor8(a, b,   r, p, k) { r = 0; p = 1; for (k = 0; k < 8; k++) { if (a % 2 != b % 2) r += p; a = int(a / 2); b = int(b / 2); p *= 2 }; return r }
    NR == 1 { key = $0 } NR == 2 { pad = $0 + 0 } NR == 3 { msg = $0 }
    END {
      if (length(key) > 128) exit 1
      for (i = 0; i < 64; i++) { k = (2 * i < length(key)) ? hexval(substr(key, 2 * i + 1, 2)) : 0; printf "\\%03o", xor8(k, pad) }
      for (i = 0; i < length(msg) / 2; i++) printf "\\%03o", hexval(substr(msg, 2 * i + 1, 2))
      printf "\n"
    }'
}

# _totp_sha1 hashes the bytes the octal escapes in $1 spell, printing
# lower-case hex. printf is a builtin, so the escapes never reach argv.
_totp_sha1() {
  # shellcheck disable=SC2059 # the escapes are the format, on purpose
  printf "$1" | sha1sum | cut -c1-40
}

# totp_code <base32-secret> <counter> prints the six-digit code for that
# 30-second counter (unix time / 30). Fails on a secret that is not
# base32.
totp_code() {
  _totp_key="$(printf '%s' "$1" | _totp_b32hex)" || return 1
  [ -n "$_totp_key" ] || return 1
  _totp_msg="$(printf '%016x' "$2")" || return 1
  _totp_inner="$(_totp_sha1 "$(printf '%s\n54\n%s\n' "$_totp_key" "$_totp_msg" | _totp_block)")" || return 1
  _totp_mac="$(_totp_sha1 "$(printf '%s\n92\n%s\n' "$_totp_key" "$_totp_inner" | _totp_block)")" || return 1
  _totp_key='' _totp_inner=''
  printf '%s\n' "$_totp_mac" | awk '
    function hexval(s,   i, v) { v = 0; for (i = 1; i <= length(s); i++) v = v * 16 + index("0123456789abcdef", substr(s, i, 1)) - 1; return v }
    {
      off = hexval(substr($0, 40, 1))
      b0 = hexval(substr($0, 2 * off + 1, 2)) % 128
      b1 = hexval(substr($0, 2 * off + 3, 2))
      b2 = hexval(substr($0, 2 * off + 5, 2))
      b3 = hexval(substr($0, 2 * off + 7, 2))
      printf "%06d\n", (((b0 * 256 + b1) * 256 + b2) * 256 + b3) % 1000000
    }'
}
