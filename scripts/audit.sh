#!/usr/bin/env bash
# wg-ez — scripts/audit.sh : 270 checks HTTP contre serveur vivant.
# Orchestrateur : source scripts/audit.d/*.sh puis rend le verdict.
# Ordre de sourcing = ordre historique A..T (les bursts R/S conditionnent T16).
# Usage : BASE_URL=http://127.0.0.1:51821 [AUDIT_USER=.. AUDIT_PASS=..] bash scripts/audit.sh
#   Sans AUDIT_USER/AUDIT_PASS, les 20 slots authentifiés vérifient le 401 (total constant).
# Sortie : 0 tout passe, 1 échecs, 2 total inattendu (garde anti-dérive).
set -u
export LC_ALL=C.UTF-8

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AUDIT_D="$SCRIPT_DIR/audit.d"

# shellcheck source=scripts/audit.d/lib.sh
. "$AUDIT_D/lib.sh"          # socle : BASE, T, P, FAILS, jars, helpers (0 check)

echo "audit wg-ez :: $BASE"

# shellcheck source=scripts/audit.d/info.sh
. "$AUDIT_D/info.sh"         # A (6) + B (5) + C (6) = 17
# shellcheck source=scripts/audit.d/auth.sh
. "$AUDIT_D/auth.sh"         # D (8) + E (6) + F (8) = 22
# shellcheck source=scripts/audit.d/clients.sh
. "$AUDIT_D/clients.sh"      # G (15)
# shellcheck source=scripts/audit.d/admin.sh
. "$AUDIT_D/admin.sh"        # H (12) + I (6) + J (10) = 28
# shellcheck source=scripts/audit.d/cnf.sh
. "$AUDIT_D/cnf.sh"          # K (10)
# shellcheck source=scripts/audit.d/metrics.sh
. "$AUDIT_D/metrics.sh"      # L (14) + M (10) = 24
# shellcheck source=scripts/audit.d/ui.sh
. "$AUDIT_D/ui.sh"           # N (30) + O (60) + P (10) = 100
# shellcheck source=scripts/audit.d/authed.sh
. "$AUDIT_D/authed.sh"       # Q (20)
# shellcheck source=scripts/audit.d/ratelimit.sh
. "$AUDIT_D/ratelimit.sh"    # R (4) + S (3) = 7
# shellcheck source=scripts/audit.d/misc.sh
. "$AUDIT_D/misc.sh"         # T (27)
# Total : 17+22+15+28+10+24+100+20+7+27 = 270.

# ================= verdict =================
echo "--------------------------------------------------"
echo "audit: $P/$T checks passed"
if [ "${#FAILS[@]}" -gt 0 ]; then printf '%s\n' "${FAILS[@]}"; fi
[ "$T" -ne 270 ] && { echo "audit: TOTAL=$T != 270, script à recalibrer" >&2; exit 2; }
[ "$P" -ne "$T" ] && exit 1
exit 0
