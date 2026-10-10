# authed.sh : Q. slots authentifiés (20 checks, 401 sans creds).
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : Q. Définit : SESSION, acode, apost, qc, qp (locaux au fichier).

# ================= Q. slots authentifiés (20, 401 sans creds) =================
SESSION=0
if [ -n "${AUDIT_USER:-}" ] && [ -n "${AUDIT_PASS:-}" ]; then
  esc() { python3 -c "import sys,json;print(json.dumps(sys.argv[1]))" "$1"; }
  payload=$(printf '{"username":%s,"password":%s}' "$(esc "$AUDIT_USER")" "$(esc "$AUDIT_PASS")")
  c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -d "$payload" -X POST "$BASE/api/auth/password" 2>/dev/null || echo "000")
  if [ "$c" = 200 ] && grep -q "wg-ez" "$JAR" 2>/dev/null; then SESSION=1; fi
  if has "$(curl -sS --max-time 10 -b "$JAR" "$BASE/api/auth/pending" 2>/dev/null || true)" "TOTP_REQUIRED"; then SESSION=0; fi
fi
acode() { # GET avec jar auth -> code
  curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR" -c "$JAR" "$BASE$1" 2>/dev/null || echo "000"
}
apost() { # POST JSON avec jar auth -> code
  curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR" -c "$JAR" -H 'Content-Type: application/json' -d "$2" -X POST "$BASE$1" 2>/dev/null || echo "000"
}
qc() { # qc "label" url setAuth... — 401 si SESSION=0, sinon setAuth.
  local label="$1" url="$2"; shift 2
  local c; c=$(acode "$url")
  if [ "$SESSION" = 1 ]; then inset "$c" "$@" && g=ok || g="status=$c"; chk "$label" "$g" "ok"
  else inset "$c" 401 && g=ok || g="status=$c"; chk "$label" "$g" "ok"; fi #check
}
qp() { # qp "label" url json setAuth... — idem en POST.
  local label="$1" url="$2" data="$3"; shift 3
  local c; c=$(apost "$url" "$data")
  if [ "$SESSION" = 1 ]; then inset "$c" "$@" && g=ok || g="status=$c"; chk "$label" "$g" "ok"
  else inset "$c" 401 && g=ok || g="status=$c"; chk "$label" "$g" "ok"; fi #check
}
qc "Q01 GET /api/session (200|401)" "/api/session" 200 #check
qc "Q02 GET /api/client (200|401)" "/api/client" 200 #check
qp "Q03 POST /api/client {} (400|401)" "/api/client" '{}' 400 422 #check
qc "Q04 GET /api/client/1 (200|404|401)" "/api/client/1" 200 404 #check
qc "Q05 GET /api/admin/general (200|403|401)" "/api/admin/general" 200 403 #check
qp "Q06 POST /api/admin/general {} (200|400|403|401)" "/api/admin/general" '{}' 200 400 403 #check
qp "Q07 POST /api/me {} (200|400|401)" "/api/me" '{}' 200 400 #check
qc "Q08 configuration .conf (200|404|401)" "/api/client/1/configuration" 200 404 #check
qc "Q09 qrcode.svg (200|404|401)" "/api/client/1/qrcode.svg" 200 404 #check
qp "Q10 generateOneTimeLink (200|404|401, seule mutation sans apply)" "/api/client/1/generateOneTimeLink" '{}' 200 404 #check
qp "Q11 enable (200|404|422|401)" "/api/client/1/enable" '{}' 200 404 422 #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR" -c "$JAR" -X DELETE "$BASE/api/client/999999" 2>/dev/null || echo "000")
if [ "$SESSION" = 1 ]; then inset "$c" 404 && g=ok || g="status=$c"; else inset "$c" 401 && g=ok || g="status=$c"; fi
chk "Q12 DELETE client inconnu (404|401)" "$g" "ok" #check
if [ -n "${AUDIT_USER:-}" ]; then
  c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -u "$AUDIT_USER:${AUDIT_PASS:-}" "$BASE/api/session" 2>/dev/null || echo "000")
  # With 2FA active, Basic is refused with the same 401 as a wrong password
  # (no password-validity oracle), so 403 is no longer returned.
  inset "$c" 200 401 && g=ok || g="status=$c"
else
  c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -u 'x:y' "$BASE/api/session" 2>/dev/null || echo "000")
  inset "$c" 401 && g=ok || g="status=$c"
fi
chk "Q13 Basic Auth (200|401 si 2FA/mauvais mot de passe)" "$g" "ok" #check
qp "Q14 password <12 rejeté (400|401)" "/api/me/password" '{"current":"x","new":"court"}' 400 #check
qp "Q15 totp format invalide (400|401)" "/api/me/totp" '{"code":"12"}' 400 #check
qp "Q16 client __proto__ rejeté (400|401)" "/api/client" '{"name":"__proto__"}' 400 #check
qp "Q17 allowedIps vide rejeté (400|401, null=héritage)" "/api/client" '{"name":"t","allowedIps":[]}' 400 #check
qp "Q18 port 99999 rejeté (400|401)" "/api/admin/interface" '{"port":99999}' 400 #check
qp "Q19 firewallIps proto sans port rejeté (400|401)" "/api/client" '{"name":"t","firewallIps":["10.0.0.1/tcp"]}' 400 #check
qp "Q20 totp 5 chiffres rejeté (400|401)" "/api/me/totp" '{"code":"12345"}' 400 #check
