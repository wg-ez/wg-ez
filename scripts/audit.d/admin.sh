# admin.sh : H. admin sans auth (12), I. me sans auth (6), J. setup gating (10) = 28 checks.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : H, I, J. Lit : BASE, JAR_ANON.

# ================= H. admin sans auth (12) =================
chk "H01 GET /api/admin/general sans auth 401" "$(sok /api/admin/general 401)" "ok" #check
c=$(pcode /api/admin/general '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H02 POST /api/admin/general sans auth 401" "$g" "ok" #check
chk "H03 GET /api/admin/hooks sans auth 401" "$(sok /api/admin/hooks 401)" "ok" #check
c=$(pcode /api/admin/hooks '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H04 POST /api/admin/hooks sans auth 401" "$g" "ok" #check
chk "H05 GET /api/admin/interface sans auth 401" "$(sok /api/admin/interface 401)" "ok" #check
c=$(pcode /api/admin/interface '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H06 POST /api/admin/interface sans auth 401" "$g" "ok" #check
chk "H07 GET /api/admin/userconfig sans auth 401" "$(sok /api/admin/userconfig 401)" "ok" #check
c=$(pcode /api/admin/userconfig '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H08 POST /api/admin/userconfig sans auth 401" "$g" "ok" #check
c=$(pcode /api/admin/interface/restart '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H09 restart sans auth 401" "$g" "ok" #check
c=$(pcode /api/admin/interface/cidr '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "H10 cidr sans auth 401" "$g" "ok" #check
chk "H11 ip-info sans auth 401" "$(sok /api/admin/ip-info 401)" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR_ANON" -H 'Content-Type: application/json' -d 'notjson' -X POST "$BASE/api/admin/general" 2>/dev/null || echo "000")
inset "$c" 401 && g=ok || g="status=$c"
chk "H12 POST admin JSON malformé sans auth 401 (auth d'abord)" "$g" "ok" #check

# ================= I. me sans auth (6) =================
c=$(pcode /api/me '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "I01 POST /api/me sans auth 401" "$g" "ok" #check
c=$(pcode /api/me/password '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "I02 POST /api/me/password sans auth 401" "$g" "ok" #check
c=$(pcode /api/me/totp '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "I03 POST /api/me/totp sans auth 401" "$g" "ok" #check
chk "I04 GET /api/me (401|404|405)" "$(sok /api/me 401 404 405)" "ok" #check
c=$(mcode /api/me PUT); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "I05 PUT /api/me rejeté" "$g" "ok" #check
c=$(mcode /api/me DELETE); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "I06 DELETE /api/me rejeté" "$g" "ok" #check

# ================= J. setup gating (10) =================
c=$(pcode /api/setup/2 '{"username":"a","password":"longpassword12"}'); inset "$c" 400 403 404 && g=ok || g="status=$c"
chk "J01 POST /api/setup/2 hors setup refusé" "$g" "ok" #check
c=$(gcode /api/setup/2); inset "$c" 400 403 404 405 && g=ok || g="status=$c"
chk "J02 GET /api/setup/2 méthode non autorisée" "$g" "ok" #check
chk "J03 GET /api/setup/3 hors setup refusé" "$(sok /api/setup/3 400 401 403 404)" "ok" #check
c=$(pcode /api/setup/3 '{"host":"x","port":51820}'); inset "$c" 400 401 403 404 && g=ok || g="status=$c"
chk "J04 POST /api/setup/3 via Auth: 401 non authentifié / 400 hors setup" "$g" "ok" #check
chk "J05 GET /setup/ (page ou redirect)" "$(sok /setup/ 200 302 303 307 308)" "ok" #check
chk "J06 GET /setup/2 (page ou redirect)" "$(sok /setup/2 200 302 303 307 308)" "ok" #check
c=$(pcode /api/setup/4 '{}'); inset "$c" 404 && g=ok || g="status=$c"
chk "J07 POST /api/setup/4 inexistant 404 (étape supprimée)" "$g" "ok" #check
chk "J08 GET /setup/3 (page ou redirect)" "$(sok /setup/3 200 302 303 307 308)" "ok" #check
chk "J09 GET /setup/4 supprimé (redirect login ou 404)" "$(sok /setup/4 302 303 307 308 404)" "ok" #check
loc=$(curl -sS -o /dev/null -w "%{redirect_url}" --max-time 10 -b "$JAR_ANON" "$BASE/setup/2" 2>/dev/null || true)
if [ -z "$loc" ]; then g="page-ok"; elif has "$loc" "setup" || has "$loc" "login"; then g="redir-ok"; else g="loc=$loc"; fi
chk "J10 /setup/* redirige vers setup ou login" "$g" "redir-ok" "page-ok" #check
