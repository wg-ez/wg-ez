# auth.sh : D. login négatif (8), E. pending 2FA (6), F. session gates (8) = 22 checks.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : D, E, F. Lit : BASE, JAR_ANON.

# ================= D. login négatif (8) =================
c=$(pcode /api/auth/password '{"username":"nope","password":"wrongpassword12"}'); inset "$c" 401 && g=ok || g="status=$c"
chk "D01 login user inconnu 401 (avec argon2 factice côté serveur)" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":"admin","password":"court"}'); inset "$c" 400 401 && g=ok || g="status=$c"
chk "D02 login password <12 chars rejeté" "$g" "ok" #check
c=$(pcode /api/auth/password '{}'); inset "$c" 400 && g=ok || g="status=$c"
chk "D03 login champs manquants 400" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR_ANON" -H 'Content-Type: application/json' -d '{oops' -X POST "$BASE/api/auth/password" 2>/dev/null || echo "000")
inset "$c" 400 && g=ok || g="status=$c"
chk "D04 login JSON malformé 400" "$g" "ok" #check
chk "D05 GET /api/auth/password rejeté" "$(sok /api/auth/password 401 404 405)" "ok" #check
h=$(curl -sS -o /dev/null -D - --max-time 10 -b "$JAR_ANON" -H 'Content-Type: application/json' -d '{"username":"nope","password":"wrongpassword12"}' -X POST "$BASE/api/auth/password" 2>/dev/null | grep -i "^set-cookie:" || true)
has "$h" "wg-ez" && g="leak" || g=ok
chk "D06 échec login ne pose aucun cookie wg-ez" "$g" "ok" #check
ct=$(curl -sS -o /dev/null -w "%{content_type}" --max-time 10 -b "$JAR_ANON" -H 'Content-Type: application/json' -d '{"username":"nope","password":"wrongpassword12"}' -X POST "$BASE/api/auth/password" 2>/dev/null || echo "")
has "$ct" "application/json" && g=ok || g="ct=$ct"
chk "D07 échec login répond en JSON" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":"__proto__","password":"wrongpassword12"}'); inset "$c" 400 401 && g=ok || g="status=$c"
chk "D08 login refuse __proto__ (anti pollution prototype)" "$g" "ok" #check

# ================= E. pending 2FA (6) =================
chk "E01 GET /api/auth/pending sans id (400|404)" "$(sok /api/auth/pending 400 404)" "ok" #check
c=$(pcode /api/auth/verify-2fa '{"id":"nope","code":"000000"}'); inset "$c" 400 401 404 && g=ok || g="status=$c"
chk "E02 verify-2fa pending inconnu rejeté" "$g" "ok" #check
c=$(pcode /api/auth/verify-2fa '{"id":"nope","code":"12345"}'); inset "$c" 400 && g=ok || g="status=$c"
chk "E03 verify-2fa exige exactement 6 chiffres" "$g" "ok" #check
c=$(pcode /api/auth/cancel '{"id":"nope"}'); inset "$c" 200 400 404 && g=ok || g="status=$c"
chk "E04 cancel pending inconnu (200|400|404, idempotent)" "$g" "ok" #check
chk "E05 GET /api/auth/verify-2fa rejeté" "$(sok /api/auth/verify-2fa 401 404 405)" "ok" #check
c=$(pcode /api/auth/verify-2fa '{"id":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","code":"000000"}')
inset "$c" 400 404 && g=ok || g="status=$c"
chk "E06 pending id surlong rejeté" "$g" "ok" #check

# ================= F. session gates (8) =================
chk "F01 GET /api/session sans auth 401" "$(sok /api/session 401)" "ok" #check
c=$(mcode /api/session DELETE); inset "$c" 401 && g=ok || g="status=$c"
chk "F02 DELETE /api/session sans auth 401" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Cookie: wg-ez=garbage' "$BASE/api/session" 2>/dev/null || echo "000")
inset "$c" 401 && g=ok || g="status=$c"
chk "F03 cookie wg-ez invalide 401" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Authorization: Bearer' "$BASE/api/session" 2>/dev/null || echo "000")
inset "$c" 401 && g=ok || g="status=$c"
chk "F04 Bearer sans token 401" "$g" "ok" #check
chk "F05 POST /api/session rejeté" "$(sok /api/session 401 404 405)" "ok" #check
chk "F06 PUT /api/session rejeté" "$(sok /api/session 401 404 405)" "ok" #check
ct=$(gct /api/session); has "$ct" "application/json" && g=ok || g="ct=$ct"
chk "F07 401 session en JSON" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Authorization: Bearer garbage' "$BASE/api/session" 2>/dev/null || echo "000")
inset "$c" 401 && g=ok || g="status=$c"
chk "F08 Bearer poubelle sur session 401" "$g" "ok" #check
