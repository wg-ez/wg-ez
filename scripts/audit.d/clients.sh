# clients.sh : G. clients sans auth (15 checks).
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : G. Lit : BASE, JAR_ANON.

# ================= G. clients sans auth (15) =================
chk "G01 GET /api/client sans auth 401" "$(sok '/api/client' 401)" "ok" #check
c=$(pcode /api/client '{"name":"x"}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G02 POST /api/client sans auth 401" "$g" "ok" #check
chk "G03 GET /api/client/1 sans auth 401" "$(sok /api/client/1 401)" "ok" #check
c=$(pcode /api/client/1 '{"name":"x"}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G04 POST /api/client/1 sans auth 401" "$g" "ok" #check
c=$(mcode /api/client/1 DELETE); inset "$c" 401 && g=ok || g="status=$c"
chk "G05 DELETE /api/client/1 sans auth 401" "$g" "ok" #check
c=$(pcode /api/client/1/enable '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G06 enable sans auth 401" "$g" "ok" #check
c=$(pcode /api/client/1/disable '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G07 disable sans auth 401" "$g" "ok" #check
c=$(pcode /api/client/1/generateOneTimeLink '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G08 generateOneTimeLink sans auth 401" "$g" "ok" #check
chk "G09 configuration sans auth 401" "$(sok /api/client/1/configuration 401)" "ok" #check
chk "G10 qrcode.svg sans auth 401" "$(sok /api/client/1/qrcode.svg 401)" "ok" #check
chk "G11 filtre+tri sans auth 401" "$(sok '/api/client?filter=x&sort=name' 401)" "ok" #check
c=$(mcode /api/client PUT); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "G12 PUT /api/client rejeté" "$g" "ok" #check
c=$(mcode /api/client/1 PATCH); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "G13 PATCH /api/client/1 rejeté" "$g" "ok" #check
chk "G14 configuration id inconnu sans auth 401 (auth avant 404)" "$(sok /api/client/999999/configuration 401)" "ok" #check
c=$(pcode /api/client/abc/enable '{}'); inset "$c" 401 && g=ok || g="status=$c"
chk "G15 enable id invalide sans auth 401" "$g" "ok" #check
