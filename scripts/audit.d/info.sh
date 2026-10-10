# info.sh : A. serveur vivant + /api/information (6), B. flags information (5), C. /api/auth/methods (6) = 17 checks.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : A, B, C. Lit : BASE, JAR_ANON. Écrit : b, bm, c, ct, g.

# ================= A. serveur vivant + /api/information (6) =================
c=$(gcode "/"); inset "$c" 200 302 303 307 308 401 403 && g=ok || g="status=$c"
chk "A01 GET / vivant (200|redirect setup|401)" "$g" "ok" #check
chk "A02 GET /api/information 200" "$(sok /api/information 200)" "ok" #check
ct=$(gct /api/information); has "$ct" "application/json" && g=ok || g="ct=$ct"
chk "A03 information content-type JSON" "$g" "ok" #check
b=$(gbody /api/information); has "$b" "version" && printf '%s' "$b" | grep -qF '"release":null' && g=ok || g="no-version-or-release"
chk "A04 information expose version + release null (V1 sans client TLS)" "$g" "ok" #check
has "$b" "stacktrace" || has "$b" "Traceback" && g="leak" || g=ok
chk "A05 jamais de stacktrace (page 500 sans détail)" "$g" "ok" #check
chk "A06 information re-appelée 200 (idempotente)" "$(sok '/api/information?cb=2' 200)" "ok" #check

# ================= B. flags information (5) =================
has "$b" '"oauthEnabled":false' && g=ok || g="no-flag"
chk "B01 information oauthEnabled=false (pas d'OAuth en V1)" "$g" "ok" #check
printf '%s' "$b" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && g=ok || g="bad-json"
chk "B02 information JSON valide" "$g" "ok" #check
has "$b" "argon2" && g="leak" || g=ok
chk "B03 information ne fuit aucun hash (argon2 absent)" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Accept-Language: fr' "$BASE/api/information" 2>/dev/null || echo "000")
inset "$c" 200 && g=ok || g="status=$c"
chk "B04 information insensible à Accept-Language" "$g" "ok" #check
c=$(mcode /api/information POST); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "B05 POST /api/information rejeté (404|405)" "$g" "ok" #check

# ================= C. /api/auth/methods (6) =================
chk "C01 GET /api/auth/methods 200" "$(sok /api/auth/methods 200)" "ok" #check
bm=$(gbody /api/auth/methods); has "$bm" '"oauthEnabled":false' && g=ok || g="no-flag"
chk "C02 methods oauthEnabled=false" "$g" "ok" #check
has "$bm" "passwordDisabled" && g=ok || g="no-flag"
chk "C03 methods expose passwordDisabled (UI sait si password actif)" "$g" "ok" #check
printf '%s' "$bm" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null && g=ok || g="bad-json"
chk "C04 methods JSON valide" "$g" "ok" #check
c=$(mcode /api/auth/methods POST); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "C05 POST /api/auth/methods rejeté" "$g" "ok" #check
ct=$(gct /api/auth/methods); has "$ct" "application/json" && g=ok || g="ct=$ct"
chk "C06 methods content-type JSON" "$g" "ok" #check
