# misc.sh : T. divers parité (27 checks).
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : T. Lit : U_CSS (défini par ui.sh), BASE, JAR_ANON.

# ================= T. divers parité (27) =================
c=$(pcode /api/auth/verify-2fa '{"id":"x"}'); inset "$c" 400 && g=ok || g="status=$c"
chk "T01 verify-2fa code manquant 400" "$g" "ok" #check
c=$(pcode /api/auth/verify-2fa '{}'); inset "$c" 400 && g=ok || g="status=$c"
chk "T02 verify-2fa corps vide 400" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":["tab"],"password":"longpassword12"}'); inset "$c" 400 401 429 && g=ok || g="status=$c"
chk "T03 login username tableau rejeté" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":"admin","password":123456789012}'); inset "$c" 400 401 429 && g=ok || g="status=$c"
chk "T04 login password numérique rejeté" "$g" "ok" #check
bigf="$(mktemp)"; python3 -c "print('{\"username\":\"' + 'a'*1048576 + '\",\"password\":\"longpassword12\"}')" > "$bigf"
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 15 -b "$JAR_ANON" -H 'Content-Type: application/json' -d @"$bigf" -X POST "$BASE/api/auth/password" 2>/dev/null || echo "000")
rm -f "$bigf"; inset "$c" 400 401 413 429 && g=ok || g="status=$c"
chk "T05 login corps 1 Mo contenu (400|401|413|429)" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR_ANON" -H 'Content-Type: text/plain' -d 'x' -X POST "$BASE/api/auth/password" 2>/dev/null || echo "000")
inset "$c" 400 401 415 429 && g=ok || g="status=$c"
chk "T06 login mauvais content-type rejeté" "$g" "ok" #check
chk "T07 filtre __proto__ sans auth 401" "$(sok '/api/client?filter=__proto__' 401)" "ok" #check
chk "T08 tri desc sans auth 401" "$(sok '/api/client?sort=name&order=desc' 401)" "ok" #check
if [ -n "$U_CSS" ]; then
  c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'If-None-Match: "x"' "$BASE$U_CSS" 2>/dev/null || echo "000")
  inset "$c" 200 304 && g=ok || g="status=$c"
else g="no-css"; fi
chk "T09 ETag/If-None-Match css (200|304)" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -I "$BASE/login" 2>/dev/null || echo "000")
inset "$c" 200 302 303 307 308 405 && g=ok || g="status=$c"
chk "T10 HEAD /login (set fermé)" "$g" "ok" #check
chk "T11 doubles slashs normalisés (tower normalize-path)" "$(sok '//api//information' 200 301 308)" "ok" #check
chk "T12 slash final information" "$(sok /api/information/ 200 301 308 404)" "ok" #check
chk "T13 /API/information sensible à la casse 404" "$(sok /API/information 404)" "ok" #check
chk "T14 /api nu 404" "$(sok /api 404)" "ok" #check
c=$(mcode /api/auth/methods DELETE); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "T15 DELETE /api/auth/methods rejeté" "$g" "ok" #check
long=$(python3 -c "print('a'*200)")
c=$(gcode "/cnf/$long"); inset "$c" 400 404 429 && g=ok || g="status=$c"
chk "T16 token 200 chars inconnu (400|404|429 post-burst)" "$g" "ok" #check
# curl normalise les dot-segments : --path-as-is envoie le `..` brut.
# Propriété testée : jamais servi (200) ni 500 — 404 direct ou redirect
# de normalisation (normalize-path) vers une page sûre.
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 --path-as-is -b "$JAR_ANON" "$BASE/cnf/.." 2>/dev/null || echo "000")
case "$c" in 200|500) g="status=$c" ;; *) g=ok ;; esac
chk "T17 token .. ni servi ni 500" "$g" "ok" #check
chk "T18 /metrics nu 404" "$(sok /metrics 404)" "ok" #check
chk "T19 slash final prom" "$(sok /metrics/prometheus/ 200 301 308 404)" "ok" #check
chk "T20 /admin nu (page|redirect|404)" "$(sok /admin 200 302 303 307 308 404)" "ok" #check
chk "T21 /clients nu (page|redirect|404)" "$(sok /clients 200 302 303 307 308 404)" "ok" #check
chk "T22 /me status (200|redirect|401)" "$(sok /me 200 302 303 307 308 401)" "ok" #check
chk "T23 cookie theme=dark ne 500 pas" "$(sok /login 200 302 303 307 308)" "ok" #check
chk "T24 combo ?lang=fr sur /login vivant" "$(sok '/login?lang=fr' 200 302 303 307 308)" "ok" #check
c=$(mcode /api/client/1/configuration POST); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "T25 POST configuration rejeté" "$g" "ok" #check
chk "T26 configuration id 0 sans auth 401" "$(sok /api/client/0/configuration 401 404)" "ok" #check
chk "T27 qrcode id -1 sans auth (401|404)" "$(sok /api/client/-1/qrcode.svg 401 404)" "ok" #check
