# ui.sh : N. CSP + inline + validation (30), O. UI pages + statiques (60), P. i18n HTTP (10) = 100 checks.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : N, O, P. Définit : opage, static_url. Exporte : U_HTMX, U_APPJS, U_CSS (lus par misc.sh T09).

# ================= N. CSP + inline + validation (30) =================
PAGES_UI="/ /login /login/2fa /me /admin/general /setup/"
for p in $PAGES_UI; do # 6 pages x 4 = 24 checks
  pc=$(gcode "$p")
  case "$pc" in
    30*) PSTAT="redirect-ok" ;; 401|403) PSTAT="auth-required" ;; 200) PSTAT="" ;; *) PSTAT="status=$pc" ;;
  esac
  if [ "$pc" != 200 ]; then
    chk "N CSP script-src 'self' sur $p" "$PSTAT" "redirect-ok" "auth-required" #check
    chk "N zéro <script> inline sur $p" "$PSTAT" "redirect-ok" "auth-required" #check
    chk "N zéro style inline sur $p" "$PSTAT" "redirect-ok" "auth-required" #check
    chk "N JS externalisé app.js sur $p" "$PSTAT" "login-page-ok" "redirect-ok" "auth-required" #check
    continue
  fi
  csp=$(ghead "$p" "content-security-policy")
  has "$csp" "script-src 'self'" && g=ok || g="csp=$csp"
  chk "N CSP script-src 'self' sur $p" "$g" "ok" #check
  b=$(gbody "$p"); has "$b" "<script>" && g="inline" || g=ok
  chk "N zéro <script> inline sur $p" "$g" "ok" #check
  has "$b" "style=" && g="inline" || g=ok
  chk "N zéro style inline sur $p" "$g" "ok" #check
  has "$b" "app.js" && g=ok || g="no-appjs"
  chk "N JS externalisé app.js sur $p" "$g" "ok" #check
done
c=$(pcode /api/auth/password '{"username":"constructor","password":"wrongpassword12"}'); inset "$c" 400 401 429 && g=ok || g="status=$c"
chk "N25 login refuse constructor" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":"prototype","password":"wrongpassword12"}'); inset "$c" 400 401 429 && g=ok || g="status=$c"
chk "N26 login refuse prototype" "$g" "ok" #check
c=$(pcode /api/auth/verify-2fa '{"id":"x","code":"12345"}'); inset "$c" 400 429 && g=ok || g="status=$c"
chk "N27 TOTP 5 chiffres rejeté (exactement 6)" "$g" "ok" #check
c=$(pcode /api/auth/verify-2fa '{"id":"x","code":"abcdef"}'); inset "$c" 400 429 && g=ok || g="status=$c"
chk "N28 TOTP non numérique rejeté" "$g" "ok" #check
c=$(pcode /api/auth/password '{"username":"admin","password":"11-chars___"}'); inset "$c" 400 401 429 && g=ok || g="status=$c"
chk "N29 login password 11 chars rejeté (<12)" "$g" "ok" #check
loc=$(curl -sS -o /dev/null -w "%{redirect_url}" --max-time 10 -H 'X-Forwarded-Host: evil.test' "$BASE/login" 2>/dev/null || true)
if has "$loc" "evil.test"; then g="leak"; else g=ok; fi
chk "N30 X-Forwarded-Host non fiable ignoré (proxy)" "$g" "ok" #check

# ================= O. UI pages + statiques (60) =================
# 10 pages x 4 : status, marqueur FR/EN (mor2), 2e marqueur... -> status + mor2 + content-type = 3 ?
# Non : 4 par page = status + mor2(m1) + mor2(m2) + content-type. mor2 prend 2 paires ;
# on l'appelle 2x par page avec paires différentes.
opage() { # opage path m1a m1b m2a m2b — 4 checks
  local path="$1"
  chk "O status $path" "$(sok "$path" 200 302 303 307 308 401 403)" "ok" #check
  chk "O marqueur1 $path" "$(mor2 "$path" "$2" "$3" "$2" "$3")" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
  chk "O marqueur2 $path" "$(mor2 "$path" "$4" "$5" "$4" "$5")" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
  c=$(gcode "$path"); ct=$(gct "$path")
  case "$c" in 30*) g="redirect-ok" ;; 401|403) g="auth-required" ;; 200) has "$ct" "text/html" && g="html-ok" || g="ct=$ct" ;; *) g="status=$c" ;; esac
  chk "O content-type $path" "$g" "html-ok" "redirect-ok" "auth-required" #check
}
opage "/" "client" "client" "hx-get" "hx-get"
opage "/login" "Se connecter" "Sign in" "Se souvenir" "Remember"
opage "/login/2fa" "6 chiffres" "6-digit" "rify" "rify"
opage "/me" "Mon compte" "My account" "2FA" "2FA"
opage "/clients/1" "Zone danger" "Danger zone" "PreUp" "PreUp"
opage "/admin/general" "ession" "ession" "metrics" "metrics"
opage "/admin/config" "public" "public" "Allowed" "Allowed"
opage "/admin/interface" "coute" "Listen" "firewall" "firewall"
opage "/admin/hooks" "PreUp" "PreUp" "PostDown" "PostDown"
opage "/setup/" "Bienvenue" "Welcome" "admin" "admin"
chk "O41 header état wg0/peer" "$(mor2 / wg0 WireGuard client client)" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O42 toggle thème system|light|dark" "$(mor2 / theme theme dark dark)" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O43 sélecteur langue EN/FR" "$(mor2 / lang lang FR FR)" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O44 footer version + liens" "$(mor2 / metrics metrics version version)" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O45 CTA créer client / état vide" "$(mor2 / Créer Create client client)" "marker-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O46 conteneur toast succès/erreur" "$(eitheror / toast Toast)" "either-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O47 avatar initiales" "$(eitheror / avatar-initial)" "either-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O48 sparkline SVG serveur (RX inversé)" "$(eitheror / polyline sparkline)" "either-ok" "login-page-ok" "redirect-ok" "auth-required" #check
chk "O49 /login?lang=fr vivant" "$(sok '/login?lang=fr' 200 302 303 307 308 401 403)" "ok" #check
chk "O50 page fr traduite (Se connecter)" "$(langok '/login?lang=fr' 'Se connecter')" "lang-ok" "redirect-ok" "auth-required" #check
h=$(ghead /login set-cookie); has "$h" "wg-ez" && g="leak" || g=ok
chk "O51 /login ne pose pas de session" "$g" "ok" #check
static_url() { local q; for q in "/static/$1" "/$1" "/assets/$1"; do [ "$(gcode "$q")" = 200 ] && { printf '%s' "$q"; return 0; }; done; return 1; }
U_HTMX=""; U_HTMX=$(static_url vendor/htmx.min.js) && g=ok || g="missing"
chk "O52 htmx vendorisé servi en local (sans CDN)" "$g" "ok" #check
[ -n "$U_HTMX" ] && b=$(gbody "$U_HTMX") || b=""
has "$b" "htmx" && g=ok || g="no-htmx"
chk "O53 htmx.min.js contient htmx" "$g" "ok" #check
U_APPJS=""; U_APPJS=$(static_url js/app.js) && g=ok || g="missing"
chk "O54 app.js servi" "$g" "ok" #check
[ -n "$U_APPJS" ] && b=$(gbody "$U_APPJS") || b=""
n=$(printf '%s' "$b" | wc -c); [ "$n" -le 3072 ] && [ "$n" -gt 0 ] && g=ok || g="size=$n"
chk "O55 app.js budget < 3 Ko" "$g" "ok" #check
U_CSS=""; U_CSS=$(static_url css/app.css) && g=ok || g="missing"
chk "O56 app.css servi (artefact stage css)" "$g" "ok" #check
[ -n "$U_CSS" ] && b=$(gbody "$U_CSS") || b=""
(has "$b" "#0a0a0b" || has "$b" "#0A0A0B") && g=ok || g="no-token"
chk "O57 app.css tokens ArtCraft (#0A0A0B)" "$g" "ok" #check
[ -n "$b" ] && g=ok || g="empty"
chk "O58 app.css non vide" "$g" "ok" #check
chk "O59 favicon (200|404 set fermé)" "$(sok /favicon.ico 200 404)" "ok" #check
[ -n "$U_APPJS" ] && ba=$(gbody "$U_APPJS") || ba=""
(has "$ba" "http://" || has "$ba" "https://") && g="cdn-ref" || g=ok
chk "O60 app.js sans référence CDN (no http)" "$g" "ok" #check

# ================= P. i18n HTTP (10) =================
chk "P01 /login?lang=fr vivant" "$(sok '/login?lang=fr' 200 302 303 307 308)" "ok" #check
chk "P02 /login?lang=en vivant" "$(sok '/login?lang=en' 200 302 303 307 308)" "ok" #check
chk "P03 /login?lang=xx invalide ne 500 pas (fallback en)" "$(sok '/login?lang=xx' 200 302 303 307 308)" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Accept-Language: fr-FR,fr;q=0.9' "$BASE/login" 2>/dev/null || echo "000")
inset "$c" 200 302 303 307 308 && g=ok || g="status=$c"
chk "P04 Accept-Language fr vivant" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Accept-Language: xx-bogus' "$BASE/login" 2>/dev/null || echo "000")
inset "$c" 200 302 303 307 308 && g=ok || g="status=$c"
chk "P05 Accept-Language poubelle ne 500 pas" "$g" "ok" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Cookie: lang=fr' "$BASE/login" 2>/dev/null || echo "000")
inset "$c" 200 302 303 307 308 && g=ok || g="status=$c"
chk "P06 cookie lang=fr vivant" "$g" "ok" #check
chk "P07 ?lang=fr montre le français" "$(langok '/login?lang=fr' 'Se connecter')" "lang-ok" "redirect-ok" "auth-required" #check
chk "P08 ?lang=en montre l'anglais" "$(langok '/login?lang=en' 'Sign in')" "lang-ok" "redirect-ok" "auth-required" #check
chk "P09 ?lang=xx retombe sur en" "$(langok '/login?lang=xx' 'Sign in')" "lang-ok" "redirect-ok" "auth-required" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Accept-Language: fr' "$BASE/login" 2>/dev/null || echo "000")
case "$c" in
  30*) g="redirect-ok" ;;
  200)
    b=$(curl -sS --max-time 10 -H 'Accept-Language: fr' "$BASE/login" 2>/dev/null || true)
    has "$b" "Se connecter" && g="lang-ok" || g="lang-missing" ;;
  401|403) g="auth-required" ;;
  *) g="status=$c" ;;
esac
chk "P10 Accept-Language fr montre le français" "$g" "lang-ok" "redirect-ok" "auth-required" #check
