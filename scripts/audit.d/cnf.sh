# cnf.sh : K. cnf / OTL (10 checks). Le burst rate-limit /cnf/* vit dans ratelimit.sh (S).
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : K. Lit : BASE, JAR_ANON. Écrit : tok.

# ================= K. cnf / OTL (10) =================
chk "K01 GET /cnf/token-inconnu 404 + seclog serveur" "$(sok /cnf/token-inexistant-xyz 404)" "ok" #check
b=$(gbody /cnf/token-inexistant-xyz); has "$b" "PrivateKey" && g="leak" || g=ok
chk "K02 404 OTL ne fuit aucune clé privée" "$g" "ok" #check
c=$(mcode /cnf/token-inexistant-xyz POST); inset "$c" 404 405 && g=ok || g="status=$c"
chk "K03 POST /cnf/* rejeté" "$g" "ok" #check
chk "K04 GET /cnf/ sans token 404" "$(sok /cnf/ 404)" "ok" #check
chk "K05 token avec slash 404" "$(sok '/cnf/a/b' 400 404)" "ok" #check
tok=$(python3 -c "import secrets;print(secrets.token_urlsafe(18))")
chk "K06 token 128b base64url inconnu 404 (pas de CRC32)" "$(sok "/cnf/$tok" 404)" "ok" #check
c=$(mcode /cnf/token-inexistant-xyz PUT); inset "$c" 404 405 && g=ok || g="status=$c"
chk "K09 PUT /cnf/* rejeté" "$g" "ok" #check
c=$(mcode /cnf/token-inexistant-xyz DELETE); inset "$c" 404 405 && g=ok || g="status=$c"
chk "K10 DELETE /cnf/* rejeté" "$g" "ok" #check
# (K07/K08 : burst rate-limit, voir section S avec /cnf.)
chk "K07 GET /cnf/token-inconnu rejoué 404 (stable)" "$(sok /cnf/token-inexistant-xyz 404)" "ok" #check
chk "K08 autre token inconnu 404" "$(sok "/cnf/${tok}xyz" 404)" "ok" #check
