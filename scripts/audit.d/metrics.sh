# metrics.sh : L. métriques (14), M. erreurs HTTP (10) = 24 checks.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : L, M. Lit : BASE, JAR_ANON. Définit : mcheck (locale au fichier).

# ================= L. métriques (14) =================
chk "L01 prom status (200|400 désactivé v15|401|403|404 selon config)" "$(sok /metrics/prometheus 200 400 401 403 404)" "ok" #check
chk "L02 json status (200|400 désactivé v15|401|403|404 selon config)" "$(sok /metrics/json 200 400 401 403 404)" "ok" #check
mp=$(gbody /metrics/prometheus); cp=$(gcode /metrics/prometheus)
mcheck() { if [ "$cp" != 200 ]; then echo "disabled"; elif has "$mp" "$1"; then echo "metrics-ok"; else echo "metrics-ko"; fi; }
chk "L03 gauge wireguard_configured_peers" "$(mcheck wireguard_configured_peers)" "metrics-ok" "disabled" #check
chk "L04 gauge wireguard_enabled_peers" "$(mcheck wireguard_enabled_peers)" "metrics-ok" "disabled" #check
chk "L05 gauge wireguard_connected_peers (<2 min)" "$(mcheck wireguard_connected_peers)" "metrics-ok" "disabled" #check
chk "L06 compteur wireguard_sent_bytes" "$(mcheck wireguard_sent_bytes)" "metrics-ok" "disabled" #check
chk "L07 compteur wireguard_received_bytes" "$(mcheck wireguard_received_bytes)" "metrics-ok" "disabled" #check
chk "L08 gauge wireguard_latest_handshake_seconds" "$(mcheck wireguard_latest_handshake_seconds)" "metrics-ok" "disabled" #check
chk "L09 gauge wireguard_peer_endpoint_info" "$(mcheck wireguard_peer_endpoint_info)" "metrics-ok" "disabled" #check
if [ "$cp" != 200 ]; then g="disabled"; elif has "$mp" "# HELP" || has "$mp" "# TYPE"; then g="metrics-ok"; else g="metrics-ko"; fi
chk "L10 format texte OpenMetrics écrit main (# HELP/# TYPE)" "$g" "metrics-ok" "disabled" #check
mj=$(gbody /metrics/json); cj=$(gcode /metrics/json)
if [ "$cj" != 200 ]; then g="disabled"; elif printf '%s' "$mj" | python3 -c "import sys,json;json.load(sys.stdin)" 2>/dev/null; then g="metrics-ok"; else g="metrics-ko"; fi
chk "L11 JSON métriques valide" "$g" "metrics-ok" "disabled" #check
if [ "$cj" != 200 ]; then g="disabled"; elif has "$mj" "clients" || has "$mj" "peers"; then g="metrics-ok"; else g="metrics-ko"; fi
chk "L12 JSON reprend clients + compteurs" "$g" "metrics-ok" "disabled" #check
c=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -H 'Authorization: Bearer wrong' "$BASE/metrics/prometheus" 2>/dev/null || echo "000")
inset "$c" 200 400 401 403 404 && g=ok || g="status=$c"
chk "L13 Bearer poubelle (200 public|400 désactivé|401|403|404)" "$g" "ok" #check
c=$(mcode /metrics/prometheus POST); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "L14 POST /metrics/prometheus rejeté" "$g" "ok" #check

# ================= M. erreurs HTTP (10) =================
chk "M01 page inconnue 404" "$(sok /route-inexistante-xyz 404)" "ok" #check
b=$(gbody /route-inexistante-xyz); (has "$b" "stacktrace" || has "$b" "Traceback") && g="leak" || g=ok
chk "M02 page 404 sans stacktrace" "$g" "ok" #check
c=$(mcode /api/client PUT); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "M03 PUT /api/client rejeté" "$g" "ok" #check
c=$(mcode /api/information PATCH); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "M04 PATCH /api/information rejeté" "$g" "ok" #check
c=$(mcode /api/information DELETE); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "M05 DELETE /api/information rejeté" "$g" "ok" #check
c=$(mcode /metrics/json POST); inset "$c" 401 404 405 && g=ok || g="status=$c"
chk "M06 POST /metrics/json rejeté" "$g" "ok" #check
c=$(mcode / TRACE); inset "$c" 400 403 404 405 501 && g=ok || g="status=$c"
chk "M07 TRACE bloqué" "$g" "ok" #check
c=$(mcode /api/information OPTIONS); inset "$c" 200 204 404 405 && g=ok || g="status=$c"
chk "M08 OPTIONS information (set fermé)" "$g" "ok" #check
chk "M09 client id inconnu sans auth 401 (auth avant 404)" "$(sok /api/client/999999 401)" "ok" #check
chk "M10 client id invalide sans auth 401" "$(sok /api/client/abc 401)" "ok" #check
