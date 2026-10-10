# ratelimit.sh : R. rate-limit login 10/min/(IP,user)+50/min/IP (4), S. rate-limit /cnf/* 20/min/IP (3) = 7 checks. Ordre imposé : après authed.sh, avant misc.sh.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : R, S. Les bursts consomment le quota ; T16 s'y réfère.

# ================= R. rate-limit login 10/min/(IP,user)+50/min/IP (4) =================
# Le burst est auto-suffisant : 15 essais sur le même username dépassent la
# limite fine 10/min/(IP,user) quel que soit le quota déjà consommé, donc seul
# le dernier essai est asserté 429. La limite coarse 50/min/IP n'est pas
# atteinte par ce burst.
RLAST=""; R429=0; R500=0
for _ in $(seq 1 15); do
  c=$(pcode /api/auth/password '{"username":"rl","password":"rate-limit-probe-12"}')
  RLAST="$c"; [ "$c" = 429 ] && R429=1; [ "$c" = 500 ] && R500=1
done
inset "$RLAST" 429 && g=ok || g="status=$RLAST"
chk "R01 burst login 15x: dernier essai 429 (10/min/IP+username)" "$g" "ok" #check
[ "$R429" = 1 ] && g=ok || g="no-429"
chk "R02 burst login: au moins un 429 observé" "$g" "ok" #check
[ "$R500" = 0 ] && g=ok || g="saw-500"
chk "R03 burst login: jamais 500" "$g" "ok" #check
chk "R04 /api/information intacte pendant le burst login" "$(sok /api/information 200)" "ok" #check

# ================= S. rate-limit /cnf/* 20/min/IP (3) =================
SFIRST=""; SLAST=""; S429=0; S500=0
for _ in $(seq 1 25); do
  c=$(gcode /cnf/audit-probe-nope)
  [ -z "$SFIRST" ] && SFIRST="$c"; SLAST="$c"; [ "$c" = 429 ] && S429=1; [ "$c" = 500 ] && S500=1
done
inset "$SFIRST" 404 && g=ok || g="status=$SFIRST"
chk "S01 burst cnf: 1er essai 404" "$g" "ok" #check
inset "$SLAST" 429 && g=ok || g="status=$SLAST"
chk "S02 burst cnf: dernier essai 429 (20/min/IP)" "$g" "ok" #check
[ "$S429" = 1 ] && [ "$S500" = 0 ] && g=ok || g="429=$S429 500=$S500"
chk "S03 burst cnf: 429 vu, jamais 500" "$g" "ok" #check
