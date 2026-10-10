# lib.sh : socle sourcé par audit.sh (init + helpers HTTP/verdict). Zéro check.
# Sourcé par scripts/audit.sh dans un shell commun (mêmes globals, `set -u` hérité).
# Sections : Aucun. Fournit : BASE, T, P, FAILS, JAR_ANON/JAR, chk, gcode, gbody, gct, ghead, pcode, mcode, has, inset, sok, mor2, eitheror, langok.

set -u
export LC_ALL=C.UTF-8

BASE="${BASE_URL:-http://127.0.0.1:${PORT:-51821}}"
T=0; P=0; FAILS=()
JAR_ANON="$(mktemp)"; JAR="$(mktemp)"
trap 'rm -f "$JAR_ANON" "$JAR"' EXIT

chk() { # chk "label" got want1 [want2...] — EXACTEMENT 270 appels à l'exécution.
  local label="$1" got="$2"; shift 2
  T=$((T + 1))
  local w
  for w in "$@"; do
    if [ "$got" = "$w" ]; then P=$((P + 1)); return 0; fi
  done
  FAILS+=("$label :: got=[$got] want=[$*]")
}

# --- HTTP bas niveau (jamais de `set -e`, un curl mort donne 000/"" ) ---
gcode() { # GET -> code
  curl -sS -o /dev/null -w "%{http_code}" --max-time 10 ${3:-} -b "$JAR_ANON" "$BASE$1" 2>/dev/null || echo "000"
}
gbody() { # GET -> corps (avec jar auth si $3=auth)
  local jar="$JAR_ANON"; [ "${3:-anon}" = "auth" ] && jar="$JAR"
  curl -sS --max-time 10 -b "$jar" -c "$jar" "$BASE$1" 2>/dev/null || true
}
gct() { # GET -> content-type
  curl -sS -o /dev/null -w "%{content_type}" --max-time 10 -b "$JAR_ANON" "$BASE$1" 2>/dev/null || echo ""
}
ghead() { # GET -> valeur d'un header de réponse (insensible à la casse)
  curl -sS -o /dev/null -D - --max-time 10 -b "$JAR_ANON" "$BASE$1" 2>/dev/null \
    | grep -i "^$2:" | head -1 | cut -d: -f2- | tr -d '\r' | sed 's/^ *//'
}
pcode() { # POST JSON -> code (jar anonyme par défaut)
  local jar="$JAR_ANON"; [ "${4:-anon}" = "auth" ] && jar="$JAR"
  curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$jar" -c "$jar" \
    -H 'Content-Type: application/json' -d "$2" -X POST "$BASE$1" 2>/dev/null || echo "000"
}
mcode() { # méthode arbitraire -> code
  curl -sS -o /dev/null -w "%{http_code}" --max-time 10 -b "$JAR_ANON" -X "$2" "$BASE$1" 2>/dev/null || echo "000"
}
has() { printf '%s' "$1" | grep -qF "$2"; }
inset() { local v="$1"; shift; local x; for x in "$@"; do [ "$v" = "$x" ] && return 0; done; return 1; }

# --- helpers de verdict (n'appellent JAMAIS chk : chaque chk reste au top-level) ---
sok() { # sok url set... -> "ok" | "status=NNN"
  local url="$1"; shift; local c; c=$(gcode "$url")
  if inset "$c" "$@"; then echo "ok"; else echo "status=$c"; fi
}
mor2() { # mor2 url m1a m1b m2a m2b : page HTML (marqueurs FR/EN) ou redirect/login.
  local url="$1" c; c=$(gcode "$url")
  case "$c" in
    30*) echo "redirect-ok" ;;
    401|403) echo "auth-required" ;;
    200)
      local b; b=$(gbody "$url")
      if (has "$b" "$2" || has "$b" "$3") && (has "$b" "$4" || has "$b" "$5"); then echo "marker-ok"
      elif has "$b" "password"; then echo "login-page-ok"
      else echo "marker-missing"; fi ;;
    *) echo "status=$c" ;;
  esac
}
eitheror() { # eitheror url a b : contient a OU b (page 200), sinon redirect/login.
  local url="$1" c; c=$(gcode "$url")
  case "$c" in
    30*) echo "redirect-ok" ;;
    401|403) echo "auth-required" ;;
    200)
      local b; b=$(gbody "$url")
      if has "$b" "$2" || has "$b" "$3"; then echo "either-ok"
      elif has "$b" "password"; then echo "login-page-ok"
      else echo "either-missing"; fi ;;
    *) echo "status=$c" ;;
  esac
}
langok() { # langok url marker : page traduite (200+marqueur) ou redirect/login.
  local url="$1" c; c=$(gcode "$url")
  case "$c" in
    30*) echo "redirect-ok" ;;
    401|403) echo "auth-required" ;;
    200) has "$(gbody "$url")" "$2" && echo "lang-ok" || echo "lang-missing" ;;
    *) echo "status=$c" ;;
  esac
}
