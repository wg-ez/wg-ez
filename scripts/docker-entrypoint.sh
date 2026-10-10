#!/bin/sh
# wg-ez — entrypoint runtime.
#
# `exec` : le binaire devient PID 1 et recoit directement SIGTERM/SIGINT.
# L'arret propre est deja gere dans le binaire (`with_graceful_shutdown` puis
# `Tunnel::shutdown`). Un shell intermediaire ne ferait que relayer le signal.
# `set -u` strict, pas de bashisme.
set -u

exec /usr/local/bin/wg-ez "$@"
