#!/bin/sh
# wg-ez — entrypoint runtime.
#
# `exec` : le binaire devient PID 1 et recoit directement SIGTERM/SIGINT.
# L'arret propre est deja gere dans le binaire (`with_graceful_shutdown` puis
# `Tunnel::shutdown`). Un shell intermediaire ne ferait que relayer le signal.
# `set -u` strict, pas de bashisme.
set -u

# Rootless (Podman, user namespace) : le conteneur ne peut pas charger
# `ip_tables`/`iptable_nat`, donc `iptables-legacy` echoue sur `-t nat`
# ("Permission denied (you must be root)"). Les binaires nft de l'image
# s'appuient sur des modules deja charges sur tout hote moderne : bascule
# automatique si la table nat legacy est inutilisable. Docker/rootful garde
# legacy (la sonde reussit), donc aucun changement de comportement.
legacy_down=0
if ! iptables -t nat -S >/dev/null 2>&1 \
   && [ -x /usr/sbin/iptables-nft ] && [ -x /usr/sbin/ip6tables-nft ]; then
    legacy_down=1
    ln -sf /usr/sbin/iptables-nft /usr/bin/iptables
    ln -sf /usr/sbin/iptables-nft /usr/sbin/iptables
    ln -sf /usr/sbin/ip6tables-nft /usr/bin/ip6tables
    ln -sf /usr/sbin/ip6tables-nft /usr/sbin/ip6tables
fi

# Ubuntu confine `/usr/bin/wg-quick` (AppArmor) et son profil interdit le
# `readlink` busybox d'Alpine : passer par `bash /usr/bin/wg-quick` via un
# shim dans `/usr/local/bin` contourne la transition de profil. Le shim n'est
# cree qu'en rootless legacy (`legacy_down`) ou dans un conteneur Podman
# (`/run/.containerenv`) : Docker/rootful garde le wg-quick d'origine.
if [ -x /usr/bin/wg-quick ] && [ -w /usr/local/bin ] \
   && { [ "$legacy_down" = 1 ] || [ -e /run/.containerenv ]; }; then
    printf '#!/bin/bash\nexec /bin/bash /usr/bin/wg-quick "$@"\n' > /usr/local/bin/wg-quick
    chmod +x /usr/local/bin/wg-quick
fi

exec /usr/local/bin/wg-ez "$@"
