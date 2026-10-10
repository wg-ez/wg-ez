-- 003_ipv6_hooks.sql : upgrade des hooks serveur par defaut v4-only vers
-- v4+v6 (NAT66 + FORWARD ip6tables) pour le pool IPv6 seede
-- `fd00:dead:beef:cafe:babe:face:feed:0/112`.
--
-- Ne touche QUE les hooks restes exactement au defaut seede par 002 : toute
-- personnalisation utilisateur (admin ou CLI) est preservee. Idempotent : une
-- fois migre, la clause WHERE ne matche plus.

UPDATE hooks
SET postUp = 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd00:dead:beef:cafe:babe:face:feed:0/112 -o eth0 -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT'
WHERE postUp = 'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT';

UPDATE hooks
SET postDown = 'iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -s fd00:dead:beef:cafe:babe:face:feed:0/112 -o eth0 -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport 51820 -j ACCEPT; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT'
WHERE postDown = 'iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT';
