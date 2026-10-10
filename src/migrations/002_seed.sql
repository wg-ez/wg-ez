-- 002_seed.sql : seed idempotent (INSERT OR IGNORE) du setup initial.
-- Interface wg0 en 10.8.0.0/24 + pool IPv6, hooks NAT/FORWARD v4+v6, defauts
-- wg0, ligne general avec setupStep = 1 (setup non termine).

INSERT OR IGNORE INTO general (id, setupStep, sessionTimeout, metricsPrometheus, metricsJson, metricsPassword)
VALUES (1, 1, 3600, 0, 0, NULL);

INSERT OR IGNORE INTO interfaces (name, device, port, privateKey, publicKey, ipv4Cidr, ipv6Cidr, mtu, routingTable, firewallEnabled)
VALUES ('wg0', 'eth0', 51820, '', '', '10.8.0.0/24', 'fd00:dead:beef:cafe:babe:face:feed:0/112', 1420, 'auto', 0);

INSERT OR IGNORE INTO hooks (id, preUp, postUp, preDown, postDown)
VALUES (
  'wg0',
  '',
  'iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -s fd00:dead:beef:cafe:babe:face:feed:0/112 -o eth0 -j MASQUERADE; ip6tables -A INPUT -p udp -m udp --dport 51820 -j ACCEPT; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -A FORWARD -o wg0 -j ACCEPT',
  '',
  'iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE; iptables -D INPUT -p udp -m udp --dport 51820 -j ACCEPT; iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -s fd00:dead:beef:cafe:babe:face:feed:0/112 -o eth0 -j MASQUERADE; ip6tables -D INPUT -p udp -m udp --dport 51820 -j ACCEPT; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -D FORWARD -o wg0 -j ACCEPT'
);

INSERT OR IGNORE INTO user_configs (id, defaultMtu, defaultKeepalive, defaultDnsV4, defaultDnsV6, defaultAllowedIpsV4, defaultAllowedIpsV6, defaultPreSharedKey, host, port)
VALUES ('wg0', 1420, 0, '["1.1.1.1"]', '["2606:4700:4700::1111"]', '["0.0.0.0/0"]', '["::/0"]', 1, '', 51820);
