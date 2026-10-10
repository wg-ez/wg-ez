-- 001_schema.sql : schema V1 (hors AWG et hors OAuth).
-- Aucun champ AWG, aucune colonne SaveConfig, aucune colonne `enabled` sur interfaces.
-- Dates en TEXT ISO-8601, booleens en INTEGER 0/1, listes en JSON TEXT.

-- Interfaces WireGuard (cle primaire = nom, defaut wg0).
CREATE TABLE IF NOT EXISTS interfaces (
  name TEXT PRIMARY KEY,
  device TEXT NOT NULL DEFAULT 'eth0',
  port INTEGER NOT NULL UNIQUE DEFAULT 51820,
  privateKey TEXT NOT NULL DEFAULT '',
  publicKey TEXT NOT NULL DEFAULT '',
  ipv4Cidr TEXT NOT NULL DEFAULT '10.8.0.0/24',
  ipv6Cidr TEXT NOT NULL DEFAULT 'fd00:dead:beef:cafe:babe:face:feed:0/112',
  mtu INTEGER NOT NULL DEFAULT 1420,
  routingTable TEXT NOT NULL DEFAULT 'auto',
  firewallEnabled INTEGER NOT NULL DEFAULT 0
);

-- Comptes : role 1 = ADMIN, 2 = CLIENT. password NULL = login password interdit.
-- Aucune colonne OAuth en V1.
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE,
  password TEXT,
  name TEXT NOT NULL,
  role INTEGER NOT NULL DEFAULT 2,
  totpKey TEXT,
  totpVerified INTEGER NOT NULL DEFAULT 0,
  enabled INTEGER NOT NULL DEFAULT 1
);

-- Clients : userId RESTRICT, interfaceId CASCADE ON UPDATE (+ CASCADE ON DELETE).
-- Les listes qui acceptent les deux familles sont eclatees v4/v6 (une colonne
-- par famille) : `allowedIpsV4`/`dnsV4` NULL = heritage du defaut global v4,
-- `firewallIpsV4` NULL = heritage de `allowedIpsV4` puis du defaut global v4,
-- idem cote v6. `serverAllowedIpsV4`/`V6` NOT NULL defaut [].
-- Aucune migration : la config repart de zero (volume neuf).
CREATE TABLE IF NOT EXISTS clients (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  interfaceId TEXT NOT NULL REFERENCES interfaces(name) ON DELETE CASCADE ON UPDATE CASCADE,
  name TEXT NOT NULL,
  ipv4Address TEXT UNIQUE,
  ipv6Address TEXT UNIQUE,
  privateKey TEXT NOT NULL,
  publicKey TEXT NOT NULL,
  preSharedKey TEXT NOT NULL DEFAULT '',
  allowedIpsV4 TEXT,
  allowedIpsV6 TEXT,
  serverAllowedIpsV4 TEXT NOT NULL DEFAULT '[]',
  serverAllowedIpsV6 TEXT NOT NULL DEFAULT '[]',
  firewallIpsV4 TEXT,
  firewallIpsV6 TEXT,
  dnsV4 TEXT,
  dnsV6 TEXT,
  mtu INTEGER,
  persistentKeepalive INTEGER,
  serverEndpoint TEXT,
  enabled INTEGER NOT NULL DEFAULT 1,
  expiresAt TEXT,
  createdAt TEXT NOT NULL,
  updatedAt TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_clients_pubkey_iface ON clients(publicKey, interfaceId);

-- Sessions : cle primaire = SHA-256 hex du token (le token clair n'est jamais stocke).
CREATE TABLE IF NOT EXISTS sessions (
  tokenHash TEXT PRIMARY KEY,
  userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expiresAt TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(userId);

-- Liens a usage unique : id = clientId (un seul lien par client), CASCADE.
-- token unique, 128 bits aleatoires en base64url sans padding ; expiresAt = creation + 5 min.
CREATE TABLE IF NOT EXISTS one_time_links (
  id INTEGER PRIMARY KEY REFERENCES clients(id) ON DELETE CASCADE,
  token TEXT NOT NULL UNIQUE,
  expiresAt TEXT NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_otl_token ON one_time_links(token);

-- Hooks serveur par interface (id = nom d'interface, CASCADE).
CREATE TABLE IF NOT EXISTS hooks (
  id TEXT PRIMARY KEY REFERENCES interfaces(name) ON DELETE CASCADE ON UPDATE CASCADE,
  preUp TEXT NOT NULL DEFAULT '',
  postUp TEXT NOT NULL DEFAULT '',
  preDown TEXT NOT NULL DEFAULT '',
  postDown TEXT NOT NULL DEFAULT ''
);

-- Defauts globaux par interface (id = nom d'interface, CASCADE).
-- DNS et AllowedIPs sont eclates v4/v6 : chaque famille a son propre pool de
-- defauts, pour que desactiver une famille ne touche jamais les valeurs de
-- l'autre (elles restent en base, simplement inutilisees).
CREATE TABLE IF NOT EXISTS user_configs (
  id TEXT PRIMARY KEY REFERENCES interfaces(name) ON DELETE CASCADE ON UPDATE CASCADE,
  defaultMtu INTEGER NOT NULL DEFAULT 1420,
  defaultKeepalive INTEGER NOT NULL DEFAULT 0,
  defaultDnsV4 TEXT NOT NULL DEFAULT '["1.1.1.1"]',
  defaultDnsV6 TEXT NOT NULL DEFAULT '["2606:4700:4700::1111"]',
  defaultAllowedIpsV4 TEXT NOT NULL DEFAULT '["0.0.0.0/0"]',
  defaultAllowedIpsV6 TEXT NOT NULL DEFAULT '["::/0"]',
  defaultPreSharedKey INTEGER NOT NULL DEFAULT 1,
  host TEXT NOT NULL DEFAULT '',
  port INTEGER NOT NULL DEFAULT 51820
);

-- Reglages globaux : ligne unique id = 1. setupStep 0 = setup termine.
CREATE TABLE IF NOT EXISTS general (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  setupStep INTEGER NOT NULL DEFAULT 1,
  sessionTimeout INTEGER NOT NULL DEFAULT 3600,
  metricsPrometheus INTEGER NOT NULL DEFAULT 0,
  metricsJson INTEGER NOT NULL DEFAULT 0,
  metricsPassword TEXT
);
