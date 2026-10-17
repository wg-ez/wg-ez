-- 005_api_tokens.sql : jetons d'API longue durée.
-- Seul le SHA-256 hex du token clair est stocké (`tokenHash`, jamais le clair).
-- `expiresAt` NULL = permanent ; `enabled` permet la révocation douce.
-- Dates en TEXT ISO-8601 canonique (comparaison lexicographique valide).
-- `IF NOT EXISTS` : migration idempotente (un rejeu ne casse rien et recrée la
-- table si un ancien binaire n'avait tamponné que `user_version` sans le DDL).
CREATE TABLE IF NOT EXISTS api_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  expiresAt TEXT,
  lastUsedAt TEXT,
  createdAt TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(tokenHash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(userId);
