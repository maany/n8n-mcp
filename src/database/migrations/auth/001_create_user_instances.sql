CREATE TABLE IF NOT EXISTS user_instances (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  instance_name TEXT NOT NULL,
  n8n_api_url TEXT NOT NULL,
  n8n_api_key_encrypted TEXT NOT NULL,
  n8n_api_key_iv TEXT NOT NULL,
  n8n_api_key_auth_tag TEXT NOT NULL,
  is_default INTEGER DEFAULT 0,
  timeout_ms INTEGER DEFAULT 30000,
  max_retries INTEGER DEFAULT 3,
  metadata TEXT,
  verification_status TEXT DEFAULT 'unverified'
    CHECK(verification_status IN ('unverified', 'valid', 'invalid', 'expired')),
  last_verified_at DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(user_id, instance_name),
  FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_user_instances_user_id ON user_instances(user_id);
CREATE INDEX IF NOT EXISTS idx_user_instances_default ON user_instances(user_id, is_default);
CREATE INDEX IF NOT EXISTS idx_user_instances_url ON user_instances(n8n_api_url);
