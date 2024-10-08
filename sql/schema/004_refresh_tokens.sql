-- +gooseUp
CREATE TABLE refresh_tokens (
  token TEXT PRIMARY KEY,
  created_at TIMESTAMP NOT NULL,
  udpated_at TIMESTAMP NOT NULL,
  user_id UUID,
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  expires_at TIMESTAMP NOT NULL,
  revoked_at TIMESTAMP
);

-- +gooseDown
DROP TABLE refresh_tokens;
