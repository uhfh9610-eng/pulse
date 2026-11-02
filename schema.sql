 CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, email TEXT NOT NULL UNIQUE,
  pass_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);

CREATE TABLE IF NOT EXISTS communities (
  name TEXT PRIMARY KEY, title TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  community TEXT NOT NULL REFERENCES communities(name),
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  title TEXT NOT NULL, body TEXT NOT NULL DEFAULT '',
  hidden INTEGER NOT NULL DEFAULT 0,
  hidden_by TEXT, hidden_reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_posts_community ON posts(community, created_at DESC);

CREATE TABLE IF NOT EXISTS comments (
  id TEXT PRIMARY KEY,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  parent_id TEXT REFERENCES comments(id) ON DELETE CASCADE,
  author_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  hidden INTEGER NOT NULL DEFAULT 0,
  hidden_by TEXT, hidden_reason TEXT,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_comments_post ON comments(post_id, created_at);
CREATE INDEX IF NOT EXISTS idx_comments_parent ON comments(parent_id);

CREATE TABLE IF NOT EXISTS votes (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  target_type TEXT NOT NULL CHECK (target_type IN ('post','comment')),
  target_id TEXT NOT NULL, value INTEGER NOT NULL CHECK (value IN (-1,1)),
  created_at INTEGER NOT NULL,
  PRIMARY KEY (user_id, target_type, target_id)
);
CREATE INDEX IF NOT EXISTS idx_votes_target ON votes(target_type, target_id);

CREATE TABLE IF NOT EXISTS saved (
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  post_id TEXT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL, PRIMARY KEY (user_id, post_id)
);

CREATE TABLE IF NOT EXISTS reports (
  id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_id TEXT NOT NULL,
  reporter_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  reason TEXT NOT NULL, created_at INTEGER NOT NULL, resolved INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_reports_open ON reports(resolved, created_at DESC);

CREATE TABLE IF NOT EXISTS rate_limits (
  key TEXT NOT NULL, window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (key, window_start)
);

CREATE TABLE IF NOT EXISTS roles (
  user_id TEXT PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK (role IN ('main_admin','sub_admin')),
  granted_at INTEGER NOT NULL, expires_at INTEGER
);

CREATE TABLE IF NOT EXISTS elections (
  id TEXT PRIMARY KEY,
  cycle TEXT NOT NULL UNIQUE,
  phase TEXT NOT NULL,
  nomination_ends INTEGER NOT NULL,
  voting_ends INTEGER NOT NULL,
  winner_id TEXT REFERENCES users(id) ON DELETE SET NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS candidates (
  id TEXT PRIMARY KEY,
  election_id TEXT NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  statement TEXT NOT NULL DEFAULT '',
  disqualified INTEGER NOT NULL DEFAULT 0,
  dq_reason TEXT,
  created_at INTEGER NOT NULL,
  UNIQUE (election_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_candidates_election ON candidates(election_id, disqualified);

CREATE TABLE IF NOT EXISTS election_votes (
  election_id TEXT NOT NULL REFERENCES elections(id) ON DELETE CASCADE,
  voter_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  candidate_id TEXT NOT NULL REFERENCES candidates(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (election_id, voter_id)
);

CREATE TABLE IF NOT EXISTS audit_log (
  id TEXT PRIMARY KEY, actor_id TEXT, action TEXT NOT NULL,
  detail TEXT, created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

INSERT OR IGNORE INTO communities (name, title, description, created_at) VALUES
  ('webdev','Web Development','HTML, CSS, JS, frameworks, and the messy parts in between.',0),
  ('programming','Programming','Computer programming news, articles, and discussion.',0),
  ('design','Design','UI, UX, typography, color, and the craft of making things feel right.',0),
  ('todayilearned','Today I Learned','You learn something new every day. Post what surprised you.',0),
  ('buildinpublic','Building in Public','Share progress, launches, metrics, and lessons from shipping.',0);
