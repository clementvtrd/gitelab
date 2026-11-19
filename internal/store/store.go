package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/clementvtrd/gitelab/internal/model"
	_ "modernc.org/sqlite"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	for _, p := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA busy_timeout=5000",
		"PRAGMA foreign_keys=ON",
	} {
		if _, err := db.Exec(p); err != nil {
			return nil, err
		}
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

const schema = `
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  email TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  is_admin INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS tokens(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_used_at DATETIME
);
CREATE TABLE IF NOT EXISTS ssh_keys(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE,
  key_type TEXT NOT NULL,
  key_blob BLOB NOT NULL,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS repos(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  owner TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  private INTEGER NOT NULL DEFAULT 0,
  created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(owner, name)
);
CREATE TABLE IF NOT EXISTS members(
  repo_id INTEGER NOT NULL REFERENCES repos(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role TEXT NOT NULL CHECK(role IN ('read','write')),
  PRIMARY KEY(repo_id, user_id)
);
CREATE TABLE IF NOT EXISTS sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at DATETIME NOT NULL
);
`

func (s *Store) migrate() error {
	_, err := s.db.Exec(schema)
	return err
}

func scanUser(row interface{ Scan(...any) error }) (*model.User, error) {
	u := &model.User{}
	err := row.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.IsAdmin, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow("SELECT COUNT(*) FROM users").Scan(&n)
	return n, err
}

func (s *Store) CreateUser(username, email, passwordHash string, admin bool) (*model.User, error) {
	res, err := s.db.Exec(
		"INSERT INTO users(username, email, password_hash, is_admin) VALUES(?,?,?,?)",
		username, email, passwordHash, admin)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	id, _ := res.LastInsertId()
	return s.UserByID(id)
}

func (s *Store) UserByName(name string) (*model.User, error) {
	u, err := scanUser(s.db.QueryRow(
		"SELECT id, username, email, password_hash, is_admin, created_at FROM users WHERE username=?", name))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) UserByID(id int64) (*model.User, error) {
	u, err := scanUser(s.db.QueryRow(
		"SELECT id, username, email, password_hash, is_admin, created_at FROM users WHERE id=?", id))
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) ListUsers() ([]model.User, error) {
	rows, err := s.db.Query("SELECT id, username, email, password_hash, is_admin, created_at FROM users ORDER BY username")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}
	return out, rows.Err()
}

func (s *Store) CreateToken(userID int64, name, hash string) (int64, error) {
	res, err := s.db.Exec("INSERT INTO tokens(user_id, name, hash) VALUES(?,?,?)", userID, name, hash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) TokenByHash(hash string) (*model.Token, error) {
	t := &model.Token{}
	err := s.db.QueryRow(
		"SELECT id, user_id, name, hash, created_at, last_used_at FROM tokens WHERE hash=?", hash).
		Scan(&t.ID, &t.UserID, &t.Name, &t.Hash, &t.CreatedAt, &t.LastUsedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	_, _ = s.db.Exec("UPDATE tokens SET last_used_at=CURRENT_TIMESTAMP WHERE id=?", t.ID)
	return t, nil
}

func (s *Store) ListTokens(userID int64) ([]model.Token, error) {
	rows, err := s.db.Query(
		"SELECT id, user_id, name, hash, created_at, last_used_at FROM tokens WHERE user_id=? ORDER BY id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Token
	for rows.Next() {
		var t model.Token
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.Hash, &t.CreatedAt, &t.LastUsedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteToken(userID, id int64) error {
	_, err := s.db.Exec("DELETE FROM tokens WHERE id=? AND user_id=?", id, userID)
	return err
}

func (s *Store) CreateSSHKey(userID int64, name, fingerprint, keyType string, blob []byte) (int64, error) {
	res, err := s.db.Exec(
		"INSERT INTO ssh_keys(user_id, name, fingerprint, key_type, key_blob) VALUES(?,?,?,?,?)",
		userID, name, fingerprint, keyType, blob)
	if err != nil {
		if isUniqueViolation(err) {
			return 0, ErrConflict
		}
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SSHKeyByFingerprint(fp string) (*model.SSHKey, error) {
	k := &model.SSHKey{}
	err := s.db.QueryRow(
		"SELECT id, user_id, name, fingerprint, key_type, key_blob, created_at FROM ssh_keys WHERE fingerprint=?", fp).
		Scan(&k.ID, &k.UserID, &k.Name, &k.Fingerprint, &k.KeyType, &k.KeyBlob, &k.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return k, nil
}

func (s *Store) ListSSHKeys(userID int64) ([]model.SSHKey, error) {
	rows, err := s.db.Query(
		"SELECT id, user_id, name, fingerprint, key_type, key_blob, created_at FROM ssh_keys WHERE user_id=? ORDER BY id", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SSHKey
	for rows.Next() {
		var k model.SSHKey
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Fingerprint, &k.KeyType, &k.KeyBlob, &k.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

func (s *Store) DeleteSSHKey(userID, id int64) error {
	_, err := s.db.Exec("DELETE FROM ssh_keys WHERE id=? AND user_id=?", id, userID)
	return err
}

func (s *Store) CreateRepo(owner, name, description string, private bool) (*model.Repo, error) {
	_, err := s.db.Exec(
		"INSERT INTO repos(owner, name, description, private) VALUES(?,?,?,?)",
		owner, name, description, private)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return s.RepoByName(owner, name)
}

func (s *Store) RepoByName(owner, name string) (*model.Repo, error) {
	r := &model.Repo{}
	err := s.db.QueryRow(
		"SELECT id, owner, name, description, private, created_at FROM repos WHERE owner=? AND name=?",
		owner, name).Scan(&r.ID, &r.Owner, &r.Name, &r.Description, &r.Private, &r.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (s *Store) ListRepos() ([]model.Repo, error) {
	return s.listRepos("SELECT id, owner, name, description, private, created_at FROM repos ORDER BY owner, name", nil)
}

func (s *Store) ListReposForUser(userID int64, username string) ([]model.Repo, error) {
	return s.listRepos(
		`SELECT DISTINCT r.id, r.owner, r.name, r.description, r.private, r.created_at
		 FROM repos r LEFT JOIN members m ON m.repo_id = r.id
		 WHERE r.private = 0 OR r.owner = ? OR m.user_id = ?
		 ORDER BY r.owner, r.name`, []any{username, userID})
}

func (s *Store) listRepos(query string, args []any) ([]model.Repo, error) {
	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Repo
	for rows.Next() {
		var r model.Repo
		if err := rows.Scan(&r.ID, &r.Owner, &r.Name, &r.Description, &r.Private, &r.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) AddMember(repoID, userID int64, role string) error {
	_, err := s.db.Exec(
		"INSERT INTO members(repo_id, user_id, role) VALUES(?,?,?) ON CONFLICT(repo_id, user_id) DO UPDATE SET role=excluded.role",
		repoID, userID, role)
	return err
}

func (s *Store) Role(repoID, userID int64) (string, bool) {
	var role string
	err := s.db.QueryRow("SELECT role FROM members WHERE repo_id=? AND user_id=?", repoID, userID).Scan(&role)
	if err != nil {
		return "", false
	}
	return role, true
}

func (s *Store) CanRead(r *model.Repo, u *model.User) bool {
	if !r.Private {
		return true
	}
	if u == nil {
		return false
	}
	if r.Owner == u.Username {
		return true
	}
	role, ok := s.Role(r.ID, u.ID)
	return ok && (role == "read" || role == "write")
}

func (s *Store) CanWrite(r *model.Repo, u *model.User) bool {
	if u == nil {
		return false
	}
	if r.Owner == u.Username {
		return true
	}
	role, ok := s.Role(r.ID, u.ID)
	return ok && role == "write"
}

func (s *Store) CreateSession(tokenHash string, userID int64, expires time.Time) error {
	_, err := s.db.Exec("INSERT INTO sessions(token_hash, user_id, expires_at) VALUES(?,?,?)", tokenHash, userID, expires)
	return err
}

func (s *Store) SessionByHash(tokenHash string) (int64, time.Time, error) {
	var uid int64
	var exp time.Time
	err := s.db.QueryRow("SELECT user_id, expires_at FROM sessions WHERE token_hash=?", tokenHash).Scan(&uid, &exp)
	if err == sql.ErrNoRows {
		return 0, time.Time{}, ErrNotFound
	}
	if err != nil {
		return 0, time.Time{}, err
	}
	return uid, exp, nil
}

func (s *Store) DeleteSession(tokenHash string) error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE token_hash=?", tokenHash)
	return err
}

func (s *Store) PurgeExpiredSessions() error {
	_, err := s.db.Exec("DELETE FROM sessions WHERE expires_at < CURRENT_TIMESTAMP")
	return err
}

func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
