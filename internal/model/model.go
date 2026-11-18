package model

import "time"

type User struct {
	ID           int64
	Username     string
	Email        string
	PasswordHash string
	IsAdmin      bool
	CreatedAt    time.Time
}

type Token struct {
	ID         int64
	UserID     int64
	Name       string
	Hash       string
	CreatedAt  time.Time
	LastUsedAt *time.Time
}

type SSHKey struct {
	ID          int64
	UserID      int64
	Name        string
	Fingerprint string
	KeyType     string
	KeyBlob     []byte
	CreatedAt   time.Time
}

type Repo struct {
	ID          int64
	Owner       string
	Name        string
	Description string
	Private     bool
	CreatedAt   time.Time
}

func (r Repo) FullName() string { return r.Owner + "/" + r.Name }
func (r Repo) GitPath() string  { return r.Owner + "/" + r.Name + ".git" }

type Member struct {
	RepoID int64
	UserID int64
	Role   string
}
