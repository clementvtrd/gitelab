package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"

	glssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/clementvtrd/gitelab/internal/config"
	"github.com/clementvtrd/gitelab/internal/gitutil"
	"github.com/clementvtrd/gitelab/internal/store"
)

type ctxKey string

const userIDKey ctxKey = "uid"

type Server struct {
	cfg *config.Config
	db  *store.Store
	srv *glssh.Server
}

func New(cfg *config.Config, db *store.Store) (*Server, error) {
	signer, err := hostSigner(cfg.HostKeyPath())
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, db: db}
	srv := &glssh.Server{
		Addr: cfg.SSHAddr,
		PublicKeyHandler: func(ctx glssh.Context, key glssh.PublicKey) bool {
			k, err := db.SSHKeyByFingerprint(gossh.FingerprintSHA256(key))
			if err != nil {
				return false
			}
			ctx.SetValue(userIDKey, k.UserID)
			return true
		},
		Handler: s.handle,
	}
	srv.AddHostKey(signer)
	s.srv = srv
	return s, nil
}

func (s *Server) ListenAndServe() error {
	log.Printf("ssh listening on %s", s.cfg.SSHAddr)
	return s.srv.ListenAndServe()
}

func (s *Server) Serve(l net.Listener) error {
	return s.srv.Serve(l)
}

// handle runs only git commands: git-upload-pack, git-receive-pack,
// git-upload-archive. Anything else is rejected.
func (s *Server) handle(sess glssh.Session) {
	uid, _ := sess.Context().Value(userIDKey).(int64)
	if uid == 0 {
		sess.Write([]byte("public key authentication required\n"))
		_ = sess.Exit(1)
		return
	}
	cmd := sess.Command()
	if len(cmd) != 2 {
		sess.Write([]byte("unsupported command\n"))
		_ = sess.Exit(1)
		return
	}
	verb, path := cmd[0], strings.TrimPrefix(cmd[1], "/")
	var gitVerb string
	switch verb {
	case "git-upload-pack":
		gitVerb = "upload-pack"
	case "git-receive-pack":
		gitVerb = "receive-pack"
	case "git-upload-archive":
		gitVerb = "upload-archive"
	default:
		sess.Write([]byte("unsupported command\n"))
		_ = sess.Exit(1)
		return
	}
	path = strings.TrimSuffix(path, ".git")
	owner, name, ok := strings.Cut(path, "/")
	if !ok || !gitutil.ValidName(owner) || !gitutil.ValidName(name) {
		sess.Write([]byte("bad repository path\n"))
		_ = sess.Exit(1)
		return
	}
	repo, err := s.db.RepoByName(owner, name)
	user, uerr := s.db.UserByID(uid)
	write := gitVerb == "receive-pack"
	if err != nil || uerr != nil ||
		(write && !s.db.CanWrite(repo, user)) ||
		(!write && !s.db.CanRead(repo, user)) {
		sess.Write([]byte("access denied\n"))
		_ = sess.Exit(1)
		return
	}
	dir, err := gitutil.RepoDir(s.cfg.ReposRoot(), owner, name)
	if err != nil {
		_ = sess.Exit(1)
		return
	}
	if _, err := os.Stat(dir); err != nil {
		sess.Write([]byte("repository not found\n"))
		_ = sess.Exit(1)
		return
	}
	env := os.Environ()
	for _, e := range sess.Environ() {
		if strings.HasPrefix(e, "GIT_PROTOCOL=") {
			env = append(env, e)
		}
	}
	c := exec.Command("git", gitVerb, dir)
	c.Env = env
	c.Stdin = sess
	c.Stdout = sess
	c.Stderr = sess.Stderr()
	if err := c.Run(); err != nil {
		_ = sess.Exit(1)
		return
	}
	_ = sess.Exit(0)
}

func hostSigner(path string) (glssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return gossh.ParsePrivateKey(b)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	blk, err := gossh.MarshalPrivateKey(priv, "gitelab")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(blk), 0o600); err != nil {
		return nil, err
	}
	return gossh.NewSignerFromKey(priv)
}
