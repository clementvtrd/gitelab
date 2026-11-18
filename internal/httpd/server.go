package httpd

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"html/template"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/clementvtrd/gitelab/internal/auth"
	"github.com/clementvtrd/gitelab/internal/config"
	"github.com/clementvtrd/gitelab/internal/gitutil"
	"github.com/clementvtrd/gitelab/internal/model"
	"github.com/clementvtrd/gitelab/internal/store"
)

type view struct {
	Title, Name, CSRF, Error string
	User                     *model.User
	Repos                    []model.Repo
	Repo                     *model.Repo
	Ref, Path, Parent        string
	Entries                  []gitutil.TreeEntry
	BlobSize                 int64
	BlobText                 string
	BlobBinary               bool
	Commits                  []gitutil.Commit
	CommitSHA, CommitMeta    string
	Diff                     string
	Branches                 []gitutil.Branch
	Tokens                   []model.Token
	Keys                     []model.SSHKey
	NewToken                 string
	Users                    []model.User
	ExternalURL              string
}

type failEntry struct {
	count       int
	lockedUntil time.Time
}

type Server struct {
	cfg    *config.Config
	db     *store.Store
	tmpls  map[string]*template.Template
	secret []byte
	mu     sync.Mutex
	fails  map[string]failEntry
}

func New(cfg *config.Config, db *store.Store) (*Server, error) {
	tmpls, err := loadTemplates()
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &Server{cfg: cfg, db: db, tmpls: tmpls, secret: secret, fails: make(map[string]failEntry)}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("GET /{$}", s.home)
	mux.HandleFunc("GET /login", s.getLogin)
	mux.HandleFunc("POST /login", s.postLogin)
	mux.HandleFunc("POST /logout", s.postLogout)
	mux.HandleFunc("GET /repos", s.auth(s.getRepos))
	mux.HandleFunc("POST /repos", s.auth(s.postRepos))
	mux.HandleFunc("GET /r/{owner}/{repo}", s.auth(s.getRepo))
	mux.HandleFunc("GET /r/{owner}/{repo}/{rest...}", s.auth(s.repoPage))
	mux.HandleFunc("GET /settings", s.auth(s.getSettings))
	mux.HandleFunc("POST /settings/tokens", s.auth(s.postToken))
	mux.HandleFunc("POST /settings/tokens/{id}/delete", s.auth(s.deleteToken))
	mux.HandleFunc("POST /settings/ssh-keys", s.auth(s.postSSHKey))
	mux.HandleFunc("POST /settings/ssh-keys/{id}/delete", s.auth(s.deleteSSHKey))
	mux.HandleFunc("GET /admin/users", s.auth(s.admin(s.getAdminUsers)))
	mux.HandleFunc("POST /admin/users", s.auth(s.admin(s.postAdminUser)))
	mux.HandleFunc("GET /{owner}/{repo}/{path...}", s.gitHTTP)
	mux.HandleFunc("POST /{owner}/{repo}/{path...}", s.gitHTTP)
	return s.withCSRF(mux)
}

func (s *Server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.currentUser(r) == nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *Server) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u := s.currentUser(r)
		if u == nil || !u.IsAdmin {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (s *Server) currentUser(r *http.Request) *model.User {
	c, err := r.Cookie("gitelab_session")
	if err != nil || c.Value == "" {
		return nil
	}
	uid, exp, err := s.db.SessionByHash(auth.HashToken(c.Value))
	if err != nil || time.Now().After(exp) {
		return nil
	}
	u, err := s.db.UserByID(uid)
	if err != nil {
		return nil
	}
	return u
}

func isGitPath(p string) bool {
	parts := strings.Split(strings.Trim(p, "/"), "/")
	if len(parts) < 3 {
		return false
	}
	if strings.HasSuffix(parts[1], ".git") {
		return true
	}
	switch parts[2] {
	case "info", "git-upload-pack", "git-receive-pack":
		return true
	}
	return false
}

func (s *Server) withCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cv := ""
		if c, err := r.Cookie("gitelab_csrf"); err == nil && c.Value != "" {
			cv = c.Value
		} else {
			b := make([]byte, 16)
			if _, err := rand.Read(b); err != nil {
				http.Error(w, "server error", http.StatusInternalServerError)
				return
			}
			cv = hex.EncodeToString(b)
			http.SetCookie(w, &http.Cookie{
				Name: "gitelab_csrf", Value: cv, Path: "/",
				HttpOnly: true, SameSite: http.SameSiteLaxMode,
			})
		}
		if r.Method == http.MethodPost && !isGitPath(r.URL.Path) {
			if err := r.ParseForm(); err != nil {
				http.Error(w, "bad form", http.StatusBadRequest)
				return
			}
			if r.PostForm.Get("csrf") != s.csrfToken(cv) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) csrfToken(cv string) string {
	m := hmac.New(sha256.New, s.secret)
	m.Write([]byte(cv))
	return hex.EncodeToString(m.Sum(nil))
}

func (s *Server) csrf(r *http.Request) string {
	c, _ := r.Cookie("gitelab_csrf")
	return s.csrfToken(c.Value)
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, name, title string, mutate func(v *view)) {
	v := view{
		Title: title, Name: name,
		User: s.currentUser(r), CSRF: s.csrf(r),
		ExternalURL: s.cfg.ExternalURL,
	}
	if mutate != nil {
		mutate(&v)
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	tmpl, ok := s.tmpls[name]
	if !ok {
		http.Error(w, "unknown page", http.StatusInternalServerError)
		return
	}
	if err := tmpl.ExecuteTemplate(w, "layout", v); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain")
	w.Write([]byte("ok\n"))
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) != nil {
		http.Redirect(w, r, "/repos", http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) tooManyFails(r *http.Request) bool {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[ip]
	if time.Now().Before(f.lockedUntil) {
		return true
	}
	return f.count >= 10
}

func (s *Server) addFail(r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := s.fails[ip]
	f.count++
	if f.count >= 10 {
		f.lockedUntil = time.Now().Add(15 * time.Minute)
	}
	s.fails[ip] = f
}

func (s *Server) resetFails(r *http.Request) {
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fails, ip)
}
