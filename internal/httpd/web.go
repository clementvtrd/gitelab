package httpd

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/clementvtrd/gitelab/internal/auth"
	"github.com/clementvtrd/gitelab/internal/gitutil"
	"github.com/clementvtrd/gitelab/internal/model"
	"github.com/clementvtrd/gitelab/internal/store"
)

func (s *Server) getLogin(w http.ResponseWriter, r *http.Request) {
	if s.currentUser(r) != nil {
		http.Redirect(w, r, "/repos", http.StatusSeeOther)
		return
	}
	s.render(w, r, "login", "Connexion", nil)
}

func (s *Server) postLogin(w http.ResponseWriter, r *http.Request) {
	if s.tooManyFails(r) {
		http.Error(w, "too many attempts, try again later", http.StatusTooManyRequests)
		return
	}
	username := strings.TrimSpace(r.PostForm.Get("username"))
	password := r.PostForm.Get("password")
	u, err := s.db.UserByName(username)
	if err != nil || !auth.VerifyPassword(password, u.PasswordHash) {
		s.addFail(r)
		s.render(w, r, "login", "Connexion", func(v *view) { v.Error = "Identifiants invalides" })
		return
	}
	s.resetFails(r)
	plain, hash, err := auth.NewSessionToken()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	expires := time.Now().AddDate(0, 0, s.cfg.SessionDays)
	if err := s.db.CreateSession(hash, u.ID, expires); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: "gitelab_session", Value: plain, Path: "/",
		Expires: expires, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, "/repos", http.StatusSeeOther)
}

func (s *Server) postLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("gitelab_session"); err == nil {
		_ = s.db.DeleteSession(auth.HashToken(c.Value))
		http.SetCookie(w, &http.Cookie{Name: "gitelab_session", Value: "", Path: "/", MaxAge: -1})
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) getRepos(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	repos, err := s.db.ListReposForUser(u.ID, u.Username)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.render(w, r, "repos", "Dépôts", func(v *view) { v.Repos = repos })
}

func (s *Server) postRepos(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	name := strings.TrimSpace(r.PostForm.Get("name"))
	desc := strings.TrimSpace(r.PostForm.Get("description"))
	private := r.PostForm.Get("private") == "1"
	if !gitutil.ValidName(name) {
		s.renderReposError(w, r, u, "Nom invalide (lettres, chiffres, . _ -, max 64 caractères)")
		return
	}
	repo, err := s.db.CreateRepo(u.Username, name, desc, private)
	if err != nil {
		msg := "server error"
		if err == store.ErrConflict {
			msg = "Un dépôt portant ce nom existe déjà"
		}
		s.renderReposError(w, r, u, msg)
		return
	}
	if _, err := gitutil.InitBare(s.cfg.ReposRoot(), repo.Owner, repo.Name); err != nil {
		http.Error(w, "failed to init repo: "+err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/r/"+repo.Owner+"/"+repo.Name, http.StatusSeeOther)
}

func (s *Server) renderReposError(w http.ResponseWriter, r *http.Request, u *model.User, msg string) {
	repos, _ := s.db.ListReposForUser(u.ID, u.Username)
	s.render(w, r, "repos", "Dépôts", func(v *view) { v.Repos = repos; v.Error = msg })
}

// loadRepo resolves owner/repo from the request and enforces read access.
func (s *Server) loadRepo(w http.ResponseWriter, r *http.Request) (*model.Repo, bool) {
	owner := r.PathValue("owner")
	name := r.PathValue("repo")
	if !gitutil.ValidName(owner) || !gitutil.ValidName(name) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return nil, false
	}
	repo, err := s.db.RepoByName(owner, name)
	if err != nil || !s.db.CanRead(repo, s.currentUser(r)) {
		http.NotFound(w, r)
		return nil, false
	}
	return repo, true
}

func (s *Server) repoDir(repo *model.Repo) string {
	dir, _ := gitutil.RepoDir(s.cfg.ReposRoot(), repo.Owner, repo.Name)
	return dir
}

func (s *Server) getRepo(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.loadRepo(w, r)
	if !ok {
		return
	}
	http.Redirect(w, r, "/r/"+repo.Owner+"/"+repo.Name+"/tree/HEAD", http.StatusSeeOther)
}

// repoPage dispatches /r/{owner}/{repo}/{rest...} where rest is one of:
// tree/{ref}/{path...}, blob/{ref}/{path...}, commits/{ref}, commit/{sha}, branches
func (s *Server) repoPage(w http.ResponseWriter, r *http.Request) {
	repo, ok := s.loadRepo(w, r)
	if !ok {
		return
	}
	rest := strings.Trim(r.PathValue("rest"), "/")
	if rest == "" {
		http.Redirect(w, r, "/r/"+repo.Owner+"/"+repo.Name+"/tree/HEAD", http.StatusSeeOther)
		return
	}
	segments := strings.Split(rest, "/")
	need := func(n int) bool {
		if len(segments) < n {
			http.NotFound(w, r)
			return false
		}
		return true
	}
	switch segments[0] {
	case "tree":
		if !need(2) {
			return
		}
		s.showTree(w, r, repo, segments[1], strings.Join(segments[2:], "/"))
	case "blob":
		if !need(2) {
			return
		}
		s.showBlob(w, r, repo, segments[1], strings.Join(segments[2:], "/"))
	case "commits":
		if !need(2) {
			return
		}
		s.showCommits(w, r, repo, segments[1])
	case "commit":
		if !need(2) {
			return
		}
		s.showCommit(w, r, repo, segments[1])
	case "branches":
		s.showBranches(w, r, repo)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) showTree(w http.ResponseWriter, r *http.Request, repo *model.Repo, ref, path string) {
	entries, err := gitutil.Tree(s.repoDir(repo), ref, path)
	if err != nil {
		http.Error(w, "ref not found", http.StatusNotFound)
		return
	}
	parent := ""
	if i := strings.LastIndex(path, "/"); path != "" && i >= 0 {
		parent = path[:i]
	}
	s.render(w, r, "tree", repo.FullName(), func(v *view) {
		v.Repo = repo
		v.Ref = ref
		v.Path = path
		v.Parent = parent
		v.Entries = entries
	})
}

func (s *Server) showBlob(w http.ResponseWriter, r *http.Request, repo *model.Repo, ref, path string) {
	size, content, isText, err := gitutil.Blob(s.repoDir(repo), ref, path)
	if err != nil {
		http.Error(w, "blob not found", http.StatusNotFound)
		return
	}
	s.render(w, r, "blob", path, func(v *view) {
		v.Repo = repo
		v.Ref = ref
		v.Path = path
		v.BlobSize = size
		v.BlobText = content
		v.BlobBinary = !isText
	})
}

func (s *Server) showCommits(w http.ResponseWriter, r *http.Request, repo *model.Repo, ref string) {
	commits, err := gitutil.Log(s.repoDir(repo), ref, 100)
	if err != nil {
		http.Error(w, "ref not found", http.StatusNotFound)
		return
	}
	s.render(w, r, "commits", "Commits", func(v *view) {
		v.Repo = repo
		v.Ref = ref
		v.Commits = commits
	})
}

func (s *Server) showCommit(w http.ResponseWriter, r *http.Request, repo *model.Repo, sha string) {
	dir := s.repoDir(repo)
	meta, err := gitutil.ShowMeta(dir, sha)
	if err != nil {
		http.Error(w, "commit not found", http.StatusNotFound)
		return
	}
	diff, _ := gitutil.Diff(dir, sha)
	s.render(w, r, "commit", sha, func(v *view) {
		v.Repo = repo
		v.CommitSHA = sha
		v.CommitMeta = meta
		v.Diff = diff
	})
}

func (s *Server) showBranches(w http.ResponseWriter, r *http.Request, repo *model.Repo) {
	branches, err := gitutil.Branches(s.repoDir(repo))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	s.render(w, r, "branches", "Branches", func(v *view) {
		v.Repo = repo
		v.Branches = branches
	})
}

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) {
	s.renderSettings(w, r, "", "")
}

func (s *Server) renderSettings(w http.ResponseWriter, r *http.Request, newToken, errMsg string) {
	u := s.currentUser(r)
	tokens, _ := s.db.ListTokens(u.ID)
	keys, _ := s.db.ListSSHKeys(u.ID)
	s.render(w, r, "settings", "Paramètres", func(v *view) {
		v.Tokens = tokens
		v.Keys = keys
		v.NewToken = newToken
		v.Error = errMsg
	})
}

func (s *Server) postToken(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" {
		s.renderSettings(w, r, "", "Nom requis")
		return
	}
	plain, hash, err := auth.NewToken()
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if _, err := s.db.CreateToken(u.ID, name, hash); err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	s.renderSettings(w, r, plain, "")
}

func (s *Server) deleteToken(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.db.DeleteToken(u.ID, id)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) postSSHKey(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	name := strings.TrimSpace(r.PostForm.Get("name"))
	keyLine := strings.TrimSpace(r.PostForm.Get("key"))
	pub, comment, _, _, err := gossh.ParseAuthorizedKey([]byte(keyLine))
	if err != nil {
		s.renderSettings(w, r, "", "Clé SSH invalide")
		return
	}
	if name == "" {
		name = comment
	}
	if name == "" {
		name = pub.Type()
	}
	fp := gossh.FingerprintSHA256(pub)
	_, err = s.db.CreateSSHKey(u.ID, name, fp, pub.Type(), pub.Marshal())
	if err == store.ErrConflict {
		s.renderSettings(w, r, "", "Cette clé est déjà enregistrée")
		return
	}
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) deleteSSHKey(w http.ResponseWriter, r *http.Request) {
	u := s.currentUser(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.db.DeleteSSHKey(u.ID, id)
	http.Redirect(w, r, "/settings", http.StatusSeeOther)
}

func (s *Server) getAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, _ := s.db.ListUsers()
	s.render(w, r, "admin", "Administration", func(v *view) { v.Users = users })
}

func (s *Server) postAdminUser(w http.ResponseWriter, r *http.Request) {
	username := strings.TrimSpace(r.PostForm.Get("username"))
	email := strings.TrimSpace(r.PostForm.Get("email"))
	password := r.PostForm.Get("password")
	if !auth.ValidUsername(username) || password == "" {
		s.renderAdminError(w, r, "Nom d'utilisateur ou mot de passe invalide")
		return
	}
	hash, err := auth.HashPassword(password)
	if err != nil {
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	if _, err := s.db.CreateUser(username, email, hash, false); err != nil {
		msg := "server error"
		if err == store.ErrConflict {
			msg = "Cet utilisateur existe déjà"
		}
		s.renderAdminError(w, r, msg)
		return
	}
	http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
}

func (s *Server) renderAdminError(w http.ResponseWriter, r *http.Request, msg string) {
	users, _ := s.db.ListUsers()
	s.render(w, r, "admin", "Administration", func(v *view) { v.Users = users; v.Error = msg })
}
