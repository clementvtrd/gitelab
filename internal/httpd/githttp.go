package httpd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"

	"github.com/clementvtrd/gitelab/internal/auth"
	"github.com/clementvtrd/gitelab/internal/gitutil"
	"github.com/clementvtrd/gitelab/internal/model"
)

// gitHTTP proxies git smart HTTP requests to `git http-backend` after
// resolving the repo and checking permissions. Auth is HTTP Basic with a
// personal access token as the password.
// envWith returns base with the given KEY=value entries replacing any
// existing entry with the same key (execve env lookup returns the first
// match, so duplicates must be avoided).
func envWith(base []string, overrides ...string) []string {
	skip := make(map[string]bool, len(overrides))
	for _, o := range overrides {
		k, _, _ := strings.Cut(o, "=")
		skip[k] = true
	}
	out := make([]string, 0, len(base)+len(overrides))
	for _, e := range base {
		k, _, _ := strings.Cut(e, "=")
		if !skip[k] {
			out = append(out, e)
		}
	}
	return append(out, overrides...)
}

func (s *Server) gitHTTP(w http.ResponseWriter, r *http.Request) {
	owner := r.PathValue("owner")
	name := strings.TrimSuffix(r.PathValue("repo"), ".git")
	rest := r.PathValue("path")
	if !gitutil.ValidName(owner) || !gitutil.ValidName(name) {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	repo, err := s.db.RepoByName(owner, name)
	if err != nil {
		http.NotFound(w, r)
		return
	}

	var user *model.User
	if u, p, ok := r.BasicAuth(); ok && p != "" {
		if tok, err := s.db.TokenByHash(auth.HashToken(p)); err == nil {
			if uu, err := s.db.UserByID(tok.UserID); err == nil && (u == "" || uu.Username == u) {
				user = uu
			}
		}
	}

	write := strings.HasPrefix(rest, "git-receive-pack") ||
		(rest == "info/refs" && r.URL.Query().Get("service") == "git-receive-pack")
	if write && !s.db.CanWrite(repo, user) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gitelab"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}
	if !write && !s.db.CanRead(repo, user) {
		w.Header().Set("WWW-Authenticate", `Basic realm="gitelab"`)
		http.Error(w, "authentication required", http.StatusUnauthorized)
		return
	}

	dir, err := gitutil.RepoDir(s.cfg.ReposRoot(), owner, name)
	if err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if _, err := os.Stat(dir); err != nil {
		http.NotFound(w, r)
		return
	}

	env := envWith(os.Environ(),
		"GIT_PROJECT_ROOT="+s.cfg.ReposRoot(),
		"GIT_HTTP_EXPORT_ALL=1",
		"PATH_INFO=/"+repo.GitPath()+"/"+rest,
		"QUERY_STRING="+r.URL.RawQuery,
		"REQUEST_METHOD="+r.Method,
		"CONTENT_TYPE="+r.Header.Get("Content-Type"),
		"REMOTE_ADDR="+r.RemoteAddr,
	)
	if user != nil {
		env = envWith(env, "REMOTE_USER="+user.Username)
	}
	if r.ContentLength > 0 {
		env = envWith(env, fmt.Sprintf("CONTENT_LENGTH=%d", r.ContentLength))
	}
	if ce := r.Header.Get("Content-Encoding"); ce != "" {
		env = envWith(env, "HTTP_CONTENT_ENCODING="+ce)
	}
	if gp := r.Header.Get("Git-Protocol"); gp != "" {
		env = envWith(env, "HTTP_GIT_PROTOCOL="+gp)
	}

	cmd := exec.Command("git", "http-backend")
	cmd.Dir = s.cfg.ReposRoot()
	cmd.Env = env
	cmd.Stdin = r.Body
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	pr, pw := io.Pipe()
	cmd.Stdout = pw
	if err := cmd.Start(); err != nil {
		http.Error(w, "failed to start git http-backend", http.StatusInternalServerError)
		return
	}
	go func() { pw.CloseWithError(cmd.Wait()) }()

	br := bufio.NewReader(pr)
	status := http.StatusOK
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			log.Printf("githttp header read: %v; stderr: %s", err, stderr.String())
			http.Error(w, "bad gateway", http.StatusBadGateway)
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "status":
			fmt.Sscanf(strings.TrimSpace(v), "%d", &status)
		case "content-type":
			w.Header().Set("Content-Type", strings.TrimSpace(v))
		default:
			w.Header().Set(k, v)
		}
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, br)
	if stderr.Len() > 0 {
		log.Printf("git http-backend: %s", strings.TrimSpace(stderr.String()))
	}
}
