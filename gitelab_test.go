package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	gossh "golang.org/x/crypto/ssh"

	"github.com/clementvtrd/gitelab/internal/auth"
	"github.com/clementvtrd/gitelab/internal/config"
	"github.com/clementvtrd/gitelab/internal/httpd"
	"github.com/clementvtrd/gitelab/internal/sshd"
	"github.com/clementvtrd/gitelab/internal/store"
)

func get(t *testing.T, client *http.Client, url string) (int, string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func postForm(t *testing.T, client *http.Client, url string, form url.Values) (int, string) {
	t.Helper()
	resp, err := client.PostForm(url, form)
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)
var tokenRe = regexp.MustCompile(`<code>(gtl_[0-9a-f]+)</code>`)

func csrfOf(t *testing.T, body string) string {
	t.Helper()
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no csrf token in page:\n%.500s", body)
	}
	return m[1]
}

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestEndToEnd(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{
		DataDir:     dir,
		HTTPAddr:    "127.0.0.1:0",
		SSHAddr:     "127.0.0.1:0",
		ExternalURL: "http://gitelab.local",
		SessionDays: 30,
	}
	if err := os.MkdirAll(cfg.ReposRoot(), 0o755); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(cfg.DBPath())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	hash, err := auth.HashPassword("s3cret")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateUser("admin", "admin@localhost", hash, true); err != nil {
		t.Fatal(err)
	}

	hs, err := httpd.New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	hl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	hsrv := &http.Server{Handler: hs.Handler()}
	go hsrv.Serve(hl)
	defer hsrv.Close()
	base := "http://" + hl.Addr().String()

	ss, err := sshd.New(cfg, db)
	if err != nil {
		t.Fatal(err)
	}
	sl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go ss.Serve(sl)
	sshAddr := sl.Addr().String()

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 15 * time.Second,
	}

	// healthz
	if code, body := get(t, client, base+"/healthz"); code != 200 || strings.TrimSpace(body) != "ok" {
		t.Fatalf("healthz: %d %q", code, body)
	}

	// login page gives a csrf token
	code, body := get(t, client, base+"/login")
	if code != 200 {
		t.Fatalf("GET /login: %d", code)
	}
	csrf := csrfOf(t, body)

	// wrong password rejected
	code, _ = postForm(t, client, base+"/login", url.Values{
		"username": {"admin"}, "password": {"wrong"}, "csrf": {csrf},
	})
	if code != 200 {
		t.Fatalf("bad login should render login page (200), got %d", code)
	}

	// good login redirects
	code, _ = postForm(t, client, base+"/login", url.Values{
		"username": {"admin"}, "password": {"s3cret"}, "csrf": {csrf},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("login: expected 303, got %d", code)
	}

	// create a repo
	_, body = get(t, client, base+"/repos")
	csrf = csrfOf(t, body)
	code, _ = postForm(t, client, base+"/repos", url.Values{
		"name": {"test"}, "description": {"dépôt de test"}, "csrf": {csrf},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("create repo: expected 303, got %d", code)
	}

	// create a PAT
	_, body = get(t, client, base+"/settings")
	csrf = csrfOf(t, body)
	code, body = postForm(t, client, base+"/settings/tokens", url.Values{
		"name": {"ci"}, "csrf": {csrf},
	})
	if code != 200 {
		t.Fatalf("create token: %d", code)
	}
	m := tokenRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no token in settings page:\n%.500s", body)
	}
	token := m[1]

	// clone over HTTP with the PAT, commit, push
	cloneURL := strings.Replace(base, "http://", "http://admin:"+token+"@", 1) + "/admin/test.git"
	work := t.TempDir()
	runGit(t, work, "clone", cloneURL, "repo")
	repoDir := filepath.Join(work, "repo")
	if err := os.WriteFile(filepath.Join(repoDir, "hello.txt"), []byte("bonjour gitelab\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, repoDir, "add", "hello.txt")
	runGit(t, repoDir, "-c", "user.email=t@example.com", "-c", "user.name=test", "commit", "-m", "init")
	runGit(t, repoDir, "push", "origin", "HEAD")

	out := runGit(t, work, "ls-remote", cloneURL)
	if !strings.Contains(out, "refs/heads/main") {
		t.Fatalf("ls-remote missing main:\n%s", out)
	}

	// web browse shows the pushed file
	code, body = get(t, client, base+"/r/admin/test/tree/HEAD")
	if code != 200 || !strings.Contains(body, "hello.txt") {
		t.Fatalf("tree page: code=%d contains hello.txt=%v", code, strings.Contains(body, "hello.txt"))
	}
	code, body = get(t, client, base+"/r/admin/test/commits/HEAD")
	if code != 200 || !strings.Contains(body, "init") {
		t.Fatalf("commits page: code=%d", code)
	}

	// git over SSH: register a key, then run git-upload-pack through the SSH server
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := gossh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pubLine := strings.TrimSpace(string(gossh.MarshalAuthorizedKey(signer.PublicKey())))
	_, body = get(t, client, base+"/settings")
	csrf = csrfOf(t, body)
	code, _ = postForm(t, client, base+"/settings/ssh-keys", url.Values{
		"name": {"test-key"}, "key": {pubLine}, "csrf": {csrf},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("add ssh key: expected 303, got %d", code)
	}

	scfg := &gossh.ClientConfig{
		User:            "git",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	conn, err := gossh.Dial("tcp", sshAddr, scfg)
	if err != nil {
		t.Fatalf("ssh dial: %v", err)
	}
	defer conn.Close()
	sess, err := conn.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	var outBuf bytes.Buffer
	sess.Stdin = strings.NewReader("")
	sess.Stdout = &outBuf
	// stdin is closed immediately, so upload-pack exits non-zero after
	// sending the ref advertisement — what matters is the advertisement.
	_ = sess.Run("git-upload-pack '/admin/test.git'")
	if !strings.Contains(outBuf.String(), "refs/heads/main") {
		t.Fatalf("unexpected upload-pack output: %q", outBuf.String())
	}

	// unknown key is rejected
	_, priv2, _ := ed25519.GenerateKey(rand.Reader)
	signer2, _ := gossh.NewSignerFromKey(priv2)
	scfg2 := &gossh.ClientConfig{
		User:            "git",
		Auth:            []gossh.AuthMethod{gossh.PublicKeys(signer2)},
		HostKeyCallback: gossh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}
	if _, err := gossh.Dial("tcp", sshAddr, scfg2); err == nil {
		t.Fatal("unknown ssh key should be rejected")
	}

	// private repo is not readable anonymously over HTTP
	_, body = get(t, client, base+"/repos")
	csrf = csrfOf(t, body)
	code, _ = postForm(t, client, base+"/repos", url.Values{
		"name": {"secret"}, "private": {"1"}, "csrf": {csrf},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("create private repo: %d", code)
	}
	anon := &http.Client{Timeout: 10 * time.Second}
	resp, err := anon.Get(base + "/admin/secret.git/info/refs?service=git-upload-pack")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("anonymous read of private repo: expected 401, got %d", resp.StatusCode)
	}
}
