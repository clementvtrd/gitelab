package gitutil

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$`)

func ValidName(s string) bool {
	return nameRe.MatchString(s) && !strings.Contains(s, "..")
}

func RepoDir(root, owner, name string) (string, error) {
	if !ValidName(owner) || !ValidName(name) {
		return "", fmt.Errorf("invalid repo name %q/%q", owner, name)
	}
	return filepath.Join(root, owner, name+".git"), nil
}

func Run(repoDir string, args ...string) (string, error) {
	full := append([]string{"-c", "safe.directory=*"}, args...)
	cmd := exec.Command("git", full...)
	if repoDir != "" {
		cmd.Dir = repoDir
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func InitBare(root, owner, name string) (string, error) {
	dir, err := RepoDir(root, owner, name)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return "", err
	}
	if _, err := Run("", "-c", "init.defaultBranch=main", "init", "--bare", dir); err != nil {
		return "", err
	}
	return dir, nil
}

type TreeEntry struct {
	Mode  string
	Type  string
	SHA   string
	Name  string
	Size  int64
	IsDir bool
}

func Tree(dir, ref, path string) ([]TreeEntry, error) {
	args := []string{"ls-tree", "--long", ref}
	if path != "" {
		args = append(args, "--", path)
	}
	out, err := Run(dir, args...)
	if err != nil {
		return nil, err
	}
	var entries []TreeEntry
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		meta, name, ok := strings.Cut(line, "\t")
		if !ok {
			continue
		}
		f := strings.Fields(meta)
		if len(f) != 4 {
			continue
		}
		size, _ := strconv.ParseInt(f[3], 10, 64)
		entries = append(entries, TreeEntry{
			Mode: f[0], Type: f[1], SHA: f[2], Name: name, Size: size, IsDir: f[1] == "tree",
		})
	}
	return entries, nil
}

type Commit struct {
	SHA     string
	Short   string
	Author  string
	Email   string
	Unix    int64
	Subject string
}

func Log(dir, ref string, limit int) ([]Commit, error) {
	format := "%H%x1f%an%x1f%ae%x1f%at%x1f%s%x1e"
	out, err := Run(dir, "log", "--no-color", "--format="+format, "-"+strconv.Itoa(limit), ref)
	if err != nil {
		return nil, err
	}
	var commits []Commit
	for _, rec := range strings.Split(out, "\x1e") {
		rec = strings.TrimSpace(rec)
		if rec == "" {
			continue
		}
		f := strings.SplitN(rec, "\x1f", 5)
		if len(f) != 5 {
			continue
		}
		unix, _ := strconv.ParseInt(f[3], 10, 64)
		sha := f[0]
		short := sha
		if len(short) > 7 {
			short = short[:7]
		}
		commits = append(commits, Commit{SHA: sha, Short: short, Author: f[1], Email: f[2], Unix: unix, Subject: f[4]})
	}
	return commits, nil
}

type Branch struct {
	Name  string
	Short string
}

func Branches(dir string) ([]Branch, error) {
	out, err := Run(dir, "for-each-ref", "--format=%(refname:short)%x1f%(objectname:short)", "refs/heads")
	if err != nil {
		return nil, err
	}
	var branches []Branch
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		if line == "" {
			continue
		}
		name, short, ok := strings.Cut(line, "\x1f")
		if !ok {
			continue
		}
		branches = append(branches, Branch{Name: name, Short: short})
	}
	return branches, nil
}

func ShowMeta(dir, sha string) (string, error) {
	return Run(dir, "show", "-s", "--no-color", "--format=fuller", sha)
}

func Diff(dir, sha string) (string, error) {
	return Run(dir, "diff-tree", "--root", "-p", "--no-commit-id", sha)
}

func Blob(dir, ref, path string) (size int64, content string, isText bool, err error) {
	szOut, err := Run(dir, "cat-file", "-s", ref+":"+path)
	if err != nil {
		return 0, "", false, err
	}
	size, _ = strconv.ParseInt(strings.TrimSpace(szOut), 10, 64)
	if size > 1<<20 {
		return size, "", false, nil
	}
	content, err = Run(dir, "show", ref+":"+path)
	if err != nil {
		return size, "", false, err
	}
	head := content
	if len(head) > 512 {
		head = head[:512]
	}
	return size, content, !strings.Contains(head, "\x00"), nil
}
