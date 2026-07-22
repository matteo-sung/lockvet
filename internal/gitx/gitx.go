// Package gitx shells out to git for revision-aware file access.
package gitx

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Repo is a handle to a git repository working directory.
type Repo struct{ Dir string }

// Open locates the repository root at or above dir.
func Open(dir string) (*Repo, error) {
	out, err := run(dir, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil, fmt.Errorf("not a git repository (or git not installed): %w", err)
	}
	return &Repo{Dir: strings.TrimSpace(out)}, nil
}

// ChangedFiles lists paths changed between base and target revision.
// target == "" means the working tree (including untracked files).
func (r *Repo) ChangedFiles(base, target string) ([]string, error) {
	args := []string{"diff", "--name-only", base}
	if target != "" {
		args = append(args, target)
	}
	out, err := run(r.Dir, args...)
	if err != nil {
		return nil, err
	}
	files := splitLines(out)
	if target == "" { // also surface untracked lockfiles
		if out, err := run(r.Dir, "ls-files", "--others", "--exclude-standard"); err == nil {
			files = append(files, splitLines(out)...)
		}
	}
	return files, nil
}

// Show returns the file contents at a revision, or the working-tree file
// when rev == "". A missing file returns (nil, nil).
func (r *Repo) Show(rev, path string) ([]byte, error) {
	if rev == "" {
		data, err := os.ReadFile(filepath.Join(r.Dir, path))
		if os.IsNotExist(err) {
			return nil, nil
		}
		return data, err
	}
	cmd := exec.Command("git", "show", rev+":"+path)
	cmd.Dir = r.Dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if strings.Contains(msg, "does not exist") || strings.Contains(msg, "exists on disk, but not in") {
			return nil, nil
		}
		return nil, fmt.Errorf("git show %s:%s: %s", rev, path, strings.TrimSpace(msg))
	}
	return stdout.Bytes(), nil
}

// ResolveRev verifies a revision exists and returns a short display form.
func (r *Repo) ResolveRev(rev string) error {
	_, err := run(r.Dir, "rev-parse", "--verify", rev+"^{commit}")
	if err != nil {
		return fmt.Errorf("unknown revision %q", rev)
	}
	return nil
}

func run(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}
