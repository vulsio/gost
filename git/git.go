package git

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/inconshreveable/log15"
	"github.com/knqyf263/gost/util"
	"golang.org/x/xerrors"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing/object"
	"gopkg.in/src-d/go-git.v4/plumbing/storer"
)

// CloneOrPull clones or pulls vuln-list repository
func CloneOrPull(url, repoPath string) (map[string]struct{}, error) {
	exists, err := util.Exists(filepath.Join(repoPath, ".git"))
	if err != nil {
		return nil, xerrors.Errorf("failed to check if a file exists: %w", err)
	}

	updatedFiles := map[string]struct{}{}
	if exists {
		log15.Debug("git pull")
		files, err := pull(repoPath)
		if err != nil {
			return nil, xerrors.Errorf("failed to pull repository: %w", err)
		}

		for _, filename := range files {
			updatedFiles[strings.TrimSpace(filename)] = struct{}{}
		}
	} else {
		if !util.IsCommandAvailable("git") {
			log15.Warn("Recommend installing git (if not, DB update is very slow)")
		}
		log15.Debug("remove an existed directory")

		suffix := " It will take a while for the first time..."
		s := util.NewSpinner(suffix)
		s.Start()
		defer s.Stop()

		if err = os.RemoveAll(repoPath); err != nil {
			return nil, xerrors.Errorf("failed to remove an existed directory: %w", err)
		}

		if err = os.MkdirAll(repoPath, 0700); err != nil {
			return nil, xerrors.Errorf("failed to mkdir: %w", err)
		}
		if err := clone(url, repoPath); err != nil {
			return nil, xerrors.Errorf("failed to clone repository: %w", err)
		}

	}

	// Need to refresh all vulnerabilities
	err = filepath.Walk(repoPath, func(path string, info os.FileInfo, err error) error {
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(repoPath, path)
		if err != nil {
			return xerrors.Errorf("failed to get a relative path: %w", err)
		}
		updatedFiles[rel] = struct{}{}
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in file walk: %w", err)
	}

	return updatedFiles, nil
}

func clone(url, repoPath string) error {
	if util.IsCommandAvailable("git") {
		return cloneByOSCommand(url, repoPath)
	}

	_, err := git.PlainClone(repoPath, false, &git.CloneOptions{
		URL: url,
	})
	if err != nil && err != git.ErrRepositoryAlreadyExists {
		return xerrors.Errorf("unexpected error in git clone: %w", err)
	}
	return nil
}

func cloneByOSCommand(url, repoPath string) error {
	commandAndArgs := []string{"clone", "--depth=1", url, repoPath}
	_, err := util.Exec("git", commandAndArgs)
	if err != nil {
		return xerrors.Errorf("error in git clone: %w", err)
	}
	return nil
}

func pull(repoPath string) ([]string, error) {
	if util.IsCommandAvailable("git") {
		return pullByOSCommand(repoPath)
	}

	r, err := git.PlainOpen(repoPath)
	if err != nil {
		return nil, xerrors.Errorf("failed to open repository: %w", err)
	}

	log15.Debug("Retrieve the branch being pointed by HEAD")
	ref, err := r.Head()
	if err != nil {
		return nil, xerrors.Errorf("failed to get HEAD: %w", err)
	}

	log15.Debug("Get the working directory for the repository")
	w, err := r.Worktree()
	if err != nil {
		return nil, xerrors.Errorf("failed to get the working directory: %w", err)
	}

	log15.Debug("Pull the latest changes from the origin remote and merge into the current branch")
	err = w.Pull(&git.PullOptions{RemoteName: "origin"})
	if err != nil && err != git.NoErrAlreadyUpToDate {
		return nil, err
	} else if err == git.NoErrAlreadyUpToDate {
		return []string{}, nil
	}

	log15.Debug("Retrieve the commit history")
	commits, err := r.Log(&git.LogOptions{})
	if err != nil {
		return nil, xerrors.Errorf("error in git log: %w", err)
	}

	log15.Debug("Detect the updated files")
	var prevCommit *object.Commit
	var updatedFiles []string
	err = commits.ForEach(func(commit *object.Commit) error {
		if prevCommit == nil {
			prevCommit = commit
			return nil
		}

		patch, err := commit.Patch(prevCommit)
		if err != nil {
			return xerrors.Errorf("error in patch: %w", err)
		}
		for _, stat := range patch.Stats() {
			updatedFiles = append(updatedFiles, stat.Name)
		}

		if commit.Hash == ref.Hash() {
			return storer.ErrStop
		}

		prevCommit = commit
		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("error in commit foreach: %w", err)
	}

	return updatedFiles, nil
}

func pullByOSCommand(repoPath string) ([]string, error) {
	gitDir := filepath.Join(repoPath, ".git")
	commandArgs := []string{"--git-dir", gitDir, "--work-tree", repoPath}

	revParseCmd := []string{"rev-parse", "HEAD"}
	output, err := util.Exec("git", append(commandArgs, revParseCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git rev-parse: %w", err)
	}
	commitHash := strings.TrimSpace(output)

	pullCmd := []string{"pull", "origin", "main"}
	_, err = util.Exec("git", append(commandArgs, pullCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git pull: %w", err)
	}

	diffCmd := []string{"diff", commitHash, "HEAD", "--name-only"}
	output, err = util.Exec("git", append(commandArgs, diffCmd...))
	if err != nil {
		return nil, xerrors.Errorf("error in git diff: %w", err)
	}
	updatedFiles := strings.Split(strings.TrimSpace(output), "\n")
	return updatedFiles, nil
}
