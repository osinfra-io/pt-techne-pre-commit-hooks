package tofudir

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// FindDirsWithTofuFiles recursively finds directories containing .tf or .tofu files.
func FindDirsWithTofuFiles(root string) ([]string, error) {
	return walkDirs(root)
}

func walkDirs(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	var errs []error
	hasTofuFiles := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() {
			if strings.HasPrefix(name, ".") {
				continue
			}
			path := filepath.Join(dir, name)
			subDirs, err := walkDirs(path)
			if err != nil {
				errs = append(errs, err)
			}
			dirs = append(dirs, subDirs...)
		} else if strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tofu") {
			hasTofuFiles = true
		}
	}
	if hasTofuFiles {
		dirs = append(dirs, dir)
	}
	return dirs, errors.Join(errs...)
}
