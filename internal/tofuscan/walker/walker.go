package walker

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// FindTofuFiles recursively finds all .tofu files under the given paths,
// skipping hidden directories (names starting with ".").
func FindTofuFiles(paths []string) ([]string, error) {
	var files []string
	for _, root := range paths {
		info, err := os.Stat(root)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			if filepath.Ext(root) == ".tofu" {
				files = append(files, root)
			}
			continue
		}
		err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && strings.HasPrefix(d.Name(), ".") && d.Name() != "." {
				return fs.SkipDir
			}
			if !d.IsDir() && filepath.Ext(path) == ".tofu" {
				files = append(files, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
