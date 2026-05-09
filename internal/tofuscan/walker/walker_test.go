package walker

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestFindTofuFiles(t *testing.T) {
	tmp := t.TempDir()

	// Create a directory tree with mixed file types.
	dirs := []string{
		filepath.Join(tmp, "modules", "vpc"),
		filepath.Join(tmp, "envs", "prod"),
		filepath.Join(tmp, ".terraform", "modules", "vpc"),
		filepath.Join(tmp, ".git"),
		filepath.Join(tmp, ".hidden"),
	}
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}

	tofuFiles := []string{
		filepath.Join(tmp, "main.tofu"),
		filepath.Join(tmp, "modules", "vpc", "main.tofu"),
		filepath.Join(tmp, "envs", "prod", "backend.tofu"),
	}
	ignoredFiles := []string{
		filepath.Join(tmp, ".terraform", "modules", "vpc", "main.tofu"),
		filepath.Join(tmp, ".git", "hooks.tofu"),
		filepath.Join(tmp, ".hidden", "secret.tofu"),
	}
	nonTofuFiles := []string{
		filepath.Join(tmp, "main.tf"),
		filepath.Join(tmp, "README.md"),
		filepath.Join(tmp, "modules", "vpc", "outputs.tf"),
	}

	allFiles := append(append(tofuFiles, ignoredFiles...), nonTofuFiles...)
	for _, f := range allFiles {
		if err := os.WriteFile(f, []byte("# placeholder"), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := FindTofuFiles([]string{tmp})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	sort.Strings(got)
	sort.Strings(tofuFiles)

	if len(got) != len(tofuFiles) {
		t.Fatalf("got %d files, want %d\ngot: %v", len(got), len(tofuFiles), got)
	}
	for i := range got {
		if got[i] != tofuFiles[i] {
			t.Errorf("file[%d]: got %q, want %q", i, got[i], tofuFiles[i])
		}
	}
}

func TestFindTofuFilesSingleFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "single.tofu")
	if err := os.WriteFile(f, []byte("# test"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := FindTofuFiles([]string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 1 || got[0] != f {
		t.Errorf("got %v, want [%s]", got, f)
	}
}

func TestFindTofuFilesNonTofuFile(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "main.tf")
	if err := os.WriteFile(f, []byte("# test"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := FindTofuFiles([]string{f})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected no files, got %v", got)
	}
}

func TestFindTofuFilesNonexistentPath(t *testing.T) {
	_, err := FindTofuFiles([]string{"/nonexistent/path"})
	if err == nil {
		t.Error("expected error for nonexistent path, got nil")
	}
}
