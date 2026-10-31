package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/zclconf/go-cty/cty"

	"pre-commit-hooks/internal/tofudir"
)

type declaration struct {
	file string
	kind string
	name string
}

type lintDiagnostic struct {
	Severity string
	Summary  string
	Detail   string
	Range    *struct {
		Filename string
		Start    struct{ Line int }
	}
}

func newLintRunner() func(string, []string) (string, error) {
	var used map[declaration]bool
	return func(dir string, args []string) (string, error) {
		if used == nil {
			root, err := os.Getwd()
			if err != nil {
				return "", err
			}
			dirs, err := tofudir.FindDirsWithTofuFiles(root)
			if err != nil {
				return "", err
			}
			used, err = referencedDeclarations(dirs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Shared lint indexing failed; reporting unfiltered lint diagnostics: %v\n", err)
				used = make(map[declaration]bool)
			}
		}
		cmd := exec.Command("tofu", append(args, "-json")...)
		cmd.Dir = dir
		raw, cmdErr := cmd.CombinedOutput()
		var result struct{ Diagnostics []lintDiagnostic }
		if err := json.Unmarshal(raw, &result); err != nil {
			return string(raw), errors.Join(cmdErr, fmt.Errorf("decode lint diagnostics: %w", err))
		}
		var out strings.Builder
		for _, diagnostic := range result.Diagnostics {
			if diagnostic.Severity == "warning" && diagnostic.Range != nil {
				kind := ""
				switch diagnostic.Summary {
				case "Local value not used (core:unused-local)":
					kind = "local"
				case "Input variable not used (core:unused-variable)":
					kind = "var"
				}
				if kind != "" {
					file, err := filepath.EvalSymlinks(filepath.Join(dir, diagnostic.Range.Filename))
					if err != nil {
						return "", fmt.Errorf("resolve lint declaration: %w", err)
					}
					parts := strings.Split(diagnostic.Detail, "\"")
					if len(parts) == 3 && used[declaration{file, kind, parts[1]}] {
						continue
					}
				}
			}
			severity := diagnostic.Severity
			switch severity {
			case "warning":
				severity = "Warning"
			case "error":
				severity = "Error"
			}
			fmt.Fprintf(&out, "%s: %s\n", severity, diagnostic.Summary)
			if diagnostic.Range != nil {
				fmt.Fprintf(&out, "  on %s line %d:\n", diagnostic.Range.Filename, diagnostic.Range.Start.Line)
			}
			fmt.Fprintln(&out, diagnostic.Detail)
		}
		return out.String(), cmdErr
	}
}

// Shared declarations can be unused in a partial fixture while used in another
// configuration that loads the same canonical file. Match by file, not just name.
func referencedDeclarations(dirs []string) (map[declaration]bool, error) {
	used := make(map[declaration]bool)
	byDir := make(map[string]map[string]declaration)
	for _, dir := range dirs {
		canonicalDir, err := filepath.EvalSymlinks(dir)
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		declarations := make(map[string]declaration)
		byDir[canonicalDir] = declarations
		names := make(map[string]bool, len(entries))
		for _, entry := range entries {
			names[entry.Name()] = true
		}
		var references []hcl.Traversal
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || ignoredConfigFilename(name) ||
				!strings.HasSuffix(name, ".tofu") && !strings.HasSuffix(name, ".tf") {
				continue
			}
			if strings.HasSuffix(name, ".tf") && names[strings.TrimSuffix(name, ".tf")+".tofu"] {
				continue
			}
			path := filepath.Join(dir, name)
			canonical, err := filepath.EvalSymlinks(path)
			if err != nil {
				return nil, err
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return nil, err
			}
			file, diagnostics := hclsyntax.ParseConfig(raw, path, hcl.InitialPos)
			if diagnostics.HasErrors() {
				return nil, fmt.Errorf("parse lint context: %s", diagnostics.Error())
			}
			body := file.Body.(*hclsyntax.Body)
			for _, block := range body.Blocks {
				if block.Type == "variable" && len(block.Labels) == 1 {
					name := block.Labels[0]
					declarations["var."+name] = declaration{canonical, "var", name}
				}
				if block.Type == "locals" {
					for name := range block.Body.Attributes {
						declarations["local."+name] = declaration{canonical, "local", name}
					}
				}
			}
			_ = hclsyntax.VisitAll(body, func(node hclsyntax.Node) hcl.Diagnostics {
				if attribute, ok := node.(*hclsyntax.Attribute); ok {
					references = append(references, attribute.Expr.Variables()...)
				}
				return nil
			})
		}
		markReferences(references, declarations, used)
	}
	for _, dir := range dirs {
		for _, testDir := range []string{dir, filepath.Join(dir, "tests")} {
			paths, err := filepath.Glob(filepath.Join(testDir, "*.tftest.hcl"))
			if err != nil {
				return nil, err
			}
			for _, path := range paths {
				if ignoredConfigFilename(filepath.Base(path)) {
					continue
				}
				raw, err := os.ReadFile(path)
				if err != nil {
					return nil, err
				}
				file, diagnostics := hclsyntax.ParseConfig(raw, path, hcl.InitialPos)
				if diagnostics.HasErrors() {
					return nil, fmt.Errorf("parse lint test context: %s", diagnostics.Error())
				}
				for _, run := range file.Body.(*hclsyntax.Body).Blocks {
					if run.Type != "run" {
						continue
					}
					moduleDir := dir
					for _, block := range run.Body.Blocks {
						if block.Type == "module" {
							if source, ok := block.Body.Attributes["source"]; ok {
								value, diags := source.Expr.Value(nil)
								if !diags.HasErrors() && value.IsKnown() && !value.IsNull() && value.Type() == cty.String {
									moduleDir = filepath.Clean(filepath.Join(dir, value.AsString()))
								}
							}
						}
					}
					canonicalDir, err := filepath.EvalSymlinks(moduleDir)
					if err != nil {
						continue
					}
					for _, block := range run.Body.Blocks {
						if block.Type != "assert" {
							continue
						}
						for _, attribute := range block.Body.Attributes {
							markReferences(attribute.Expr.Variables(), byDir[canonicalDir], used)
						}
					}
				}
			}
		}
	}
	return used, nil
}

func ignoredConfigFilename(name string) bool {
	return strings.HasPrefix(name, ".") || strings.HasSuffix(name, "~") ||
		strings.HasPrefix(name, "#") && strings.HasSuffix(name, "#")
}

func markReferences(references []hcl.Traversal, declarations map[string]declaration, used map[declaration]bool) {
	for _, reference := range references {
		if len(reference) < 2 {
			continue
		}
		attribute, ok := reference[1].(hcl.TraverseAttr)
		if !ok {
			continue
		}
		if declaration, ok := declarations[reference.RootName()+"."+attribute.Name]; ok {
			used[declaration] = true
		}
	}
}
