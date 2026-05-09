package engine

import (
	"bufio"
	"context"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
)

// Violation represents a single policy violation.
type Violation struct {
	File         string `json:"file"`
	Line         int    `json:"line"`
	Resource     string `json:"resource"`
	RuleID       string `json:"rule_id"`
	CISControl   string `json:"cis_control"`
	ProfileLevel string `json:"profile_level"`
	Severity     string `json:"severity"`
	Title        string `json:"title"`
	Description  string `json:"description"`
}

// Run parses the given .tofu files and evaluates all embedded CIS policies.
func Run(ctx context.Context, files []string, policiesFS fs.FS) ([]Violation, error) {
	configs, err := parser.ParseConfigurationsAs(files, "hcl2")
	if err != nil {
		return nil, fmt.Errorf("parse tofu files: %w", err)
	}

	compiler, err := loadCompiler(policiesFS)
	if err != nil {
		return nil, fmt.Errorf("load policies: %w", err)
	}

	prepared, err := rego.New(
		rego.Query("data.regofu.deny"),
		rego.Compiler(compiler),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare policy query: %w", err)
	}

	var violations []Violation

	// Per-file evaluation for resource-specific checks.
	for file, config := range configs {
		fileViolations, err := evaluate(ctx, file, config, prepared)
		if err != nil {
			return nil, fmt.Errorf("evaluate %s: %w", file, err)
		}
		for _, v := range fileViolations {
			if v.Resource != "global" {
				violations = append(violations, v)
			}
		}
	}

	// Merged evaluation for global/existence checks (e.g. "a log sink must
	// exist somewhere"). Combining all files into one input prevents
	// existence rules from firing once per file.
	merged := mergeConfigs(configs)
	globalViolations, err := evaluate(ctx, "", merged, prepared)
	if err != nil {
		return nil, fmt.Errorf("evaluate merged config: %w", err)
	}
	for _, v := range globalViolations {
		if v.Resource == "global" {
			violations = append(violations, v)
		}
	}

	return violations, nil
}

// loadCompiler reads all .rego files from the embedded FS and compiles them.
func loadCompiler(policiesFS fs.FS) (*ast.Compiler, error) {
	modules := make(map[string]string)

	err := fs.WalkDir(policiesFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(path, ".rego") || strings.HasSuffix(path, "_test.rego") {
			return nil
		}
		content, err := fs.ReadFile(policiesFS, path)
		if err != nil {
			return err
		}
		modules[path] = string(content)
		return nil
	})
	if err != nil {
		return nil, err
	}

	compiler, err := ast.CompileModules(modules)
	if err != nil {
		return nil, fmt.Errorf("compile rego modules: %w", err)
	}
	return compiler, nil
}

// evaluate runs all policies against a single file's parsed config.
func evaluate(ctx context.Context, file string, input interface{}, prepared rego.PreparedEvalQuery) ([]Violation, error) {
	rs, err := prepared.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	var violations []Violation
	lineIndex := resourceLineIndex(file)
	for _, result := range rs {
		for _, expr := range result.Expressions {
			items, ok := expr.Value.([]interface{})
			if !ok {
				continue
			}
			for _, item := range items {
				v, ok := item.(map[string]interface{})
				if !ok {
					continue
				}
				name := stringVal(v, "resource")
				violations = append(violations, Violation{
					File:         file,
					Line:         lineIndex[name],
					Resource:     name,
					RuleID:       stringVal(v, "rule_id"),
					CISControl:   stringVal(v, "cis_control"),
					ProfileLevel: stringVal(v, "profile_level"),
					Severity:     stringVal(v, "severity"),
					Title:        stringVal(v, "title"),
					Description:  stringVal(v, "description"),
				})
			}
		}
	}
	return violations, nil
}

// resourceLineIndex scans a file for HCL resource declarations and returns a
// map of resource label to line number. This is a best-effort text scan — it
// does not use an HCL parser, so line numbers may be missing for resources
// with unusual formatting.
func resourceLineIndex(file string) map[string]int {
	index := make(map[string]int)
	f, err := os.Open(file)
	if err != nil {
		return index
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "resource ") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) >= 3 {
			name := strings.Trim(parts[2], `"{}`)
			if _, exists := index[name]; !exists {
				index[name] = lineNum
			}
		}
	}
	// Scan errors are ignored; partial results are still useful.
	return index
}

// mergeConfigs deep-merges all per-file parsed configs into a single input.
// This lets existence/global policies (resource == "global") check whether a
// resource type is defined anywhere across the entire scan, not just per file.
func mergeConfigs(configs map[string]interface{}) interface{} {
	merged := make(map[string]interface{})
	for _, config := range configs {
		configMap, ok := config.(map[string]interface{})
		if !ok {
			continue
		}
		deepMerge(merged, configMap)
	}
	return merged
}

func deepMerge(dst, src map[string]interface{}) {
	for key, srcVal := range src {
		dstVal, exists := dst[key]
		if !exists {
			dst[key] = srcVal
			continue
		}
		dstMap, dstOk := dstVal.(map[string]interface{})
		srcMap, srcOk := srcVal.(map[string]interface{})
		if dstOk && srcOk {
			deepMerge(dstMap, srcMap)
		} else {
			dst[key] = srcVal
		}
	}
}

func stringVal(m map[string]interface{}, key string) string {
	if v, ok := m[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
