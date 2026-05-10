package engine

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/open-policy-agent/conftest/parser"
	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/zclconf/go-cty/cty"
	ctyjson "github.com/zclconf/go-cty/cty/json"
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

type symbolTable struct {
	locals    map[string]interface{}
	variables map[string]interface{}
}

// RunResult holds the output of a policy evaluation run.
type RunResult struct {
	Violations    []Violation
	ResourceTypes map[string]struct{}
}

// Run parses the given .tofu files and evaluates all embedded CIS policies.
func Run(ctx context.Context, files []string, policiesFS fs.FS) (*RunResult, error) {
	configs, err := parser.ParseConfigurationsAs(files, "hcl2")
	if err != nil {
		return nil, fmt.Errorf("parse tofu files: %w", err)
	}

	// Build one symbol table per module directory so that variable and local
	// definitions in any file (e.g. variables.tofu, locals.tofu) are visible
	// when resolving references in resource files (e.g. main.tofu).
	dirSymbols := buildDirSymbolTables(files)

	normalizedConfigs := make(map[string]interface{}, len(configs))
	for file, config := range configs {
		normalizedConfigs[file] = normalizeConfig(file, config, dirSymbols)
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
	for file, config := range normalizedConfigs {
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
	merged := mergeConfigs(normalizedConfigs)
	globalViolations, err := evaluate(ctx, "", merged, prepared)
	if err != nil {
		return nil, fmt.Errorf("evaluate merged config: %w", err)
	}
	for _, v := range globalViolations {
		if v.Resource == "global" {
			violations = append(violations, v)
		}
	}

	return &RunResult{
		Violations:    violations,
		ResourceTypes: extractResourceTypes(normalizedConfigs),
	}, nil
}

// extractResourceTypes collects the set of OpenTofu resource type names
// present across all parsed configs (e.g. "google_compute_instance").
func extractResourceTypes(configs map[string]interface{}) map[string]struct{} {
	types := make(map[string]struct{})
	for _, config := range configs {
		configMap, ok := config.(map[string]interface{})
		if !ok {
			continue
		}
		resources, ok := configMap["resource"].(map[string]interface{})
		if !ok {
			continue
		}
		for resourceType := range resources {
			types[resourceType] = struct{}{}
		}
	}
	return types
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

func normalizeConfig(file string, config interface{}, dirSymbols map[string]*symbolTable) interface{} {
	if file == "" {
		return config
	}

	dir := filepath.Dir(file)
	symbols, ok := dirSymbols[dir]
	if !ok {
		return config
	}

	return resolveReferences(config, symbols)
}

// buildDirSymbolTables groups the given files by directory and builds one
// merged symbol table per directory so that variable defaults and locals
// defined in any file within a module are visible when resolving references
// in other files of the same module.
func buildDirSymbolTables(files []string) map[string]*symbolTable {
	byDir := make(map[string][]string)
	for _, file := range files {
		dir := filepath.Dir(file)
		byDir[dir] = append(byDir[dir], file)
	}

	dirSymbols := make(map[string]*symbolTable, len(byDir))
	for dir, dirFiles := range byDir {
		symbols, err := loadSymbolTableFromFiles(dirFiles)
		if err != nil {
			continue
		}
		dirSymbols[dir] = symbols
	}
	return dirSymbols
}

func loadSymbolTableFromFiles(files []string) (*symbolTable, error) {
	variables := make(map[string]cty.Value)
	pending := make(map[string]*hclsyntax.Attribute)

	for _, file := range files {
		src, err := os.ReadFile(file)
		if err != nil {
			continue
		}

		f, diags := hclsyntax.ParseConfig(src, file, hcl.Pos{Line: 1, Column: 1})
		if diags.HasErrors() {
			continue
		}

		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}

		for name, value := range collectVariableDefaults(body) {
			variables[name] = value
		}

		for _, block := range body.Blocks {
			if block.Type != "locals" {
				continue
			}
			for name, attr := range block.Body.Attributes {
				pending[name] = attr
			}
		}
	}

	locals := resolveLocals(pending, variables) // resolves inter-local and var references

	variableValues, err := ctyMapToGo(variables)
	if err != nil {
		return nil, err
	}
	localValues, err := ctyMapToGo(locals)
	if err != nil {
		return nil, err
	}

	return &symbolTable{
		locals:    localValues,
		variables: variableValues,
	}, nil
}

func collectVariableDefaults(body *hclsyntax.Body) map[string]cty.Value {
	defaults := make(map[string]cty.Value)
	for _, block := range body.Blocks {
		if block.Type != "variable" || len(block.Labels) != 1 {
			continue
		}

		attr, ok := block.Body.Attributes["default"]
		if !ok {
			continue
		}

		value, diags := attr.Expr.Value(nil)
		if diags.HasErrors() {
			continue
		}

		defaults[block.Labels[0]] = value
	}

	return defaults
}

func resolveLocals(pending map[string]*hclsyntax.Attribute, variables map[string]cty.Value) map[string]cty.Value {

	locals := make(map[string]cty.Value)
	for len(pending) > 0 {
		resolvedAny := false
		ctx := &hcl.EvalContext{
			Variables: map[string]cty.Value{
				"local": ctyObject(locals),
				"var":   ctyObject(variables),
			},
		}

		for name, attr := range pending {
			value, diags := attr.Expr.Value(ctx)
			if diags.HasErrors() {
				continue
			}

			locals[name] = value
			delete(pending, name)
			resolvedAny = true
		}

		if !resolvedAny {
			break
		}
	}

	return locals
}

func ctyObject(values map[string]cty.Value) cty.Value {
	if len(values) == 0 {
		return cty.EmptyObjectVal
	}

	return cty.ObjectVal(values)
}

func ctyMapToGo(values map[string]cty.Value) (map[string]interface{}, error) {
	converted := make(map[string]interface{}, len(values))
	for name, value := range values {
		goValue, err := ctyToGo(value)
		if err != nil {
			return nil, err
		}
		converted[name] = goValue
	}
	return converted, nil
}

func ctyToGo(value cty.Value) (interface{}, error) {
	encoded, err := ctyjson.Marshal(value, value.Type())
	if err != nil {
		return nil, err
	}

	var out interface{}
	if err := json.Unmarshal(encoded, &out); err != nil {
		return nil, err
	}

	return out, nil
}

func resolveReferences(value interface{}, symbols *symbolTable) interface{} {
	switch typed := value.(type) {
	case []interface{}:
		resolved := make([]interface{}, 0, len(typed))
		for _, item := range typed {
			resolved = append(resolved, resolveReferences(item, symbols))
		}
		return resolved
	case map[string]interface{}:
		resolved := make(map[string]interface{}, len(typed))
		for key, item := range typed {
			resolved[key] = resolveReferences(item, symbols)
		}
		return resolved
	case string:
		if resolved, ok := resolveReferenceString(typed, symbols); ok {
			return resolveReferences(resolved, symbols)
		}
		return typed
	default:
		return value
	}
}

func resolveReferenceString(value string, symbols *symbolTable) (interface{}, bool) {
	if !strings.HasPrefix(value, "${") || !strings.HasSuffix(value, "}") {
		return nil, false
	}

	expr := strings.TrimSuffix(strings.TrimPrefix(value, "${"), "}")
	switch {
	case strings.HasPrefix(expr, "var."):
		return lookupReference(symbols.variables, strings.Split(strings.TrimPrefix(expr, "var."), "."))
	case strings.HasPrefix(expr, "local."):
		return lookupReference(symbols.locals, strings.Split(strings.TrimPrefix(expr, "local."), "."))
	default:
		return nil, false
	}
}

func lookupReference(root map[string]interface{}, path []string) (interface{}, bool) {
	if len(path) == 0 {
		return nil, false
	}

	current, ok := root[path[0]]
	if !ok {
		return nil, false
	}

	for _, segment := range path[1:] {
		switch typed := current.(type) {
		case map[string]interface{}:
			var ok bool
			current, ok = typed[segment]
			if !ok {
				return nil, false
			}
		case []interface{}:
			index, err := strconv.Atoi(segment)
			if err != nil || index < 0 || index >= len(typed) {
				return nil, false
			}
			current = typed[index]
		default:
			return nil, false
		}
	}

	return current, true
}
