# Hooks for Infrastructure as Code (IaC) tools

[![Go Tests](https://img.shields.io/github/actions/workflow/status/osinfra-io/pt-techne-pre-commit-hooks/go-test.yml?style=for-the-badge&logo=go&color=00ADD8&label=Go%20Tests)](https://github.com/osinfra-io/pt-techne-pre-commit-hooks/actions/workflows/go-test.yml)
[![Dependabot](https://img.shields.io/github/actions/workflow/status/osinfra-io/pt-techne-pre-commit-hooks/dependabot.yml?style=for-the-badge&logo=github&color=2088FF&label=Dependabot)](https://github.com/osinfra-io/pt-techne-pre-commit-hooks/actions/workflows/dependabot.yml)

This repository contains a collection of hooks for Infrastructure as Code (IaC) tools. The hooks are designed to be used with [pre-commit](https://pre-commit.com/), a framework for managing and maintaining multi-language pre-commit hooks.

## Available Hooks

### tofu-fmt

#### Formats OpenTofu configuration files

Runs `tofu fmt` to rewrite your OpenTofu (`.tf`, `.tofu`, `.tfvars`) files to a canonical format and style. This helps ensure consistency and readability across your infrastructure codebase. It will not modify files in `.terraform/` directories.

### tofu-validate

#### Validates OpenTofu configuration files

Runs `tofu validate` to check your configuration for syntax errors and internal consistency, without accessing remote services or APIs. This helps catch mistakes before applying changes. It will not validate files in `.terraform/` directories.

### tofu-test

#### Runs OpenTofu automated tests

Runs `tofu test` to execute automated tests defined in `.tftest.hcl` files. This helps validate your infrastructure code with comprehensive test coverage, ensuring your configurations behave as expected. Tests are executed in the root directory only. The hook will skip execution if no test files are found.

### tofu-scan

#### Checks OpenTofu files against CIS benchmarks

Runs `tofuscan` to check your OpenTofu (`.tofu`) files against CIS benchmark policies using OPA/Rego. Covers [CIS Google Cloud Platform Foundation Benchmark v5.0.0](docs/tofuscan/cis-gcp-v5.0.0.md) and [CIS Google Kubernetes Engine (GKE) Benchmark v1.8.0](docs/tofuscan/cis-gke-v1.8.0.md). It will not scan files in `.terraform/` directories.

---

## Usage

To use these hooks, add them to your `.pre-commit-config.yaml` file. Below are example configurations for the `tofufmt` and `tofuvalidate` hooks.

### Example: `tofu-fmt`

Formats your OpenTofu configuration files to a canonical format and style.

```yaml
- repo: https://github.com/osinfra-io/pt-techne-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-fmt
```

### Example: `tofu-validate`

Validates your OpenTofu configuration files for syntax and internal consistency.

```yaml
- repo: https://github.com/osinfra-io/pt-techne-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-validate
      # Optional: pass additional args to tofu validate
      # args: ["-no-color"]
```

### Example: `tofu-test`

Runs OpenTofu automated tests defined in `.tftest.hcl` files.

```yaml
- repo: https://github.com/osinfra-io/pt-techne-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-test
      # verbose: true                # show hook output on success
      # Optional: pass additional args to tofu test
      # args: ["-verbose"]            # show per-assertion output
      # args: ["-filter=TestFoo"]     # equals-form flag
      # args: ["-filter", "TestFoo"]  # split-form flag (both tokens required)
```

Both equals-form (`-filter=TestFoo`) and split-form (`-filter TestFoo`) flags are supported. When using split-form flags, include both the flag and its value as separate list entries. `-verbose` controls the level of detail `tofu test` itself emits.

### Example: `tofu-scan`

Checks OpenTofu files against CIS Google Cloud Foundations Benchmark policies using OPA/Rego. Covers CIS Google Cloud Platform Foundation Benchmark v5.0.0 and CIS Google Kubernetes Engine (GKE) Benchmark v1.8.0.

```yaml
- repo: https://github.com/osinfra-io/pt-techne-pre-commit-hooks
  rev: <release-or-commit-sha>
  hooks:
    - id: tofu-scan
      # verbose: true     # show hook output on success
      # Optional: pass additional args to tofu scan
      # args: ["--warn-only"]
```

`--warn-only` allows commits to pass even when violations are found. Violations are still printed so they remain visible.

#### Skipping violations

To suppress a specific violation, add a skip comment **inside** the resource block:

```hcl
resource "google_compute_firewall" "allow_ssh" {
  # tofu-scan skip: CIS 3.6 - Required for bastion host access
  name    = "allow-ssh-bastion"
  network = "default"
}
```

The format is `# tofu-scan skip: CIS <control> [- <reason>]`. Skip comments placed outside a resource block are ignored. Skipped violations appear in the output summary so they remain visible.

Replace `<release-or-commit-sha>` with the desired version or commit hash.

For more details, see the `.pre-commit-hooks.yaml` in this repository.
