package regallint

import (
	"os/exec"

	"pre-commit-hooks/internal/testutil"
)

// CheckRegalInstalled delegates to shared testutil implementation.
var CheckRegalInstalled = testutil.CheckRegalInstalled

// RunRegalLint runs regal lint with the provided args (flags and/or file paths).
// Returns combined output and error.
func RunRegalLint(args []string) (string, error) {
	a := append([]string{"lint"}, args...)
	// no-dd-sa:go-security/command-injection - https://github.com/osinfra-io/pt-techne-pre-commit-hooks/issues/8
	cmd := exec.Command("regal", a...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
