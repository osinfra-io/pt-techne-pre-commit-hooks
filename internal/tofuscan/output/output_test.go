package output

import (
	"testing"
	"unicode/utf8"
)

func TestTruncatePath(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		maxLen int
		want   string
	}{
		{
			name:   "short path unchanged",
			path:   "/home/user/main.tofu",
			maxLen: 80,
			want:   "/home/user/main.tofu",
		},
		{
			name:   "long path truncated",
			path:   "/home/brett/repositories/osinfra-io/platform-group/arche/pt-arche-google-kubernetes-engine/.terraform/modules/test.tests.default.gke_fleet_host_regional.test.helpers/child/helpers.tofu",
			maxLen: 80,
			want:   "/home/brett/repositories/osinfra-io/platform-group/arche/pt-arche-…/helpers.tofu",
		},
		{
			name:   "exact length unchanged",
			path:   "/a/b/c.tofu",
			maxLen: 11,
			want:   "/a/b/c.tofu",
		},
		{
			name:   "very small maxLen hard truncates",
			path:   "/a/very-long-filename.tofu",
			maxLen: 10,
			want:   "/a/very-l…",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := truncatePath(tc.path, tc.maxLen)
			if got != tc.want {
				t.Errorf("truncatePath(%q, %d)\n got: %q\nwant: %q", tc.path, tc.maxLen, got, tc.want)
			}
			visibleLen := utf8.RuneCountInString(got)
			if visibleLen > tc.maxLen {
				t.Errorf("visible length %d exceeds maxLen %d", visibleLen, tc.maxLen)
			}
		})
	}
}
