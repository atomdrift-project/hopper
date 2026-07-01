package pkgparse

import "testing"

func TestBuildPURL(t *testing.T) {
	cases := []struct {
		name          string
		eco, pkg, ver string
		want          string
		wantOK        bool
	}{
		// Registry-form inputs (the live forager path).
		{"npm plain", "npm", "lodash", "4.17.21", "pkg:npm/lodash@4.17.21", true},
		{"npm scoped", "npm", "@babel/core", "7.24.0", "pkg:npm/%40babel/core@7.24.0", true},
		{"npm no version", "npm", "express", "", "pkg:npm/express", true},
		{"pypi lower", "pypi", "Django", "5.0.1", "pkg:pypi/django@5.0.1", true},
		{"pypi underscore", "pypi", "ruamel_yaml", "0.18.6", "pkg:pypi/ruamel-yaml@0.18.6", true},
		{"pypi alias pip", "pip", "requests", "2.31.0", "pkg:pypi/requests@2.31.0", true},
		{"golang alias go", "go", "rsc.io/quote", "v1.5.2", "pkg:golang/rsc.io/quote@v1.5.2", true},
		{"crates", "crates", "serde", "1.0.197", "pkg:cargo/serde@1.0.197", true},
		{"cargo alias", "cargo", "tokio", "1.36.0", "pkg:cargo/tokio@1.36.0", true},
		{"composer", "packagist", "Symfony/Console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},
		{"nuget", "nuget", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3", true},
		{"gem", "rubygems", "rails", "7.1.3", "pkg:gem/rails@7.1.3", true},
		{"huggingface", "huggingface", "microsoft/resnet-50", "main", "pkg:huggingface/microsoft/resnet-50@main", true},

		// Runtime/language-form inputs (the backfill path over samples.ecosystem):
		// these are exactly the cases the old forager mapping dropped, freezing
		// the bad-PURL bloom.
		{"language javascript", "javascript", "@scope/evil", "1.0.0", "pkg:npm/%40scope/evil@1.0.0", true},
		{"language python", "python", "Mailconfirmer", "3.3.27", "pkg:pypi/mailconfirmer@3.3.27", true},
		{"language ruby", "ruby", "rails", "7.1.3", "pkg:gem/rails@7.1.3", true},
		{"language rust", "rust", "serde", "1.0.0", "pkg:cargo/serde@1.0.0", true},
		{"language java", "java", "org.apache:commons", "1.0", "pkg:maven/org.apache/commons@1.0", true},
		{"language dotnet", "dotnet", "Newtonsoft.Json", "13.0.3", "pkg:nuget/Newtonsoft.Json@13.0.3", true},
		{"language php", "php", "symfony/console", "6.4.0", "pkg:composer/symfony/console@6.4.0", true},

		// Malformed coordinate for the type → no PURL.
		{"maven missing group", "maven", "commons-lang3", "3.14.0", "", false},
		{"composer missing vendor", "packagist", "console", "6.4.0", "", false},

		// Ambiguous / non-package ecosystems → skip-unclear, stay empty.
		{"unsupported chrome", "chrome", "abcdefghijklmnop", "1.0", "", false},
		{"unsupported openvsx", "openvsx", "ms-python.python", "2024.0.0", "", false},
		{"unsupported vscode", "vscode", "ms-python.python", "1.0", "", false},
		{"unsupported distro", "debian", "bash", "5.2", "", false},
		{"unsupported conda", "conda", "numpy", "1.0", "", false},
		{"unknown", "github_actions", "actions/checkout", "v4", "", false},
		{"empty", "", "", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := BuildPURL(tc.eco, tc.pkg, tc.ver)
			if ok != tc.wantOK {
				t.Fatalf("BuildPURL(%q,%q,%q) ok = %v, want %v", tc.eco, tc.pkg, tc.ver, ok, tc.wantOK)
			}
			if got != tc.want {
				t.Errorf("BuildPURL(%q,%q,%q) = %q, want %q", tc.eco, tc.pkg, tc.ver, got, tc.want)
			}
		})
	}
}

func TestPURLIdentity(t *testing.T) {
	// Identity is version-less and stable across versions.
	got, ok := PURLIdentity("javascript", "@scope/evil")
	if !ok || got != "pkg:npm/%40scope/evil" {
		t.Fatalf("PURLIdentity = %q,%v; want pkg:npm/%%40scope/evil,true", got, ok)
	}
}
