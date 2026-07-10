package pkgparse

import "testing"

func TestParseFilename(t *testing.T) {
	tests := []struct {
		filename    string
		wantName    string
		wantVersion string
	}{
		// npm tarballs.
		{"lodash-4.17.21.tgz", "lodash", "4.17.21"},
		{"react-dom-18.0.0.tgz", "react-dom", "18.0.0"},
		{"react-18.0.0-rc.0.tgz", "react", "18.0.0-rc.0"},
		// pypi wheels and source tarballs.
		{"requests-2.31.0.tar.gz", "requests", "2.31.0"},
		{"flask-3.1.3-py3-none-any.whl", "flask", "3.1.3-py3-none-any"},
		{"pyyaml-6.0.3-cp310-cp310-macosx_10_13_x86_64.whl", "pyyaml", "6.0.3-cp310-cp310-macosx_10_13_x86_64"},
		{"numpy-1.26.0-cp312-cp312-manylinux_2_17_x86_64.whl", "numpy", "1.26.0-cp312-cp312-manylinux_2_17_x86_64"},
		// jfrog pypi.
		{"hermes_px-0.0.4-py3-none-any.whl", "hermes_px", "0.0.4-py3-none-any"},
		{"telnyx-4.93.0-py3-none-any.whl", "telnyx", "4.93.0-py3-none-any"},
		// crates.io (versions can carry build metadata via "+").
		{"serde-1.0.193.crate", "serde", "1.0.193"},
		{"alasco-money-1.0.0.crate", "alasco-money", "1.0.0"},
		{"toml-1.0.6+spec-1.1.0.crate", "toml", "1.0.6+spec-1.1.0"},
		{"regex-automata-0.4.14.crate", "regex-automata", "0.4.14"},
		// rubygems.
		{"rails-7.0.4.gem", "rails", "7.0.4"},
		{"json-2.19.3.gem", "json", "2.19.3"},
		// nuget — both hyphen-version and dot-separated forms.
		{"Newtonsoft.Json-13.0.3.nupkg", "Newtonsoft.Json", "13.0.3"},
		{"Microsoft.Extensions.Http.Polly.10.0.5.nupkg", "Microsoft.Extensions.Http.Polly", "10.0.5"},
		{"System.Drawing.Common.10.0.5.nupkg", "System.Drawing.Common", "10.0.5"},
		// maven jar / clojars.
		{"junit-4.13.2.jar", "junit", "4.13.2"},
		{"ring-ring-headers-0.4.0.jar", "ring-ring-headers", "0.4.0"},
		// pub (dart).
		{"flutter_launcher_icons-0.14.4.tar.gz", "flutter_launcher_icons", "0.14.4"},
		{"google_fonts-8.0.2.tar.gz", "google_fonts", "8.0.2"},
		// hex (erlang/elixir) — bare .tar extension.
		{"makeup-1.2.1.tar", "makeup", "1.2.1"},
		{"jason-1.5.0-alpha.2.tar", "jason", "1.5.0-alpha.2"},
		// CRAN — underscore-separated tarball.
		{"devtools_2.5.2.tar.gz", "devtools", "2.5.2"},
		{"data.table_1.18.2.1.tar.gz", "data.table", "1.18.2.1"},
		// CPAN — hyphenated names with dotted versions.
		{"Template-Toolkit-3.102.tar.gz", "Template-Toolkit", "3.102"},
		{"Log-Log4perl-1.57.tar.gz", "Log-Log4perl", "1.57"},
		// hackage (haskell).
		{"bytestring-0.9.2.1.tar.gz", "bytestring", "0.9.2.1"},
		{"optparse-applicative-0.9.1.1.tar.gz", "optparse-applicative", "0.9.1.1"},
		// alpine/wolfi apk.
		{"zfs-2.4.1-r0.apk", "zfs", "2.4.1-r0"},
		{"ztunnel-1.29-compat-1.29.0-r0.apk", "ztunnel-1.29-compat", "1.29.0-r0"},
		{"zellij-fish-completion-0.43.1-r5.apk", "zellij-fish-completion", "0.43.1-r5"},
		// debian deb.
		{"wget_1.21.4-1ubuntu3_amd64.deb", "wget", "1.21.4-1ubuntu3"},
		// fedora rpm (binary and src).
		{"curl-8.0.0-1.fc40.x86_64.rpm", "curl", "8.0.0-1.fc40"},
		{"emacs-30.1-8.fc42.src.rpm", "emacs", "30.1-8.fc42"},
		{"qgis-3.42.1-2.fc42.aarch64.rpm", "qgis", "3.42.1-2.fc42"},
		// archlinux pkg.
		{"python-3.12.0-1-x86_64.pkg.tar.zst", "python", "3.12.0-1"},
		{"util-linux-2.42-1-x86_64.pkg.tar.zst", "util-linux", "2.42-1"},
		{"linux-lts-6.18.23-1-x86_64.pkg.tar.zst", "linux-lts", "6.18.23-1"},
		// conda packages.
		{"scikit-learn-1.8.0-py314hb68c362_0.conda", "scikit-learn", "1.8.0-py314hb68c362_0"},
		// vscode/openvsx vsix (publisher.extension-version).
		{"publisher.extension-1.0.0.vsix", "publisher.extension", "1.0.0"},
		{"vscode.debug-auto-launch-1.95.3.vsix", "vscode.debug-auto-launch", "1.95.3"},
		{"dranaven.flask-live-craft-0.1.4.vsix", "dranaven.flask-live-craft", "0.1.4"},
		{"Ericsson123.DarkThemed-1.0.0.vsix", "Ericsson123.DarkThemed", "1.0.0"},
		// portableapps installer (underscore separator).
		{"NotepadPPPortable_8.9.4.paf.exe", "NotepadPPPortable", "8.9.4"},
		{"FirefoxPortable_115.5.0.paf.exe", "FirefoxPortable", "115.5.0"},
		// golang module zips with v-prefix versions.
		{"github.com-jackc-pgx-v5-v5.9.1.zip", "github.com-jackc-pgx-v5", "v5.9.1"},
		{"github.com-gorilla-mux-v1.8.1.zip", "github.com-gorilla-mux", "v1.8.1"},
		// docker image tarballs.
		{"docker.io_library_logstash_9.2.4.tar.xz", "docker.io_library_logstash", "9.2.4"},
		{"docker.io_library_memcached_1.6.40-alpine3.23.tar.xz", "docker.io_library_memcached", "1.6.40-alpine3.23"},
		// chrome extension crx (some have version, most are bare IDs).
		{"ublock-1.50.0.crx", "ublock", "1.50.0"},
		// Bare-ID files (no version) — correct outcome is empty.
		{"cjpalhdlnbpafiamejdnhcphjbkeiagm.crx", "", ""},
		{"git.nupkg", "", ""},
		{"MetaStealer.zip", "", ""},
		// SHA256-named files — no semantically meaningful split. The
		// parser sees a long hex string with no separator and returns
		// empty. The .jar extension form would technically match the
		// generic pattern via the digit-led suffix, but we accept that
		// case as cosmetically odd; what matters is the bare-SHA case
		// (most common) returns empty.
		{"60d11b7004c80ae17a900094bbddd0a92273167af2b15f7597b9749d1b5edaa2", "", ""},
		// Other no-shape inputs.
		{"evil.exe", "", ""},
		{"random_blob", "", ""},
		{"_unknown", "", ""},
		{"sha256-hashes.txt", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.filename, func(t *testing.T) {
			gotName, gotVersion, _ := ParseFilename(tt.filename)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("ParseFilename(%q) = (%q, %q), want (%q, %q)",
					tt.filename, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestParseFilenameArch(t *testing.T) {
	cases := map[string]string{
		// deb/rpm/alpm filenames carry the architecture; it becomes the
		// purl-spec `arch` qualifier value.
		"wget_1.21.4-1ubuntu3_amd64.deb":     "amd64",
		"curl-8.0.0-1.fc40.x86_64.rpm":       "x86_64",
		"qgis-3.42.1-2.fc42.aarch64.rpm":     "aarch64",
		"kernel-6.10.0-1.fc41.src.rpm":       "src",
		"python-3.12.0-1-x86_64.pkg.tar.zst": "x86_64",
		"python-pip-21.0-1-any.pkg.tar.zst":  "any",
		// apk keeps arch in the repository path, not the filename.
		"zfs-2.4.1-r0.apk": "",
		// Non-distro formats have no arch.
		"lodash-4.17.21.tgz": "",
		"evil.exe":           "",
	}
	for filename, want := range cases {
		if _, _, got := ParseFilename(filename); got != want {
			t.Errorf("ParseFilename(%q) arch = %q, want %q", filename, got, want)
		}
	}
}
