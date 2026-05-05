package website

// SourceKind classifies a source by the infrastructure its Discover() and
// fetch URLs hit. The fetcher uses this to apply different default polling
// intervals per kind.
type SourceKind string

const (
	// KindVendorWebsite is a small or medium upstream that we should poll
	// politely. Examples: ccleaner.com, cpuid.com, nssm.cc, winscp.net.
	// This is the default for any source not explicitly classified.
	KindVendorWebsite SourceKind = "vendor-website"

	// KindLargeInfra is GitHub Releases, Microsoft's winget-pkgs, signed
	// CDN URLs (Azure Blob via objects.githubusercontent.com), and similar
	// "Google-scale" backends that can absorb frequent polling.
	KindLargeInfra SourceKind = "large-infra"
)

// largeInfraSources lists every Source whose Discover() hits large-scale
// infrastructure — primarily the GitHub Releases helper. Membership in this
// set unlocks the shorter --default-interval (vs. --vendor-interval).
//
// Entries here are kept in sync by hand. When adding a new extractor that
// wraps githubReleaseAssets / wingetInstallerURLs / a Google-scale API, add
// it here. The TestSourceKindsCovered test fails fast if this list and the
// Default() registry drift apart.
var largeInfraSources = map[string]bool{
	// Source kind = large-infra: discovery hits GitHub Releases, GitHub
	// tree pages (winget shadow source), or a Google-scale JSON API.
	"amass":                true,
	"audacity":             true,
	"balenaetcher":         true,
	"beekeeperstudio":      true,
	"bitwarden":            true,
	"bruno":                true,
	"bun":                  true,
	"colima":               true,
	"comfyui":              true,
	"conemu":               true,
	"cutter":               true,
	"dbeaver":              true,
	"deno":                 true,
	"dnspyex":              true,
	"elementdesktop":       true,
	"foundry":              true,
	"frida":                true,
	"ghidra":               true,
	"gitforwindows":        true,
	"githubdesktop":        true,
	"golang":               true, // go.dev/dl/?mode=json — Google-scale
	"gpt4all":              true,
	"handbrake":            true,
	"hashcat":              true,
	"helix":                true,
	"hwinfo":               true, // winget shadow source → hits github.com
	"ilspy":                true,
	"insomnia":             true,
	"iperf3":               true,
	"angryipscanner":       true,
	"janai":                true,
	"julia":                true,
	"k3d":                  true,
	"keepassxc":            true,
	"khoj":                 true,
	"kind":                 true,
	"lapce":                true,
	"lazygit":              true,
	"librehardwaremonitor": true,
	"lighthouse":           true,
	"lima":                 true,
	"mattermostdesktop":    true,
	"mimikatz":             true,
	"minikube":             true,
	"mpv":                  true,
	"mremoteng":            true,
	"mullvadvpn":           true,
	"multipass":            true,
	"notepadpp":            true,
	"nuclei":               true,
	"obsstudio":            true,
	"peazip":               true,
	"pebear":               true,
	"pinokio":              true,
	"podmandesktop":        true,
	"protonvpnwin":         true,
	"qbittorrent":          true,
	"radare2":              true,
	"rancherdesktop":       true,
	"rclone":               true,
	"reth":                 true,
	"rizin":                true,
	"rpiimager":            true,
	"rufus":                true,
	"sliver":               true,
	"sqlitebrowser":        true,
	"subfinder":            true,
	"systeminformer":       true,
	"tabby":                true,
	"telegramdesktop":      true,
	"temurin17":            true,
	"temurin21":            true,
	"textgenwebui":         true,
	"unetbootin":           true,
	"vagrant":              true,
	"ventoy":               true,
	"winmerge":             true,
	"winsw":                true,
	"x64dbg":               true,
	"yara":                 true,
	"zaproxy":              true,
	"zed":                  true,
}

// KindOf returns the [SourceKind] for s. Defaults to [KindVendorWebsite]
// for any source not in [largeInfraSources].
func KindOf(s Source) SourceKind {
	if largeInfraSources[s.Name()] {
		return KindLargeInfra
	}
	return KindVendorWebsite
}
