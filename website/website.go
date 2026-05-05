// Package website holds the per-vendor download-page extractors used by the
// supply-chain fetcher. Each extractor implements [Source]; [Default] returns
// the list of sources the binary ships with. Discovery (parsing release
// pages, calling product APIs, querying GitHub Releases) lives here;
// fetching, hashing, and sidecar metadata live in cmd/fetcher.
package website

import (
	"context"
	"net/http"
)

// Target is one binary asset to fetch.
type Target struct {
	// URL is the canonical fetch URL. Required.
	URL string
	// Variant labels which artifact this is when a vendor offers several
	// (e.g. "windows-full-installer", "windows-portable", "macos-arm64").
	// Used in log lines and sidecar metadata; not part of the on-disk path.
	Variant string
	// Filename overrides the on-disk filename. Empty means: use the URL's
	// last path segment, or the Content-Disposition header at fetch time.
	Filename string
}

// Source is one upstream vendor we monitor.
type Source interface {
	// Name is a stable identifier (e.g. "ccleaner"). Must be unique
	// across all sources returned by [Default].
	Name() string
	// Hostname is the directory under fetched/. Multiple sources may
	// share a hostname when one vendor distributes several products.
	Hostname() string
	// MonitorPage is the human-facing download page. Recorded in sidecar
	// metadata so an analyst can see what a user would have visited.
	MonitorPage() string
	// Discover returns the current set of binaries to fetch. The supplied
	// http.Client is preconfigured with the project User-Agent.
	Discover(ctx context.Context, hc *http.Client) ([]Target, error)
}

// Default returns every source the binary ships with. Order is stable.
func Default() []Source {
	return []Source{
		newAmass(),
		newAudacity(),
		newBalenaetcher(),
		newBeekeeperstudio(),
		newBitwarden(),
		newBruno(),
		newBun(),
		newCCleaner(),
		newColima(),
		newComfyui(),
		newConEmu(),
		newCPUZ(),
		newCutter(),
		newDbeaver(),
		newDeno(),
		newDnSpy(),
		newElementdesktop(),
		newFoundry(),
		newFrida(),
		newGhidra(),
		newGitforwindows(),
		newGithubdesktop(),
		newGolang(),
		newGpt4all(),
		newHandBrake(),
		newHashcat(),
		newHelix(),
		newHWiNFO(),
		newHWMonitor(),
		newILSpy(),
		newInsomnia(),
		newIperf3(),
		newIPScan(),
		newJanai(),
		newJulia(),
		newK3d(),
		newKeePassXC(),
		newKhoj(),
		newKind(),
		newLapce(),
		newLazygit(),
		newLibreHardwareMonitor(),
		newLighthouse(),
		newLima(),
		newMattermostdesktop(),
		newMimikatz(),
		newMinikube(),
		newMpv(),
		newMRemoteNG(),
		newMullvadvpn(),
		newMultipass(),
		newNmap(),
		newNodeJS(),
		newNotepadPP(),
		newNSSM(),
		newNuclei(),
		newOBSStudio(),
		newOllama(),
		newPeazip(),
		newPEBear(),
		newPinokio(),
		newPodmandesktop(),
		newProtonvpnwin(),
		newQbittorrent(),
		newRadare2(),
		newRancherdesktop(),
		newRclone(),
		newReth(),
		newRizin(),
		newRpiimager(),
		newRufus(),
		newRustup(),
		newSevenZip(),
		newSignaldesktop(),
		newSliver(),
		newSQLiteBrowser(),
		newSubfinder(),
		newSystemInformer(),
		newTabby(),
		newTailscale(),
		newTelegramdesktop(),
		newTemurin17(),
		newTemurin21(),
		newTextgenwebui(),
		newUnetbootin(),
		newVagrant(),
		newVentoy(),
		newWinmerge(),
		newWinSCP(),
		newWinSW(),
		newWireshark(),
		newX64dbg(),
		newYara(),
		newZaproxy(),
		newZed(),
	}
}
