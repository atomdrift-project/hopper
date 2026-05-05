# Supply-Chain Fetchers

Daily fetchers that pull official installers/binaries from upstream vendor websites, hash them, and stage them into hopper as samples. The goal is to catch supply-chain attacks of the hwmonitor / daemontools / 7-Zip / FileZilla / CCleaner shape — where an attacker swaps the payload behind a stable filename or pushes a trojanized release through the legitimate distribution path.

## Threat model

Catch:

1. **Silent payload swap.** Vendor URL stays the same, file name stays the same, but the bytes change between fetches without a corresponding version bump or release note.
2. **Trojanized release.** A new version ships from the canonical source, and we want the binary archived for diffing once IOCs surface.
3. **Distribution-path compromise.** Mirror, CDN, ad-injected installer, typosquat, or DNS hijack pointing the canonical hostname at attacker bytes — visible as a sha256 change against our baseline.

Out of scope (handled elsewhere or low marginal value):

- Package-manager ecosystems (npm, PyPI, crates.io, Homebrew bottles, apt/dnf repos) — different distribution model, different monitoring.
- Microsoft-signed first-party tooling shipped through Microsoft.com / Windows Update — covered by their own integrity machinery.
- Browser extensions and IDE extensions — separate fetcher class.

## Storage layout

Files land on disk under a hostname-rooted tree, with each download renamed to `<sha256>-<original-filename>` so payload swaps are detectable even when the filename is reused:

```
fetched/
  hwinfo.com/
    hwi_822.zip                                  # symlink → latest sha256
    a3f2…-hwi_822.zip
    7c81…-hwi_822.zip                            # earlier observation
  ollama.com/
    Ollama-darwin.zip
    e9b1…-Ollama-darwin.zip
  github.com/
    x64dbg/x64dbg/
      snapshot_2025-XX-XX.zip
      4d22…-snapshot_2025-XX-XX.zip
```

Each fetch writes a sidecar `<sha256>.json` recording: fetched_at (UTC), source URL, final URL after redirects, redirect chain, HTTP status, content-length, content-type, server header, and ETag/Last-Modified. These feed hopper alongside the binary itself.

## Hopper integration

Each fetched binary is loaded into hopper as a sample with provenance `supply-chain-watch:<hostname>`, initial verdict `unknown`. Litmus workers analyze it like any other sample. The fetcher additionally writes an alerts stream for:

- New sha256 observed for a (hostname, canonical-path) pair we have prior history on.
- Final-URL hostname change (redirect drift).
- Content-length delta > 25% with no version bump in the surrounding HTML.

A first-observation of a new version is **not** an alert by itself — only a baseline. The alert fires on subsequent silent mutation.

## Fetcher contract

Each fetcher is a small unit (Go function or config-driven entry) that exposes:

```
Vendor      string   // "hwinfo"
Hostname    string   // "hwinfo.com"     — directory under fetched/
Discover()  []URL    // returns one or more current canonical download URLs
```

`Discover` is what makes this non-trivial: most vendors don't expose a stable URL. Strategies, in order of preference:

1. **Stable URL** — a URL the vendor commits to keeping fresh (`ollama.com/download/Ollama-darwin.zip`, `nodejs.org/dist/latest/`).
2. **GitHub Releases API** — for vendors who release on GitHub (x64dbg, Ventoy, dnSpyEx, LibreHardwareMonitor, lazygit, Foundry, …). Cheap and reliable.
3. **HTML scrape with anchored selector** — parse the vendor's download page for the first link matching a fixed regex. Pin the selector tightly so layout changes fail loudly rather than silently fetching the wrong thing.
4. **JSON/XML feed** — RSS, atom, or vendor-specific JSON manifest where it exists (Python's release JSON, Rust's dist channel, Go's download JSON, JetBrains products feed).

Fetchers must be idempotent and safe to run hourly even if scheduled daily — re-fetching a known sha256 is a no-op that updates only the `last_seen_at` timestamp.

## Schedule & execution

- Daily fetch, jittered across a 6-hour window so we don't hammer any one vendor at the same minute.
- Per-host concurrency cap of 1.
- Polite User-Agent identifying the project and a contact address.
- Respect `robots.txt` for the *crawling* of release pages; the fetch of the actual installer URL is a single GET we treat as a normal client download.
- Hard cap per fetch: 2 GB. Anything larger logs and skips (DaVinci Resolve, CUDA Toolkit, NVIDIA drivers will hit this — see notes).

## Per-source fields

Each source carries three URLs. The first two are recorded in metadata; the third is what we actually fetch:

- **`monitor_page`** — the URL a human would visit in a browser. Recorded in every sidecar so an analyst can see what a victim would have seen.
- **`discovery_url`** — what the extractor scrapes/calls to learn the current download URL(s). May be the same as `monitor_page` (HTML scrape of the download page), or different (a hidden JSON API the page calls on load — see CCleaner). Lives in extractor source, not the sidecar.
- **`fetch_url`** — the actual binary URL. Discovered fresh on every run; may be one URL or several variants.

Worked examples from the two extractors built so far:

| Source | monitor_page | discovery_url | fetch_url(s) |
|---|---|---|---|
| ccleaner | `https://www.ccleaner.com/ccleaner/download/standard` | `https://www.ccleaner.com/api/product/info?product=ccleaner&variant=free` (hidden JSON API the page calls) | `https://bits.avcdn.net/.../installertype_ONLINE/...`, `.../installertype_FULL/...`, `https://download.ccleaner.com/portable/ccsetup<NNN>.zip` |
| 7zip | `https://www.7-zip.org/download.html` | same page (HTML scrape) | 15× `https://github.com/ip7z/7zip/releases/download/<version>/<file>` |

The monitor-page URL for every entry below is documented inside its extractor (`website/<source>.go`) when implemented; the table above is the canonical source of truth, not the bullet list.

## Rollout

**Phase 1 — first 25 fetchers** (covers the highest-signal targets: the ones that match the hwmonitor / daemontools / 7-Zip / FileZilla shape most closely, plus a representative ML target so we exercise the larger-binary path):

1. HWiNFO — hwinfo.com
2. CPU-Z — cpuid.com
3. CrystalDiskInfo — crystalmark.info
4. LibreHardwareMonitor — github.com/LibreHardwareMonitor/LibreHardwareMonitor
5. NSSM — nssm.cc
6. System Informer — systeminformer.sourceforge.io
7. Wireshark — wireshark.org
8. Nmap — nmap.org
9. PuTTY — chiark.greenend.org.uk
10. WinSCP — winscp.net
11. Ghidra — github.com/NationalSecurityAgency/ghidra
12. x64dbg — github.com/x64dbg/x64dbg
13. HxD — mh-nexus.de
14. Rufus — rufus.ie
15. balenaEtcher — etcher.balena.io
16. Ventoy — github.com/ventoy/Ventoy
17. 7-Zip — 7-zip.org
18. FileZilla — filezilla-project.org
19. Notepad++ — notepad-plus-plus.org
20. Cursor — cursor.com
21. Ollama — ollama.com
22. LM Studio — lmstudio.ai
23. KeePassXC — keepassxc.org
24. Tailscale — tailscale.com
25. Cygwin — cygwin.com

**Phase 1 success criteria:** 25 fetchers running on a daily cron for two weeks with zero false alerts, every binary archived with sidecar metadata, hopper ingesting them with `supply-chain-watch` provenance, and at least one real version-bump observation per fetcher that we can confirm against the vendor's own release notes. Then we evaluate fetcher LOC, alert noise, and bandwidth before scheduling phase 2.

---

## The 250 prospective targets

Organized by category, with the canonical hostname each fetcher would target. Specific download paths are determined at `Discover()` time.

### System monitoring & hardware (15)

1. HWiNFO — hwinfo.com
2. CPU-Z — cpuid.com
3. GPU-Z — techpowerup.com
4. CrystalDiskInfo — crystalmark.info
5. CrystalDiskMark — crystalmark.info
6. LibreHardwareMonitor — github.com/LibreHardwareMonitor
7. Open Hardware Monitor — openhardwaremonitor.org
8. MSI Afterburner — msi.com
9. ThrottleStop — techpowerup.com
10. Core Temp — alcpu.com
11. Speccy — ccleaner.com
12. AIDA64 — aida64.com
13. FurMark — geeks3d.com
14. OCCT — ocbase.com
15. Prime95 — mersenne.org

### Sysadmin & service supervision (10)

16. NSSM — nssm.cc
17. WinSW — github.com/winsw/winsw
18. s6 — skarnet.org
19. runit — smarden.org
20. supervisord — supervisord.org
21. System Informer (Process Hacker) — systeminformer.sourceforge.io
22. AutoHotkey — autohotkey.com
23. Cygwin — cygwin.com
24. MSYS2 — msys2.org
25. ConEmu — conemu.github.io

### Network & remote-admin (20)

26. Wireshark — wireshark.org
27. Nmap / Zenmap / Ncat — nmap.org
28. PuTTY — chiark.greenend.org.uk
29. WinSCP — winscp.net
30. MobaXterm — mobatek.net
31. Tabby — tabby.sh
32. Termius — termius.com
33. mRemoteNG — mremoteng.org
34. Royal TS — royalapps.com
35. Advanced IP Scanner — advanced-ip-scanner.com
36. Angry IP Scanner — angryip.org
37. SoftPerfect Network Scanner — softperfect.com
38. PingPlotter — pingplotter.com
39. SmartFTP — smartftp.com
40. Cyberduck — cyberduck.io
41. Bitvise SSH Client — bitvise.com
42. KiTTY — 9bis.net
43. SecureCRT / SecureFX — vandyke.com
44. SolarWinds free tools — solarwinds.com
45. iperf3 — iperf.fr

### Reverse engineering & malware analysis (20)

46. Ghidra — ghidra-sre.org
47. IDA Free — hex-rays.com
48. x64dbg — x64dbg.com
49. Cutter — cutter.re
50. Rizin — rizin.re
51. Radare2 — github.com/radareorg/radare2
52. dnSpyEx — github.com/dnSpyEx/dnSpy
53. ILSpy — github.com/icsharpcode/ILSpy
54. HxD — mh-nexus.de
55. 010 Editor — sweetscape.com
56. Detect It Easy — github.com/horsicq/Detect-It-Easy
57. PE-bear — github.com/hasherezade/pe-bear
58. CFF Explorer — ntcore.com
59. Resource Hacker — angusj.com
60. API Monitor — rohitab.com
61. Frida — frida.re
62. YARA — github.com/VirusTotal/yara
63. Binary Ninja Free — binary.ninja
64. Hopper Disassembler — hopperapp.com
65. Hiew — hiew.ru

### Security & pentest (15)

66. Burp Suite Community — portswigger.net
67. OWASP ZAP — zaproxy.org
68. Metasploit Framework — metasploit.com
69. SQLmap — sqlmap.org
70. Hashcat — hashcat.net
71. John the Ripper — openwall.com
72. Aircrack-ng — aircrack-ng.org
73. Mimikatz — github.com/gentilkiwi/mimikatz
74. Sliver — github.com/BishopFox/sliver
75. Havoc C2 — havocframework.com
76. Caido — caido.io
77. Nuclei — projectdiscovery.io
78. Subfinder — projectdiscovery.io
79. Amass — github.com/owasp-amass/amass
80. Responder — github.com/lgandx/Responder

### Imaging & boot media (10)

81. Rufus — rufus.ie
82. balenaEtcher — etcher.balena.io
83. Ventoy — ventoy.net
84. Win32 Disk Imager — sourceforge.net/projects/win32diskimager
85. Raspberry Pi Imager — raspberrypi.com
86. UNetbootin — unetbootin.github.io
87. YUMI — pendrivelinux.com
88. dd for Windows — chrysocome.net
89. HDD Raw Copy — hddguru.com
90. Clonezilla — clonezilla.org

### File / archive / transfer (15)

91. 7-Zip — 7-zip.org
92. WinRAR — rarlab.com
93. PeaZip — peazip.github.io
94. FileZilla — filezilla-project.org
95. Total Commander — ghisler.com
96. Double Commander — doublecmd.sourceforge.io
97. FreeCommander — freecommander.com
98. SyncBack — 2brightsparks.com
99. FreeFileSync — freefilesync.org
100. rclone — rclone.org
101. rsync for Windows — itefix.net
102. WinMerge — winmerge.org
103. Beyond Compare — scootersoftware.com
104. Meld — meldmerge.org
105. KDiff3 — kdiff3.sourceforge.net

### Developer editors & IDEs (15)

106. Cursor — cursor.com
107. Zed — zed.dev
108. Sublime Text — sublimetext.com
109. Sublime Merge — sublimemerge.com
110. Notepad++ — notepad-plus-plus.org
111. UltraEdit — ultraedit.com
112. EmEditor — emeditor.com
113. Lapce — lapce.dev
114. Helix — helix-editor.com
115. Nova — nova.app
116. RStudio / Posit — posit.co
117. JetBrains Toolbox — jetbrains.com
118. JetBrains IDEs (IntelliJ, GoLand, PyCharm, …) — jetbrains.com
119. Eclipse — eclipse.org
120. Apache NetBeans — netbeans.apache.org

### Database & data tools (15)

121. DBeaver — dbeaver.io
122. HeidiSQL — heidisql.com
123. TablePlus — tableplus.com
124. DBVisualizer — dbvis.com
125. Beekeeper Studio — beekeeperstudio.io
126. pgAdmin — pgadmin.org
127. MySQL Workbench — mysql.com
128. SQLiteStudio — sqlitestudio.pl
129. DB Browser for SQLite — sqlitebrowser.org
130. Navicat — navicat.com
131. Sequel Ace — sequel-ace.com
132. Postman — postman.com
133. Insomnia — insomnia.rest
134. Bruno — usebruno.com
135. Hoppscotch — hoppscotch.io

### Container, virtualization & infra desktops (15)

136. Docker Desktop — docker.com
137. Rancher Desktop — rancherdesktop.io
138. Podman Desktop — podman-desktop.io
139. OrbStack — orbstack.dev
140. Lima — github.com/lima-vm/lima
141. Colima — github.com/abiosoft/colima
142. Multipass — multipass.run
143. VirtualBox — virtualbox.org
144. VMware Workstation Player — vmware.com
145. UTM — mac.getutm.app
146. Parallels Desktop — parallels.com
147. Vagrant — vagrantup.com
148. Minikube — minikube.sigs.k8s.io
149. kind — kind.sigs.k8s.io
150. k3d — k3d.io

### Git & VCS clients (10)

151. Git for Windows — git-scm.com
152. GitHub Desktop — desktop.github.com
153. GitKraken — gitkraken.com
154. Sourcetree — sourcetreeapp.com
155. Fork — git-fork.com
156. Tower — git-tower.com
157. SmartGit — syntevo.com
158. TortoiseGit — tortoisegit.org
159. TortoiseSVN — tortoisesvn.net
160. lazygit — github.com/jesseduffield/lazygit

### ML / local-AI runtimes (20)

161. Ollama — ollama.com
162. LM Studio — lmstudio.ai
163. Jan — jan.ai
164. GPT4All — nomic.ai / gpt4all.io
165. ComfyUI — github.com/comfyanonymous/ComfyUI
166. Stable Diffusion WebUI (Automatic1111) — github.com/AUTOMATIC1111/stable-diffusion-webui
167. text-generation-webui (oobabooga) — github.com/oobabooga/text-generation-webui
168. Pinokio — pinokio.computer
169. Backyard AI (Faraday) — backyard.ai
170. Msty — msty.app
171. AnythingLLM — anythingllm.com
172. Continue — continue.dev
173. Open WebUI — openwebui.com
174. Khoj — khoj.dev
175. Anaconda Distribution — anaconda.com
176. Miniconda — anaconda.com
177. Mamba / Micromamba — mamba.readthedocs.io
178. Hugging Face CLI — huggingface.co
179. NVIDIA CUDA Toolkit — developer.nvidia.com
180. NVIDIA GPU drivers — nvidia.com

### Language toolchain installers (15)

181. Python — python.org
182. Node.js — nodejs.org
183. Go — go.dev
184. Rustup — rustup.rs
185. Bun — bun.sh
186. Deno — deno.com
187. Adoptium Temurin JDK — adoptium.net
188. Amazon Corretto JDK — aws.amazon.com/corretto
189. Azul Zulu JDK — azul.com
190. .NET SDK — dot.net
191. RubyInstaller — rubyinstaller.org
192. PHP for Windows — windows.php.net
193. Erlang/OTP — erlang.org
194. Elixir — elixir-lang.org
195. Julia — julialang.org

### Crypto wallets & node software (10)

196. Electrum — electrum.org
197. Exodus — exodus.com
198. Ledger Live — ledger.com
199. Trezor Suite — trezor.io
200. Phantom Desktop — phantom.app
201. Sparrow Wallet — sparrowwallet.com
202. Wasabi Wallet — wasabiwallet.io
203. Bitcoin Core — bitcoincore.org
204. Monero GUI — getmonero.org
205. Electrum-LTC — electrum-ltc.org

### Media & creator tools (10)

206. OBS Studio — obsproject.com
207. Streamlabs — streamlabs.com
208. HandBrake — handbrake.fr
209. Audacity — audacityteam.org
210. VLC — videolan.org
211. mpv — mpv.io
212. Shotcut — shotcut.org
213. DaVinci Resolve — blackmagicdesign.com
214. Krita — krita.org
215. GIMP — gimp.org

### Crypto / blockchain dev tools (5)

216. Foundry — getfoundry.sh
217. Solana CLI — solana.com / release.solana.com
218. Geth — geth.ethereum.org
219. Lighthouse — lighthouse.sigmaprime.io
220. Reth — github.com/paradigmxyz/reth

### Misc high-trust desktop power tools (10)

221. Everything (search) — voidtools.com
222. Listary — listary.com
223. Revo Uninstaller — revouninstaller.com
224. CCleaner — ccleaner.com
225. Malwarebytes — malwarebytes.com
226. KeePass — keepass.info
227. KeePassXC — keepassxc.org
228. BleachBit — bleachbit.org
229. WizTree — diskanalyzer.com
230. WinDirStat — windirstat.net

### Communication & collab desktops (10)

231. Slack — slack.com
232. Discord — discord.com
233. Signal — signal.org
234. Telegram — telegram.org
235. Element (Matrix) — element.io
236. Zoom — zoom.us
237. Mattermost Desktop — mattermost.com
238. Rocket.Chat Desktop — rocket.chat
239. Thunderbird — thunderbird.net
240. Mailspring — getmailspring.com

### Password managers, 2FA, VPN, privacy (10)

241. Bitwarden — bitwarden.com
242. 1Password — 1password.com
243. WireGuard — wireguard.com
244. OpenVPN Connect — openvpn.net
245. Tailscale — tailscale.com
246. Mullvad VPN — mullvad.net
247. Proton VPN — protonvpn.com
248. Tor Browser — torproject.org
249. Mullvad Browser — mullvad.net
250. YubiKey Manager / Yubico Authenticator — yubico.com

---

## Findings while building the first two extractors (ccleaner, 7zip)

- **Cloudflare-walled vendors are handled via the winget shadow-source, not a headless browser.** HWiNFO (`www.hwinfo.com`) and the alternate `dappcdn.com` mirror both gate the download *page* behind Cloudflare's managed challenge. The download *binary* itself, however, is hosted on a non-Cloudflare CDN (`sac.sk` for HWiNFO) — Cloudflare on the install URL would break their own users. Microsoft's public `winget-pkgs` repo publishes the canonical installer URL plus a vendor-blessed `InstallerSha256` for thousands of Windows tools. By looking up the URL in the winget manifest instead of scraping the vendor page, we sidestep Cloudflare entirely *and* gain a free integrity cross-check (the manifest's claimed SHA-256 must match our computed SHA-256). No browser, no rate-limit dance. We avoid the GitHub Contents API (60-req/hr anonymous limit) by scraping the embedded JSON in GitHub's tree-page HTML, which is unrate-limited.
- **`github.com` redirects to short-lived signed CDN URLs.** Any source hosted on GitHub Releases — x64dbg, Ventoy, LibreHardwareMonitor, dnSpyEx, lazygit, Foundry, plus 7-Zip's actual binaries — terminates at a signed Azure Blob URL with a multi-kilobyte JWT in the query string. Recording the full final URL is worse than useless: it bloats the sidecar with bytes that go stale within minutes. The fetcher records only **`final_host`** (and only when it differs from the request host), preserving the redirect-drift signal without the noise.
- **Sidecar shape after two extractors.** Stable on: `first_seen_at`, `last_seen_at`, `source`, `hostname`, `variant`, `monitor_page`, `fetch_url`, `final_host`, `filename`, `sha256`, `etag`, `last_modified`, `server`, `size_bytes`. Dropped before they were ever useful: full final URL, redirect chain, HTTP status code, content-type. Drop early; add back only if a real use case shows up.
- **Engine generalized cleanly.** Adding 7-Zip (HTML scrape with goquery, version detection from a `<P><B>` heading, multi-platform variant set, GitHub-hosted binaries) required zero engine changes — the `Source` interface (`Name`, `Hostname`, `MonitorPage`, `Discover(ctx, hc) ([]Target, error)`) was sufficient. Confidence increased that this scales to 250 sources.
- **Vendor LBs are flaky; retries pay for themselves immediately.** First 7-source run hit a hard failure on `nssm.cc/release/nssm-2.24.zip`. Investigation: the site fronts ~50% of requests with a broken nginx backend that always returns 503; the other backend (Apache) serves correctly. Rates and `Server` header confirmed via curl. Fix: `retryTransport` with 5 attempts, exponential backoff, and `CloseIdleConnections` between attempts (so each retry dials fresh and gets a new LB pick). Tested empirically that User-Agent / Accept-header richness did NOT change the 503 rate — this was upstream backend rotation, not anti-bot fingerprinting. Saved as a project memory: measure UA effect before adding fingerprint workarounds, since broken-backend rotation looks identical from the outside.
- **Reusing existing internal patterns saves work.** `harvest/pkg/registry/github_release.go` already had a no-API-key GitHub Releases discovery flow (HEAD `/releases/latest` → tag, GET `/releases/expanded_assets/<tag>` → regex-scrape). Adapted into `website/github_release.go`. With one helper, x64dbg / Ventoy / LibreHardwareMonitor / Rufus all became 6-line extractors. The same helper will cover Ghidra, dnSpyEx, lazygit, Foundry, Reth, ILSpy, Detect-It-Easy, PE-bear, and most other GitHub-hosted phase-1 candidates.
- **Status (2026-05-05):** 95 extractors registered, lint-clean. All 95 pass `--discover-only` (the dry-run mode that exercises every extractor's `Discover()` without fetching binary bytes) in ~64 seconds with zero errors. 8 extractors that surfaced bugs (`aircrackng`, `anythingllm`, `bitcoincore`, `corretto21`, `geth`, `hoppscotch`, `openwebui`, `sqlmap`) were dropped — each had a tagged GitHub release with **no binary attachments** because the vendor distributes via a different channel (vendor site, PyPI, electron-builder yml, etc.). Re-adding each requires its own vendor-direct extractor.
- **Polling discipline:** Sources are classified into two kinds via `website.KindOf(s)`:
  - `KindVendorWebsite` (13 sources today) — small upstreams; default cap **20h** between polls.
  - `KindLargeInfra` (82 sources) — GitHub Releases, the winget shadow source, Google-scale APIs; default cap **1h**.
  - State is in-memory per-process. For one-shot CLI invocations the cap is a no-op (relevant only when a wrapper or future loop mode calls `runSource` repeatedly within one process).
  - Override via `--vendor-interval=<dur> --default-interval=<dur>`; `0` disables.
- **Operational flags:**
  - `--discover-only` runs every extractor's `Discover()` and logs what would be fetched without consuming bandwidth — the recommended first command on any new deployment.
  - `--list` prints `name kind hostname monitor-page` for every registered source. Categories covered: hardware monitoring, service supervision, network/admin tools, reverse engineering, security/pentest (incl. Mimikatz, ZAP, sqlmap, hashcat, aircrack-ng), file/archive, editors (Cursor pending — JS-rendered), VCS/git (incl. Git for Windows, GitHub Desktop), databases & API clients (DBeaver, Beekeeper, Insomnia, Bruno, Hoppscotch), containers/VMs (Rancher Desktop, Podman Desktop, Multipass, Vagrant, Lima, Colima, Minikube, kind, k3d), ML/AI (Ollama, Jan, GPT4All, ComfyUI, AnythingLLM, Khoj, text-gen-webui, Open WebUI, Pinokio), language toolchains (Go, Node.js, Rustup, Bun, Deno, Julia, Temurin 17/21, Corretto 21), crypto (Bitcoin Core, Geth, Lighthouse, Reth, Foundry), media (HandBrake, Audacity, OBS, mpv), comms (Element, Signal, Mattermost, Telegram), VPN (Mullvad, ProtonVPN, Tailscale), password managers (KeePassXC, Bitwarden), boot media (Rufus, Ventoy, balenaEtcher, Raspberry Pi Imager, UNetbootin), maintenance (CCleaner). The `githubReleaseAssets` helper backs roughly two-thirds of the 101 — one helper covered the majority of vendors in 6-line per-source files. Test runs (subset): 16/16 baseline in 10m 25s; per-extractor live tests pass at the rate the harness was designed for.
- **Discovery shapes encountered so far:**
  1. **Static hardcoded URL list** (Ollama, Tailscale) — vendor publishes "latest" URLs that rotate underneath; Source returns a constant list, ~30 lines.
  2. **JSON API call** (CCleaner) — vendor's HTML page calls a hidden API; Source replicates that API call.
  3. **HTML scrape with goquery** (NSSM, 7-Zip, Wireshark) — version detection from a heading, then collect all artifact `<a href>`s containing that version.
  4. **HTML scrape with regex** (Nmap, WinSCP) — small static pages where regex is simpler than DOM parsing. WinSCP needed a 2-step Discover (vendor page → confirmation page → CDN URL); the Source interface absorbed that without engine changes.
  5. **GitHub Releases helper** (Rufus, Ventoy, x64dbg, LibreHardwareMonitor, Ghidra, Notepad++, KeePassXC) — `githubReleaseAssets("owner/repo")` covers any project whose vendor page is a thin wrapper over GitHub. 7-line extractors. This single helper covered 7 of 16 sources.
  6. **winget shadow-source** (HWiNFO) — for vendors whose download pages are Cloudflare-walled. Microsoft's manifest names a non-Cloudflare CDN URL plus a vendor-blessed SHA-256 cross-check. Free integrity signal.
- **Bugs caught by adding sources:**
  - Nmap's HTML uses uppercase `<A HREF=...>` while modern sites use lowercase — regex must be case-insensitive.
  - WinSCP version regex needed to anchor on dotted-int boundaries (`\d+(?:\.\d+)*`) rather than greedy `[0-9.]+` which captured trailing dots.
  - Ollama doesn't host Linux binaries on its own domain; install.sh fetches them from GitHub. Don't fabricate "ollama.com/download/ollama-linux-*" URLs.
  - GitHub's tree-page HTML embeds the *parent and root* trees too (for sidebar nav); the version-listing regex must filter on the path prefix or it picks up sibling directories like "manifests/9".

## Open questions before phase 1

- **Storage backend.** Sidecar JSON on disk vs. rows in hopper's existing Postgres. Sidecar is simpler and survives DB rebuilds; the DB approach lets the dashboard surface diffs natively. Probably both: bytes + JSON on disk, an index row in PG.
- **Authenticode / codesign extraction.** Worth doing in the fetcher, or defer to litmus once the sample is ingested? Leaning defer — keep the fetcher dumb.
- **GitHub Releases as a hostname.** A meaningful chunk of phase-1 candidates live there. We treat the upstream project's hostname (e.g. `7-zip.org`) as the directory, not `github.com` — what matters is who published, not where it's hosted. `final_host` records the actual delivery CDN.
- **First-observation behavior.** Phase 1 will produce 25 "new sha256" events on day one. We suppress alerts for the first observation per (hostname, canonical-path) pair and only alert from the second distinct hash onward.
- **Cloudflare companion.** Will it be a separate binary that periodically writes a list of discovered URLs into a file the fetcher reads, or a subprocess invoked by the fetcher? Probably the former — different release cadence (chromedp updates more often) and different operational profile (heavyweight, separate from the daily fetch loop).
- **JS-rendered SPA download flows** (DAEMON Tools Lite, Cursor) are a sibling problem to Cloudflare-walled pages: the actual installer URL is constructed at runtime via JS state, not embedded in static HTML. Same answer applies — defer to the headless companion. winget covers some (HWiNFO worked) but not all (DAEMON Tools Lite isn't in winget).
- **Engine: 3-redirect cap.** http.Client's default is 10 hops. Most legitimate vendor downloads finish in ≤2 hops (vendor → CDN, or vendor → object store → signed-CDN). 3 is the user-confirmed cap; chains beyond that are usually a misbehaving redirect loop and should fail loudly.
