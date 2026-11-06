package hopper

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"syscall"
)

// LocationDedupeOptions controls physical deduplication. Verify=false trusts
// catalogued SHA identities and checks file metadata without reading payloads.
type LocationDedupeOptions struct{ Consolidate, DryRun, Verify bool }

// DedupeLocations shares bytes within each filesystem. With consolidate it also
// retires copies on other filesystems, but only when a usable location matches
// the sample's resolved classification. Workflow directories are never retired.
// Classification is never changed by this operation. Dry runs do not hash files.
func (db *DB) DedupeLocations(ctx context.Context, root, sha string, consolidate, dryRun bool) (DedupeResult, error) {
	return db.DedupeLocationsWithOptions(ctx, root, sha, LocationDedupeOptions{Consolidate: consolidate, DryRun: dryRun, Verify: true})
}

// DedupeLocationsWithOptions trusts catalogued content identities unless Verify
// requests rehashing. Metadata checks and classification rules apply in both modes.
func (db *DB) DedupeLocationsWithOptions(ctx context.Context, root, sha string, opts LocationDedupeOptions) (DedupeResult, error) {
	consolidate := opts.Consolidate
	var result DedupeResult
	locs, err := db.TopLevelLocationsForSHA(ctx, sha)
	if err != nil {
		return result, err
	}
	if !consolidate {
		rels := make([]string, 0, len(locs))
		for _, loc := range locs {
			rels = append(rels, loc.Path)
		}
		return linkDuplicateLocations(ctx, root, sha, rels, opts)
	}
	var label, skip, source string
	if consolidate {
		err := db.queryLocations(ctx, `SELECT label, skip, label_source FROM samples WHERE sha256 = $1`, []any{sha}, func(rows locationRows) error {
			if !rows.Next() {
				return fmt.Errorf("hopper: sample %s is absent", sha)
			}
			return rows.Scan(&label, &skip, &source)
		})
		if err != nil {
			return result, err
		}
	}
	var candidates []dedupeLocation
	for _, loc := range locs {
		_, abs, err := resolveMovePath(root, loc.Path)
		if err != nil {
			result.Skipped++
			continue
		}
		info, err := os.Lstat(abs)
		if consolidate && errors.Is(err, os.ErrNotExist) {
			// The old catalog row is a move's retry record even after unlinking.
			candidates = append(candidates, dedupeLocation{location: loc, missing: true})
			continue
		}
		if err != nil || !info.Mode().IsRegular() {
			result.Skipped++
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			result.Skipped++
			continue
		}
		// Dev width varies by OS.
		dev := uint64(st.Dev) //nolint:gosec,unconvert,nolintlint // filesystem device identifier
		candidates = append(candidates, dedupeLocation{location: loc, device: dev, size: info.Size()})
	}
	plan := planLocationDedupe(candidates, label, skip, source, consolidate)
	if consolidate && plan.survivor == nil && len(candidates) > 1 {
		result.Unresolved++
	}
	applied, err := db.applyLocationDedupeOptions(ctx, root, sha, label, plan, opts)
	applied.Skipped += result.Skipped
	applied.Unresolved += result.Unresolved
	return applied, err
}

func (db *DB) applyLocationDedupe(ctx context.Context, root, sha, label string, plan locationDedupePlan, dryRun bool) (DedupeResult, error) {
	return db.applyLocationDedupeOptions(ctx, root, sha, label, plan, LocationDedupeOptions{DryRun: dryRun, Verify: true})
}

func (db *DB) applyLocationDedupeOptions(
	ctx context.Context, root, sha, label string, plan locationDedupePlan, opts LocationDedupeOptions,
) (DedupeResult, error) {
	dryRun := opts.DryRun
	var result DedupeResult
	// Consolidate first: do not hard-link files on a filesystem we will discard.
	for _, victim := range plan.remove {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		if dryRun {
			message := "would retire duplicate location"
			if victim.missing {
				message = "would retire obsolete location"
				result.Obsolete++
			}
			slog.InfoContext(ctx, message, "sha256", sha, "old_path", victim.location.Path,
				"survivor", plan.survivor.location.Path, "label", label)
			result.BytesSaved += victim.size
			result.Removed++
			continue
		}
		moved, err := db.moveLocation(ctx, MoveLocationOptions{
			DataRoot: root, SHA256: sha, OldPath: victim.location.Path, NewPath: plan.survivor.location.Path, ExpectedLabel: label,
		}, opts.Verify)
		if errors.Is(err, ErrLocationLabelChanged) {
			result.Unresolved++
			return result, nil
		}
		if errors.Is(err, errDedupeMetadata) || errors.Is(err, os.ErrNotExist) {
			slog.WarnContext(ctx, "dedupe location skipped", "sha256", sha, "path", victim.location.Path, "error", err)
			result.Skipped++
			continue
		}

		if err != nil {
			return result, err
		}
		if moved.Relocated {
			result.Removed++
			if !moved.SourceRemoved {
				result.Obsolete++
			}
		}
		result.BytesSaved += moved.BytesFreed
	}
	for _, group := range plan.link {
		rels := make([]string, 0, len(group))
		for _, c := range group {
			rels = append(rels, c.location.Path)
		}
		linked, err := linkDuplicateLocations(ctx, root, sha, rels, opts)
		if err != nil {
			return result, err
		}
		result.Linked += linked.Linked
		result.Skipped += linked.Skipped
		result.BytesSaved += linked.BytesSaved
	}
	return result, nil
}

type dedupeLocation struct {
	location *SampleLocation
	device   uint64
	size     int64
	missing  bool
}

type locationDedupePlan struct {
	survivor *dedupeLocation
	remove   []dedupeLocation
	link     [][]dedupeLocation
}

// Classify first; age only chooses among copies in the winning label directory.
func planLocationDedupe(candidates []dedupeLocation, label, skip, source string, consolidate bool) locationDedupePlan {
	var plan locationDedupePlan
	candidates = slices.Clone(candidates)
	slices.SortFunc(candidates, func(a, b dedupeLocation) int {
		at, bt := a.location.FirstSeenAt, b.location.FirstSeenAt
		if at.IsZero() != bt.IsZero() {
			if at.IsZero() {
				return 1
			}
			return -1
		}
		if c := at.Compare(bt); c != 0 {
			return c
		}
		return strings.Compare(a.location.Path, b.location.Path)
	})
	if consolidate && skip != skipConflict && source != labelSourceConflict && classificationPool(label) != "" && classificationPool(label) == label {
		for i, c := range candidates {
			if !c.missing && classificationPool(moveRoot(c.location.Path)) == label {
				plan.survivor = &candidates[i]
				break
			}
		}
	}
	groups := map[uint64][]dedupeLocation{}
	for _, c := range candidates {
		if plan.survivor != nil && (c.missing || c.device != plan.survivor.device) && classificationPool(moveRoot(c.location.Path)) != "" {
			plan.remove = append(plan.remove, c)
		} else if !c.missing {
			groups[c.device] = append(groups[c.device], c)
		}
	}
	// Stable ordering makes dry-run reports and tests reproducible.
	devices := make([]uint64, 0, len(groups))
	for dev := range groups {
		devices = append(devices, dev)
	}
	slices.Sort(devices)
	for _, dev := range devices {
		if len(groups[dev]) > 1 {
			plan.link = append(plan.link, groups[dev])
		}
	}
	return plan
}

func classificationPool(root string) string {
	switch root {
	case labelGood, labelBad, labelSighted, labelInconclusive, labelDualUse:
		return root
	case PoolPurgatory:
		return labelInconclusive
	default:
		return ""
	}
}
