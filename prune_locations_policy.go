package hopper

import "context"

func normalizeLocationCaps(opts LocationPruneOptions) LocationPruneOptions {
	if opts.GoodMaxPaths == 0 {
		opts.GoodMaxPaths = 256
	}
	if opts.UnknownMaxPaths == 0 {
		opts.UnknownMaxPaths = 512
	}
	if opts.MaxPaths > 0 {
		opts.GoodMaxPaths = opts.MaxPaths
		opts.UnknownMaxPaths = opts.MaxPaths
	}
	return opts
}

func locationLabelCap(label, skip, source string, opts LocationPruneOptions) int {
	if skip == skipConflict || source == labelSourceConflict {
		return 0
	}
	switch label {
	case labelGood:
		return opts.GoodMaxPaths
	case labelUnknown:
		return opts.UnknownMaxPaths
	default:
		return 0
	}
}

func locationLabelStats(labels *LocationPruneLabels, label string) *LocationPruneLabelStats {
	switch label {
	case labelGood:
		return &labels.Good
	case labelUnknown:
		return &labels.Unknown
	case labelBad:
		return &labels.Bad
	default:
		return &labels.Other
	}
}

func (db *DB) pruneCurrentLabel(ctx context.Context, sha string) (sample pruneSample, err error) {
	err = db.queryLocations(ctx, `SELECT label,skip,label_source FROM samples WHERE sha256=$1`, []any{sha}, func(rows locationRows) error {
		if rows.Next() {
			return rows.Scan(&sample.Label, &sample.Skip, &sample.Source)
		}
		return rows.Err()
	})
	return sample, err
}
