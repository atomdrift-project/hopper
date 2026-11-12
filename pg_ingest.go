package hopper

import "strings"

// sampleObservationSQLPG defines the resolved values once for both the upsert
// and its pre-filter. Comparing the result, rather than the incoming label,
// avoids rewriting already-resolved conflicts and protected reviewed labels.
func sampleObservationSQLPG() (assignments, changed string) {
	updates := []struct{ column, value string }{
		{"label", `CASE
		WHEN samples.label IN ('inconclusive', 'dual-use', 'purgatory') THEN samples.label
		WHEN EXCLUDED.label_source = 'marker' THEN EXCLUDED.label
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'bad'
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN EXCLUDED.label
		ELSE samples.label
	END`},
		{"label_source", `CASE
		WHEN samples.label IN ('inconclusive', 'dual-use', 'purgatory') THEN samples.label_source
		WHEN EXCLUDED.label_source = 'marker' THEN 'marker'
		WHEN samples.label_source = 'marker' THEN EXCLUDED.label_source
		WHEN (samples.label = 'good' AND EXCLUDED.label = 'bad')
		  OR (samples.label = 'bad' AND EXCLUDED.label = 'good') THEN 'conflict'
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + ` THEN EXCLUDED.label_source
		ELSE samples.label_source
	END`},
		{"feed", `CASE WHEN EXCLUDED.feed <> '' THEN EXCLUDED.feed ELSE samples.feed END`},
		{"ecosystem", `CASE WHEN EXCLUDED.ecosystem <> '' THEN EXCLUDED.ecosystem ELSE samples.ecosystem END`},
		{"path", `CASE WHEN EXCLUDED.path  <> ''   THEN EXCLUDED.path  ELSE samples.path  END`},
		// Filename follows the selected path, including corrections at that path.
		{"filename", `CASE WHEN EXCLUDED.path <> '' THEN EXCLUDED.filename ELSE samples.filename END`},
		{"mtime", `CASE WHEN EXCLUDED.mtime IS NOT NULL THEN EXCLUDED.mtime ELSE samples.mtime END`},
		{"url", `CASE WHEN samples.url     = '' THEN EXCLUDED.url     ELSE samples.url     END`},
		{"domain", `CASE WHEN samples.domain  = '' THEN EXCLUDED.domain  ELSE samples.domain  END`},
		// The first sidecar supersedes a filename guess; subsequent observations
		// only fill missing package identity. Capture provenance is write-once.
		{"package", `CASE WHEN EXCLUDED.package <> '' AND (samples.package = '' OR (samples.provenance IS NULL AND EXCLUDED.provenance IS NOT NULL))
	             THEN EXCLUDED.package ELSE samples.package END`},
		{"version", `CASE WHEN EXCLUDED.version <> '' AND (samples.version = '' OR (samples.provenance IS NULL AND EXCLUDED.provenance IS NOT NULL))
	          THEN EXCLUDED.version ELSE samples.version END`},
		{"purl_base", `CASE WHEN EXCLUDED.purl_base <> ''
             AND (samples.purl_base = '' OR (samples.provenance IS NULL AND EXCLUDED.provenance IS NOT NULL))
	            THEN EXCLUDED.purl_base ELSE samples.purl_base END`},
		{"provenance", `CASE WHEN samples.provenance IS NOT NULL THEN samples.provenance ELSE EXCLUDED.provenance END`},
		{"fetched_at", `CASE WHEN samples.fetched_at IS NOT NULL THEN samples.fetched_at ELSE EXCLUDED.fetched_at END`},
		// Reviewed labels keep their skips. Marker and pool transitions may
		// change quarantine; missing/unsupported recover, while hard skips stick.
		{"skip", `CASE
		WHEN samples.label IN ('inconclusive', 'dual-use', 'purgatory') THEN samples.skip
		WHEN EXCLUDED.label_source = 'marker' THEN 'misclassified'
		WHEN samples.label_source = 'marker' AND samples.skip = 'misclassified' THEN ''
		WHEN ((samples.label = 'good' AND EXCLUDED.label = 'bad')
		   OR (samples.label = 'bad' AND EXCLUDED.label = 'good'))
		  AND samples.skip IN ('', 'misclassified', 'conflict', 'missing', 'unsupported') THEN 'conflict'
		WHEN ` + labelRankSQL("EXCLUDED.label") + `
		   > ` + labelRankSQL("samples.label") + `
		  AND samples.skip IN ('misclassified', 'conflict') THEN ''
		WHEN samples.skip IN ('missing','unsupported') THEN ''
		ELSE samples.skip
	END`},
	}
	var sets, oldValues, newValues []string
	for _, u := range updates {
		sets = append(sets, u.column+" = "+u.value)
		// Provenance is write-once. Do not detoast an existing sidecar just to
		// compare it with itself on every observation.
		if u.column != "provenance" {
			oldValues = append(oldValues, "samples."+u.column)
			newValues = append(newValues, u.value)
		}
	}
	return strings.Join(sets, ",\n"), `EXCLUDED.parent = '' AND (
 ROW(` + strings.Join(oldValues, ", ") + `) IS DISTINCT FROM ROW(` + strings.Join(newValues, ", ") + `)
 OR (samples.provenance IS NULL AND EXCLUDED.provenance IS NOT NULL))`
}

var sampleObservationSetPG, sampleObservationChangedPG = sampleObservationSQLPG()

// Staging carries occurrence path/parent separately from the containment
// projection written to samples. Compare against the latter, just as INSERT does.
var stagedSampleChangedPG = strings.NewReplacer(
	"EXCLUDED.path", "st.sample_path",
	"EXCLUDED.parent", "st.sample_parent",
	"EXCLUDED.", "st.",
	"samples.", "s.",
).Replace(sampleObservationChangedPG)

var stagedLocationChangedPG = strings.NewReplacer(
	"EXCLUDED.", "st.",
	"sample_locations.", "l.",
).Replace(locationChangePredicatePG)
