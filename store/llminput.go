package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// A file owed a description (QueueDescribe) used to cost a whole scan again:
// postdoc's LLM pass reads what its own analysis of the file left in memory.
// A worker whose LLM pass did not run now uploads what that pass needs, an
// opaque blob kept in llm_inputs, and the next worker with an LLM handed the
// file fetches it and runs only that pass. Hopper never looks inside it.
//
// An input is kept while it can serve: until an LLM has described the file
// (writer.describe deletes it in the transaction that stores the llm
// verdict) or for describeWindow, the week a file is owed a description at
// all (ExpireDescribe).

// SetLLMInput stores input as what the LLM pass needs to describe the file
// with digest sha256, replacing any input stored for it before. known is
// false when hopper has no such file. stored is false also when an LLM has
// described the file already: the input could serve nothing, and is not kept.
// A failed LLM call (an llm verdict with outcome error) described nothing, so
// its input is kept for the retry.
func (st *Store) SetLLMInput(ctx context.Context, sha256, input []byte) (known, stored bool, err error) {
	err = st.pool.QueryRow(ctx, `WITH s AS (
			SELECT id FROM samples WHERE sha256 = $1
		), put AS (
			INSERT INTO llm_inputs (sample_id, input)
			SELECT s.id, $2 FROM s
			WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.sample_id = s.id AND v.scanner_id = $3 AND v.outcome = 'ok')
			ON CONFLICT (sample_id) DO UPDATE SET input = EXCLUDED.input, stored_at = now()
			RETURNING 1
		)
		SELECT EXISTS (SELECT 1 FROM s), EXISTS (SELECT 1 FROM put)`, sha256, input, jurors["llm"]).Scan(&known, &stored)
	if err != nil {
		return false, false, fmt.Errorf("store: set llm input: %w", err)
	}
	return known, stored, nil
}

// LLMInput returns the input stored for the file with digest sha256
// (SetLLMInput), or ErrNotFound.
func (st *Store) LLMInput(ctx context.Context, sha256 []byte) ([]byte, error) {
	var input []byte
	err := st.pool.QueryRow(ctx, `SELECT i.input FROM llm_inputs i JOIN samples s ON s.id = i.sample_id
		WHERE s.sha256 = $1`, sha256).Scan(&input)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("store: llm input: %w", err)
	}
	return input, nil
}
