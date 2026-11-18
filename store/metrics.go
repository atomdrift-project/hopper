package store

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

var writePhaseHistogram = sync.OnceValue(func() metric.Float64Histogram {
	h, err := otel.Meter("github.com/atomdrift-project/hopper/store").Float64Histogram(
		"hopper.store_write_phase.seconds",
		metric.WithDescription("Time per verdict write attempt, split into connection acquisition and transaction."),
		metric.WithExplicitBucketBoundaries(0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 4, 8, 16, 30, 60),
	)
	if err != nil {
		return nil
	}
	return h
})

func recordWritePhase(ctx context.Context, phase string, d time.Duration, err error) {
	if h := writePhaseHistogram(); h != nil {
		outcome := "ok"
		if err != nil {
			outcome = "error"
		}
		h.Record(ctx, d.Seconds(), metric.WithAttributes(
			attribute.String("phase", phase), attribute.String("outcome", outcome)))
	}
}
