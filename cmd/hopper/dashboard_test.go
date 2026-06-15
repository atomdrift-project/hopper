package main

import (
	"testing"
	"time"
)

func TestFormatETA(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{30 * time.Second, "30s"},
		{90 * time.Second, "1m30s"},
		{2*time.Hour + 5*time.Minute, "2h05m"},
		{25 * time.Hour, "1d01h"},                      // days branch: 1 day, 1 hour
		{104*24*time.Hour + 30*time.Minute, "104d00h"}, // large rescan ETA reads in days, not 2496h
	}
	for _, tt := range tests {
		if got := formatETA(tt.d); got != tt.want {
			t.Errorf("formatETA(%s) = %q, want %q", tt.d, got, tt.want)
		}
	}
}
