package main

import "testing"

func TestParseCgroupV2Path(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
		wantErr bool
	}{
		{
			name:    "plain unified",
			content: "0::/atomdrift.slice/hopper.service\n",
			want:    "/atomdrift.slice/hopper.service",
		},
		{
			name: "hybrid hierarchy picks the v2 line",
			content: "12:pids:/system.slice/x.service\n" +
				"1:name=systemd:/system.slice/x.service\n" +
				"0::/system.slice/x.service\n",
			want: "/system.slice/x.service",
		},
		{
			name:    "root cgroup",
			content: "0::/\n",
			want:    "/",
		},
		{
			name:    "no v2 entry",
			content: "12:pids:/system.slice/x.service\n",
			wantErr: true,
		},
		{
			name:    "malformed relative path",
			content: "0::relative\n",
			wantErr: true,
		},
		{
			name:    "empty",
			content: "",
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseCgroupV2Path(tt.content)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("path = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSDWatchdogIntervalUnarmed(t *testing.T) {
	// A test process is not under a watchdog-armed systemd unit; the parse
	// must come back disarmed rather than inventing an interval.
	t.Setenv("WATCHDOG_USEC", "")
	t.Setenv("NOTIFY_SOCKET", "")
	if _, ok := sdWatchdogInterval(); ok {
		t.Fatal("watchdog armed without WATCHDOG_USEC")
	}
	// Armed but aimed at another pid: also disarmed.
	t.Setenv("WATCHDOG_USEC", "180000000")
	t.Setenv("NOTIFY_SOCKET", "/run/systemd/notify")
	t.Setenv("WATCHDOG_PID", "1")
	if _, ok := sdWatchdogInterval(); ok {
		t.Fatal("watchdog armed for a different WATCHDOG_PID")
	}
}
