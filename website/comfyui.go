package website

import (
	"context"
	"net/http"
)

func newComfyui() *comfyui { return &comfyui{} }

type comfyui struct{}

func (*comfyui) Name() string        { return "comfyui" }
func (*comfyui) Hostname() string    { return "comfy.org" }
func (*comfyui) MonitorPage() string { return "https://www.comfy.org/" }

func (*comfyui) Discover(ctx context.Context, hc *http.Client) ([]Target, error) {
	return githubReleaseAssets(ctx, hc, "Comfy-Org/ComfyUI")
}
