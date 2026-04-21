package secprobe

import "github.com/yrighc/gomap/internal/secprobe/core"

type Prober = core.Prober
type Registry = core.Registry

func NewRegistry() *Registry { return core.NewRegistry() }
