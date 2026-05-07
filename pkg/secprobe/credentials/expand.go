package credentials

import (
	"strings"

	"github.com/yrighc/gomap/internal/secprobe/core"
)

type Options struct {
	Profile        string
	AllowEmptyUser bool
	AllowEmptyPass bool
}

func Expand(base []core.Credential, opts Options) []core.Credential {
	if len(base) == 0 {
		return nil
	}

	out := make([]core.Credential, 0, len(base)*4)
	seen := make(map[string]struct{}, len(base)*4)
	uniqueBase := make([]core.Credential, 0, len(base))

	for _, cred := range base {
		before := len(out)
		appendUnique(&out, seen, cred)
		if len(out) != before {
			uniqueBase = append(uniqueBase, cred)
		}
	}

	for _, cred := range uniqueBase {
		switch strings.TrimSpace(opts.Profile) {
		case "static_basic":
			appendStaticBasic(&out, seen, cred)
		}
	}

	for _, cred := range uniqueBase {
		if opts.AllowEmptyUser {
			appendUnique(&out, seen, core.Credential{
				Username: "",
				Password: cred.Password,
			})
		}
		if opts.AllowEmptyPass {
			appendUnique(&out, seen, core.Credential{
				Username: cred.Username,
				Password: "",
			})
		}
	}

	return out
}

func appendStaticBasic(out *[]core.Credential, seen map[string]struct{}, cred core.Credential) {
	if cred.Username == "" {
		return
	}

	appendUnique(out, seen, core.Credential{
		Username: cred.Username,
		Password: cred.Username,
	})
	appendUnique(out, seen, core.Credential{
		Username: cred.Username,
		Password: cred.Username + "123",
	})
	appendUnique(out, seen, core.Credential{
		Username: cred.Username,
		Password: cred.Username + "@123",
	})
}

func appendUnique(out *[]core.Credential, seen map[string]struct{}, cred core.Credential) {
	key := cred.Username + "\x00" + cred.Password
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, cred)
}
