package credentials

import (
	"strings"

	"github.com/yrighc/gomap/pkg/secprobe/strategy"
)

type Options struct {
	Profile        string
	AllowEmptyUser bool
	AllowEmptyPass bool
}

func Expand(base []strategy.Credential, opts Options) []strategy.Credential {
	if len(base) == 0 {
		return nil
	}

	out := make([]strategy.Credential, 0, len(base)*4)
	seen := make(map[string]struct{}, len(base)*4)
	uniqueBase := make([]strategy.Credential, 0, len(base))

	for _, cred := range base {
		before := len(out)
		appendUnique(&out, seen, cred)
		if len(out) != before {
			uniqueBase = append(uniqueBase, cred)
		}
	}

	if strings.TrimSpace(opts.Profile) == "static_basic" {
		for _, cred := range uniqueBase {
			appendStaticBasic(&out, seen, cred)
			if opts.AllowEmptyUser {
				appendUnique(&out, seen, strategy.Credential{
					Username: "",
					Password: cred.Password,
				})
			}
			if opts.AllowEmptyPass {
				appendUnique(&out, seen, strategy.Credential{
					Username: cred.Username,
					Password: "",
				})
			}
		}
	}

	return out
}

func appendStaticBasic(out *[]strategy.Credential, seen map[string]struct{}, cred strategy.Credential) {
	if cred.Username == "" {
		return
	}

	appendUnique(out, seen, strategy.Credential{
		Username: cred.Username,
		Password: cred.Username,
	})
	appendUnique(out, seen, strategy.Credential{
		Username: cred.Username,
		Password: cred.Username + "123",
	})
	appendUnique(out, seen, strategy.Credential{
		Username: cred.Username,
		Password: cred.Username + "@123",
	})
}

func appendUnique(out *[]strategy.Credential, seen map[string]struct{}, cred strategy.Credential) {
	key := cred.Username + "\x00" + cred.Password
	if _, ok := seen[key]; ok {
		return
	}
	seen[key] = struct{}{}
	*out = append(*out, cred)
}
