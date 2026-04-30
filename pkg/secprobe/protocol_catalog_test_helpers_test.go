package secprobe

import "github.com/yrighc/gomap/pkg/secprobe/metadata"

func swapMetadataSpecLoaderForTest(loader func() (map[string]metadata.Spec, error)) func() {
	previous := metadataSpecLoader
	metadataSpecLoader = loader
	resetBuiltinMetadataSpecsForTest()
	return func() {
		metadataSpecLoader = previous
		resetBuiltinMetadataSpecsForTest()
	}
}
