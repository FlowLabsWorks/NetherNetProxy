package schemacodec

import (
	"os"
	"path/filepath"
)

// DirSource serves the json/ folder of a checkout of Mojang/bedrock-protocol-docs.
type DirSource string

// File implements Source.
func (d DirSource) File(name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(string(d), "json", name))
}

// MapSource serves schema files from memory.
type MapSource map[string]string

// File implements Source.
func (m MapSource) File(name string) ([]byte, error) {
	s, ok := m[name]
	if !ok {
		return nil, os.ErrNotExist
	}
	return []byte(s), nil
}
