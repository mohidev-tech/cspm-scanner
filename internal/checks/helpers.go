package checks

import (
	"strings"

	"github.com/mohidev-tech/cspm-scanner/internal/scanner"
)

// attr returns the literal source text of an attribute on the resource,
// case-insensitive on the key. Empty string if absent.
func attr(r scanner.Resource, key string) string {
	if v, ok := r.Attributes[key].(string); ok {
		return v
	}
	return ""
}

// attrBool returns true when the attribute exists and resolves to a literal `true`.
// Variable references like "var.encrypted" are conservative: they read as NOT true.
func attrBool(r scanner.Resource, key string) bool {
	return strings.EqualFold(attr(r, key), "true")
}

// nestedBlock returns the first child block of `key`, normalized to a map.
// Many TF blocks (ingress, server_side_encryption_configuration) can appear
// once or many times — callers should handle both shapes.
func nestedBlock(r scanner.Resource, key string) map[string]interface{} {
	switch v := r.Attributes[key].(type) {
	case map[string]interface{}:
		return v
	case []map[string]interface{}:
		if len(v) > 0 {
			return v[0]
		}
	}
	return nil
}

func nestedBlocks(r scanner.Resource, key string) []map[string]interface{} {
	switch v := r.Attributes[key].(type) {
	case []map[string]interface{}:
		return v
	case map[string]interface{}:
		return []map[string]interface{}{v}
	}
	return nil
}

// nestedAttr is attr() but inside a nested block.
func nestedAttr(b map[string]interface{}, key string) string {
	if b == nil {
		return ""
	}
	if v, ok := b[key].(string); ok {
		return v
	}
	return ""
}
