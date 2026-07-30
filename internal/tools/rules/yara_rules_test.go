package rules

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestYaraSyntaxAdvisories pins the two shapes of legal YARA the old hard gate
// rejected: whitespace before the condition colon, and a brace inside a string
// literal. Neither may be reported as a syntax problem the caller must fix, and
// neither blocks a write anymore.
func TestYaraSyntaxAdvisories(t *testing.T) {
	t.Run("a plain rule has no advisories", func(t *testing.T) {
		rule := `rule Evil {
	strings:
		$a = "bad"
	condition:
		$a
}`
		assert.Empty(t, yaraSyntaxAdvisories(rule))
	})

	t.Run("whitespace before the condition colon is accepted", func(t *testing.T) {
		rule := `rule Evil {
	strings:
		$a = "bad"
	condition :
		$a
}`
		assert.Empty(t, yaraSyntaxAdvisories(rule))
	})

	t.Run("a rule written on a single line is accepted", func(t *testing.T) {
		rule := `rule Evil { strings: $a = "bad" condition : $a }`
		assert.Empty(t, yaraSyntaxAdvisories(rule))
	})

	t.Run("a brace in a string literal is only an advisory", func(t *testing.T) {
		rule := `rule Evil {
	strings:
		$a = "{"
	condition:
		$a
}`
		advisories := yaraSyntaxAdvisories(rule)
		assert.Len(t, advisories, 1)
		assert.Contains(t, advisories[0], "unbalanced")
	})

	t.Run("content that is not YARA at all is flagged", func(t *testing.T) {
		advisories := yaraSyntaxAdvisories("just some text")
		assert.Len(t, advisories, 3)
	})
}
