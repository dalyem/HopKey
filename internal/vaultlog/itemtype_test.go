package vaultlog

import (
	"strings"
	"testing"

	"github.com/dalyem/hopkey/internal/model"
)

// An item_put of a type this build doesn't know fails the public stage as
// a schema violation, and says that a newer hop wrote it (crypto spec rev
// 17 amendment, §1).
func TestUnknownItemTypeSaysUpgrade(t *testing.T) {
	op := &ItemPutOp{Op: "item_put", ItemID: model.ID{1}, Type: "access"}
	err := op.validate()
	if err == nil || RuleOf(err) != RuleSchema || !strings.Contains(err.Error(), "upgrade hop on this device") || !strings.Contains(err.Error(), "access") {
		t.Errorf("validate: %v (rule %q)", err, RuleOf(err))
	}
	op.Type = model.TypePolicy
	if err := op.validate(); err != nil {
		t.Errorf("policy: %v", err)
	}
}
