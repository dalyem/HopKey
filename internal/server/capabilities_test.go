package server

import (
	"testing"
)

// GET /v1/capabilities answers without authentication with the item types
// this build accepts, access among them (crypto spec rev 17, §5.3).
func TestCapabilities(t *testing.T) {
	e := newEnv(t)
	r := e.do("GET", "/v1/capabilities", "", nil)
	want := `{"item_types":["access","credential","grant","host","key","policy","snippet"],"v":1}`
	if r.status != 200 || string(r.body) != want {
		t.Errorf("capabilities: %s", r)
	}
}
