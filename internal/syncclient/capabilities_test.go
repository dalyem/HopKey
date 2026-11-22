package syncclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/dalyem/hopkey/internal/model"
)

// The client's handling of GET /v1/capabilities (crypto spec rev 17,
// §5.3): only a v1 answer that lists access lets access records through.
func TestItemTypes(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		sleep  bool
		want   []model.Type
		err    error
	}{
		{"v1", 200, `{"v":1,"item_types":["access","host","key"]}`, false, []model.Type{model.TypeAccess, model.TypeHost, model.TypeKey}, nil},
		{"extra members and unknown types", 200, `{"v":1,"item_types":["future","host"],"limits":{}}`, false, []model.Type{model.TypeHost}, nil},
		{"404: an older server", 404, `{"error":{"code":"not_found","message":"x"}}`, false,
			[]model.Type{model.TypeCredential, model.TypeGrant, model.TypeHost, model.TypeKey, model.TypePolicy, model.TypeSnippet}, nil},
		{"v2", 200, `{"v":2,"item_types":["access"]}`, false, nil, ErrCapabilitiesNewer},
		{"not JSON", 200, `nope`, false, nil, ErrCapabilitiesUnknown},
		{"not an object", 200, `[1]`, false, nil, ErrCapabilitiesUnknown},
		{"no item_types", 200, `{"v":1}`, false, nil, ErrCapabilitiesUnknown},
		{"item_types null", 200, `{"v":1,"item_types":null}`, false, nil, ErrCapabilitiesUnknown},
		{"no v", 200, `{"item_types":[]}`, false, nil, ErrCapabilitiesUnknown},
		{"500", 500, `{}`, false, nil, ErrCapabilitiesUnknown},
		{"timeout", 200, `{"v":1,"item_types":["access"]}`, true, nil, ErrCapabilitiesUnknown},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/capabilities" || r.Header.Get("Authorization") != "" {
					t.Errorf("request %s %v", r.URL.Path, r.Header)
				}
				if c.sleep {
					time.Sleep(300 * time.Millisecond)
				}
				w.WriteHeader(c.status)
				w.Write([]byte(c.body))
			}))
			defer ts.Close()
			cl, err := New(ts.URL, Options{DevInsecure: true, Timeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			got, err := cl.ItemTypes(context.Background())
			if c.err != nil {
				if !errors.Is(err, c.err) {
					t.Fatalf("err %v, want %v", err, c.err)
				}
				return
			}
			if err != nil || !slices.Equal(got, c.want) {
				t.Fatalf("got %v, %v; want %v", got, err, c.want)
			}
		})
	}
}
