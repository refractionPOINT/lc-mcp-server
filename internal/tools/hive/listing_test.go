package hive

import (
	"errors"
	"testing"

	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakePager struct {
	page    lc.HiveConfigData
	next    string
	err     error
	gotArgs lc.HiveArgs
	gotOpts lc.ListPageOptions
}

func (f *fakePager) ListPage(args lc.HiveArgs, opts lc.ListPageOptions) (lc.HiveConfigData, string, error) {
	f.gotArgs, f.gotOpts = args, opts
	return f.page, f.next, f.err
}

func record(data map[string]interface{}) lc.HiveData {
	return lc.HiveData{
		Data:   data,
		UsrMtd: lc.UsrMtd{Enabled: true, Tags: []string{"t"}, Comment: "c"},
		SysMtd: lc.SysMtd{CreatedBy: "me"},
	}
}

func TestParseListArgs(t *testing.T) {
	t.Run("defaults depend on the shape", func(t *testing.T) {
		req, err := ParseListArgs(map[string]interface{}{}, false)
		require.NoError(t, err)
		assert.Equal(t, ListRequest{Limit: DefaultListLimit}, req)

		req, err = ParseListArgs(map[string]interface{}{"metadata_only": true}, false)
		require.NoError(t, err)
		assert.Equal(t, ListRequest{Limit: DefaultMetadataListLimit, MetadataOnly: true}, req)

		req, err = ParseListArgs(map[string]interface{}{}, true)
		require.NoError(t, err)
		assert.Equal(t, ListRequest{Limit: DefaultMetadataListLimit, MetadataOnly: true}, req)
	})

	t.Run("limit and cursor are taken and the limit is capped", func(t *testing.T) {
		req, err := ParseListArgs(map[string]interface{}{"limit": float64(10), "cursor": "abc"}, false)
		require.NoError(t, err)
		assert.Equal(t, 10, req.Limit)
		assert.Equal(t, "abc", req.Cursor)

		req, err = ParseListArgs(map[string]interface{}{"limit": float64(100000)}, false)
		require.NoError(t, err)
		assert.Equal(t, MaxListLimit, req.Limit)
	})

	t.Run("invalid values are rejected", func(t *testing.T) {
		for _, args := range []map[string]interface{}{
			{"limit": float64(0)},
			{"limit": float64(-3)},
			{"limit": 2.5},
			{"limit": "ten"},
			{"cursor": 12.0},
			{"metadata_only": "yes"},
		} {
			_, err := ParseListArgs(args, false)
			assert.Error(t, err, "%v", args)
		}
	})

	t.Run("explicit nulls are ignored", func(t *testing.T) {
		req, err := ParseListArgs(map[string]interface{}{"limit": nil, "cursor": nil, "metadata_only": nil}, false)
		require.NoError(t, err)
		assert.Equal(t, ListRequest{Limit: DefaultListLimit}, req)
	})
}

func TestListRecordsWithData(t *testing.T) {
	f := &fakePager{
		page: lc.HiveConfigData{"a": record(map[string]interface{}{"x": 1, "big": "payload"})},
		next: "NEXT",
	}
	resp, err := ListRecords(f, "playbook", "oid-1", "playbooks", ListRequest{Limit: 7, Cursor: "CUR"}, nil)
	require.NoError(t, err)

	assert.Equal(t, lc.HiveArgs{HiveName: "playbook", PartitionKey: "oid-1"}, f.gotArgs)
	assert.Equal(t, 7, f.gotOpts.Limit)
	assert.Equal(t, "CUR", f.gotOpts.Cursor)
	assert.False(t, f.gotOpts.MtdOnly)
	assert.Equal(t, listPageMaxBytes, f.gotOpts.MaxBytes, "pages with data are size bounded")

	assert.Equal(t, 1, resp["count"])
	assert.Equal(t, true, resp["has_more"])
	assert.Equal(t, "NEXT", resp["next_cursor"])
	rec := resp["playbooks"].(map[string]interface{})["a"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"x": 1, "big": "payload"}, rec["data"])
	assert.Equal(t, true, rec["enabled"])
	assert.Equal(t, []string{"t"}, rec["tags"])
	assert.Equal(t, "c", rec["comment"])
	assert.Equal(t, lc.SysMtd{CreatedBy: "me"}, rec["metadata"])
}

func TestListRecordsLastPage(t *testing.T) {
	f := &fakePager{page: lc.HiveConfigData{"a": record(nil)}}
	resp, err := ListRecords(f, "h", "o", "k", ListRequest{Limit: 5}, nil)
	require.NoError(t, err)
	assert.Equal(t, false, resp["has_more"])
	assert.NotContains(t, resp, "next_cursor")
}

func TestListRecordsMetadataOnly(t *testing.T) {
	// Even if the backend were to send data, a metadata-only listing must not
	// pass it on.
	f := &fakePager{page: lc.HiveConfigData{"a": record(map[string]interface{}{"secret": "v"})}}
	resp, err := ListRecords(f, "lookup", "o", "lookups", ListRequest{Limit: 9, MetadataOnly: true}, nil)
	require.NoError(t, err)

	assert.True(t, f.gotOpts.MtdOnly)
	assert.Zero(t, f.gotOpts.MaxBytes)
	rec := resp["lookups"].(map[string]interface{})["a"].(map[string]interface{})
	assert.NotContains(t, rec, "data")
	assert.Equal(t, true, rec["enabled"])
}

func TestListRecordsBrief(t *testing.T) {
	f := &fakePager{page: lc.HiveConfigData{"a": record(map[string]interface{}{"description": "d", "text": "long"})}}
	resp, err := ListRecords(f, "sop", "o", "sops", ListRequest{Limit: 5}, func(d map[string]interface{}) map[string]interface{} {
		return BriefData(d, "description")
	})
	require.NoError(t, err)
	rec := resp["sops"].(map[string]interface{})["a"].(map[string]interface{})
	assert.Equal(t, map[string]interface{}{"description": "d"}, rec["data"])
}

func TestListRecordsError(t *testing.T) {
	boom := errors.New("boom")
	_, err := ListRecords(&fakePager{err: boom}, "h", "o", "k", ListRequest{Limit: 5}, nil)
	assert.ErrorIs(t, err, boom)
}

func TestListNames(t *testing.T) {
	f := &fakePager{
		page: lc.HiveConfigData{"zeta": record(nil), "alpha": record(nil), "mid": record(nil)},
		next: "N",
	}
	names, next, err := ListNames(f, "secret", "o", ListRequest{Limit: 3, Cursor: "C"})
	require.NoError(t, err)
	assert.Equal(t, []string{"alpha", "mid", "zeta"}, names)
	assert.Equal(t, "N", next)
	assert.True(t, f.gotOpts.MtdOnly, "names must come from a metadata-only listing")
	assert.Equal(t, 3, f.gotOpts.Limit)
	assert.Equal(t, "C", f.gotOpts.Cursor)

	_, _, err = ListNames(&fakePager{err: errors.New("x")}, "secret", "o", ListRequest{})
	assert.Error(t, err)
}

func TestRestrictListingForcesSecretsMetadataOnly(t *testing.T) {
	for _, name := range []string{"secret", "Secret", " secret "} {
		got := restrictListing(name, ListRequest{Limit: 10})
		assert.True(t, got.MetadataOnly, name)
	}
	got := restrictListing("dr-general", ListRequest{Limit: 10})
	assert.False(t, got.MetadataOnly)
}
