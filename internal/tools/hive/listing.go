package hive

import (
	"fmt"
	"math"
	"sort"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

const (
	// DefaultListLimit is the number of records a listing tool returns when
	// the caller does not give a limit and the records carry their data.
	DefaultListLimit = 50
	// DefaultMetadataListLimit is the page size when records come without
	// their data, which is far cheaper for both the backend and the model.
	DefaultMetadataListLimit = 200
	// MaxListLimit is the largest page a caller can ask for. It is also the
	// largest page the API gateway accepts.
	MaxListLimit = 500
	// listPageMaxBytes bounds the size of a page of records carrying data. A
	// tool result is read by a model, so it is kept far below the API's own
	// page bound. The first record of a page is always returned.
	listPageMaxBytes = 1 << 20
)

// RecordPager is the part of the hive client the listing tools use, so they
// can be tested without a backend.
type RecordPager interface {
	ListPage(args lc.HiveArgs, opts lc.ListPageOptions) (lc.HiveConfigData, string, error)
}

// ListRequest is the paging and shape request shared by the hive listing
// tools.
type ListRequest struct {
	// Limit is the maximum number of records in the page.
	Limit int
	// Cursor is the next_cursor of the previous page, empty for the first.
	Cursor string
	// MetadataOnly returns the records without their data. The backend does
	// not load the data at all.
	MetadataOnly bool
}

// WithListPagingParams adds the `limit` and `cursor` parameters to a listing
// tool.
func WithListPagingParams() mcp.ToolOption {
	return func(t *mcp.Tool) {
		mcp.WithNumber("limit",
			mcp.Description(fmt.Sprintf("Maximum number of records to return in this page (default %d, or %d when no record data is returned; max %d). The page can hold fewer records than the limit. When the response has has_more=true, pass its next_cursor as `cursor` to get the next page.", DefaultListLimit, DefaultMetadataListLimit, MaxListLimit)))(t)
		mcp.WithString("cursor",
			mcp.Description("Opaque cursor: the next_cursor of the previous page. Leave empty for the first page."))(t)
	}
}

// withMetadataOnlyParam adds the `metadata_only` parameter to a listing tool
// whose records carry data.
func withMetadataOnlyParam() mcp.ToolOption {
	return mcp.WithBoolean("metadata_only",
		mcp.Description("If true, return only each record's metadata (enabled, tags, comment, system metadata) without its data. This is much cheaper for large records; fetch a record by name to get its data."))
}

// ParseListArgs reads the paging and shape parameters of a listing tool.
// metadataOnlyDefault is the shape used when `metadata_only` is not given.
func ParseListArgs(args map[string]interface{}, metadataOnlyDefault bool) (ListRequest, error) {
	req := ListRequest{MetadataOnly: metadataOnlyDefault}
	if v, ok := args["metadata_only"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return req, fmt.Errorf("metadata_only must be a boolean")
		}
		req.MetadataOnly = b
	}
	if v, ok := args["cursor"]; ok && v != nil {
		c, ok := v.(string)
		if !ok {
			return req, fmt.Errorf("cursor must be a string")
		}
		req.Cursor = c
	}
	req.Limit = DefaultListLimit
	if req.MetadataOnly {
		req.Limit = DefaultMetadataListLimit
	}
	if v, ok := args["limit"]; ok && v != nil {
		f, ok := v.(float64)
		if !ok || f != math.Trunc(f) || f < 1 {
			return req, fmt.Errorf("limit must be a positive integer")
		}
		req.Limit = int(min(f, MaxListLimit))
	}
	return req, nil
}

// ListRecords lists one page of a hive and builds the tool result: the
// records under key, the number of records in the page and, when there are
// more, has_more and next_cursor. brief, when not nil, reduces each record's
// data (it is ignored for metadata-only listings, which have no data).
func ListRecords(pager RecordPager, hiveName, oid, key string, req ListRequest, brief func(map[string]interface{}) map[string]interface{}) (map[string]interface{}, error) {
	opts := lc.ListPageOptions{
		Limit:   req.Limit,
		Cursor:  req.Cursor,
		MtdOnly: req.MetadataOnly,
	}
	if !req.MetadataOnly {
		opts.MaxBytes = listPageMaxBytes
	}
	page, next, err := pager.ListPage(lc.HiveArgs{HiveName: hiveName, PartitionKey: oid}, opts)
	if err != nil {
		return nil, err
	}

	records := make(map[string]interface{}, len(page))
	for name, rec := range page {
		out := map[string]interface{}{
			"enabled":  rec.UsrMtd.Enabled,
			"tags":     rec.UsrMtd.Tags,
			"comment":  rec.UsrMtd.Comment,
			"metadata": rec.SysMtd,
		}
		if !req.MetadataOnly {
			payload := rec.Data
			if brief != nil {
				payload = brief(payload)
			}
			out["data"] = payload
		}
		records[name] = out
	}

	resp := map[string]interface{}{
		key:        records,
		"count":    len(records),
		"has_more": next != "",
	}
	if next != "" {
		resp["next_cursor"] = next
	}
	return resp, nil
}

// ListNames lists one page of a hive and returns only the record names, in
// order, and the cursor of the next page. The records are always listed
// metadata-only, so the backend never loads their data (this is what keeps
// secret values out of a listing).
func ListNames(pager RecordPager, hiveName, oid string, req ListRequest) ([]string, string, error) {
	page, next, err := pager.ListPage(lc.HiveArgs{HiveName: hiveName, PartitionKey: oid}, lc.ListPageOptions{
		Limit:   req.Limit,
		Cursor:  req.Cursor,
		MtdOnly: true,
	})
	if err != nil {
		return nil, "", err
	}
	names := make([]string, 0, len(page))
	for name := range page {
		names = append(names, name)
	}
	sort.Strings(names)
	return names, next, nil
}

var _ RecordPager = (*lc.HiveClient)(nil)
