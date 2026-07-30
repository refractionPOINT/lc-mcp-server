package hive

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
)

// The hive write API replaces usr_mtd wholesale: legion_config_hive
// hives/access.go SetRecord does `newRecord.UsrMtd = *record.UsrMtd` when the
// request carries a usr_mtd, so any field the request omits is lost (tags,
// comment, expiry, ui_actions) and `enabled` is forced to whatever was sent.
// The gateway only forwards a usr_mtd when the form actually carries one
// (lc_api-go service/endpoint_hive.go hive_SetRecord), and the accessor keeps
// the record's existing metadata when `record.UsrMtd == nil`. So the way to
// update a record's content without touching its metadata is to send the data
// with no usr_mtd at all — which the SDK's HiveClient.Add cannot do (it always
// builds one from its args), hence the direct POST below.

// MetadataOverrides carries the usr_mtd fields a caller explicitly asked to
// change as part of a record write. A nil/absent field means "leave alone".
type MetadataOverrides struct {
	Enabled *bool
	Tags    []string
	Comment *string
	Expiry  *int64
}

// IsEmpty reports whether the caller asked for no metadata change at all.
func (o MetadataOverrides) IsEmpty() bool {
	return o.Enabled == nil && o.Tags == nil && o.Comment == nil && o.Expiry == nil
}

// MergeUsrMtd applies the overrides on top of a record's existing metadata.
// Fields the caller did not supply are carried over untouched, including
// ui_actions which no tool parameter can express.
func MergeUsrMtd(existing lc.UsrMtd, o MetadataOverrides) lc.UsrMtd {
	merged := existing
	if o.Enabled != nil {
		merged.Enabled = *o.Enabled
	}
	if o.Tags != nil {
		merged.Tags = o.Tags
	}
	if o.Comment != nil {
		merged.Comment = *o.Comment
	}
	if o.Expiry != nil {
		merged.Expiry = *o.Expiry
	}
	return merged
}

// WithMetadataOverrideParams adds the optional enabled/tags/comment parameters
// shared by every set_* tool. Without them a caller has no way to change a
// record's metadata as part of a content write, and with them the change is
// explicit instead of a side effect.
func WithMetadataOverrideParams() mcp.ToolOption {
	return func(t *mcp.Tool) {
		mcp.WithBoolean("enabled",
			mcp.Description("Optional. Whether the record is enabled. Omit to keep the record's current state (a new record defaults to enabled)."))(t)
		mcp.WithArray("tags",
			mcp.WithStringItems(),
			mcp.Description("Optional. Replaces the record's tags. Omit to keep the existing tags."))(t)
		mcp.WithString("comment",
			mcp.Description("Optional. Replaces the record's comment. Omit to keep the existing comment."))(t)
	}
}

// ParseMetadataOverrides extracts the optional enabled/tags/comment parameters.
// Anything present but of the wrong type is an error rather than a silent drop.
func ParseMetadataOverrides(args map[string]interface{}) (MetadataOverrides, error) {
	o := MetadataOverrides{}

	if v, ok := args["enabled"]; ok && v != nil {
		b, ok := v.(bool)
		if !ok {
			return o, errors.New("enabled parameter must be a boolean")
		}
		o.Enabled = &b
	}

	if v, ok := args["tags"]; ok && v != nil {
		tags, ok := stringSlice(v)
		if !ok {
			return o, errors.New("tags parameter must be an array of strings")
		}
		if tags == nil {
			tags = []string{}
		}
		o.Tags = tags
	}

	if v, ok := args["comment"]; ok && v != nil {
		s, ok := v.(string)
		if !ok {
			return o, errors.New("comment parameter must be a string")
		}
		o.Comment = &s
	}

	return o, nil
}

// RecordWrite describes a hive record content write.
type RecordWrite struct {
	HiveName string
	// PartitionKey defaults to the organization OID when empty.
	PartitionKey string
	Key          string
	Data         lc.Dict
	Overrides    MetadataOverrides
}

// SetRecord writes a record's content while preserving the metadata the caller
// did not explicitly override.
//
// The record's current metadata is read first so that:
//   - a record that does not exist yet is created enabled (the hive defaults a
//     metadata-less create to enabled=false, which is not what "create this
//     rule" means), and
//   - explicit overrides are merged onto the existing metadata instead of
//     replacing it.
//
// When the caller supplied no overrides the write omits usr_mtd entirely, which
// is the only way to keep ui_actions (no HiveArgs/tool parameter carries them).
// A metadata read that fails for a reason other than "no such record" is only
// fatal when overrides were requested: without overrides the write still
// preserves everything, so the tool reports a warning instead of refusing to
// write. The returned warning is empty when nothing noteworthy happened.
func SetRecord(org *lc.Organization, w RecordWrite) (warning string, err error) {
	if w.HiveName == "" {
		return "", errors.New("hive name is required")
	}
	if w.Key == "" {
		return "", errors.New("record key is required")
	}
	partitionKey := w.PartitionKey
	if partitionKey == "" {
		partitionKey = org.GetOID()
	}

	client := lc.NewHiveClient(org)
	existing, mtdErr := client.GetMTD(lc.HiveArgs{
		HiveName:     w.HiveName,
		PartitionKey: partitionKey,
		Key:          w.Key,
	})

	var usrMtd *lc.UsrMtd
	switch {
	case mtdErr == nil:
		// Existing record: only send a usr_mtd when something must change.
		if !w.Overrides.IsEmpty() {
			merged := MergeUsrMtd(existing.UsrMtd, w.Overrides)
			usrMtd = &merged
		}
	case isRecordNotFound(mtdErr):
		// New record: default to enabled, then apply any overrides.
		created := MergeUsrMtd(lc.UsrMtd{Enabled: true}, w.Overrides)
		usrMtd = &created
	case !w.Overrides.IsEmpty():
		// The caller asked for a metadata change we cannot make safely: we
		// would have to send a usr_mtd built from the overrides alone, wiping
		// every field we could not read.
		return "", fmt.Errorf("failed to read existing metadata of '%s' in hive '%s' (required to apply enabled/tags/comment): %v", w.Key, w.HiveName, mtdErr)
	default:
		warning = fmt.Sprintf("could not read the current metadata of '%s' in hive '%s' (%v); the content was written without touching usr_mtd, so if this call created the record it is disabled until enabled with set_hive_record_enabled", w.Key, w.HiveName, mtdErr)
	}

	if err := postRecordData(org, w.HiveName, partitionKey, w.Key, w.Data, usrMtd); err != nil {
		return "", err
	}
	return warning, nil
}

// postRecordData POSTs a record's data to the hive data endpoint, including a
// usr_mtd only when one is given. The payload rides in gzdata (gzip+base64) so
// large records are not capped by the gateway's 10MB form limit, matching what
// the SDK's HiveClient.Add does.
func postRecordData(org *lc.Organization, hiveName, partitionKey, key string, data lc.Dict, usrMtd *lc.UsrMtd) error {
	zDat := &bytes.Buffer{}
	b64 := base64.NewEncoder(base64.StdEncoding, zDat)
	z := gzip.NewWriter(b64)
	if err := json.NewEncoder(z).Encode(data); err != nil {
		return err
	}
	if err := z.Close(); err != nil {
		return err
	}
	if err := b64.Close(); err != nil {
		return err
	}

	req := lc.Dict{"gzdata": zDat.String()}
	if usrMtd != nil {
		req["usr_mtd"] = *usrMtd
	}

	resp := lc.Dict{}
	return org.GenericPOSTRequest(fmt.Sprintf("hive/%s/%s/%s/data", hiveName, partitionKey, url.PathEscape(key)), req, &resp)
}

// SetRecordMetadata reads a record's metadata, hands it to mutate and writes the
// whole thing back.
//
// The write goes to the metadata endpoint directly rather than through the SDK's
// HiveClient.Update because Update rebuilds usr_mtd from lc.HiveArgs, which has
// no ui_actions field — so it silently deletes the UI action buttons of the
// hives that have them (playbook, ai_skill, ai_agent, app), while the endpoint
// itself takes the metadata as a JSON blob and forwards it verbatim.
func SetRecordMetadata(org *lc.Organization, hiveName, partitionKey, key string, mutate func(existing lc.UsrMtd) lc.UsrMtd) error {
	if hiveName == "" {
		return errors.New("hive name is required")
	}
	if key == "" {
		return errors.New("record key is required")
	}
	if partitionKey == "" {
		partitionKey = org.GetOID()
	}

	client := lc.NewHiveClient(org)
	existing, err := client.GetMTD(lc.HiveArgs{
		HiveName:     hiveName,
		PartitionKey: partitionKey,
		Key:          key,
	})
	if err != nil {
		return err
	}

	req := lc.Dict{"usr_mtd": mutate(existing.UsrMtd)}
	// Guard against a concurrent change between the read and the write; the
	// endpoint ignores an empty etag.
	if existing.SysMtd.Etag != "" {
		req["etag"] = existing.SysMtd.Etag
	}

	resp := lc.Dict{}
	return org.GenericPOSTRequest(fmt.Sprintf("hive/%s/%s/%s/mtd", hiveName, partitionKey, url.PathEscape(key)), req, &resp)
}

// isRecordNotFound reports whether an error is the hive's "no such record".
func isRecordNotFound(err error) bool {
	return err != nil && strings.Contains(err.Error(), "RECORD_NOT_FOUND")
}

// BriefData keeps only the given index fields of a record payload, which is
// what makes a listing usable as an index instead of a dump of every document
// body. Mirrors the python CLI's --brief (commands/_hive_shortcut.py): a nil
// payload stays nil ("absent" is not "filtered") and a payload that is not an
// object becomes empty rather than being handed back unfiltered.
func BriefData(data map[string]interface{}, indexFields ...string) map[string]interface{} {
	if data == nil {
		return nil
	}
	brief := map[string]interface{}{}
	for _, field := range indexFields {
		if v, ok := data[field]; ok {
			brief[field] = v
		}
	}
	return brief
}

// briefArg reads the optional `brief` listing parameter.
func briefArg(args map[string]interface{}) bool {
	b, _ := args["brief"].(bool)
	return b
}

// withBriefParam adds the `brief` parameter to a document-hive listing tool.
func withBriefParam(indexFields string) mcp.ToolOption {
	return mcp.WithBoolean("brief",
		mcp.Description(fmt.Sprintf("If true, keep only %s in each record's data and drop the rest of the payload. Metadata is unaffected. Use this to find the record you want, then fetch it in full.", indexFields)))
}
