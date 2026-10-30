package hive

import (
	lc "github.com/refractionPOINT/go-limacharlie/limacharlie"
	"github.com/refractionpoint/lc-mcp-go/internal/tools"
)

// Client is the SDK's hive client with the record key checked before it reaches a
// request path. The SDK escapes a key with url.PathEscape, which leaves "." and
// ".." as they are, so every method that puts args.Key into a path refuses those
// keys first (see tools.ValidateHiveRecordKey). Listing and batch calls carry no
// key in a path and are the SDK's own.
//
// Tools must build their hive client with NewClient, never lc.NewHiveClient;
// TestHiveKeyPathsAreOnlyBuiltByCheckedCode fails otherwise.
type Client struct {
	*lc.HiveClient
}

// NewClient returns a hive client for the organization.
func NewClient(org *lc.Organization) *Client {
	return &Client{HiveClient: lc.NewHiveClient(org)}
}

// Get reads a record's data.
func (c *Client) Get(args lc.HiveArgs) (*lc.HiveData, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.Get(args)
}

// GetMTD reads a record's metadata.
func (c *Client) GetMTD(args lc.HiveArgs) (*lc.HiveData, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.GetMTD(args)
}

// Add creates or replaces a record.
func (c *Client) Add(args lc.HiveArgs) (*lc.HiveResp, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.Add(args)
}

// Update changes an existing record.
func (c *Client) Update(args lc.HiveArgs) (*lc.HiveResp, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.Update(args)
}

// UpdateTx reads a record, hands it to tx and writes the result back.
func (c *Client) UpdateTx(args lc.HiveArgs, tx func(record *lc.HiveData) (*lc.HiveData, error)) (*lc.HiveResp, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.UpdateTx(args, tx)
}

// Remove deletes a record.
func (c *Client) Remove(args lc.HiveArgs) (interface{}, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	return c.HiveClient.Remove(args)
}

// Rename gives a record a new name. The new name becomes the record's key, so it
// is held to the same rule: a record named ".." could never be addressed again.
func (c *Client) Rename(args lc.HiveArgs, newName string) (*lc.HiveResp, error) {
	if err := tools.ValidateHiveRecordKey(args.Key); err != nil {
		return nil, err
	}
	if err := tools.ValidateHiveRecordKey(newName); err != nil {
		return nil, err
	}
	return c.HiveClient.Rename(args, newName)
}
