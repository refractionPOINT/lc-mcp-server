package state

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/refractionpoint/lc-mcp-go/internal/redis"
)

// Token lifecycle: issuing, refreshing and revoking the tokens of a grant.
//
// A grant (a sign-in) is a family: every token it ever issues carries the
// family id, and Redis holds, next to the token records themselves,
//
//	oauth:family:<id>             the grant's current refresh and access token
//	oauth:tokfam:<sha256(token)>  token -> family id, for refresh and access
//	                              tokens, kept as long as the token could live
//	oauth:revoked:fam:<id>        set when the grant is revoked
//	oauth:revoked:tok:<sha256>    set when a token is revoked
//	oauth:refresh_claim:<sha256>  the refresh in flight on a refresh token,
//	                              valued with the id of the attempt that owns it
//	oauth:rotation:<sha256>       the outcome of a refresh token's rotation
//
// The refresh record stays in place for the whole refresh: a claim is a
// separate key, so revocation can always find the token, its family and its
// access token, whatever refresh is running. Every step that changes more than
// one key is a single Lua script, so it either happened or it did not:
//
//   - claim: take the claim for one attempt (idempotent for that attempt)
//   - publish: create the successors and retire the old tokens, only for the
//     attempt that still owns the claim, and only if nothing was revoked
//   - revoke: mark the grant, tombstone the token and delete the grant's
//     current tokens and claim
//
// The Redis client retries a command whose reply was lost, so a script can run
// twice with the same arguments. claim and publish recognise the repeat (same
// attempt id) and answer as they did the first time; revoke is idempotent.
//
// The scripts name some keys themselves (a family's current tokens) instead of
// receiving them in KEYS, so they need a standalone or primary/replica Redis.

// luaPrelude is shared by the scripts below. Key prefixes come from the Go
// constants; there is no SHA-256 in Lua, so every hash is computed by the
// caller and handed in.
var luaPrelude = fmt.Sprintf(`
local P_REFRESH = %q
local P_TOKEN = %q
local P_CLAIM = %q
local P_FAMILY = %q
local P_FAMILY_REVOKED = %q

-- decode returns the table a JSON record holds, or nil when it is not JSON.
local function decode(rec)
	local ok, obj = pcall(cjson.decode, rec)
	if ok and type(obj) == 'table' then
		return obj
	end
	return nil
end

-- str returns obj[name] when it is a non-empty string.
local function str(obj, name)
	if obj then
		local v = obj[name]
		if type(v) == 'string' and v ~= '' then
			return v
		end
	end
	return nil
end

-- extend gives an existing key at least ms milliseconds to live.
local function extend(key, ms)
	local cur = redis.call('PTTL', key)
	if cur == -1 or (cur >= 0 and cur < tonumber(ms)) then
		redis.call('PEXPIRE', key, ms)
	end
end

-- kill_family revokes a grant: the marker that blocks every write for it, and
-- the current tokens and claim its record names.
local function kill_family(fam, marker_ttl)
	redis.call('SET', P_FAMILY_REVOKED .. fam, '1', 'PX', marker_ttl)
	local fk = P_FAMILY .. fam
	if redis.call('EXISTS', fk) == 1 then
		local rt = redis.call('HGET', fk, 'rt')
		local rth = redis.call('HGET', fk, 'rth')
		local at = redis.call('HGET', fk, 'at')
		if rt then redis.call('DEL', P_REFRESH .. rt) end
		if rth then redis.call('DEL', P_CLAIM .. rth) end
		if at then redis.call('DEL', P_TOKEN .. at) end
		redis.call('DEL', fk)
	end
end
`, RefreshPrefix, TokenPrefix, RefreshClaimPrefix, FamilyPrefix, RevokedFamilyPrefix)

// Results of the claim script.
const (
	claimOK       = 1
	claimNotFound = 0
	claimRevoked  = -1
	claimTaken    = -2
)

// claimScript takes the claim of a refresh token for one attempt.
//
//	KEYS: 1 refresh record, 2 claim, 3 token tombstone, 4 token->family index
//	ARGV: 1 attempt id, 2 claim ttl (ms), 3 fresh family id (used only for a
//	      token that has no family), 4 ttl (ms) for a record without expiry
//
// Returns {status, record, family}. The record is not touched. A repeat of the
// attempt that already holds the claim succeeds again. A token without a family
// (issued before families existed) gets one here, by writing its index with
// SET NX, so two first uses agree on it and revocation can find it from then on.
var claimScript = redis.NewScript(luaPrelude + `
local rec = redis.call('GET', KEYS[1])
if not rec then
	return {0, '', ''}
end
local fam = str(decode(rec), 'family_id')
if not fam then
	local idx = redis.call('GET', KEYS[4])
	if idx then fam = idx end
end
if redis.call('EXISTS', KEYS[3]) == 1 then
	return {-1, '', fam or ''}
end
if fam and redis.call('EXISTS', P_FAMILY_REVOKED .. fam) == 1 then
	return {-1, '', fam}
end
if not redis.call('SET', KEYS[2], ARGV[1], 'NX', 'PX', ARGV[2]) then
	if redis.call('GET', KEYS[2]) ~= ARGV[1] then
		return {-2, '', fam or ''}
	end
end
local ttl = redis.call('PTTL', KEYS[1])
if ttl < 1 then ttl = ARGV[4] end
if fam then
	redis.call('SET', KEYS[4], fam, 'NX', 'PX', ttl)
else
	redis.call('SET', KEYS[4], ARGV[3], 'NX', 'PX', ttl)
	fam = redis.call('GET', KEYS[4])
end
return {1, rec, fam}
`)

// releaseScript drops a claim, only if the attempt that asks owns it.
//
//	KEYS: 1 claim; ARGV: 1 attempt id
var releaseScript = redis.NewScript(`
if redis.call('GET', KEYS[1]) == ARGV[1] then
	return redis.call('DEL', KEYS[1])
end
return 0
`)

// Results of the publish script.
const (
	publishDone     = 1
	publishReplayed = 2
	publishConflict = 0
	publishRevoked  = -1
	publishLost     = -2
)

// publishScript creates the successors of a claimed refresh token and retires
// the old ones.
//
//	KEYS: 1 claim, 2 old refresh record, 3 old refresh tombstone, 4 family
//	      marker, 5 rotation record, 6 new access record, 7 new refresh record,
//	      8 family record, 9 new access index, 10 new refresh index, 11 old
//	      refresh index, and when the old refresh token named an access token
//	      12 old access record, 13 old access index
//	ARGV: 1 attempt id, 2 family id, 3 access json, 4 access ttl (ms),
//	      5 refresh json, 6 refresh ttl (ms), 7 new access token, 8 new refresh
//	      token, 9 sha256 of the new refresh token, 10 rotation record value,
//	      11 rotation record ttl (ms), 12 ttl (ms) for a record without expiry,
//	      13 family record ttl (ms)
//
// It publishes only when the claim is still the attempt's own (an expired or
// taken-over claim cannot), the refresh token still exists, and neither the
// token nor its family was revoked. Then, in one step: the successors are
// created (create-only), the old refresh record and access record are deleted,
// the indices and the family record are updated, the claim is dropped and the
// outcome is recorded. A repeat of an attempt that already published finds the
// record and answers publishReplayed.
var publishScript = redis.NewScript(luaPrelude + `
local done = redis.call('GET', KEYS[5])
if done then
	if done == ARGV[10] then return 2 end
	return -2
end
if redis.call('EXISTS', KEYS[3]) == 1 or redis.call('EXISTS', KEYS[4]) == 1 then
	return -1
end
if redis.call('GET', KEYS[1]) ~= ARGV[1] then
	return -2
end
local old_ttl = redis.call('PTTL', KEYS[2])
if old_ttl == -2 then
	return -1
end
if redis.call('EXISTS', KEYS[6]) == 1 or redis.call('EXISTS', KEYS[7]) == 1 then
	return 0
end
if old_ttl < 1 then old_ttl = ARGV[12] end
redis.call('SET', KEYS[6], ARGV[3], 'PX', ARGV[4])
redis.call('SET', KEYS[7], ARGV[5], 'PX', ARGV[6])
redis.call('SET', KEYS[9], ARGV[2], 'PX', ARGV[4])
redis.call('SET', KEYS[10], ARGV[2], 'PX', ARGV[6])
redis.call('SET', KEYS[11], ARGV[2], 'NX', 'PX', old_ttl)
if #KEYS >= 13 then
	local t = redis.call('PTTL', KEYS[12])
	if t > 0 then
		redis.call('SET', KEYS[13], ARGV[2], 'NX', 'PX', t)
	end
	redis.call('DEL', KEYS[12])
end
redis.call('DEL', KEYS[2])
redis.call('DEL', KEYS[1])
redis.call('HSET', KEYS[8], 'rt', ARGV[8], 'rth', ARGV[9], 'at', ARGV[7])
extend(KEYS[8], ARGV[13])
redis.call('SET', KEYS[5], ARGV[10], 'PX', ARGV[11])
return 1
`)

// Results of the issue script.
const (
	issueDone     = 1
	issueConflict = 0
	issueRevoked  = -1
)

// issueScript stores the first token pair of a new grant.
//
//	KEYS: 1 access record, 2 refresh record, 3 family marker, 4 family record,
//	      5 access index, 6 refresh index
//	ARGV: 1 access json, 2 access ttl (ms), 3 refresh json, 4 refresh ttl (ms),
//	      5 family id, 6 access token, 7 refresh token, 8 sha256 of the refresh
//	      token, 9 family record ttl (ms)
//
// Create-only, and safe to repeat: a record that already holds exactly the
// value being stored is what an earlier run of this call left.
var issueScript = redis.NewScript(luaPrelude + `
if redis.call('EXISTS', KEYS[3]) == 1 then
	return -1
end
local a = redis.call('GET', KEYS[1])
if a and a ~= ARGV[1] then return 0 end
local r = redis.call('GET', KEYS[2])
if r and r ~= ARGV[3] then return 0 end
redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2])
redis.call('SET', KEYS[2], ARGV[3], 'PX', ARGV[4])
redis.call('SET', KEYS[5], ARGV[5], 'PX', ARGV[2])
redis.call('SET', KEYS[6], ARGV[5], 'PX', ARGV[4])
redis.call('HSET', KEYS[4], 'rt', ARGV[7], 'rth', ARGV[8], 'at', ARGV[6])
extend(KEYS[4], ARGV[9])
return 1
`)

// Results of the revoke script.
const (
	revokeNothing  = 0
	revokeRefresh  = 1
	revokeAccess   = 2
	revokeByIndex  = 3
	revokeRepeated = 4
)

// revokeTokenScript revokes the grant of a presented token, of either kind.
//
//	KEYS: 1 refresh record of the token, 2 access record of the token, 3 token
//	      tombstone, 4 refresh claim of the token, 5 token->family index
//	ARGV: 1 tombstone ttl (ms), 2 family marker ttl (ms)
//
// The family comes from the token's record, or, when the record is gone (the
// token was rotated away), from its index. A token with no family (issued
// before families existed) is revoked on its own, with the access token its
// refresh record names. Otherwise the grant is marked revoked and its current
// refresh token, access token and claim are deleted, in the same step. A token
// that is not known at all changes nothing, so unauthenticated callers cannot
// fill Redis with records.
var revokeTokenScript = redis.NewScript(luaPrelude + `
local rrec = redis.call('GET', KEYS[1])
local arec = redis.call('GET', KEYS[2])
local obj = nil
if rrec then
	obj = decode(rrec)
elseif arec then
	obj = decode(arec)
end
local fam = str(obj, 'family_id')
if not fam then
	local idx = redis.call('GET', KEYS[5])
	if idx then fam = idx end
end
if not (rrec or arec or fam) then
	if redis.call('EXISTS', KEYS[3]) == 1 then return 4 end
	return 0
end
redis.call('SET', KEYS[3], '1', 'PX', ARGV[1])
if rrec then
	local named = str(obj, 'access_token')
	if named then redis.call('DEL', P_TOKEN .. named) end
	redis.call('DEL', KEYS[1])
end
if arec then redis.call('DEL', KEYS[2]) end
redis.call('DEL', KEYS[4])
if fam then kill_family(fam, ARGV[2]) end
if rrec then return 1 end
if arec then return 2 end
return 3
`)

// revokeFamilyScript revokes a grant by its id.
//
//	KEYS: 1 family marker, 2 family record; ARGV: 1 family id, 2 marker ttl (ms)
var revokeFamilyScript = redis.NewScript(luaPrelude + `
kill_family(ARGV[1], ARGV[2])
return 1
`)

// Results of the access token update script.
const (
	updateDone    = 1
	updateGone    = 0
	updateRevoked = -1
)

// updateAccessScript rewrites a stored access token (lifetime extension,
// refreshed Firebase tokens) and keeps the token's index and its family record
// alive at least as long as the token.
//
//	KEYS: 1 access record, and for a token with a family 2 family marker,
//	      3 access index, 4 family record
//	ARGV: 1 access json, 2 ttl (ms), 3 family id
//
// It never creates the record (SET XX), and refuses once the family is revoked.
var updateAccessScript = redis.NewScript(luaPrelude + `
local fam = #KEYS >= 4
if fam and redis.call('EXISTS', KEYS[2]) == 1 then
	return -1
end
if not redis.call('SET', KEYS[1], ARGV[1], 'PX', ARGV[2], 'XX') then
	return 0
end
if fam then
	if redis.call('PTTL', KEYS[3]) == -2 then
		redis.call('SET', KEYS[3], ARGV[3], 'PX', ARGV[2])
	else
		extend(KEYS[3], ARGV[2])
	end
	extend(KEYS[4], ARGV[2])
end
return 1
`)

// Errors of the token lifecycle.
var (
	// ErrRefreshTokenNotFound means there is no such refresh token: unknown,
	// expired, already rotated away or revoked and deleted.
	ErrRefreshTokenNotFound = errors.New("refresh token not found")
	// ErrClaimLost means the refresh attempt no longer owns its claim: it
	// expired, or the grant was revoked, or another attempt took over.
	ErrClaimLost = errors.New("refresh claim lost")
)

// ms renders a duration as the millisecond count the scripts take.
func ms(d time.Duration) string {
	return strconv.FormatInt(d.Milliseconds(), 10)
}

// scriptInt reads the integer a script returned.
func scriptInt(res interface{}, err error) (int64, error) {
	if err != nil {
		return 0, err
	}
	n, ok := res.(int64)
	if !ok {
		return 0, fmt.Errorf("unexpected script reply %T", res)
	}
	return n, nil
}

// randomID returns a 128-bit random identifier.
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// detached is a context for cleanup that must outlive a cancelled request.
func detached(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
}

// ===== Issuing =====

// scriptCall is a script invocation with its arguments fixed. Running the same
// call twice is what a client library does when a reply is lost.
type scriptCall struct {
	script *redis.Script
	keys   []string
	args   []interface{}
}

func (m *Manager) run(ctx context.Context, c *scriptCall) (int64, error) {
	return scriptInt(m.redis.Run(ctx, c.script, c.keys, c.args...))
}

// IssueTokens stores the first access and refresh token of a new grant, and
// the family and index records that let revocation find them, in one atomic
// step. Both must carry the same non-empty family id. It is create-only: it
// returns ErrAlreadyExists if either token exists with other content, and
// ErrTokenRevoked if the family was revoked. If the Redis client repeats the
// command because a reply was lost, the repeat succeeds.
func (m *Manager) IssueTokens(ctx context.Context, at *AccessTokenData, rt *RefreshTokenData) error {
	call, err := m.prepareIssue(at, rt)
	if err != nil {
		return err
	}
	return m.issue(ctx, call)
}

func (m *Manager) prepareIssue(at *AccessTokenData, rt *RefreshTokenData) (*scriptCall, error) {
	if at.FamilyID == "" || at.FamilyID != rt.FamilyID {
		return nil, errors.New("issued tokens must belong to one family")
	}
	atData, atTTL, err := m.encodeAccessToken(at)
	if err != nil {
		return nil, err
	}
	rtData, err := m.encodeRefreshToken(rt)
	if err != nil {
		return nil, err
	}
	rtTTL := RefreshTTL * time.Second
	fam := at.FamilyID
	return &scriptCall{
		script: issueScript,
		keys: []string{
			TokenPrefix + at.AccessToken,
			RefreshPrefix + rt.RefreshToken,
			RevokedFamilyPrefix + fam,
			FamilyPrefix + fam,
			TokenFamilyPrefix + tokenHash(at.AccessToken),
			TokenFamilyPrefix + tokenHash(rt.RefreshToken),
		},
		args: []interface{}{
			atData, ms(atTTL), rtData, ms(rtTTL), fam, at.AccessToken, rt.RefreshToken, tokenHash(rt.RefreshToken), ms(max(atTTL, rtTTL)),
		},
	}, nil
}

func (m *Manager) issue(ctx context.Context, call *scriptCall) error {
	n, err := m.run(ctx, call)
	if err != nil {
		return fmt.Errorf("failed to store tokens: %w", err)
	}
	switch n {
	case issueDone:
		return nil
	case issueConflict:
		return ErrAlreadyExists
	case issueRevoked:
		return ErrTokenRevoked
	}
	return fmt.Errorf("unexpected issue result %d", n)
}

// ===== Refresh claims =====

// RefreshClaim is the right of one refresh attempt to rotate a refresh token.
// The refresh record is not touched while it is held: the claim is a separate
// key that expires on its own, and publishing needs it to still be the
// attempt's own.
type RefreshClaim struct {
	Token string
	// Owner identifies the attempt; it is the value of the claim key.
	Owner string
	// FamilyID is the grant of the token, assigned by the claim to a token
	// that had none.
	FamilyID string
	Data     *RefreshTokenData
}

// ErrRefreshInFlight means the refresh token is claimed by another attempt.
var ErrRefreshInFlight = errors.New("refresh in flight")

// ClaimRefreshToken claims a refresh token for a new attempt. Exactly one
// attempt holds a token's claim at a time. It returns ErrRefreshTokenNotFound
// for a token that does not exist, ErrTokenRevoked for one that was revoked
// (or whose grant was), and ErrRefreshInFlight when another attempt holds the
// claim. Whoever gets a claim must release it (ReleaseRefreshClaim) unless it
// publishes.
func (m *Manager) ClaimRefreshToken(ctx context.Context, refreshToken string) (*RefreshClaim, error) {
	owner, err := randomID()
	if err != nil {
		return nil, err
	}
	return m.claimAs(ctx, refreshToken, owner)
}

// claimAs is ClaimRefreshToken for a given attempt id. Claiming again as the
// attempt that already holds the claim succeeds again, which is what makes a
// claim whose reply was lost safe to repeat.
func (m *Manager) claimAs(ctx context.Context, refreshToken, owner string) (*RefreshClaim, error) {
	fresh, err := m.GenerateFamilyID()
	if err != nil {
		return nil, err
	}
	h := tokenHash(refreshToken)
	keys := []string{
		RefreshPrefix + refreshToken,
		RefreshClaimPrefix + h,
		RevokedTokenPrefix + h,
		TokenFamilyPrefix + h,
	}
	res, err := m.redis.Run(ctx, claimScript, keys, owner, ms(RefreshClaimTTL), fresh, ms(RefreshTTL*time.Second))
	if err != nil {
		// The claim may have been taken although no reply came back. It is ours
		// alone to drop, and nobody else should have to wait out its expiry.
		cleanup, cancel := detached(ctx)
		defer cancel()
		m.releaseClaim(cleanup, h, owner)
		return nil, fmt.Errorf("failed to claim refresh token: %w", err)
	}
	reply, ok := res.([]interface{})
	if !ok || len(reply) != 3 {
		return nil, fmt.Errorf("unexpected claim reply %v", res)
	}
	status, ok1 := reply[0].(int64)
	raw, ok2 := reply[1].(string)
	fam, ok3 := reply[2].(string)
	if !ok1 || !ok2 || !ok3 {
		return nil, fmt.Errorf("unexpected claim reply %v", res)
	}
	switch status {
	case claimNotFound:
		return nil, ErrRefreshTokenNotFound
	case claimRevoked:
		return nil, ErrTokenRevoked
	case claimTaken:
		return nil, ErrRefreshInFlight
	case claimOK:
	default:
		return nil, fmt.Errorf("unexpected claim status %d", status)
	}

	data, err := m.decodeRefreshToken(raw)
	if err != nil {
		// A record we cannot read is not ours to consume; nothing was changed
		// but the claim.
		cleanup, cancel := detached(ctx)
		defer cancel()
		m.releaseClaim(cleanup, h, owner)
		return nil, err
	}
	return &RefreshClaim{Token: refreshToken, Owner: owner, FamilyID: fam, Data: data}, nil
}

// ReleaseRefreshClaim gives a claim up without publishing. It deletes the claim
// key only while the key still holds this attempt's id: an attempt whose claim
// expired, was taken over, or was cleared by a revocation cannot disturb
// whoever holds it now. The refresh record is untouched, so the token stays
// usable.
func (m *Manager) ReleaseRefreshClaim(ctx context.Context, claim *RefreshClaim) {
	m.releaseClaim(ctx, tokenHash(claim.Token), claim.Owner)
}

func (m *Manager) releaseClaim(ctx context.Context, tokenHash, owner string) {
	if _, err := m.redis.Run(ctx, releaseScript, []string{RefreshClaimPrefix + tokenHash}, owner); err != nil {
		m.logger.Warn("Failed to release refresh claim", "error", err)
	}
}

// PublishRotation stores the successor access and refresh tokens of a claimed
// refresh token and retires the old ones (the old refresh record, and the
// access token it was issued with), as one atomic step.
//
//   - ErrTokenRevoked: the token or its grant was revoked; nothing was written.
//   - ErrClaimLost: the claim expired, was cleared, or another attempt rotated
//     the token; nothing was written.
//   - ErrAlreadyExists: a successor id is taken; nothing was written.
//
// Publishing again as the same attempt with the same successors (a retry after
// a lost reply) succeeds without changing anything. The successors must carry
// the family of the claim.
func (m *Manager) PublishRotation(ctx context.Context, claim *RefreshClaim, at *AccessTokenData, rt *RefreshTokenData) error {
	call, err := m.preparePublish(claim, at, rt)
	if err != nil {
		return err
	}
	return m.publish(ctx, call)
}

func (m *Manager) preparePublish(claim *RefreshClaim, at *AccessTokenData, rt *RefreshTokenData) (*scriptCall, error) {
	if claim.FamilyID == "" || at.FamilyID != claim.FamilyID || rt.FamilyID != claim.FamilyID {
		return nil, errors.New("successor tokens must carry the family of the claim")
	}
	atData, atTTL, err := m.encodeAccessToken(at)
	if err != nil {
		return nil, err
	}
	rtData, err := m.encodeRefreshToken(rt)
	if err != nil {
		return nil, err
	}
	rtTTL := RefreshTTL * time.Second
	fam := claim.FamilyID
	h := tokenHash(claim.Token)
	newAT, newRT := tokenHash(at.AccessToken), tokenHash(rt.RefreshToken)
	keys := []string{
		RefreshClaimPrefix + h,
		RefreshPrefix + claim.Token,
		RevokedTokenPrefix + h,
		RevokedFamilyPrefix + fam,
		RotationPrefix + h,
		TokenPrefix + at.AccessToken,
		RefreshPrefix + rt.RefreshToken,
		FamilyPrefix + fam,
		TokenFamilyPrefix + newAT,
		TokenFamilyPrefix + newRT,
		TokenFamilyPrefix + h,
	}
	if old := claim.Data.AccessToken; old != "" {
		keys = append(keys, TokenPrefix+old, TokenFamilyPrefix+tokenHash(old))
	}
	return &scriptCall{
		script: publishScript,
		keys:   keys,
		args: []interface{}{
			claim.Owner, fam, atData, ms(atTTL), rtData, ms(rtTTL), at.AccessToken, rt.RefreshToken, newRT,
			claim.Owner + ":" + newAT + ":" + newRT, ms(RotationRecordTTL), ms(rtTTL), ms(max(atTTL, rtTTL)),
		},
	}, nil
}

func (m *Manager) publish(ctx context.Context, call *scriptCall) error {
	n, err := m.run(ctx, call)
	if err != nil {
		return fmt.Errorf("failed to publish rotated tokens: %w", err)
	}
	switch n {
	case publishDone, publishReplayed:
		return nil
	case publishConflict:
		return ErrAlreadyExists
	case publishRevoked:
		return ErrTokenRevoked
	case publishLost:
		return ErrClaimLost
	}
	return fmt.Errorf("unexpected publish result %d", n)
}

// ===== Revocation =====

// RevokeOutcome says what a revocation found.
type RevokeOutcome int

const (
	// RevokedNothing: the token is not known (never issued, expired, or
	// revoked long enough ago that nothing remembers it). Nothing was written.
	RevokedNothing RevokeOutcome = iota
	// RevokedRefreshToken: a live refresh token, and its grant, was revoked.
	RevokedRefreshToken
	// RevokedAccessToken: a live access token, and its grant, was revoked.
	RevokedAccessToken
	// RevokedGrantByToken: the token was already rotated away, but it still led
	// to its grant, which was revoked.
	RevokedGrantByToken
	// RevokedAlready: the token was revoked before and nothing else was found.
	RevokedAlready
)

// RevokeToken revokes the grant of a refresh or access token in one atomic
// step, whatever refresh may be running on it. The grant is marked revoked, the
// token is tombstoned, and the grant's current refresh token, access token and
// claim are deleted; a refresh that is in flight can then publish nothing. The
// family is found from the token's record or, for a token that was rotated away
// already, from its index. A token without a family (issued before families
// existed) is revoked by itself, with the access token its refresh record
// names. A token nobody knows changes nothing and is reported as
// RevokedNothing; a backend failure is an error and leaves nothing half done:
// the call can be repeated.
func (m *Manager) RevokeToken(ctx context.Context, token string) (RevokeOutcome, error) {
	h := tokenHash(token)
	keys := []string{
		RefreshPrefix + token,
		TokenPrefix + token,
		RevokedTokenPrefix + h,
		RefreshClaimPrefix + h,
		TokenFamilyPrefix + h,
	}
	n, err := scriptInt(m.redis.Run(ctx, revokeTokenScript, keys, ms(RevokedTokenTTL), ms(RevokedFamilyTTL)))
	if err != nil {
		return RevokedNothing, fmt.Errorf("failed to revoke token: %w", err)
	}
	switch n {
	case revokeNothing:
		return RevokedNothing, nil
	case revokeRefresh:
		return RevokedRefreshToken, nil
	case revokeAccess:
		return RevokedAccessToken, nil
	case revokeByIndex:
		return RevokedGrantByToken, nil
	case revokeRepeated:
		return RevokedAlready, nil
	}
	return RevokedNothing, fmt.Errorf("unexpected revoke result %d", n)
}

// RevokeFamily revokes a grant by its id: it is marked revoked and its current
// refresh token, access token and claim are deleted, in one atomic step.
func (m *Manager) RevokeFamily(ctx context.Context, familyID string) error {
	if familyID == "" {
		return nil
	}
	keys := []string{RevokedFamilyPrefix + familyID, FamilyPrefix + familyID}
	if _, err := scriptInt(m.redis.Run(ctx, revokeFamilyScript, keys, familyID, ms(RevokedFamilyTTL))); err != nil {
		return fmt.Errorf("failed to revoke token family: %w", err)
	}
	return nil
}

// RevokeAccessToken revokes the grant of an access token; see RevokeToken.
func (m *Manager) RevokeAccessToken(ctx context.Context, accessToken string) error {
	_, err := m.RevokeToken(ctx, accessToken)
	return err
}

// RevokeRefreshToken revokes the grant of a refresh token; see RevokeToken.
func (m *Manager) RevokeRefreshToken(ctx context.Context, refreshToken string) error {
	_, err := m.RevokeToken(ctx, refreshToken)
	return err
}
