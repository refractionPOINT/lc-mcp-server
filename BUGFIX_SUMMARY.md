# Bug Fix Summary: UID Mode OID Handling and HiveRecord Serialization

## Issues Fixed

### Issue 1: "oid parameter is required in UID mode" Error on Nested Calls
**Error Message:**
```
Error executing tool get_rule: 'oid' parameter is required in UID mode.
Please specify the organization ID for this operation.
```

**Root Cause:**
When wrapper functions (like `get_dr_general_rule`, `get_dr_managed_rule`, etc.) called base functions (like `get_rule`), they didn't pass through the `oid` parameter. In UID mode, the multi-mode wrapper validates that an `oid` is provided, causing nested calls to fail.

**Example Flow:**
1. User calls `get_dr_general_rule(rule_name="X", oid="OID-1")`
2. Wrapper extracts and validates `oid="OID-1"`, creates SDK
3. Wrapper calls actual `get_dr_general_rule(rule_name="X")` (no oid)
4. Function calls `get_rule("dr-general", "X", ctx)` (no oid)
5. Inner wrapper checks for oid, finds None, raises error ❌

### Issue 2: "Object of type HiveRecord is not JSON serializable"
**Error Message:**
```
Error executing tool get_rule: Object of type HiveRecord is not JSON serializable
```

**Root Cause:**
The `get_rule` function returned the raw `HiveRecord` object from `hive.get()` instead of calling `.toJSON()` to convert it to a serializable dictionary.

**Code:**
```python
rule = hive.get(rule_name)
return {"rule": rule if rule else {}}  # ❌ HiveRecord not serializable
```

## Solutions Implemented

### Solution 1: OID Context Variable for Nested Calls

**Changes Made:**

1. **Added new context variable** (server.py:171-173):
   ```python
   current_oid_context_var = contextvars.ContextVar[str | None](
       "current_oid", default=None  # Stores the current OID for nested calls in UID mode
   )
   ```

2. **Modified async wrapper** (server.py:564-605):
   - Line 565: Changed `oid = kwargs.pop('oid', None)` to `oid = kwargs.pop('oid', None) or current_oid_context_var.get()`
   - Line 593: Store OID in context: `oid_token = current_oid_context_var.set(oid)`
   - Line 605: Reset OID context: `current_oid_context_var.reset(oid_token)`

3. **Modified sync wrapper** (server.py:622-663):
   - Same changes as async wrapper for synchronous functions

**How It Works:**
- When a wrapped function is called with an OID, it stores the OID in a context variable
- Nested wrapped functions inherit the OID from context automatically
- Context variables are request-scoped, so interleaved requests with different OIDs remain isolated
- Each request maintains its own OID throughout all nested calls

**Example Flow (Fixed):**
1. User calls `get_dr_general_rule(rule_name="X", oid="OID-1")`
2. Wrapper extracts `oid="OID-1"`, creates SDK
3. Wrapper stores OID in context: `current_oid_context_var.set("OID-1")`
4. Wrapper calls actual `get_dr_general_rule(rule_name="X")`
5. Function calls `get_rule("dr-general", "X", ctx)` (no oid param)
6. Inner wrapper: `oid = None or current_oid_context_var.get()` → "OID-1" ✓
7. Inner wrapper uses existing SDK, succeeds ✓

### Solution 2: HiveRecord Serialization

**Changes Made:**

Modified `get_rule` function (server.py:3441):
```python
# Before:
return {"rule": rule if rule else {}}

# After:
return {"rule": rule.toJSON() if rule else {}}
```

**How It Works:**
- `hive.get()` returns a `HiveRecord` object
- `.toJSON()` method converts it to a plain dictionary
- Dictionary is JSON serializable and can be returned via MCP

## Testing

### Existing Tests
All 23 existing UID mode tests continue to pass:
```bash
python3 -m pytest test_uid_mode.py -v
# Result: 23 passed
```

### New Tests
Created `test_nested_oid_calls.py` to verify fixes:

1. **Test Nested Calls with OID Context**
   - Verifies nested wrapped calls inherit OID from context
   - Confirms no "oid required" error when OID is in context
   - Status: ✓ PASSED

2. **Test HiveRecord Serialization**
   - Verifies `get_rule()` calls `rule.toJSON()`
   - Confirms HiveRecord objects are properly serialized
   - Status: ✓ PASSED

## Files Modified

1. **server.py**
   - Lines 171-173: Added `current_oid_context_var`
   - Lines 564-605: Updated async wrapper in `wrap_tool_for_multi_mode`
   - Lines 622-663: Updated sync wrapper in `wrap_tool_for_multi_mode`
   - Line 3441: Fixed `get_rule` to call `.toJSON()`

## Backward Compatibility

✓ All changes are backward compatible:
- Normal mode (non-UID) operation unchanged
- Existing function signatures unchanged
- Only behavior: nested calls now work in UID mode
- Only improvement: HiveRecord objects are now serializable

## Impact on Interleaved OID Calls

The solution correctly handles interleaved requests with different OIDs:

**Scenario:** Two concurrent requests with different OIDs
```
Request A (OID-1) starts → stores OID-1 in context A
Request B (OID-2) starts → stores OID-2 in context B (separate)
Request A continues with nested calls → uses OID-1 from context A
Request B continues with nested calls → uses OID-2 from context B
No interference between requests ✓
```

**Why it works:** Python's `contextvars` are request-scoped (isolated per async task), ensuring each request maintains its own OID context even when requests are interleaved.

## Verification

To verify the fixes are working:

```bash
# Run all UID mode tests
python3 -m pytest test_uid_mode.py -v

# Run new nested call tests
python3 test_nested_oid_calls.py

# Check Python syntax
python3 -m py_compile server.py
```

All tests should pass with these fixes in place.
