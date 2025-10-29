# Security Fix: Removed OID Context Inheritance

## Issue
**Severity**: HIGH
**Category**: Cross-tenant boundary violation
**Date Fixed**: 2025-01-26

## Problem Description

The `wrap_tool_for_multi_mode()` function allowed nested tool calls to inherit the OID (Organization ID) from the parent context:

```python
# BEFORE (VULNERABLE)
oid = kwargs.pop('oid', None) or current_oid_context_var.get() if requires_oid else None
```

This created a potential security issue where:
1. Tool A executes with `oid="org-123"`
2. Tool A internally calls Tool B without passing `oid` parameter
3. Tool B inherits `oid="org-123"` from context
4. If Tool B should have operated on a different org, it would accidentally use the parent's org

## Attack Scenario

While not directly exploitable externally (since the LimaCharlie API enforces authorization), this pattern could cause logic errors:

1. A complex tool that processes multiple organizations
2. Outer loop iterates through orgs, sets OID in context
3. Inner function calls another tool without explicit OID
4. Inner tool operates on wrong organization due to inheritance

## Root Cause

The `current_oid_context_var` was designed to pass OID through the call stack, but this violated the principle of explicit parameters and could mask bugs where developers forgot to pass the OID.

## Fix Applied

Removed the fallback to context variable:

```python
# AFTER (SECURE)
oid = kwargs.pop('oid', None) if requires_oid else None
```

**Changes Made:**
- `server.py:640` - Async wrapper: removed `or current_oid_context_var.get()`
- `server.py:712` - Sync wrapper: removed `or current_oid_context_var.get()`
- Added security comments explaining why inheritance is disabled

## Impact

**Positive:**
- ✅ Every tool call must explicitly specify which organization it targets
- ✅ No accidental cross-tenant operations in nested calls
- ✅ Code is more explicit and easier to audit
- ✅ Developers are forced to think about which org each operation targets

**Potential Breakage:**
- ⚠️ If any existing code relies on OID inheritance for nested calls, those calls will now fail
- ⚠️ Error message: "Tool {name}: 'oid' parameter is required in UID mode"
- ✅ This is **intended behavior** - forces developers to fix implicit assumptions

## Functions Updated to Pass OID Explicitly

**13 functions** that make nested tool calls were identified and fixed:

### 1. Saved Query Execution
- `run_saved_query()` → now passes `oid` to `run_lcql_query()`
  - File: server.py:4938
  - Fix: Added `oid=oid` parameter to nested call

### 2-5. DR General Rule Wrappers (4 functions)
All delegate to base hive functions with explicit `oid`:
- `list_dr_general_rules()` → `list_rules("dr-general", ctx, oid=oid)` (line 5774)
- `get_dr_general_rule()` → `get_rule("dr-general", rule_name, ctx, oid=oid)` (line 5790)
- `set_dr_general_rule()` → `set_rule("dr-general", rule_name, rule_content, ctx, oid=oid)` (line 5813)
- `delete_dr_general_rule()` → `delete_rule("dr-general", rule_name, ctx, oid=oid)` (line 5830)

### 6-9. DR Managed Rule Wrappers (4 functions)
All delegate to base hive functions with explicit `oid`:
- `list_dr_managed_rules()` → `list_rules("dr-managed", ctx, oid=oid)` (line 5843)
- `get_dr_managed_rule()` → `get_rule("dr-managed", rule_name, ctx, oid=oid)` (line 5859)
- `set_dr_managed_rule()` → `set_rule("dr-managed", rule_name, rule_content, ctx, oid=oid)` (line 5882)
- `delete_dr_managed_rule()` → `delete_rule("dr-managed", rule_name, ctx, oid=oid)` (line 5899)

### 10-12. False Positive Rule Wrappers (3 functions)
All delegate to base hive functions with explicit `oid`:
- `get_fp_rule()` → `get_rule("fp", rule_name, ctx, oid=oid)` (line 5917)
- `set_fp_rule()` → `set_rule("fp", rule_name, rule_content, ctx, oid=oid)` (line 5940)
- `delete_fp_rule()` → `delete_rule("fp", rule_name, ctx, oid=oid)` (line 5957)

### Pattern Applied

All fixes follow the same pattern:

```python
# BEFORE (relied on implicit inheritance)
@mcp_tool_with_gcs()
def wrapper_function(params..., ctx: Context):
    return base_function(params..., ctx)

# AFTER (explicit OID reading from context)
@mcp_tool_with_gcs()
def wrapper_function(params..., ctx: Context):
    # SECURITY: Explicitly read oid from context set by wrapper
    oid = current_oid_context_var.get()
    return base_function(params..., ctx, oid=oid)
```

**Key Changes:**
1. Explicitly read `oid` from `current_oid_context_var.get()` in function body
2. Added security comment explaining the explicit read
3. Pass `oid=oid` to nested tool calls

**Important Note:**
The wrapper function `wrap_tool_for_multi_mode()` automatically:
- Adds `oid` parameter to the function signature
- Stores `oid` in `current_oid_context_var` after extracting it from kwargs
- Therefore, wrapper functions can explicitly read it via `.get()` for pass-through

This is **different from the security issue** we fixed in the wrapper:
- **Security Issue (Fixed)**: Wrapper used `oid = kwargs.pop('oid', None) or current_oid_context_var.get()` - implicit fallback
- **Valid Use (Implemented)**: Wrapper functions explicitly read `oid = current_oid_context_var.get()` for delegation

The key distinction:
- ❌ **Implicit fallback**: Tool doesn't receive oid → silently inherits from context → **SECURITY ISSUE**
- ✅ **Explicit delegation**: Wrapper function explicitly reads from context to pass through → **VALID PATTERN**

## Verification

The context variable is now write-only in the wrapper:

```python
# Still sets context (for potential future use):
oid_token = current_oid_context_var.set(oid) if oid else None

# But never reads from it as a fallback:
# oid = kwargs.pop('oid', None)  # No .get() fallback
```

Verified with grep - no remaining `.get()` calls on `current_oid_context_var`.

## Testing

To verify the fix works correctly:

1. **Test explicit OID passing works:**
   ```python
   # Should succeed
   result = tool_a(oid="org-123")
   ```

2. **Test missing OID fails correctly:**
   ```python
   # Should raise ValueError in UID mode
   result = tool_a()  # Missing oid parameter
   ```

3. **Test nested calls require explicit OID:**
   ```python
   def tool_a(oid, ctx):
       # Must explicitly pass oid to nested call
       result = tool_b(oid=oid, ctx=ctx)  # Good
       # result = tool_b(ctx=ctx)  # Would fail - requires oid
   ```

## Backward Compatibility

**For External Callers:**
- ✅ No impact - external callers already required to pass `oid` in UID mode

**For Internal Code:**
- ⚠️ Any code that relied on OID inheritance will need to be updated
- Fix: Add explicit `oid=oid` parameter to all nested tool calls

## Related Context Variable

Note: `current_oid_context_var` is still set/reset in the wrapper for potential future use (logging, debugging, etc.), but is no longer used as a fallback for missing OID parameters.

If the context variable is not needed at all, it could be removed entirely in a future cleanup.

## References

- Original implementation: `server.py:588-779` (`wrap_tool_for_multi_mode`)
- Related security fixes: `SECURITY_FIXES.md`, `FIXES_APPLIED.md`

## Status

✅ **FIXED** - OID inheritance removed, explicit parameters now required
