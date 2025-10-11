from starlette.exceptions import HTTPException
from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.server import Context
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, RedirectResponse
from typing import Any
import limacharlie
import limacharlie.Replay
import json
import uuid
import time
from google import genai
from google.genai import types
import os
import pathlib
import traceback
import yaml
import asyncio
from concurrent.futures import ThreadPoolExecutor
import atexit
import logging
import sys
import contextvars
import contextlib
from starlette.types import ASGIApp, Receive, Scope, Send
import shlex
from datetime import datetime, timedelta
import functools
import tempfile

# Try to import GCS libraries if available
try:
    from google.cloud import storage
    import google.auth
    from google.auth.transport.requests import Request as AuthRequest
    GCS_AVAILABLE = True
except ImportError:
    GCS_AVAILABLE = False
    storage = None
    google = None
    AuthRequest = None

# Create a dedicated thread pool for SDK calls with more threads
# This prevents thread pool exhaustion when handling concurrent requests
SDK_THREAD_POOL = ThreadPoolExecutor(max_workers=100, thread_name_prefix="sdk-worker")

# Create contextvars to store the current HTTP request and SDK
request_context_var = contextvars.ContextVar[Request | None](
    "http_request", default=None
)
sdk_context_var = contextvars.ContextVar[limacharlie.Manager | None](
    "lc_sdk", default=None
)

# Global registry for all tool functions (before registration)
# Maps tool_name -> (func, is_async)
TOOL_REGISTRY: dict[str, tuple[Any, bool]] = {}

# Main MCP instance will be created after tool registration based on profile
mcp = None

# GCS Configuration
GCS_BUCKET_NAME = os.getenv("GCS_BUCKET_NAME")  # No default - use temp files if not set
GCS_URL_EXPIRY_HOURS = int(os.getenv("GCS_URL_EXPIRY_HOURS", "24"))  # Default: 24 hours
GCS_TOKEN_THRESHOLD = int(os.getenv("GCS_TOKEN_THRESHOLD", "1000"))  # Default: 1000 tokens
GCS_SIGNER_SERVICE_ACCOUNT = os.getenv("GCS_SIGNER_SERVICE_ACCOUNT", "mcp-server@lc-api.iam.gserviceaccount.com")
# PUBLIC_MODE determines whether to use HTTP header auth (true) or local SDK auth (false)
PUBLIC_MODE = os.getenv("PUBLIC_MODE", "false").lower() == "true"
# Profile selection for filtering tools (default: "all" for backward compatibility)
MCP_PROFILE = os.getenv("MCP_PROFILE", "all").lower()
# LLM retry configuration
LLM_YAML_RETRY_COUNT = int(os.getenv("LLM_YAML_RETRY_COUNT", "10"))  # Default: 10 retries for YAML parsing

# Profile Definitions - maps profile names to sets of tool names
# "core" tools are included in all profiles
PROFILES = {
    "core": {
        "test_tool",
        "get_sensor_info",
        "list_sensors",
        "get_online_sensors",
        "is_online",
        "search_hosts",
    },
    "historical_data": {
        # Historical telemetry and analysis
        "get_historic_events",
        "get_historic_detections",
        "get_time_when_sensor_has_data",
        # LCQL queries
        "run_lcql_query",
        "list_saved_queries",
        "get_saved_query",
        "run_saved_query",
        "set_saved_query",
        "delete_saved_query",
        # Artifacts
        "list_artifacts",
        "get_artifact",
        # IOC search
        "search_iocs",
        "batch_search_iocs",
        # Event schemas
        "get_event_schema",
        "get_event_schemas_batch",
        "get_event_types_with_schemas",
        "get_event_types_with_schemas_for_platform",
        # Platform info
        "get_platform_names",
        "list_with_platform",
    },
    "live_investigation": {
        # Process inspection
        "get_processes",
        "get_process_modules",
        "get_process_strings",
        "find_strings",
        # System information
        "get_packages",
        "get_services",
        "get_autoruns",
        "get_drivers",
        "get_users",
        "get_network_connections",
        "get_os_version",
        "get_registry_keys",
        # YARA scanning
        "yara_scan_process",
        "yara_scan_file",
        "yara_scan_directory",
        "yara_scan_memory",
        # Status and tasking
        "is_isolated",
        "reliable_tasking",
        "list_reliable_tasks",
    },
    "threat_response": {
        # Network isolation
        "isolate_network",
        "rejoin_network",
        "is_isolated",
        # Sensor management
        "add_tag",
        "remove_tag",
        "delete_sensor",
        # Reliable tasking for response actions
        "reliable_tasking",
        "list_reliable_tasks",
    },
    "fleet_management": {
        # Sensor management
        "delete_sensor",
        "add_tag",
        "remove_tag",
        # Platform information
        "list_with_platform",
        "get_platform_names",
        # Installation keys
        "list_installation_keys",
        "create_installation_key",
        "delete_installation_key",
        # Cloud sensors
        "list_cloud_sensors",
        "get_cloud_sensor",
        "set_cloud_sensor",
        "delete_cloud_sensor",
    },
    "detection_engineering": {
        # Detection rules
        "get_detection_rules",
        "get_historic_detections",
        # D&R general rules
        "list_dr_general_rules",
        "get_dr_general_rule",
        "set_dr_general_rule",
        "delete_dr_general_rule",
        # D&R managed rules
        "list_dr_managed_rules",
        "get_dr_managed_rule",
        "set_dr_managed_rule",
        "delete_dr_managed_rule",
        # False positive rules
        "get_fp_rules",
        "get_fp_rule",
        "set_fp_rule",
        "delete_fp_rule",
        # YARA rules
        "list_yara_rules",
        "get_yara_rule",
        "set_yara_rule",
        "delete_yara_rule",
        "validate_yara_rule",
        # MITRE ATT&CK
        "get_mitre_report",
        # Event schemas for rule development
        "get_event_schema",
        "get_event_schemas_batch",
    },
    "ai_powered": {
        # AI-powered generation tools
        "generate_lcql_query",
        "generate_dr_rule_detection",
        "generate_dr_rule_respond",
        "generate_sensor_selector",
        "generate_python_playbook",
        "generate_detection_summary",
    },
    "platform_admin": {
        # Outputs
        "list_outputs",
        "add_output",
        "delete_output",
        # Lookups
        "list_lookups",
        "get_lookup",
        "set_lookup",
        "delete_lookup",
        "query_lookup",
        # Secrets
        "list_secrets",
        "get_secret",
        "set_secret",
        "delete_secret",
        # Playbooks
        "list_playbooks",
        "get_playbook",
        "set_playbook",
        "delete_playbook",
        # External adapters
        "list_external_adapters",
        "get_external_adapter",
        "set_external_adapter",
        "delete_external_adapter",
        # Extensions
        "list_extension_configs",
        "get_extension_config",
        "set_extension_config",
        "delete_extension_config",
        # Hive rules
        "list_rules",
        "get_rule",
        "set_rule",
        "delete_rule",
        # Saved queries
        "list_saved_queries",
        "get_saved_query",
        "set_saved_query",
        "delete_saved_query",
        # API keys
        "list_api_keys",
        "create_api_key",
        "delete_api_key",
        # Organization
        "get_org_info",
        "get_usage_stats",
    },
}

def get_profile_tools(profile_name: str) -> set[str]:
    """
    Get the set of tool names for a given profile.
    All profiles include core tools. 'all' profile includes everything.
    """
    if profile_name == "all":
        # Return all tools from all profiles
        all_tools = set(PROFILES["core"])
        for tools in PROFILES.values():
            all_tools.update(tools)
        return all_tools

    if profile_name not in PROFILES:
        raise ValueError(f"Unknown profile: {profile_name}. Available profiles: {list(PROFILES.keys()) + ['all']}")

    # Return core tools + profile-specific tools
    return PROFILES["core"] | PROFILES[profile_name]

def estimate_token_count(data: Any) -> int:
    """Estimate token count from JSON data (roughly 4 chars per token)."""
    json_str = json.dumps(data)
    return len(json_str) // 4

def upload_to_gcs(data: dict[str, Any], tool_name: str) -> tuple[str, int]:
    """
    Upload JSON data to GCS or save to temp file and return URL/path and file size.
    
    Args:
        data: The data to upload
        tool_name: Name of the tool that generated this data
        
    Returns:
        Tuple of (signed_url_or_path, file_size_bytes)
    """
    # Convert data to JSON
    json_data = json.dumps(data, indent=2)
    json_bytes = json_data.encode('utf-8')
    
    # Create a unique filename
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    unique_id = str(uuid.uuid4())[:8]
    filename = f"{tool_name}_{timestamp}_{unique_id}.json"
    
    # If GCS_BUCKET_NAME is not defined, use local temp file
    if not GCS_BUCKET_NAME:
        try:
            # Create a temporary file that won't be auto-deleted
            with tempfile.NamedTemporaryFile(mode='w', suffix=f'_{filename}', 
                                            delete=False, encoding='utf-8') as temp_file:
                temp_file.write(json_data)
                temp_path = temp_file.name
            
            logging.info(f"Saved large result to temp file: {temp_path}")
            return temp_path, len(json_bytes)
            
        except Exception as e:
            logging.info(f"Error saving to temp file: {e}")
            raise
    
    # Use GCS if bucket name is defined
    if not GCS_AVAILABLE:
        raise RuntimeError("GCS_BUCKET_NAME is set but Google Cloud Storage libraries are not available")
    
    try:
        # Get default credentials from Cloud Run
        creds, _ = google.auth.default()
        
        # Refresh credentials to get access token
        auth_request = AuthRequest()
        creds.refresh(auth_request)
        
        # Initialize GCS client with credentials
        client = storage.Client(credentials=creds)
        bucket = client.bucket(GCS_BUCKET_NAME)
        blob = bucket.blob(filename)
        
        # Upload to GCS
        blob.upload_from_string(json_bytes, content_type='application/json')
        
        # Generate signed URL using access token
        expiry_time = datetime.utcnow() + timedelta(hours=GCS_URL_EXPIRY_HOURS)
        signed_url = blob.generate_signed_url(
            version="v4",
            expiration=expiry_time,
            method="GET",
            service_account_email=GCS_SIGNER_SERVICE_ACCOUNT,  # Specify the service account
            access_token=creds.token  # Use access token for signing
        )
        
        logging.info(f"Uploaded large result to GCS: {filename}")
        return signed_url, len(json_bytes)
        
    except Exception as e:
        logging.info(f"Error uploading to GCS: {e}")
        raise

def mcp_tool_with_gcs():
    """
    Decorator that wraps MCP tools to handle large results via GCS.
    Instead of immediately registering with an MCP instance, this stores
    the tool in TOOL_REGISTRY for later registration based on profile.
    """
    def decorator(func):
        tool_name = func.__name__
        is_async = asyncio.iscoroutinefunction(func)

        # Create wrapper for synchronous functions
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Execute the original function
            result = func(*args, **kwargs)

            # Estimate token count
            token_count = estimate_token_count(result)

            # Log token count and decision
            if token_count > GCS_TOKEN_THRESHOLD:
                logging.info(f"Tool {tool_name}: {token_count} tokens detected (threshold: {GCS_TOKEN_THRESHOLD}), uploading to GCS")
            else:
                logging.info(f"Tool {tool_name}: {token_count} tokens detected (threshold: {GCS_TOKEN_THRESHOLD}), returning inline")

            # If result is large (>threshold tokens), upload to GCS
            if token_count > GCS_TOKEN_THRESHOLD:
                try:
                    signed_url, file_size = upload_to_gcs(result, tool_name)

                    # Return alternate response
                    return {
                        "resource_link": signed_url,
                        "resource_size": file_size,
                        "success": True,
                        "reason": "results too large, see resource_link for content"
                    }
                except Exception as e:
                    logging.info(f"Failed to upload large result to GCS: {e}")
                    # Fall back to returning original result
                    return result

            # Return original result if small enough
            return result

        # Create wrapper for asynchronous functions
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            # Execute the original async function
            result = await func(*args, **kwargs)

            # Estimate token count
            token_count = estimate_token_count(result)

            # Log token count and decision
            if token_count > GCS_TOKEN_THRESHOLD:
                logging.info(f"Tool {tool_name}: {token_count} tokens detected (threshold: {GCS_TOKEN_THRESHOLD}), uploading to GCS")
            else:
                logging.info(f"Tool {tool_name}: {token_count} tokens detected (threshold: {GCS_TOKEN_THRESHOLD}), returning inline")

            # If result is large (>threshold tokens), upload to GCS
            if token_count > GCS_TOKEN_THRESHOLD:
                try:
                    # Run GCS upload in thread pool to avoid blocking
                    loop = asyncio.get_event_loop()
                    signed_url, file_size = await loop.run_in_executor(
                        SDK_THREAD_POOL, upload_to_gcs, result, tool_name
                    )

                    # Return alternate response
                    return {
                        "resource_link": signed_url,
                        "resource_size": file_size,
                        "success": True,
                        "reason": "results too large, see resource_link for content"
                    }
                except Exception as e:
                    logging.info(f"Failed to upload large result to GCS: {e}")
                    # Fall back to returning original result
                    return result

            # Return original result if small enough
            return result

        # Choose appropriate wrapper based on whether function is async
        if is_async:
            gcs_wrapped = async_wrapper
        else:
            gcs_wrapped = wrapper

        # Store in registry instead of immediately registering
        TOOL_REGISTRY[tool_name] = (gcs_wrapped, is_async)

        # Return the wrapped function (not registered yet)
        return gcs_wrapped

    return decorator

def create_mcp_for_profile(profile_name: str) -> FastMCP:
    """
    Create a FastMCP instance with tools registered for the specified profile.

    Args:
        profile_name: Name of the profile (e.g., 'historical_data', 'all')

    Returns:
        FastMCP instance with registered tools for the profile
    """
    # Create a new MCP instance
    profile_mcp = FastMCP(
        f"LC Server - {profile_name.replace('_', ' ').title()}",
        json_response=True,
        stateless_http=True
    )

    # Get tools for this profile
    profile_tools = get_profile_tools(profile_name)

    # Register tools from registry
    registered_count = 0
    for tool_name in profile_tools:
        if tool_name in TOOL_REGISTRY:
            tool_func, _ = TOOL_REGISTRY[tool_name]
            # Register with MCP
            profile_mcp.tool()(tool_func)
            registered_count += 1
        else:
            logging.warning(f"Tool {tool_name} in profile {profile_name} not found in registry")

    logging.info(f"Created MCP instance for profile '{profile_name}' with {registered_count} tools")

    # Mount MCP endpoint at root of profile path instead of /mcp
    # This allows /historical_data/ to work instead of /historical_data/mcp
    profile_mcp.settings.streamable_http_path = "/"

    return profile_mcp

# Test tool to verify MCP is working
@mcp_tool_with_gcs()
def test_tool(ctx: Context) -> dict[str, Any]:
    """Test tool to verify MCP server is working"""
    # Check if we can get SDK from context
    sdk = get_sdk_from_context(ctx)
    return {
        "status": "success", 
        "message": "MCP server is working!",
        "auth_available": sdk is not None,
        "has_sdk": sdk is not None,
        "request_id": ctx.request_id if hasattr(ctx, 'request_id') else None
    }

# Dependency: Extract Bearer token from the request
async def get_auth_info(request: Request) -> tuple[str | None, str | None, str | None]:
    # In non-public mode, return None to indicate no auth from headers
    if not PUBLIC_MODE:
        return None, None, None
    
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")

    # There are three flavors of the token determined by the UUID format
    # # of the oid and api_key:
    # 1. Just a JWT, the OID is in x-lc-oid
    # 2. A jwt:oid
    # 3. A api_key:oid
    auth_header = auth_header.removeprefix("Bearer ").strip()

    if ':' not in auth_header:
        # Case 1
        oid = request.headers.get("x-lc-oid")
        if not oid:
            raise HTTPException(status_code=401, detail=f"oid missing or invalid: {oid}")
        return auth_header, None, oid

    auth, oid = auth_header.split(':', 1)

    # Check if the auth is a UUID, if it is, then it's an api_key.
    try:
        uuid.UUID(auth)
        # Case 3
        return None, auth, oid
    except Exception:
        # Case 2
        return auth, None, oid

def make_sdk(oid: str | None = None, token: str | None = None, api_key: str | None = None) -> limacharlie.Manager:
    if PUBLIC_MODE:
        # In public mode, use the provided credentials
        if not oid:
            raise ValueError("OID is required in PUBLIC_MODE")
        logging.info(f"Making SDK for {time.time()} {oid}")
        return limacharlie.Manager(oid, jwt=token, secret_api_key=api_key)
    else:
        # In local mode, use default authentication from environment/config
        logging.info(f"Making SDK with local authentication")
        return limacharlie.Manager()

# Helper to get SDK from context headers
def get_sdk_from_context(ctx: Context) -> limacharlie.Manager | None:
    """Extract auth info from context and create SDK."""
    try:
        # Check if SDK already exists in context
        sdk = sdk_context_var.get()
        if sdk:
            return sdk
        
        if PUBLIC_MODE:
            # Get the HTTP request from the contextvar
            request = request_context_var.get()
            
            if not request:
                return None
            
            # Now try to get headers
            auth_header = request.headers.get("authorization")
            
            if not auth_header or not auth_header.startswith("Bearer "):
                return None
                
            auth_header = auth_header.removeprefix("Bearer ").strip()
            
            # Parse the auth header (same logic as get_auth_info)
            if ':' not in auth_header:
                oid = request.headers.get("x-lc-oid")
                if not oid:
                    return None
                sdk = make_sdk(oid, token=auth_header)
            else:
                auth, oid = auth_header.split(':', 1)
                
                try:
                    uuid.UUID(auth)
                    # It's an API key
                    sdk = make_sdk(oid, api_key=auth)
                except Exception:
                    # It's a JWT
                    sdk = make_sdk(oid, token=auth)
        else:
            # In local mode, create SDK with default auth
            sdk = make_sdk()
        
        # Store SDK in contextvar for this request
        if sdk:
            sdk_context_var.set(sdk)
        
        return sdk
    except Exception as e:
        logging.info(f"Error getting SDK from context: {e}")
        import traceback
        traceback.print_exc()
        return None

# These functions are no longer needed as we're using get_sdk_from_context instead

class RequestContextMiddleware:
    """Middleware that stores the HTTP request in a contextvar."""
    
    def __init__(self, app: ASGIApp):
        self.app = app
    
    async def __call__(self, scope: Scope, receive: Receive, send: Send):
        if scope["type"] == "http":
            request = Request(scope, receive)
            request_token = request_context_var.set(request)
            sdk_token = sdk_context_var.set(None)  # Reset SDK for each request
            try:
                await self.app(scope, receive, send)
            finally:
                # Clean up SDK if one was created
                sdk = sdk_context_var.get()
                if sdk:
                    try:
                        sdk.shutdown()
                    except Exception:
                        pass  # Ignore cleanup errors
                
                # Reset contextvars
                request_context_var.reset(request_token)
                sdk_context_var.reset(sdk_token)
        else:
            await self.app(scope, receive, send)

def safe_simple_request(sensor: limacharlie.Sensor, cmd: str) -> Any:
    try:
        ret = sensor.simpleRequest(cmd)
        if ret is None:
            return {"error": "timeout waiting for sensor response"}
        return ret
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}

def execute_sensor_command(ctx: Context, sid: str, cmd: str) -> dict[str, Any]:
    """Helper function to execute a sensor command with proper SDK setup."""
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        
        # Make SDK interactive
        if not sdk._inv_id:
            sdk._inv_id = f"mcp-{uuid.uuid4()}"
        sdk.make_interactive()
        
        # Get sensor and execute command
        sensor = sdk.sensor(sid)
        return safe_simple_request(sensor, cmd)
    except Exception as e:
        import traceback
        logging.info(f"Tool error: {traceback.format_exc()}")
        return {"error": f"Error issuing sensor request: {e}"}


# Middleware is no longer needed - authentication is handled via context in tools

# Sensor-related tools
@mcp_tool_with_gcs()
def get_processes(sid: str, ctx: Context) -> dict[str, Any]:
    """Get the processes for a given Sensor ID

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the process information.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_processes(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_processes --is-no-modules")
    finally:
        logging.info(f"get_processes time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_historic_events(sid: str, start_time: int, end_time: int, ctx: Context) -> dict[str, Any]:
    """Get historic events for a given Sensor ID between timestamps

    Args:
        sid (uuid str): The Sensor ID to query
        start_time (int): Start timestamp in Unix second epoch format, maximum range of 1 minute
        end_time (int): End timestamp in Unix second epoch format, maximum range of 1 minute

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "events" (list[dict[str, Any]]): On success, a list of historic events.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_historic_events(sid={json.dumps(sid)}, start_time={start_time}, end_time={end_time})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        
        sensor = sdk.sensor(sid)
        return {"events": [e for e in sensor.getHistoricEvents(start_time, end_time)]}
    except Exception as e:
        return {"error": f"Error getting historic events: {e}"}
    finally:
        logging.info(f"get_historic_events time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_process_modules(sid: str, pid: int, ctx: Context) -> dict[str, Any]:
    """Get modules for a specific process

    Args:
        sid (uuid str): The Sensor ID to query
        pid (int): The Process ID to get modules for

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the process modules.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_process_modules(sid={json.dumps(sid)}, pid={pid})")
    try:
        return execute_sensor_command(ctx, sid, f"os_processes --pid {pid}")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_process_modules time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_process_strings(sid: str, pid: int, ctx: Context) -> dict[str, Any]:
    """Get strings from a process memory

    Args:
        sid (uuid str): The Sensor ID to query
        pid (int): The Process ID to get strings from

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the process strings.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_process_strings(sid={json.dumps(sid)}, pid={pid})")
    try:
        return execute_sensor_command(ctx, sid, f"mem_strings --pid {pid}")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_process_strings time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def find_strings(sid: str, strings: list[str], pid: int = None, ctx: Context = None) -> dict[str, Any]:
    """Find strings in process memory

    Args:
        sid (uuid str): The Sensor ID to query
        strings (list[str]): List of strings to search for
        pid (int): The Process ID to search in (optional)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the found strings.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: find_strings(sid={json.dumps(sid)}, strings={json.dumps(strings)}, pid={pid})")
    try:
        cmd = "mem_find_string"
        if pid:
            cmd += f" --pid {pid}"
        for s in strings:
            cmd += f" --string {shlex.quote(s)}"
        return execute_sensor_command(ctx, sid, cmd)
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"find_strings time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_packages(sid: str, ctx: Context) -> dict[str, Any]:
    """Get installed packages

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the installed packages.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_packages(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_packages")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_packages time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_services(sid: str, ctx: Context) -> dict[str, Any]:
    """Get running services

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the running services.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_services(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_services")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_services time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_autoruns(sid: str, ctx: Context) -> dict[str, Any]:
    """Get autorun entries

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the autorun entries.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_autoruns(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_autoruns")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_autoruns time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_drivers(sid: str, ctx: Context) -> dict[str, Any]:
    """Get installed drivers

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the installed drivers.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_drivers(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_drivers")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_drivers time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_users(sid: str, ctx: Context) -> dict[str, Any]:
    """Get system users

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the system users.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_users(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_users")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_users time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_network_connections(sid: str, ctx: Context) -> dict[str, Any]:
    """Get network connections

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the network connections.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_network_connections(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "netstat")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_network_connections time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_os_version(sid: str, ctx: Context) -> dict[str, Any]:
    """Get OS version

    Args:
        sid (uuid str): The Sensor ID to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "version" (dict[str, Any]): On success, a dictionary containing the OS version information.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_os_version(sid={json.dumps(sid)})")
    try:
        return execute_sensor_command(ctx, sid, "os_version")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_os_version time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_registry_keys(sid: str, path: str, ctx: Context) -> dict[str, Any]:
    """Get registry keys

    Args:
        sid (uuid str): The Sensor ID to query
        path (str): The registry path to query

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the registry keys.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_registry_keys(sid={json.dumps(sid)}, path={json.dumps(path)})")
    try:
        return execute_sensor_command(ctx, sid, f"reg_list {shlex.quote(path)}")
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"get_registry_keys time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def yara_scan_process(sid: str, rule: str, pid: int, ctx: Context) -> dict[str, Any]:
    """Scan a specific process with YARA rules

    Args:
        sid (uuid str): The Sensor ID to query
        rule (str): The YARA rule to use for scanning
        pid (int): The Process ID to scan

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the YARA scan results.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: yara_scan_process(sid={json.dumps(sid)}, rule={json.dumps(rule)}, pid={pid})")
    try:
        cmd = f"yara_scan {shlex.quote(rule)} --pid {pid}"
        return execute_sensor_command(ctx, sid, cmd)
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"yara_scan_process time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def yara_scan_file(sid: str, rule: str, file_path: str, ctx: Context) -> dict[str, Any]:
    """Scan a specific file with YARA rules

    Args:
        sid (uuid str): The Sensor ID to query
        rule (str): The YARA rule to use for scanning
        file_path (str): The path to the file to scan

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the YARA scan results.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: yara_scan_file(sid={json.dumps(sid)}, rule={json.dumps(rule)}, file_path={json.dumps(file_path)}")
    try:
        cmd = f"yara_scan {shlex.quote(rule)} --filePath {shlex.quote(file_path)}"
        return execute_sensor_command(ctx, sid, cmd)
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"yara_scan_file time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def yara_scan_directory(sid: str, rule: str, root_directory: str, file_expression: str, depth: int = 1, ctx: Context = None) -> dict[str, Any]:
    """Scan a directory with YARA rules using a file pattern

    Args:
        sid (uuid str): The Sensor ID to query
        rule (str): The YARA rule to use for scanning
        root_directory (str): The root directory to scan
        file_expression (str): The file pattern to match
        depth (int): Optional maximum depth of the search for files to scan, defaults to 1

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the YARA scan results.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: yara_scan_directory(sid={json.dumps(sid)}, rule={json.dumps(rule)}, root_directory={json.dumps(root_directory)}, file_expression={json.dumps(file_expression)}, depth={depth})")
    try:
        cmd = f"yara_scan {shlex.quote(rule)} --root-dir {shlex.quote(root_directory)} --file-exp {shlex.quote(file_expression)}"
        if depth != 1:
            cmd += f" --depth {depth}"
        return execute_sensor_command(ctx, sid, cmd)
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"yara_scan_directory time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def yara_scan_memory(sid: str, rule: str, process_expr: str, ctx: Context) -> dict[str, Any]:
    """Scan process memory with YARA rules

    Args:
        sid (uuid str): The Sensor ID to query
        rule (str): The YARA rule to use for scanning
        process_expr (str): Process expression to match processes to scan

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict[str, Any]): On success, a dictionary containing the YARA scan results.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: yara_scan_memory(sid={json.dumps(sid)}, rule={json.dumps(rule)}, process_expr={json.dumps(process_expr)}")
    try:
        cmd = f"yara_scan {shlex.quote(rule)} --processExpr {shlex.quote(process_expr)}"
        return execute_sensor_command(ctx, sid, cmd)
    except Exception as e:
        return {"error": f"Error issuing sensor request: {e}"}
    finally:
        logging.info(f"yara_scan_memory time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def isolate_network(sid: str, ctx: Context) -> dict[str, Any]:
    """Isolate a sensor from the network

    Args:
        sid (uuid str): The Sensor ID to isolate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "status" (str): On success, a string "success".
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: isolate_network(sid={json.dumps(sid)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        sensor.isolateNetwork()
        return {"status": "success"}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"isolate_network time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def rejoin_network(sid: str, ctx: Context) -> dict[str, Any]:
    """Rejoin a sensor to the network

    Args:
        sid (uuid str): The Sensor ID to rejoin

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "status" (str): On success, a string "success".
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: rejoin_network(sid={json.dumps(sid)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        sensor.rejoinNetwork()
        return {"status": "success"}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"rejoin_network time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def is_isolated(sid: str, ctx: Context) -> dict[str, Any]:
    """Check if a sensor is isolated from the network

    Args:
        sid (uuid str): The Sensor ID to check

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "is_isolated" (bool): On success, a boolean indicating the isolation status.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: is_isolated(sid={json.dumps(sid)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        is_isolated = sensor.isIsolatedFromNetwork()
        return {"is_isolated": is_isolated}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"is_isolated time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def is_online(sid: str, ctx: Context) -> dict[str, Any]:
    """Check if a sensor is currently online

    Args:
        sid (uuid str): The Sensor ID to check

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "is_online" (bool): On success, a boolean indicating the online status.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: is_online(sid={json.dumps(sid)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        is_online = sensor.isOnline()
        return {"is_online": is_online}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"is_online time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def add_tag(sid: str, tag: str, ttl: int, ctx: Context) -> dict[str, Any]:
    """Add a tag to a sensor

    Args:
        sid (uuid str): The Sensor ID to tag
        tag (str): The tag to add
        ttl (int): Time in seconds before the tag expires

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "status" (str): On success, a string "success".
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: add_tag(sid={json.dumps(sid)}, tag={json.dumps(tag)}, ttl={ttl})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        sensor.tag(tag, ttl)
        return {"status": "success"}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"add_tag time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def remove_tag(sid: str, tag: str, ctx: Context) -> dict[str, Any]:
    """Remove a tag from a sensor

    Args:
        sid (uuid str): The Sensor ID to untag
        tag (str): The tag to remove

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "status" (str): On success, a string "success".
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: remove_tag(sid={json.dumps(sid)}, tag={json.dumps(tag)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        sensor.untag(tag)
        return {"status": "success"}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"remove_tag time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_event_schema(name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific schema definition for an event_type in LimaCharlie

    Args:
        name (str): Name of the event_type to get (e.g. 'DNS_REQUEST')

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "schema" (dict[str, Any]): On success, a dictionary containing the schema definition.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_event_schema(name={json.dumps(name)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        if not name.startswith('evt:'):
            name = f"evt:{name}"
        schema = sdk.getSchema(name)
        return {"schema": schema}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_event_schema time: {time.time() - start} seconds")

# Internal helper function that doesn't require context
async def _get_event_schemas_batch_internal(event_names: list[str], sdk: limacharlie.Manager) -> dict[str, Any]:
    """Internal version of get_event_schemas_batch that accepts SDK directly."""
    try:
        async def fetch_single_schema(name: str) -> tuple[str, dict[str, Any]]:
            """Fetch a single schema and return the name and result"""
            try:
                formatted_name = name if name.startswith('evt:') else f"evt:{name}"
                # Run the blocking SDK call in a thread pool
                schema = await asyncio.get_event_loop().run_in_executor(
                    SDK_THREAD_POOL, sdk.getSchema, formatted_name
                )
                return name, {"schema": schema}
            except Exception as e:
                return name, {"error": f"{e}"}

        # Fetch all schemas in parallel
        tasks = [fetch_single_schema(name) for name in event_names]
        results = await asyncio.gather(*tasks)

        # Separate successful schemas from errors
        schemas = {}
        errors = {}

        for name, result in results:
            if "error" in result:
                errors[name] = result["error"]
            else:
                schemas[name] = result["schema"]

        response = {"schemas": schemas}
        if errors:
            response["errors"] = errors

        return response

    except Exception as e:
        return {"error": f"{e}"}

@mcp_tool_with_gcs()
async def get_event_schemas_batch(event_names: list[str], ctx: Context) -> dict[str, Any]:
    """Get schema definitions for multiple event_types in LimaCharlie in parallel

    Args:
        event_names (list[str]): List of event_type names to get schemas for (e.g. ['DNS_REQUEST', 'PROCESS_START'])

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "schemas" (dict[str, dict[str, Any]]): On success, a dictionary mapping event names to their schema definitions.
            - "errors" (dict[str, str]): On success, a dictionary mapping event names to any error messages for failed requests.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_event_schemas_batch(event_names={json.dumps(event_names)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        
        return await _get_event_schemas_batch_internal(event_names, sdk)

    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_event_schemas_batch time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_event_types_with_schemas(ctx: Context) -> dict[str, Any]:
    """Get all available event_type with schemas available for the organization

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "event_types" (list[str]): On success, a list of event_type strings.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info("Tool called: get_event_types_with_schemas()")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        schemas = sdk.getSchemas()
        schemas = [et.removeprefix('evt:') for et in schemas['event_types'] if et.startswith("evt:")]
        return {"event_types": schemas}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_event_types_with_schemas time: {time.time() - start} seconds")

# Internal helper function that doesn't require context
def _get_event_types_with_schemas_for_platform_internal(sdk: limacharlie.Manager, platform: str) -> dict[str, Any]:
    """Internal version of get_event_types_with_schemas_for_platform that accepts SDK directly."""
    try:
        schemas = sdk.getSchemas(platform)
        schemas = [et.removeprefix('evt:') for et in schemas['event_types'] if et.startswith("evt:")]
        return {"event_types": schemas}
    except Exception as e:
        return {"error": f"{e}"}

@mcp_tool_with_gcs()
def get_event_types_with_schemas_for_platform(platform: str, ctx: Context) -> dict[str, Any]:
    """Get all available event_type with schemas available for a specific platform

    Args:
        platform (str): The platform name to get event_types for (e.g. 'windows', 'linux', 'macos', as listed in the response from get_platform_names)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "event_types" (list[str]): On success, a list of event_type strings.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: get_event_types_with_schemas_for_platform(platform={json.dumps(platform)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        return _get_event_types_with_schemas_for_platform_internal(sdk, platform)
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_event_types_with_schemas_for_platform time: {time.time() - start} seconds")

# Internal helper function that doesn't require context
def _get_platform_names_internal(sdk: limacharlie.Manager) -> dict[str, Any]:
    """Internal version of get_platform_names that accepts SDK directly."""
    try:
        ontology = sdk.getOntology()
        return {"platforms": [p for p in ontology['platforms'].keys()]}
    except Exception as e:
        return {"error": f"{e}"}

@mcp_tool_with_gcs()
def get_platform_names(ctx: Context) -> dict[str, Any]:
    """Get the platform names ontology from LimaCharlie (does not mean the tenant has sensors for these platforms)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "platforms" (list[str]): On success, a list of platform name strings.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info("Tool called: get_platform_names()")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        return _get_platform_names_internal(sdk)
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_platform_names time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_mitre_report(ctx: Context) -> dict[str, Any]:
    """Get the MITRE ATT&CK report for the organization (report on detection rule coverage)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "report" (dict[str, Any]): On success, a dictionary containing the MITRE report.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info("Tool called: get_mitre_report()")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        report = sdk.getMITREReport()
        return {"report": report}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_mitre_report time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def list_with_platform(platform: str, ctx: Context) -> dict[str, Any]:
    """List all sensors with a specific platform

    Args:
        platform (str): The platform name to list sensors for (e.g. 'windows', 'linux', 'macos', as listed in the response from get_platform_names)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "sensors" (list[dict[str, Any]]): On success, a list of sensor dictionaries with 'sid' and 'details' keys.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: list_with_platform(platform={json.dumps(platform)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensors = sdk.sensors(selector=f"plat == `{platform}`")
        return {"sensors": [{"sid": s.sid, "details": s._detailedInfo} for s in sensors]}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"list_with_platform time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_time_when_sensor_has_data(sid: str, start: int, end: int, ctx: Context) -> dict[str, Any]:
    """Get timestamps when a sensor has reported data between two epoch second timestamps less than 30 days apart

    Args:
        sid (uuid str): The Sensor ID to get the overview for
        start (int): The start timestamp in Unix second epoch format (max 30 days range)
        end (int): The end timestamp in Unix second epoch format (max 30 days range)

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "timestamps" (list[int]): On success, a list of timestamps when the sensor has data.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start_time = time.time()
    logging.info(f"Tool called: get_time_when_sensor_has_data(sid={json.dumps(sid)}, start={start}, end={end})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        sensor = sdk.sensor(sid)
        return {"timestamps": sensor.getHistoricOverview(start, end)}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_time_when_sensor_has_data time: {time.time() - start_time} seconds")

@mcp_tool_with_gcs()
def get_historic_detections(start: int, end: int, limit: int = None, cat: str = None, ctx: Context = None) -> dict[str, Any]:
    """Get historic detections for the organization between two epoch second timestamps less than 10 minutes apart

    Args:
        start (int): Start timestamp in Unix second epoch format
        end (int): End timestamp in Unix second epoch format

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "detections" (list[dict[str, Any]]): On success, a list of detection dictionaries.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start_time = time.time()
    logging.info(f"Tool called: get_historic_detections(start={start}, end={end}, limit={limit}, cat={json.dumps(cat)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        detections = list(sdk.getHistoricDetections(start, end, limit, cat))
        return {"detections": detections}
    except Exception as e:
        return {"error": f"Error getting historic detections: {e}"}
    finally:
        logging.info(f"get_historic_detections time: {time.time() - start_time} seconds")

@mcp_tool_with_gcs()
def get_detection_rules(ctx: Context) -> dict[str, Any]:
    """Get all the D&R rules for the organization

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict[str, Any]): On success, a dictionary with rule names as keys and rule details as values.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info("Tool called: get_detection_rules()")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        hive = limacharlie.Hive(sdk, "dr-general")
        genRules = {k: v.toJSON() for k, v in hive.list().items()}
        hive = limacharlie.Hive(sdk, "dr-managed")
        managedRules = {k: v.toJSON() for k, v in hive.list().items()}
        hive = limacharlie.Hive(sdk, "dr-service")
        svcRules = {k: v.toJSON() for k, v in hive.list().items()}
        return {"rules": {**genRules, **managedRules, **svcRules}}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_detection_rules time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def get_fp_rules(ctx: Context) -> dict[str, Any]:
    """Get all the False Positive rules for the organization

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict[str, Any]): On success, a dictionary with rule names as keys and rule details as values.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info("Tool called: get_fp_rules()")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        hive = limacharlie.Hive(sdk, "fp")
        rules = {k: v.toJSON() for k, v in hive.list().items()}
        return {"rules": rules}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"get_fp_rules time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def run_lcql_query(query: str, limit: int = 100, stream = "event", ctx: Context = None) -> dict[str, Any]:
    """Run a LCQL query on the organization

    Args:
        query (str): The LCQL query to run
        limit (int): The maximum number of results to return
        stream (str): The stream to query (default is "event", options include "event", "detect", "audit")

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (list[dict[str, Any]]): On success, a list of dictionaries containing the results of the query.
            - "has_more" (bool): On success, a boolean indicating if there are more results to fetch.
            - "error" (str): On failure, an error message string describing the exception.
    """
    if stream not in ["event", "detect", "audit"]:
        return {"error": f"Invalid stream '{stream}' specified. Must be one of: 'event', 'detect', 'audit'."}
    start = time.time()
    logging.info(f"Tool called: run_lcql_query(query={json.dumps(query)})")
    try:
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}
        replay = limacharlie.Replay.Replay(sdk)
        results = []
        hasMore = False
        for event in replay._doQuery(query, stream=stream, isCursorBased=True):
            results.append(event)
            if len(results) >= limit:
                hasMore = True
                break
        return {"results": results, "has_more": hasMore}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"run_lcql_query time: {time.time() - start} seconds")

def get_gemini_response(prompt: str = None, messages: list = None, system_prompt: str = None, model_name: str = 'gemini-2.5-flash-lite-preview-06-17', temperature: float = 1.0, with_search: bool = False) -> str:
    """Get a response from Gemini for a given prompt or message history.
    
    Args:
        prompt (str, optional): The single prompt to send to Gemini. Mutually exclusive with messages.
        messages (list, optional): The message history to send to Gemini. Mutually exclusive with prompt.
        system_prompt (str, optional): The system prompt to use. Defaults to None.
        model_name (str, optional): The model to use. Defaults to 'gemini-2.5-flash-lite-preview-06-17'.
        temperature (float, optional): The temperature for generation. Defaults to 1.0.
        with_search (bool, optional): Whether to enable search tools. Defaults to False.
        
    Returns:
        str: The response from Gemini
        
    Raises:
        Exception: If there's an error getting the response
    """
    start = time.time()
    try:
        # First try to get credentials from the environment
        try:
            client = genai.Client()
        except Exception as cred_error:
            # If default credentials fail, try using API key from environment
            api_key = os.getenv('GOOGLE_API_KEY')
            if not api_key:
                raise Exception("No Google API credentials available. Either set up default credentials or set GOOGLE_API_KEY environment variable.")
            client = genai.Client(api_key=api_key)

        # Build the message list
        if messages is not None:
            if prompt is not None:
                raise Exception("Cannot specify both prompt and messages parameters")
            message_list = messages
        elif prompt is not None:
            message_list = [
                {"role": "user", "parts": [{"text": prompt}]},
            ]
        else:
            raise Exception("Must specify either prompt or messages parameter")

        tools = None
        if with_search:
            tools = [types.Tool(
                google_search = types.GoogleSearch()
            )]

        response = client.models.generate_content(
            model=model_name,
            contents=message_list,
            config=types.GenerateContentConfig(
                system_instruction=system_prompt,
                temperature=temperature,
                tools=tools,
            ),
        )
        
        # Return the generated text
        return response.text.strip()
        
    except Exception as e:
        logging.info(f"Failed to get Gemini response: {str(e)}")
        raise Exception(f"Failed to get Gemini response: {str(e)}")
    finally:
        logging.info(f"Gemini response time: {time.time() - start} seconds")

def get_prompt_template(prompt_name: str) -> str:
    """Get a prompt template from the prompts directory.
    
    Args:
        prompt_name (str): The name of the prompt file without extension
        
    Returns:
        str: The prompt template content
        
    Raises:
        Exception: If the prompt file cannot be read
    """
    try:
        prompt_path = pathlib.Path(__file__).parent / 'prompts' / f'{prompt_name}.txt'
        with open(prompt_path, 'r') as f:
            return f.read().strip()
    except Exception as e:
        raise Exception(f"Failed to read prompt template {prompt_name}: {str(e)}")

def schema_type_code_to_string(code: str) -> str:
    """Convert a schema type code to a string.
    
    Args:
        code (str): The code to convert
        
    Returns:
        str: The string representation of the code
    """
    if code == 's':
        return 'string'
    elif code == 'i':
        return 'integer'
    elif code == 'f':
        return 'float'
    elif code == 'b':
        return 'boolean'
    return ''

def interpret_schema(schema: dict[str, Any]) -> str:
    """Interpret the schema returned from the API and return a simplified version.
    
    Args:
        schema (str): The schema to interpret
        
    Returns:
        str: The simplified schema
    """
    output = f'''Schema for {schema['schema']['event_type'].split(':', maxsplit=1)[1]}:\n
FieldsName\tFieldType
'''
    for event in schema['schema']['elements']:
        etype, field = event.split(':', maxsplit=1)
        output += f'{field}\t{schema_type_code_to_string(etype)}\n'
    return output

async def get_schema_from_prompt(query: str, sdk: limacharlie.Manager) -> str:
    """Get the schema from a prompt.
    
    Args:
        query (str): The query to get the schema from
        sdk (limacharlie.Manager): The SDK instance to use
        
    Returns:
        str: The schema
    """
    try:
        # First ask a small LLM to tell us what platform this is likely about.
        # Then we will fetch the relevant schema.
        # Finally we will ask a larger LLM to generate the query.
        platform_prompt = get_prompt_template('gen_platform')
        available_platforms = "\n".join(_get_platform_names_internal(sdk)['platforms'])
        platform_prompt = platform_prompt.format(platforms=available_platforms)
        platform = get_gemini_response(system_prompt=platform_prompt, prompt=query, model_name='gemini-2.5-flash-lite-preview-06-17', temperature=1.0)

        if not platform:
            return 'No platform found, extrapolate with best effort.'

        # Get the schema for the platform
        event_types = _get_event_types_with_schemas_for_platform_internal(sdk, platform)['event_types']
        events_prompt = get_prompt_template('gen_event_list')
        events_prompt = events_prompt.format(events=event_types)
        reasoned_events = get_gemini_response(system_prompt=events_prompt, prompt=query, model_name='gemini-2.5-flash-lite-preview-06-17', temperature=1.0, with_search=True)
        extract_prompt = get_prompt_template('gen_extract_event_list')
        events = get_gemini_response(system_prompt=extract_prompt, prompt=reasoned_events, model_name='gemini-2.5-flash-lite-preview-06-17', temperature=1.0)
        events = [e.strip().replace('\\', '') for e in events.split('\n') if e.strip()]
        if not events or "<no-events>" in events:
            events = event_types

        events = [e for e in events if e != 'evt:' and e != '']

        if not events:
            return 'No events found, extrapolate with best effort.'

        # Use batch function to get all schemas in parallel
        batch_result = await _get_event_schemas_batch_internal(events, sdk)
        if "error" in batch_result:
            raise Exception(f"Failed to fetch schemas: {batch_result['error']}")

        # Process successful schemas
        schema_parts = []
        for event_name in events:
            if event_name in batch_result["schemas"]:
                # The batch result contains the raw schema data, but interpret_schema expects
                # the structure that get_event_schema() returns: {"schema": schema_data}
                schema_parts.append(interpret_schema(batch_result["schemas"][event_name]))
            elif "errors" in batch_result and event_name in batch_result["errors"]:
                logging.info(f"Warning: Failed to get schema for {event_name}: {batch_result['errors'][event_name]}")

        schema = "\n".join(schema_parts)
        return schema
    except Exception as e:
        logging.info(f"get_schema_from_prompt error: {traceback.format_exc()}")
        return f"get_schema_from_prompt error: {e}"

def validate_lcql_query(sdk: limacharlie.Manager, query: str) -> dict[str, Any]:
    """Validate a LCQL query

    Args:
        sdk (limacharlie.Manager): The SDK to use
        query (str): The LCQL query to validate
    """
    logging.info(f"validate_lcql_query(query={json.dumps(query)})")
    try:
        replay = limacharlie.Replay.Replay(sdk)
        resp = replay._doQuery(query, isValidation=True)
        if resp.get('error', None):
            return {"valid": False, "error": resp['error']}
        return {"valid": True}
    except Exception as e:
        return {"error": f"{e}"}

def validate_dr_rule(sdk: limacharlie.Manager, rule: dict[str, Any]) -> dict[str, Any]:
    """Validate a D&R rule

    Args:
        sdk (limacharlie.Manager): The SDK to use
        rule (dict[str, Any]): The D&R rule to validate
    """
    logging.info(f"validate_dr_rule(rule={json.dumps(rule)})")
    start = time.time()
    try:
        replay = limacharlie.Replay.Replay(sdk)
        resp = replay.validateRule(rule)
        if resp.get('error', None):
            return {"valid": False, "error": resp['error']}
        return {"valid": True}
    except Exception as e:
        return {"error": f"{e}"}
    finally:
        logging.info(f"validate_dr_rule time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
async def generate_lcql_query(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a LCQL query based on a natural language description

    Args:
        query (str): The natural language description of the query to generate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "query" (str): On success, the generated LCQL query.
            - "explanation" (str): On success, a markdown text string explaining how the query was constructed.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_lcql_query(query={json.dumps(query)})")
    
    try:
        # Get SDK from context first, before using it
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}

        # Use an LLM to get the schema for the events for the platform
        # this prompt relates to.
        schema = await get_schema_from_prompt(query, sdk)

        # Get the prompt template and format it with the query
        prompt_template = get_prompt_template('gen_lcql')
        prompt = prompt_template.replace('{lcql_schema}', schema)

        # Loop up to LLM_YAML_RETRY_COUNT times to generate and validate the query
        max_iterations = LLM_YAML_RETRY_COUNT
        messages = [
            {"role": "user", "parts": [{"text": query}]}
        ]
        last_error = None

        for iteration in range(max_iterations):
            logging.info(f"LCQL generation attempt {iteration + 1}/{max_iterations}")

            # Get the generated query using the reusable function
            ret = get_gemini_response(messages=messages, system_prompt=prompt, model_name='gemini-2.5-flash', temperature=0.0)
            generated_query, explanation = ret.split('\n', maxsplit=1)
            generated_query = generated_query.strip()
            explanation = explanation.strip()

            # Validate the query
            validation_result = validate_lcql_query(sdk, generated_query)

            if validation_result.get("valid", False):
                logging.info(f"LCQL query validated successfully on attempt {iteration + 1}")
                return {"query": generated_query, "explanation": explanation}

            # Query is invalid, prepare for next iteration
            error_msg = validation_result.get("error", "Unknown validation error")
            last_error = error_msg
            logging.info(f"LCQL validation failed on attempt {iteration + 1}: {error_msg}")

            # Add the assistant's response and the validation error as separate messages
            messages.append({"role": "model", "parts": [{"text": ret}]})
            messages.append({"role": "user", "parts": [{"text": f"The previous query generated was invalid with this error: {error_msg}\nPlease fix the query and try again."}]})

        # If we get here, all iterations failed
        return {"error": f"Failed to generate valid LCQL query after {max_iterations} attempts. Last error: {last_error}"}
        
    except Exception as e:
        logging.info(f"generate_lcql_query error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_lcql_query time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
async def generate_dr_rule_detection(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a D&R rule's detection component based on a natural language description

    Args:
        query (str): The natural language description of the detection to generate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "detection" (str): On success, the generated D&R rule detection.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_dr_rule_detection(query={json.dumps(query)})")

    try:
        # Get SDK from context first, before using it
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}

        # Use an LLM to get the schema for the events for the platform
        # this prompt relates to.
        schema = await get_schema_from_prompt(query, sdk)

        # Get the prompt template and format it with the query
        prompt_template = get_prompt_template('gen_dr_detect')
        prompt = prompt_template.replace('{lcql_schema}', schema)

        # Loop up to LLM_YAML_RETRY_COUNT times to generate and validate the rule
        max_iterations = LLM_YAML_RETRY_COUNT
        messages = [
            {"role": "user", "parts": [{"text": query}]}
        ]
        last_error = None

        for iteration in range(max_iterations):
            logging.info(f"D&R detection generation attempt {iteration + 1}/{max_iterations}")

            # Get the generated detection using the reusable function
            ret = get_gemini_response(messages=messages, system_prompt=prompt, model_name='gemini-2.5-flash', temperature=0.0)
            generated_detection = ret.strip()

            # The models sometimes hallucinate that they need to add markdown formatting.
            # Remove it.
            generated_detection = generated_detection.replace('```yaml', '').replace('```', '').replace('```', '')

            # Try to parse the YAML first
            try:
                parsed_detection = yaml.safe_load(generated_detection)
            except yaml.YAMLError as yaml_error:
                # YAML parsing failed, prepare for next iteration
                error_msg = f"Invalid YAML syntax: {yaml_error}"
                last_error = error_msg
                logging.info(f"D&R detection YAML parsing failed on attempt {iteration + 1}: {error_msg}")

                # Add the assistant's response and the YAML error as separate messages
                messages.append({"role": "model", "parts": [{"text": ret}]})
                messages.append({"role": "user", "parts": [{"text": f"The previous detection rule generated had invalid YAML syntax with this error: {error_msg}\nPlease fix the YAML syntax and try again."}]})
                continue

            # Create a minimal D&R rule structure for validation
            test_rule = {
                "detect": parsed_detection,
                "respond": []  # Empty respond section for validation
            }

            # Validate the rule
            validation_result = validate_dr_rule(sdk, test_rule)

            if validation_result.get("valid", False):
                logging.info(f"D&R detection validated successfully on attempt {iteration + 1}")
                return {"detection": generated_detection}

            # Rule is invalid, prepare for next iteration
            error_msg = validation_result.get("error", "Unknown validation error")
            last_error = error_msg
            logging.info(f"D&R detection validation failed on attempt {iteration + 1}: {error_msg}")

            # Add the assistant's response and the validation error as separate messages
            messages.append({"role": "model", "parts": [{"text": ret}]})
            messages.append({"role": "user", "parts": [{"text": f"The previous detection rule generated was invalid with this error: {error_msg}\nPlease fix the detection rule and try again."}]})

        # If we get here, all iterations failed
        return {"error": f"Failed to generate valid D&R detection after {max_iterations} attempts. Last error: {last_error}"}

    except Exception as e:
        logging.info(f"generate_dr_rule_detection error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_dr_rule_detection time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def generate_dr_rule_respond(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a D&R rule's respond component based on a natural language description

    Args:
        query (str): The natural language description of the respond to generate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "respond" (str): On success, the generated D&R rule respond.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_dr_rule_respond(query={json.dumps(query)})")

    try:
        # Get the prompt template and format it with the query
        prompt = get_prompt_template('gen_dr_respond')

        # Get the SDK for validation
        # Get SDK from context
        sdk = get_sdk_from_context(ctx)
        if not sdk:
            return {"error": "Authentication failed - no SDK available"}

        # Loop up to LLM_YAML_RETRY_COUNT times to generate and validate the rule
        max_iterations = LLM_YAML_RETRY_COUNT
        messages = [
            {"role": "user", "parts": [{"text": query}]}
        ]
        last_error = None

        for iteration in range(max_iterations):
            logging.info(f"D&R respond generation attempt {iteration + 1}/{max_iterations}")

            # Get the generated respond using the reusable function
            ret = get_gemini_response(messages=messages, system_prompt=prompt, model_name='gemini-2.5-flash', temperature=0.0)
            generated_respond = ret.strip()

            # The models sometimes hallucinate that they need to add markdown formatting.
            # Remove it.
            generated_respond = generated_respond.replace('```yaml', '').replace('```', '').replace('```', '')

            # Try to parse the YAML first
            try:
                parsed_respond = yaml.safe_load(generated_respond)
            except yaml.YAMLError as yaml_error:
                # YAML parsing failed, prepare for next iteration
                error_msg = f"Invalid YAML syntax: {yaml_error}"
                last_error = error_msg
                logging.info(f"D&R respond YAML parsing failed on attempt {iteration + 1}: {error_msg}")

                # Add the assistant's response and the YAML error as separate messages
                messages.append({"role": "model", "parts": [{"text": ret}]})
                messages.append({"role": "user", "parts": [{"text": f"The previous respond rule generated had invalid YAML syntax with this error: {error_msg}\nPlease fix the YAML syntax and try again."}]})
                continue

            # Create a minimal D&R rule structure for validation with dummy detect
            test_rule = {
                "detect": {"op": "exists", "path": "/"},  # Dummy detect component
                "respond": parsed_respond
            }

            # Validate the rule
            validation_result = validate_dr_rule(sdk, test_rule)

            if validation_result.get("valid", False):
                logging.info(f"D&R respond validated successfully on attempt {iteration + 1}")
                return {"respond": generated_respond}

            # Rule is invalid, prepare for next iteration
            error_msg = validation_result.get("error", "Unknown validation error")
            last_error = error_msg
            logging.info(f"D&R respond validation failed on attempt {iteration + 1}: {error_msg}")

            # Add the assistant's response and the validation error as separate messages
            messages.append({"role": "model", "parts": [{"text": ret}]})
            messages.append({"role": "user", "parts": [{"text": f"""The previous respond rule generated was invalid with this error: {error_msg}
If the error relates to the platform being unknown, change it to 'json'.
Please fix the respond rule and try again."""}]})

        # If we get here, all iterations failed
        return {"error": f"Failed to generate valid D&R respond after {max_iterations} attempts. Last error: {last_error}"}
        
    except Exception as e:
        logging.info(f"generate_dr_rule_respond error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_dr_rule_respond time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def generate_sensor_selector(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a sensor selector expression based on a natural language description

    Args:
        query (str): The natural language description of the sensor selector to generate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "selector" (str): On success, the generated sensor selector expression.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_sensor_selector(query={json.dumps(query)})")

    try:
        # Get the prompt template
        prompt = get_prompt_template('gen_sensor_selector')

        # Generate the sensor selector using Gemini
        response = get_gemini_response(
            system_prompt=prompt, 
            prompt=query, 
            model_name='gemini-2.5-flash-lite-preview-06-17', 
            temperature=0.1
        )

        return {"selector": response.strip()}

    except Exception as e:
        logging.info(f"generate_sensor_selector error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_sensor_selector time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def generate_python_playbook(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a Python playbook based on a natural language description

    Args:
        query (str): The natural language description of the playbook to generate

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "playbook" (str): On success, the generated Python playbook code.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_python_playbook(query={json.dumps(query)})")

    try:
        # Get the prompt template
        prompt = get_prompt_template('gen_playbook')

        # Generate the playbook using Gemini
        response = get_gemini_response(
            system_prompt=prompt, 
            prompt=query, 
            model_name='gemini-2.5-flash', 
            temperature=0.2
        )

        return {"playbook": response.strip()}

    except Exception as e:
        logging.info(f"generate_python_playbook error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_python_playbook time: {time.time() - start} seconds")

@mcp_tool_with_gcs()
def generate_detection_summary(query: str, ctx: Context) -> dict[str, Any]:
    """Generate a detection summary for level 1 analysts based on alert data

    Args:
        query (str): The alert/detection data to summarize

    Returns:
        dict[str, Any]: A dictionary containing either:
            - "summary" (str): On success, the generated markdown summary.
            - "error" (str): On failure, an error message string describing the exception.
    """
    start = time.time()
    logging.info(f"Tool called: generate_detection_summary(query={json.dumps(query)})")

    try:
        # Get the prompt template
        prompt = get_prompt_template('gen_det_summary')

        # Generate the summary using Gemini
        response = get_gemini_response(
            system_prompt=prompt, 
            prompt=query, 
            model_name='gemini-2.5-flash-lite-preview-06-17', 
            temperature=0.3,
            with_search=True  # Enable search for MITRE ATT&CK information
        )

        return {"summary": response.strip()}

    except Exception as e:
        logging.info(f"generate_detection_summary error: {traceback.format_exc()}")
        return {"error": f"{e}"}
    finally:
        logging.info(f"generate_detection_summary time: {time.time() - start} seconds")

# ============================================================================
# PHASE 1: Core Sensor Management Tools
# ============================================================================

@mcp_tool_with_gcs()
def list_sensors(
    limit: int = None,
    with_hostname_prefix: str = None,
    with_ip: str = None,
    selector: str = None,
    with_tags: list[str] = None,
    ctx: Context = None
) -> dict[str, Any]:
    """List all sensors in the organization with optional filtering
    
    Args:
        limit (int): Optional maximum number of sensors to return
        with_hostname_prefix (str): Optional filter for sensors with hostnames starting with this prefix
        with_ip (str): Optional filter for sensors with this IP address
        selector (str): Optional sensor selector expression
        with_tags (list[str]): Optional list of tags to filter by (sensors must have all specified tags)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "sensors" (list): List of sensor information dictionaries
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_sensors(limit={json.dumps(limit)}, with_hostname_prefix={json.dumps(with_hostname_prefix)}, with_ip={json.dumps(with_ip)}, selector={json.dumps(selector)}, with_tags={json.dumps(with_tags)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get sensors based on different criteria
        sensors = []
        
        if with_hostname_prefix:
            # Use getSensorsWithHostname for hostname prefix search
            result = sdk.getSensorsWithHostname(with_hostname_prefix, as_dict=True)
            sensors = list(result.values())
        elif with_ip:
            # For IP search, we need to provide a time range - use last 7 days
            end_time = int(time.time())
            start_time = end_time - (7 * 24 * 60 * 60)
            result = sdk.getSensorsWithIp(with_ip, start_time, end_time)
            sensors = result if result else []
        else:
            # General sensor listing
            result = sdk.sensors(selector=selector, limit=limit)
            sensors = result if result else []
        
        # Filter by tags if specified
        if with_tags and sensors:
            filtered_sensors = []
            for sensor_obj in sensors:
                # Convert sensor object to dict if needed
                if hasattr(sensor_obj, '__dict__'):
                    # It's a Sensor object
                    sensor_info = sensor_obj.getInfo()
                    sensor_tags = sensor_obj.getTags()
                else:
                    # It's already a dict
                    sensor_info = sensor_obj
                    sensor_tags = sensor_info.get('tags', [])
                
                # Check if sensor has all required tags
                if all(tag in sensor_tags for tag in with_tags):
                    filtered_sensors.append(sensor_info)
            sensors = filtered_sensors
        else:
            # Convert Sensor objects to dicts
            sensor_list = []
            for sensor_obj in sensors:
                if hasattr(sensor_obj, '__dict__'):
                    sensor_list.append(sensor_obj.getInfo())
                else:
                    sensor_list.append(sensor_obj)
            sensors = sensor_list
        
        # Apply limit if not already applied
        if limit and len(sensors) > limit:
            sensors = sensors[:limit]
        
        return {"sensors": sensors}
        
    except Exception as e:
        logging.info(f"Error in list_sensors: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_sensors time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_sensor_info(sid: str, ctx: Context) -> dict[str, Any]:
    """Get detailed information about a specific sensor
    
    Args:
        sid (uuid str): The Sensor ID to get information for
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "sensor" (dict): Detailed sensor information including platform, hostname, last seen, etc.
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_sensor_info(sid={json.dumps(sid)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the sensor object
        sensor = sdk.sensor(sid)
        if sensor is None:
            return {"error": f"Sensor {sid} not found"}
        
        # Get detailed info
        sensor_info = sensor.getInfo()
        
        # Add additional useful information
        sensor_info['is_online'] = sensor.isOnline()
        sensor_info['is_isolated'] = sensor.isIsolatedFromNetwork()
        sensor_info['tags'] = sensor.getTags()
        sensor_info['platform_type'] = {
            'is_windows': sensor.isWindows(),
            'is_mac': sensor.isMac(),
            'is_linux': sensor.isLinux(),
            'is_chrome': sensor.isChrome(),
            'is_chromeos': sensor.isChromeOS()
        }
        
        return {"sensor": sensor_info}
        
    except Exception as e:
        logging.info(f"Error in get_sensor_info: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_sensor_info time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_online_sensors(ctx: Context) -> dict[str, Any]:
    """List all currently online sensors in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "sensors" (list): List of online sensor IDs with basic information
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_online_sensors()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get all online sensors
        online_sensors = sdk.getAllOnlineSensors()
        
        # Convert to list of dicts with useful info
        sensor_list = []
        for sid, sensor_info in online_sensors.items():
            sensor_data = {
                'sid': sid,
                'hostname': sensor_info.get('hostname', 'Unknown'),
                'platform': sensor_info.get('plat', 'Unknown'),
                'architecture': sensor_info.get('arch', 'Unknown'),
                'internal_ip': sensor_info.get('int_ip', 'Unknown'),
                'external_ip': sensor_info.get('ext_ip', 'Unknown'),
                'last_seen': sensor_info.get('last_seen', 0)
            }
            sensor_list.append(sensor_data)
        
        return {"sensors": sensor_list}
        
    except Exception as e:
        logging.info(f"Error in get_online_sensors: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_online_sensors time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def search_hosts(hostname_expr: str, ctx: Context) -> dict[str, Any]:
    """Search for sensors by hostname pattern
    
    Args:
        hostname_expr (str): Hostname expression to search for (supports wildcards with *)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "sensors" (list): List of matching sensors with their information
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: search_hosts(hostname_expr={json.dumps(hostname_expr)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Search for hosts matching the expression
        result = sdk.hosts(hostname_expr, as_dict=True)
        
        # Convert to list format
        sensor_list = []
        for sid, sensor_info in result.items():
            sensor_info['sid'] = sid
            sensor_list.append(sensor_info)
        
        return {"sensors": sensor_list}
        
    except Exception as e:
        logging.info(f"Error in search_hosts: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"search_hosts time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_sensor(sid: str, ctx: Context) -> dict[str, Any]:
    """Delete a sensor from the organization
    
    WARNING: This permanently removes the sensor and all its data. Use with caution.
    
    Args:
        sid (uuid str): The Sensor ID to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_sensor(sid={json.dumps(sid)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the sensor object
        sensor = sdk.sensor(sid)
        if sensor is None:
            return {"error": f"Sensor {sid} not found"}
        
        # Delete the sensor
        sensor.delete()
        
        return {
            "success": True,
            "message": f"Sensor {sid} has been deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_sensor: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_sensor time: {time.time() - start} seconds")


# ============================================================================
# PHASE 2: Replicant Services Tools
# ============================================================================

@mcp_tool_with_gcs()
def reliable_tasking(
    task: str,
    sid: str = None,
    tag: str = None,
    ttl: int = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Send a persistent (reliable) task to sensors that will retry until successful
    
    Args:
        task (str): The task command to send
        sid (uuid str): Optional specific Sensor ID to task
        tag (str): Optional tag to task all sensors with this tag
        ttl (int): Optional time-to-live in seconds for the task
        
    Note: Must specify either sid or tag, but not both
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "task_id" (str): The ID of the created task
            - "status" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: reliable_tasking(task={json.dumps(task)}, sid={json.dumps(sid)}, tag={json.dumps(tag)}, ttl={json.dumps(ttl)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Validate parameters
        if not sid and not tag:
            return {"error": "Must specify either sid or tag"}
        if sid and tag:
            return {"error": "Cannot specify both sid and tag"}
        
        # Use the Extensions API to call ext-reliable-tasking
        data = {
            "task": task,
            "ttl": ttl if ttl else 604800  # Default to 1 week (7 * 24 * 60 * 60)
        }
        
        if sid:
            data["sid"] = sid
        elif tag:
            data["tag"] = tag
        
        # Call the extension
        result = sdk.extensionRequest(
            extensionName="ext-reliable-tasking",
            action="task",
            data=data
        )
        
        return {
            "task_id": result.get('id', 'Unknown'),
            "status": "Task queued for reliable delivery"
        }
        
    except Exception as e:
        logging.info(f"Error in reliable_tasking: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"reliable_tasking time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def list_reliable_tasks(
    sid: str = None,
    tag: str = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Get pending reliable tasks for sensors
    
    Args:
        sid (uuid str): Optional specific Sensor ID to get tasks for
        tag (str): Optional tag to get tasks for all sensors with this tag
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "tasks" (list): List of pending tasks
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_reliable_tasks(sid={json.dumps(sid)}, tag={json.dumps(tag)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Use the Extensions API to call ext-reliable-tasking
        data = {}
        if sid:
            data["sid"] = sid
        elif tag:
            data["tag"] = tag
        else:
            # If neither specified, list all tasks
            data["selector"] = "*"
        
        # Call the extension
        result = sdk.extensionRequest(
            extensionName="ext-reliable-tasking",
            action="list",
            data=data
        )
        
        # Extract the tasks from the result
        tasks = result.get("tasks", [])
        
        return {"tasks": tasks if tasks else []}
        
    except Exception as e:
        logging.info(f"Error in list_reliable_tasks: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_reliable_tasks time: {time.time() - start} seconds")

# Note: responder_sweep and replay_job have been removed as they use deprecated Services
# that don't have Extension equivalents yet. These may be re-added when Extensions
# are available for these functionalities.


# ============================================================================
# PHASE 3: Organization Management Tools
# ============================================================================

@mcp_tool_with_gcs()
def list_outputs(ctx: Context) -> dict[str, Any]:
    """List all configured outputs in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "outputs" (dict): Dictionary of output configurations
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_outputs()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        outputs = sdk.outputs()
        return {"outputs": outputs if outputs else {}}
        
    except Exception as e:
        logging.info(f"Error in list_outputs: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_outputs time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def add_output(
    name: str,
    module: str,
    output_type: str,
    config: dict[str, Any] = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Create a new output configuration
    
    Args:
        name (str): Name for the output
        module (str): Module to use (e.g., 'logging', 's3', 'syslog')
        output_type (str): Type of output (e.g., 'event', 'detect', 'audit')
        config (dict): Additional configuration parameters specific to the module
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if creation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: add_output(name={json.dumps(name)}, module={json.dumps(module)}, output_type={json.dumps(output_type)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Add the output with configuration
        kwargs = config if config else {}
        sdk.add_output(name, module, output_type, **kwargs)
        
        return {
            "success": True,
            "message": f"Output '{name}' created successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in add_output: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"add_output time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_output(name: str, ctx: Context) -> dict[str, Any]:
    """Delete an output configuration
    
    Args:
        name (str): Name of the output to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_output(name={json.dumps(name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        sdk.del_output(name)
        
        return {
            "success": True,
            "message": f"Output '{name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_output: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_output time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def list_installation_keys(ctx: Context) -> dict[str, Any]:
    """List all installation keys in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "keys" (list): List of installation key information
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_installation_keys()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        keys = sdk.get_installation_keys()
        return {"keys": keys if keys else []}
        
    except Exception as e:
        logging.info(f"Error in list_installation_keys: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_installation_keys time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def create_installation_key(
    tags: list[str],
    description: str,
    quota: int = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Create a new installation key for sensor deployment
    
    Args:
        tags (list[str]): Tags to automatically apply to sensors using this key
        description (str): Description of the installation key
        quota (int): Optional maximum number of sensors that can use this key
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "key" (dict): Installation key details including the key value
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: create_installation_key(tags={json.dumps(tags)}, description={json.dumps(description)}, quota={json.dumps(quota)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Create the installation key
        key_info = sdk.create_installation_key(
            tags=tags,
            desc=description,
            quota=quota
        )
        
        return {"key": key_info}
        
    except Exception as e:
        logging.info(f"Error in create_installation_key: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"create_installation_key time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_installation_key(iid: str, ctx: Context) -> dict[str, Any]:
    """Delete an installation key
    
    Args:
        iid (str): Installation key ID to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_installation_key(iid={json.dumps(iid)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        sdk.delete_installation_key(iid)
        
        return {
            "success": True,
            "message": f"Installation key '{iid}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_installation_key: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_installation_key time: {time.time() - start} seconds")


# ============================================================================
# PHASE 4: Rule Management via Hive
# ============================================================================

@mcp_tool_with_gcs()
def list_rules(hive_name: str, ctx: Context) -> dict[str, Any]:
    """List all rules from a specific hive
    
    Args:
        hive_name (str): Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict): Dictionary of rule names to rule content
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_rules(hive_name={json.dumps(hive_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Hive interface
        from limacharlie import Hive
        hive = Hive(sdk, hive_name)
        
        # List all rules
        rules = hive.list()
        
        return {"rules": {k: v.toJSON() for k, v in rules.items()} if rules else {}}
        
    except Exception as e:
        logging.info(f"Error in list_rules: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_rules time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_rule(hive_name: str, rule_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific rule from a hive
    
    Args:
        hive_name (str): Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')
        rule_name (str): Name of the rule to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rule" (dict): Rule content and metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_rule(hive_name={json.dumps(hive_name)}, rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Hive interface
        from limacharlie import Hive
        hive = Hive(sdk, hive_name)
        
        # Get the specific rule
        rule = hive.get(rule_name)
        
        return {"rule": rule if rule else {}}
        
    except Exception as e:
        logging.info(f"Error in get_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_rule time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_rule(
    hive_name: str,
    rule_name: str,
    rule_content: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a rule in a hive
    
    Args:
        hive_name (str): Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')
        rule_name (str): Name for the rule
        rule_content (dict): Rule content (detection and response for D&R rules)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_rule(hive_name={json.dumps(hive_name)}, rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Hive interface
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, hive_name)
        
        # Create a HiveRecord and set it
        record = HiveRecord(rule_name, rule_content, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Rule '{rule_name}' set successfully in hive '{hive_name}'"
        }
        
    except Exception as e:
        logging.info(f"Error in set_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_rule time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_rule(hive_name: str, rule_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a rule from a hive
    
    Args:
        hive_name (str): Name of the hive (e.g., 'dr-general', 'dr-managed', 'fp')
        rule_name (str): Name of the rule to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_rule(hive_name={json.dumps(hive_name)}, rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Hive interface
        from limacharlie import Hive
        hive = Hive(sdk, hive_name)
        
        # Delete the rule
        hive.delete(rule_name)
        
        return {
            "success": True,
            "message": f"Rule '{rule_name}' deleted from hive '{hive_name}'"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_rule time: {time.time() - start} seconds")


# ============================================================================
# PHASE 5: Artifact Management Tools
# ============================================================================

@mcp_tool_with_gcs()
def list_artifacts(
    artifact_type: str = None,
    source: str = None,
    after: int = None,
    before: int = None,
    ctx: Context = None
) -> dict[str, Any]:
    """List collected artifacts/logs in the organization
    
    Args:
        artifact_type (str): Optional type of artifacts to filter by
        source (str): Optional source to filter by
        after (int): Optional timestamp to list artifacts after
        before (int): Optional timestamp to list artifacts before
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "artifacts" (list): List of artifact metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_artifacts(type={json.dumps(artifact_type)}, source={json.dumps(source)}, after={json.dumps(after)}, before={json.dumps(before)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Logs/Artifacts interface
        from limacharlie import Logs
        logs = Logs(sdk)
        
        # List artifacts with filters
        artifacts = logs.listArtifacts(
            type=artifact_type,
            source=source,
            after=after,
            before=before,
            withData=False
        )
        
        return {"artifacts": artifacts if artifacts else []}
        
    except Exception as e:
        logging.info(f"Error in list_artifacts: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_artifacts time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_artifact(payload_id: str, ctx: Context) -> dict[str, Any]:
    """Download or get URL for a specific artifact
    
    Args:
        payload_id (str): The payload ID of the artifact to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "url" (str): Download URL for the artifact
            - "metadata" (dict): Artifact metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_artifact(payload_id={json.dumps(payload_id)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Get the Logs/Artifacts interface
        from limacharlie import Logs
        logs = Logs(sdk)
        
        # Get the artifact - returns download URL
        # We'll return the URL rather than downloading the content
        result = logs.getOriginal(payload_id)
        
        return {
            "url": result.get('url', ''),
            "metadata": {
                "payload_id": payload_id,
                "size": result.get('size', 0)
            }
        }
        
    except Exception as e:
        logging.info(f"Error in get_artifact: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_artifact time: {time.time() - start} seconds")


# ============================================================================
# PHASE 6: Search and Investigation Tools
# ============================================================================

@mcp_tool_with_gcs()
def search_iocs(
    ioc_type: str,
    ioc_value: str,
    info_type: str,
    limit: int = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Search for Indicators of Compromise (IOCs) across the organization
    
    Args:
        ioc_type (str): Type of IOC (e.g., 'hash', 'file_path', 'domain', 'ip')
        ioc_value (str): The IOC value to search for (supports wildcards with *)
        info_type (str): Type of information to retrieve (e.g., 'summary', 'locations')
        limit (int): Optional maximum number of results
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (list): Search results
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: search_iocs(ioc_type={json.dumps(ioc_type)}, ioc_value={json.dumps(ioc_value)}, info_type={json.dumps(info_type)}, limit={json.dumps(limit)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Perform IOC search
        results = sdk.getObjectInformation(
            objType=ioc_type,
            objName=ioc_value,
            info=info_type,
            isCaseSensitive=False,
            isWithWildcards='*' in ioc_value,
            limit=limit
        )
        
        return {"results": results if results else []}
        
    except Exception as e:
        logging.info(f"Error in search_iocs: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"search_iocs time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def batch_search_iocs(
    objects: list[dict[str, str]],
    ctx: Context
) -> dict[str, Any]:
    """Batch search for multiple IOCs at once
    
    Args:
        objects (list[dict]): List of objects to search, each with 'type', 'name', and 'info' keys
            Example: [{"type": "hash", "name": "abc123...", "info": "summary"}]
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (dict): Search results organized by IOC
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: batch_search_iocs(objects count={len(objects)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Perform batch IOC search
        results = sdk.getBatchObjectInformation(
            objects=objects,
            isCaseSensitive=False
        )
        
        return {"results": results if results else {}}
        
    except Exception as e:
        logging.info(f"Error in batch_search_iocs: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"batch_search_iocs time: {time.time() - start} seconds")


# ============================================================================
# PHASE 7: Administrative Tools
# ============================================================================

@mcp_tool_with_gcs()
def get_usage_stats(ctx: Context) -> dict[str, Any]:
    """Get organization usage statistics
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "stats" (dict): Usage statistics including data retention, sensor counts, etc.
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_usage_stats()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        stats = sdk.getUsageStats()
        return {"stats": stats if stats else {}}
        
    except Exception as e:
        logging.info(f"Error in get_usage_stats: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_usage_stats time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_org_info(ctx: Context) -> dict[str, Any]:
    """Get detailed organization information and configuration
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "org" (dict): Organization details and configuration
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_org_info()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        org_info = sdk.getOrgInfo()
        return {"org": org_info if org_info else {}}
        
    except Exception as e:
        logging.info(f"Error in get_org_info: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_org_info time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def list_api_keys(ctx: Context) -> dict[str, Any]:
    """List all API keys in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "keys" (list): List of API key information (without the actual key values)
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_api_keys()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        keys = sdk.getApiKeys()
        return {"keys": keys if keys else []}
        
    except Exception as e:
        logging.info(f"Error in list_api_keys: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_api_keys time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def create_api_key(
    key_name: str,
    permissions: list[str] = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Create a new API key
    
    Args:
        key_name (str): Name for the API key
        permissions (list[str]): Optional list of permissions for the key
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "key" (dict): API key information including the actual key value (only shown once)
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: create_api_key(key_name={json.dumps(key_name)}, permissions={json.dumps(permissions)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # Create the API key
        key_info = sdk.addApiKey(
            keyName=key_name,
            permissions=permissions if permissions else []
        )
        
        return {"key": key_info}
        
    except Exception as e:
        logging.info(f"Error in create_api_key: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"create_api_key time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_api_key(key_hash: str, ctx: Context) -> dict[str, Any]:
    """Delete an API key
    
    Args:
        key_hash (str): Hash of the API key to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_api_key(key_hash={json.dumps(key_hash)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        sdk.removeApiKey(key_hash)
        
        return {
            "success": True,
            "message": f"API key '{key_hash}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_api_key: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_api_key time: {time.time() - start} seconds")


# ============================================================================
# SPECIALIZED HIVE MANAGEMENT TOOLS
# ============================================================================

# ---------- YARA Management ----------

@mcp_tool_with_gcs()
def list_yara_rules(ctx: Context) -> dict[str, Any]:
    """List all YARA rules in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict): Dictionary of YARA rule names to rule content
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_yara_rules()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "yara")
        rules = hive.list()
        
        return {"rules": {k: v.toJSON() for k, v in rules.items()} if rules else {}}
        
    except Exception as e:
        logging.info(f"Error in list_yara_rules: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_yara_rules time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_yara_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific YARA rule
    
    Args:
        rule_name (str): Name of the YARA rule to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rule" (dict): YARA rule content and metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_yara_rule(rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "yara")
        rule = hive.get(rule_name)
        
        return {"rule": rule if rule else {}}
        
    except Exception as e:
        logging.info(f"Error in get_yara_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_yara_rule time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_yara_rule(
    rule_name: str,
    rule_content: str,
    tags: list[str] = None,
    platforms: list[str] = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Create or update a YARA rule
    
    Args:
        rule_name (str): Name for the YARA rule
        rule_content (str): YARA rule content (the actual YARA syntax)
        tags (list[str]): Optional tags to apply the rule to specific sensors
        platforms (list[str]): Optional platforms to restrict the rule to
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_yara_rule(rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "yara")
        
        # Build the rule data
        rule_data = {
            "rule": rule_content
        }
        if tags:
            rule_data["tags"] = tags
        if platforms:
            rule_data["platforms"] = platforms
        
        record = HiveRecord(rule_name, rule_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"YARA rule '{rule_name}' set successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_yara_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_yara_rule time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_yara_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a YARA rule
    
    Args:
        rule_name (str): Name of the YARA rule to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_yara_rule(rule_name={json.dumps(rule_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "yara")
        hive.delete(rule_name)
        
        return {
            "success": True,
            "message": f"YARA rule '{rule_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_yara_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_yara_rule time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def validate_yara_rule(rule_content: str) -> dict[str, Any]:
    """Validate YARA rule syntax
    
    Args:
        rule_content (str): YARA rule content to validate
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "valid" (bool): True if rule syntax is valid
            - "message" (str): Validation message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: validate_yara_rule()")
    
    try:
        # Try to import yara for validation
        try:
            import yara
            # Attempt to compile the rule
            yara.compile(source=rule_content)
            return {
                "valid": True,
                "message": "YARA rule syntax is valid"
            }
        except ImportError:
            # If yara module not available, do basic syntax check
            if "rule " in rule_content and "{" in rule_content and "}" in rule_content:
                return {
                    "valid": True,
                    "message": "Basic YARA syntax appears valid (full validation unavailable)"
                }
            else:
                return {
                    "valid": False,
                    "message": "YARA rule appears to have syntax errors"
                }
        except Exception as yara_error:
            return {
                "valid": False,
                "message": f"YARA validation error: {str(yara_error)}"
            }
            
    except Exception as e:
        logging.info(f"Error in validate_yara_rule: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"validate_yara_rule time: {time.time() - start} seconds")


# ---------- Lookup Tables ----------

@mcp_tool_with_gcs()
def list_lookups(ctx: Context) -> dict[str, Any]:
    """List all lookup tables in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "lookups" (dict): Dictionary of lookup names to their content
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_lookups()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "lookup")
        lookups = hive.list()
        
        return {"lookups": {k: v.toJSON() for k, v in lookups.items()} if lookups else {}}
        
    except Exception as e:
        logging.info(f"Error in list_lookups: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_lookups time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_lookup(lookup_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific lookup table
    
    Args:
        lookup_name (str): Name of the lookup table to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "lookup" (dict): Lookup table content and metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_lookup(lookup_name={json.dumps(lookup_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "lookup")
        lookup = hive.get(lookup_name)
        
        return {"lookup": lookup if lookup else {}}
        
    except Exception as e:
        logging.info(f"Error in get_lookup: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_lookup time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_lookup(
    lookup_name: str,
    lookup_data: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a lookup table
    
    Args:
        lookup_name (str): Name for the lookup table
        lookup_data (dict): Lookup table data (key-value pairs or list of items)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_lookup(lookup_name={json.dumps(lookup_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "lookup")
        
        record = HiveRecord(lookup_name, lookup_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Lookup table '{lookup_name}' set successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_lookup: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_lookup time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_lookup(lookup_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a lookup table
    
    Args:
        lookup_name (str): Name of the lookup table to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_lookup(lookup_name={json.dumps(lookup_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "lookup")
        hive.delete(lookup_name)
        
        return {
            "success": True,
            "message": f"Lookup table '{lookup_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_lookup: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_lookup time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def query_lookup(
    lookup_name: str,
    key: str,
    ctx: Context
) -> dict[str, Any]:
    """Query a value from a lookup table
    
    Args:
        lookup_name (str): Name of the lookup table
        key (str): Key to look up in the table
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "value" (Any): The value associated with the key
            - "found" (bool): Whether the key was found
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: query_lookup(lookup_name={json.dumps(lookup_name)}, key={json.dumps(key)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "lookup")
        lookup = hive.get(lookup_name)
        
        if not lookup:
            return {"error": f"Lookup table '{lookup_name}' not found"}
        
        # Check if it's a dict-based lookup or list-based
        if isinstance(lookup, dict) and "data" in lookup:
            data = lookup["data"]
            if isinstance(data, dict):
                if key in data:
                    return {"value": data[key], "found": True}
                else:
                    return {"value": None, "found": False}
            elif isinstance(data, list):
                # For list-based lookups, check if key is in the list
                found = key in data
                return {"value": key if found else None, "found": found}
        
        return {"value": None, "found": False}
        
    except Exception as e:
        logging.info(f"Error in query_lookup: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"query_lookup time: {time.time() - start} seconds")


# ---------- Saved Queries ----------

@mcp_tool_with_gcs()
def list_saved_queries(ctx: Context) -> dict[str, Any]:
    """List all saved LCQL queries
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "queries" (dict): Dictionary of query names to their content
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_saved_queries()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "query")
        queries = hive.list()
        
        return {"queries": {k: v.toJSON() for k, v in queries.items()} if queries else {}}
        
    except Exception as e:
        logging.info(f"Error in list_saved_queries: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_saved_queries time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_saved_query(query_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific saved query
    
    Args:
        query_name (str): Name of the saved query to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "query" (dict): Query content and metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_saved_query(query_name={json.dumps(query_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "query")
        query = hive.get(query_name)
        
        return {"query": query if query else {}}
        
    except Exception as e:
        logging.info(f"Error in get_saved_query: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_saved_query time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_saved_query(
    query_name: str,
    lcql_query: str,
    description: str = None,
    ctx: Context = None
) -> dict[str, Any]:
    """Save an LCQL query for later use
    
    Args:
        query_name (str): Name for the saved query
        lcql_query (str): The LCQL query string
        description (str): Optional description of what the query does
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_saved_query(query_name={json.dumps(query_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "query")
        
        query_data = {
            "query": lcql_query
        }
        if description:
            query_data["description"] = description
        
        record = HiveRecord(query_name, query_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Query '{query_name}' saved successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_saved_query: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_saved_query time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_saved_query(query_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a saved query
    
    Args:
        query_name (str): Name of the saved query to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_saved_query(query_name={json.dumps(query_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "query")
        hive.delete(query_name)
        
        return {
            "success": True,
            "message": f"Saved query '{query_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_saved_query: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_saved_query time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def run_saved_query(
    query_name: str,
    limit: int = 100,
    ctx: Context = None
) -> dict[str, Any]:
    """Execute a saved query
    
    Args:
        query_name (str): Name of the saved query to run
        limit (int): Maximum number of results to return (default 100)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "results" (list): Query results
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: run_saved_query(query_name={json.dumps(query_name)}, limit={limit})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        # First get the saved query
        from limacharlie import Hive
        hive = Hive(sdk, "query")
        query_data = hive.get(query_name)
        
        if not query_data:
            return {"error": f"Saved query '{query_name}' not found"}
        
        # Extract the LCQL query
        lcql_query = query_data.get("query", "")
        if not lcql_query:
            return {"error": "Saved query has no query content"}
        
        # Now run it using the existing run_lcql_query function
        return run_lcql_query(lcql_query, limit, ctx=ctx)
        
    except Exception as e:
        logging.info(f"Error in run_saved_query: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"run_saved_query time: {time.time() - start} seconds")


# ---------- Secrets Management ----------

@mcp_tool_with_gcs()
def list_secrets(ctx: Context) -> dict[str, Any]:
    """List all secret names (not values) in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "secrets" (list): List of secret names
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_secrets()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "secret")
        secrets = hive.list()
        
        # Only return the names, not the values
        secret_names = list(secrets.keys()) if secrets else []
        
        return {"secrets": secret_names}
        
    except Exception as e:
        logging.info(f"Error in list_secrets: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_secrets time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_secret(secret_name: str, ctx: Context) -> dict[str, Any]:
    """Get a secret value (use with caution)
    
    Args:
        secret_name (str): Name of the secret to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "secret" (dict): Secret metadata (value is masked in logs)
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    # Don't log the secret value
    logging.info(f"Tool called: get_secret(secret_name={json.dumps(secret_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "secret")
        secret = hive.get(secret_name)
        
        return {"secret": secret if secret else {}}
        
    except Exception as e:
        logging.info(f"Error in get_secret: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_secret time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_secret(
    secret_name: str,
    secret_value: str,
    ctx: Context
) -> dict[str, Any]:
    """Store a secret securely
    
    Args:
        secret_name (str): Name for the secret
        secret_value (str): The secret value to store
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    # Don't log the secret value
    logging.info(f"Tool called: set_secret(secret_name={json.dumps(secret_name)}, value=***)")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "secret")
        
        secret_data = {
            "secret": secret_value
        }
        
        record = HiveRecord(secret_name, secret_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Secret '{secret_name}' stored successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_secret: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_secret time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_secret(secret_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a secret
    
    Args:
        secret_name (str): Name of the secret to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_secret(secret_name={json.dumps(secret_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "secret")
        hive.delete(secret_name)
        
        return {
            "success": True,
            "message": f"Secret '{secret_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_secret: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_secret time: {time.time() - start} seconds")


# ---------- Playbooks ----------

@mcp_tool_with_gcs()
def list_playbooks(ctx: Context) -> dict[str, Any]:
    """List all playbooks in the organization
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "playbooks" (dict): Dictionary of playbook names to their content
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_playbooks()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "playbook")
        playbooks = hive.list()
        
        return {"playbooks": {k: v.toJSON() for k, v in playbooks.items()} if playbooks else {}}
        
    except Exception as e:
        logging.info(f"Error in list_playbooks: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_playbooks time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_playbook(playbook_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific playbook definition
    
    Args:
        playbook_name (str): Name of the playbook to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "playbook" (dict): Playbook content and metadata
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_playbook(playbook_name={json.dumps(playbook_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "playbook")
        playbook = hive.get(playbook_name)
        
        return {"playbook": playbook if playbook else {}}
        
    except Exception as e:
        logging.info(f"Error in get_playbook: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_playbook time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_playbook(
    playbook_name: str,
    playbook_data: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a playbook
    
    Args:
        playbook_name (str): Name for the playbook
        playbook_data (dict): Playbook definition (steps, conditions, actions)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_playbook(playbook_name={json.dumps(playbook_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "playbook")
        
        record = HiveRecord(playbook_name, playbook_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Playbook '{playbook_name}' set successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_playbook: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_playbook time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_playbook(playbook_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a playbook
    
    Args:
        playbook_name (str): Name of the playbook to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_playbook(playbook_name={json.dumps(playbook_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "playbook")
        hive.delete(playbook_name)
        
        return {
            "success": True,
            "message": f"Playbook '{playbook_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_playbook: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_playbook time: {time.time() - start} seconds")


# ---------- Cloud Sensors ----------

@mcp_tool_with_gcs()
def list_cloud_sensors(ctx: Context) -> dict[str, Any]:
    """List all cloud sensor configurations
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "cloud_sensors" (dict): Dictionary of cloud sensor names to their configs
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_cloud_sensors()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "cloud_sensor")
        cloud_sensors = hive.list()
        
        return {"cloud_sensors": {k: v.toJSON() for k, v in cloud_sensors.items()} if cloud_sensors else {}}
        
    except Exception as e:
        logging.info(f"Error in list_cloud_sensors: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_cloud_sensors time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_cloud_sensor(sensor_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific cloud sensor configuration
    
    Args:
        sensor_name (str): Name of the cloud sensor to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "cloud_sensor" (dict): Cloud sensor configuration
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_cloud_sensor(sensor_name={json.dumps(sensor_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "cloud_sensor")
        cloud_sensor = hive.get(sensor_name)
        
        return {"cloud_sensor": cloud_sensor if cloud_sensor else {}}
        
    except Exception as e:
        logging.info(f"Error in get_cloud_sensor: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_cloud_sensor time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_cloud_sensor(
    sensor_name: str,
    sensor_config: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a cloud sensor configuration
    
    Args:
        sensor_name (str): Name for the cloud sensor
        sensor_config (dict): Cloud sensor configuration data
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_cloud_sensor(sensor_name={json.dumps(sensor_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "cloud_sensor")
        
        record = HiveRecord(sensor_name, sensor_config, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Cloud sensor '{sensor_name}' configured successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_cloud_sensor: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_cloud_sensor time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_cloud_sensor(sensor_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a cloud sensor configuration
    
    Args:
        sensor_name (str): Name of the cloud sensor to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_cloud_sensor(sensor_name={json.dumps(sensor_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "cloud_sensor")
        hive.delete(sensor_name)
        
        return {
            "success": True,
            "message": f"Cloud sensor '{sensor_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_cloud_sensor: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_cloud_sensor time: {time.time() - start} seconds")


# ---------- External Adapters ----------

@mcp_tool_with_gcs()
def list_external_adapters(ctx: Context) -> dict[str, Any]:
    """List all external adapter configurations
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "adapters" (dict): Dictionary of adapter names to their configs
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_external_adapters()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "external_adapter")
        adapters = hive.list()
        
        return {"adapters": {k: v.toJSON() for k, v in adapters.items()} if adapters else {}}
        
    except Exception as e:
        logging.info(f"Error in list_external_adapters: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_external_adapters time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_external_adapter(adapter_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific external adapter configuration
    
    Args:
        adapter_name (str): Name of the adapter to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "adapter" (dict): Adapter configuration
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_external_adapter(adapter_name={json.dumps(adapter_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "external_adapter")
        adapter = hive.get(adapter_name)
        
        return {"adapter": adapter if adapter else {}}
        
    except Exception as e:
        logging.info(f"Error in get_external_adapter: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_external_adapter time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_external_adapter(
    adapter_name: str,
    adapter_config: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update an external adapter configuration
    
    Args:
        adapter_name (str): Name for the adapter
        adapter_config (dict): Adapter configuration data
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_external_adapter(adapter_name={json.dumps(adapter_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "external_adapter")
        
        record = HiveRecord(adapter_name, adapter_config, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"External adapter '{adapter_name}' configured successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_external_adapter: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_external_adapter time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_external_adapter(adapter_name: str, ctx: Context) -> dict[str, Any]:
    """Delete an external adapter configuration
    
    Args:
        adapter_name (str): Name of the adapter to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_external_adapter(adapter_name={json.dumps(adapter_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "external_adapter")
        hive.delete(adapter_name)
        
        return {
            "success": True,
            "message": f"External adapter '{adapter_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_external_adapter: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_external_adapter time: {time.time() - start} seconds")


# ---------- Extension Configuration ----------

@mcp_tool_with_gcs()
def list_extension_configs(ctx: Context) -> dict[str, Any]:
    """List all extension configurations
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "configs" (dict): Dictionary of extension names to their configs
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: list_extension_configs()")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "extension_config")
        configs = hive.list()
        
        return {"configs": {k: v.toJSON() for k, v in configs.items()} if configs else {}}
        
    except Exception as e:
        logging.info(f"Error in list_extension_configs: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"list_extension_configs time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def get_extension_config(extension_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific extension configuration
    
    Args:
        extension_name (str): Name of the extension to retrieve config for
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "config" (dict): Extension configuration
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: get_extension_config(extension_name={json.dumps(extension_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "extension_config")
        config = hive.get(extension_name)
        
        return {"config": config if config else {}}
        
    except Exception as e:
        logging.info(f"Error in get_extension_config: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"get_extension_config time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def set_extension_config(
    extension_name: str,
    config_data: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update an extension configuration
    
    Args:
        extension_name (str): Name of the extension
        config_data (dict): Extension configuration data
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: set_extension_config(extension_name={json.dumps(extension_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive, HiveRecord
        hive = Hive(sdk, "extension_config")
        
        record = HiveRecord(extension_name, config_data, api=hive)
        hive.set(record)
        
        return {
            "success": True,
            "message": f"Extension '{extension_name}' configured successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in set_extension_config: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"set_extension_config time: {time.time() - start} seconds")


@mcp_tool_with_gcs()
def delete_extension_config(extension_name: str, ctx: Context) -> dict[str, Any]:
    """Delete an extension configuration
    
    Args:
        extension_name (str): Name of the extension config to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    start = time.time()
    logging.info(f"Tool called: delete_extension_config(extension_name={json.dumps(extension_name)})")
    
    try:
        sdk = get_sdk_from_context(ctx)
        if sdk is None:
            return {"error": "No authentication provided"}
        
        from limacharlie import Hive
        hive = Hive(sdk, "extension_config")
        hive.delete(extension_name)
        
        return {
            "success": True,
            "message": f"Extension config '{extension_name}' deleted successfully"
        }
        
    except Exception as e:
        logging.info(f"Error in delete_extension_config: {str(e)}")
        return {"error": str(e)}
    finally:
        logging.info(f"delete_extension_config time: {time.time() - start} seconds")


# ---------- D&R Rules - Specific Hives ----------

@mcp_tool_with_gcs()
def list_dr_general_rules(ctx: Context) -> dict[str, Any]:
    """List all general D&R rules
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict): Dictionary of rule names to rule content
            - "error" (str): On failure, an error message string
    """
    return list_rules("dr-general", ctx)


@mcp_tool_with_gcs()
def get_dr_general_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific general D&R rule
    
    Args:
        rule_name (str): Name of the rule to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rule" (dict): Rule content and metadata
            - "error" (str): On failure, an error message string
    """
    return get_rule("dr-general", rule_name, ctx)


@mcp_tool_with_gcs()
def set_dr_general_rule(
    rule_name: str,
    rule_content: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a general D&R rule
    
    Args:
        rule_name (str): Name for the rule
        rule_content (dict): Rule content (detection and response)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return set_rule("dr-general", rule_name, rule_content, ctx)


@mcp_tool_with_gcs()
def delete_dr_general_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a general D&R rule
    
    Args:
        rule_name (str): Name of the rule to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return delete_rule("dr-general", rule_name, ctx)


@mcp_tool_with_gcs()
def list_dr_managed_rules(ctx: Context) -> dict[str, Any]:
    """List all managed D&R rules
    
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rules" (dict): Dictionary of rule names to rule content
            - "error" (str): On failure, an error message string
    """
    return list_rules("dr-managed", ctx)


@mcp_tool_with_gcs()
def get_dr_managed_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific managed D&R rule
    
    Args:
        rule_name (str): Name of the rule to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rule" (dict): Rule content and metadata
            - "error" (str): On failure, an error message string
    """
    return get_rule("dr-managed", rule_name, ctx)


@mcp_tool_with_gcs()
def set_dr_managed_rule(
    rule_name: str,
    rule_content: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a managed D&R rule
    
    Args:
        rule_name (str): Name for the rule
        rule_content (dict): Rule content (detection and response)
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return set_rule("dr-managed", rule_name, rule_content, ctx)


@mcp_tool_with_gcs()
def delete_dr_managed_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a managed D&R rule
    
    Args:
        rule_name (str): Name of the rule to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return delete_rule("dr-managed", rule_name, ctx)


# ---------- False Positive Rules ----------

@mcp_tool_with_gcs()
def get_fp_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Get a specific false positive rule
    
    Args:
        rule_name (str): Name of the FP rule to retrieve
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "rule" (dict): FP rule content and metadata
            - "error" (str): On failure, an error message string
    """
    return get_rule("fp", rule_name, ctx)


@mcp_tool_with_gcs()
def set_fp_rule(
    rule_name: str,
    rule_content: dict[str, Any],
    ctx: Context
) -> dict[str, Any]:
    """Create or update a false positive rule
    
    Args:
        rule_name (str): Name for the FP rule
        rule_content (dict): FP rule content
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if operation was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return set_rule("fp", rule_name, rule_content, ctx)


@mcp_tool_with_gcs()
def delete_fp_rule(rule_name: str, ctx: Context) -> dict[str, Any]:
    """Delete a false positive rule
    
    Args:
        rule_name (str): Name of the FP rule to delete
        
    Returns:
        dict[str, Any]: A dictionary containing either:
            - "success" (bool): True if deletion was successful
            - "message" (str): Status message
            - "error" (str): On failure, an error message string
    """
    return delete_rule("fp", rule_name, ctx)

# Ensure thread pool is properly shutdown on app termination
def cleanup_thread_pool():
    logging.info("Shutting down SDK thread pool...")
    SDK_THREAD_POOL.shutdown(wait=True)
    logging.info("SDK thread pool shutdown complete")

# Initialize MCP instances based on mode
# In STDIO mode, create a single MCP for the selected profile
# In HTTP mode, create multiple MCPs and mount at different paths
app = None

if PUBLIC_MODE:
    # HTTP Mode: Create MCPs for all profiles and mount at different paths
    from starlette.applications import Starlette
    from starlette.routing import Mount

    # Create MCP instances for each profile
    profile_mcps = {}
    available_profiles = ["all"] + [p for p in PROFILES.keys() if p != "core"]

    for profile in available_profiles:
        try:
            profile_mcps[profile] = create_mcp_for_profile(profile)
        except Exception as e:
            logging.error(f"Failed to create MCP for profile {profile}: {e}")

    # Create main Starlette app with profile-based routing
    from starlette.routing import Route, Mount as StarletteMount
    from starlette.datastructures import URL
    routes = []

    # Add profile-specific endpoints (mount with trailing slash only)
    for profile, profile_mcp in profile_mcps.items():
        if profile == "all":
            # Mount "all" profile at both /mcp and / for backward compatibility
            routes.append(Mount("/mcp", profile_mcp.streamable_http_app()))
            logging.info(f"Mounted 'all' profile at /mcp")
        else:
            # Mount other profiles at /<profile_name>/ with trailing slash
            routes.append(Mount(f"/{profile}/", profile_mcp.streamable_http_app()))
            logging.info(f"Mounted '{profile}' profile at /{profile}/")

    # Create root endpoint for health checks and profile listing

    async def root(request):
        profiles_info = {}
        for profile_name in available_profiles:
            tool_count = len(get_profile_tools(profile_name))
            if profile_name == "all":
                profiles_info[profile_name] = {
                    "path": "/mcp",
                    "tools": tool_count,
                    "description": "All available tools"
                }
            else:
                profiles_info[profile_name] = {
                    "path": f"/{profile_name}",
                    "tools": tool_count,
                    "description": f"Tools for {profile_name.replace('_', ' ')}"
                }

        return JSONResponse({
            "status": "ok",
            "type": "mcp-server",
            "profiles": profiles_info
        })

    routes.insert(0, Route("/", root, methods=["GET"]))

    # Create combined lifespan to manage all profile MCP session managers
    @contextlib.asynccontextmanager
    async def combined_lifespan(app):
        async with contextlib.AsyncExitStack() as stack:
            # Initialize all profile MCP session managers
            for profile, profile_mcp in profile_mcps.items():
                await stack.enter_async_context(profile_mcp.session_manager.run())
            yield

    # Create Starlette app with all routes
    base_app = Starlette(routes=routes, lifespan=combined_lifespan)

    # Add middleware to capture HTTP requests in contextvar
    base_app.add_middleware(RequestContextMiddleware)

    # Wrap the app with ASGI middleware that rewrites paths BEFORE routing
    # This prevents 307 redirects that break MCP connections
    class TrailingSlashMiddleware:
        def __init__(self, app, profile_paths):
            self.app = app
            self.profile_paths = profile_paths

        async def __call__(self, scope, receive, send):
            if scope["type"] == "http":
                path = scope["path"]
                # Check if this is a profile path without trailing slash
                if path in self.profile_paths:
                    # Rewrite the path to include trailing slash
                    scope = dict(scope)
                    scope["path"] = path + "/"
                    scope["raw_path"] = (path + "/").encode()

            await self.app(scope, receive, send)

    # Create list of profile paths to check
    profile_paths = [f"/{p}" for p in available_profiles if p != "all"]

    # Wrap the base app with trailing slash middleware
    app = TrailingSlashMiddleware(base_app, profile_paths)

    logging.info(f"HTTP mode initialized with {len(profile_mcps)} profiles")

else:
    # STDIO Mode: Create a single MCP for the selected profile
    # This will be used in the __main__ block below
    pass

# Main entry point for STDIO mode
if __name__ == "__main__":
    import logging
    import sys

    if not PUBLIC_MODE:
        # Configure logging for STDIO mode - all output must go to stderr
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[logging.StreamHandler(sys.stderr)]
        )

        # Important: In STDIO mode, stdout is reserved for JSON-RPC messages
        # All logging is configured to use stderr, and print statements have been
        # replaced with logging calls to avoid stdout contamination

        logging.info("Starting LimaCharlie MCP Server in STDIO mode (local usage)")
        logging.info(f"Selected profile: {MCP_PROFILE}")
        logging.info("PUBLIC_MODE is false - using local SDK authentication")

        # Create MCP instance for the selected profile
        try:
            mcp = create_mcp_for_profile(MCP_PROFILE)
            logging.info(f"MCP instance created for profile: {MCP_PROFILE}")
        except ValueError as e:
            logging.error(f"Invalid profile: {e}")
            sys.exit(1)

        # Run in STDIO mode for local usage (Claude Desktop/Code)
        mcp.run(transport="stdio")
    else:
        # HTTP mode is handled by uvicorn when PUBLIC_MODE=true
        # This block is here for completeness but won't be executed when
        # the server is run via uvicorn (uvicorn server:app)
        logging.info("PUBLIC_MODE is true - HTTP mode should be run via uvicorn")

atexit.register(cleanup_thread_pool)
