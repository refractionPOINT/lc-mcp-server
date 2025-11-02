# Python LimaCharlie SDK Exploration Report

## Overview

The python-limacharlie SDK is a comprehensive Python wrapper around the LimaCharlie EDR platform API. It provides object-oriented abstractions for managing sensors, organizations, detections, and security configurations.

---

## 1. Main SDK Classes

### 1.1 Manager Class
**Location:** `/home/maxime/goProject/github.com/refractionPOINT/python-limacharlie/limacharlie/Manager.py`

**Purpose:** Primary interface for interacting with a LimaCharlie Organization

**Key Constructor Parameters:**
- `oid` (str): Organization ID (UUID)
- `secret_api_key` (str): API key for authentication
- `environment` (str): Environment name from credentials file
- `uid` (str): User ID (enables multi-org mode)
- `jwt` (str): Optional pre-generated JWT token
- `oauth_creds` (dict): OAuth credentials with 'id_token', 'refresh_token', 'provider'
- `is_interactive` (bool): Enable real-time task tracking via Spout
- `inv_id` (str): Investigation ID to propagate to tasks
- `isRetryQuotaErrors` (bool): Automatically retry on quota exceeded (HTTP 429)

**Authentication Support:**
1. API Key: `secret_api_key` parameter
2. OAuth: `oauth_creds` parameter with Firebase JWT support
3. Pre-generated JWT: Direct `jwt` parameter
4. Environment-based: Reads from `~/.limacharlie` YAML config

**Core Public Methods:**

#### Organization/User Level (Non-OID dependent)
- `userAccessibleOrgs(offset, limit, filter, sort_by, sort_order, with_names)` 
  - Returns: `{"orgs": [oid_list], "names": {oid: name_map}}`
  - Lists all organizations accessible to the authenticated user

#### Organization Level (OID-dependent)
- `getOrgInfo()` 
  - Returns: Full org configuration dict (name, settings, features, etc.)

- `sensor(sid, inv_id, detailedInfo)` 
  - Returns: `Sensor` object
  - Gets a single sensor by ID

- `sensors(inv_id, selector, limit, with_ip, with_hostname_prefix)` 
  - Returns: Generator of `Sensor` objects
  - Pagination via continuation tokens
  - Supports filtering by selector expression, IP, or hostname prefix

- `sensorsWithTag(tag)` 
  - Returns: List of `Sensor` objects with matching tag

- `getAllOnlineSensors(onlySIDs)`
  - Returns: List of online sensor IDs (strings)

- `getAllTags()` 
  - Returns: List of tag strings in use

- `getSensorsWithHostname(hostnamePrefix, as_dict)`
  - Returns: Dict or list of Sensor objects
  - Searches by hostname prefix

- `getSensorsWithIp(ip, start, end)` 
  - Returns: List of sensor data with IP
  - Requires time range (7-day window typical)

#### Object/IOC Queries (Insight-dependent)
- `getObjectInformation(objType, objName, info, isCaseSensitive, isWithWildcards, limit, isPerObject)`
  - Args:
    - objType: 'user', 'domain', 'ip', 'file_hash', 'file_path', 'file_name', 'service_name', 'package_name'
    - info: 'summary' or 'locations'
  - Returns: Dict with requested information

- `getBatchObjectInformation(objects, isCaseSensitive)`
  - Args:
    - objects: Dict[str, List[str]] = {"file_name": ["a.exe", "b.exe"], "ip": ["192.168.1.1"]}
  - Returns: Dict with time ranges as keys {"last_1_days": {...}, "last_7_days": {...}, "last_30_days": {...}}

- `getInsightHostCountPerPlatform()`
  - Returns: Dict with "mac", "windows", "linux" keys containing (1_day, 7_day, 30_day) tuples

#### Detection/Audit Queries
- `getHistoricDetections(start, end, limit, cat)`
  - Returns: Generator of detection dicts
  - Cursor-based pagination

- `getAuditLogs(start, end, limit, event_type, sid)`
  - Returns: Generator of audit log entries
  - Cursor-based pagination

- `getHistoricDetectionByID(detect_id)`
  - Returns: Single detection dict

#### Configuration Management
- `getOrgConfig(configName)`
  - Returns: Configuration value

- `setOrgConfig(configName, value)`
  - Sets organization configuration

- `getOrgURLs()`
  - Returns: Dict of service URLs

#### API/User Management
- `getApiKeys()`
  - Returns: List of API keys

- `getUsers()`
  - Returns: List of user dicts

- `getUserPermissions()`
  - Returns: List of user permission dicts

- `getGroups()`
  - Returns: List of group objects

- `getSubscriptions()`
  - Returns: Dict of subscribed services/resources

#### Installation Keys
- `get_installation_keys()`
  - Returns: List of installation key dicts

- `create_installation_key(tags, desc, iid, quota, use_public_root_ca)`
  - Returns: Created key dict

- `delete_installation_key(iid)`
  - Deletes an installation key

#### System Information
- `getUsageStats()`
  - Returns: Dict with usage statistics

- `getOntology()`
  - Returns: Dict with EDR event ontology

- `getEDREventList()`
  - Returns: Dict of all possible EDR events with IDs

- `getSchemas(platform)`
  - Returns: List of event schemas

- `getMITREReport()`
  - Returns: MITRE ATT&CK coverage report

- `get_cve_list(product, version, include_details)`
  - Returns: List of CVEs for product

#### Organization Management
- `createNewOrg(name, location, template)`
  - Returns: New org dict with OID

- `renameOrg(newName)`
  - Renames current organization

- `deleteOrg(oid, withConfirmation)`
  - Deletes an organization

---

### 1.2 Sensor Class
**Location:** `/home/maxime/goProject/github.com/refractionPOINT/python-limacharlie/limacharlie/Sensor.py`

**Purpose:** Represents a single endpoint/sensor running LimaCharlie agent

**Constructor Parameters:**
- `manager`: Manager instance
- `sid`: Sensor ID (UUID string)
- `detailedInfo`: Optional pre-fetched sensor information dict

**Platform Constants:**
- `_PLATFORM_WINDOWS = 0x10000000`
- `_PLATFORM_LINUX = 0x20000000`
- `_PLATFORM_MACOS = 0x30000000`
- `_PLATFORM_IOS = 0x40000000`
- `_PLATFORM_ANDROID = 0x50000000`
- `_PLATFORM_CHROMEOS = 0x60000000`

**Architecture Constants:**
- `_ARCHITECTURE_X86 = 0x00000001`
- `_ARCHITECTURE_X64 = 0x00000002`
- `_ARCHITECTURE_ARM = 0x00000003`
- `_ARCHITECTURE_ARM64 = 0x00000004`
- `_ARCHITECTURE_ALPINE64 = 0x00000005`
- `_ARCHITECTURE_CHROME = 0x00000006`

**Core Methods:**

#### Information Retrieval
- `getInfo()`
  - Returns: Dict with keys: plat, arch, hostname, is_isolated, should_isolate, is_sealed, should_seal
  - Platform/arch values converted to strings ('windows', 'linux', 'macos', 'x86', 'x64', etc.)

- `getTags()`
  - Returns: List/dict-like of tag strings

- `isOnline()`
  - Returns: Boolean

- `isWindows()`, `isMac()`, `isLinux()`, `isChrome()`, `isChromeOS()`
  - Returns: Boolean platform checks

- `hostname()`
  - Returns: Hostname string

#### Task Execution
- `task(tasks, inv_id)`
  - Args: tasks as string or list of strings in command-line format
  - Returns: REST API response dict
  - Sends async task(s) to sensor

- `request(tasks)`
  - Returns: FutureResults object
  - For use with interactive Manager (is_interactive=True)
  - Allows tracking responses in real-time via Spout

- `simpleRequest(tasks, timeout, until_completion)`
  - Returns: Single event dict, list of events, or None
  - Blocking wait for sensor response

#### Tag Management
- `tag(tag, ttl)`
  - Args: tag (str or list), ttl (optional seconds)
  - Returns: API response dict

- `untag(tag)`
  - Returns: API response dict

#### Historical Data (Insight/Retention)
- `getHistoricEvents(start, end, limit, eventType, isForward, outputName)`
  - Returns: Generator of event dicts
  - Cursor-based pagination
  - Unix timestamps (seconds)

- `getHistoricOverview(start, end)`
  - Returns: List of timestamps where data is available
  - Useful for finding gaps in data

- `isDataAvailableFor(timestamp)`
  - Returns: Boolean

- `getRetainedEventCount(startTime, endTime, isDetailed)`
  - Returns: Event count dict

- `getChildrenEvents(atom)`
  - Returns: List of child events

- `getEventByAtom(atom)`
  - Returns: Single event dict

- `getObjectTimeline(start, end, bucketing, onlyTypes)`
  - Returns: Timeline dict grouped by bucketing (day/hour/minute)

---

### 1.3 Billing Class
**Location:** `/home/maxime/goProject/github.com/refractionPOINT/python-limacharlie/limacharlie/Billing.py`

**Purpose:** Manage billing and subscription information

**Constructor:** `Billing(manager)`

**Methods:**
- `getOrgStatus()`
  - Returns: Organization billing status dict

- `getOrgDetails()`
  - Returns: Organization details including plan, usage, etc.

- `getOrgInvoiceURL(year, month, format)`
  - Returns: Invoice download URL dict

- `getAvailablePlans()`
  - Returns: Dict with available plan configurations
  - Keys: "plans" -> List of plan dicts with Datacenter/Region info

- `getUserAuthRequirements()`
  - Returns: Auth requirement flags

- `getSkuDefinitions()`
  - Returns: Dict of SKU pricing and definitions

---

### 1.4 Model Class
**Location:** `/home/maxime/goProject/github.com/refractionPOINT/python-limacharlie/limacharlie/Model.py`

**Purpose:** Manage custom data models in LimaCharlie

**Constructor:** `Model(manager, modelName)`

**Methods:**
- `get(primary_key)`
  - Returns: Single record dict

- `mget(index_key_name, index_key_value)`
  - Returns: List of matching records

- `add(primary_key, fields, expiry)`
  - Creates/updates record

- `delete(primary_key)`
  - Deletes a record

- `query(start_model_name, start_index_key_name, start_index_key_value, plan)`
  - Returns: Query result following relational plan

- `list(limit, show_expiry, cursor)`
  - Returns: Paginated list of records with cursor

---

### 1.5 Replay Class
**Location:** `/home/maxime/goProject/github.com/refractionPOINT/python-limacharlie/limacharlie/Replay.py`

**Purpose:** Execute Detection & Response rules against historical data

**Constructor:** `Replay(manager)`

**Core Methods:**
- `scanEntireOrg(startTime, endTime, ruleName, namespace, ruleContent, isRunTrace, limitEvent, limitEval, isStateful, isDryRun, stream)`
  - Returns: ResultsIterator of events matching rule

- `scanHistoricalSensor(sid, startTime, endTime, ruleName, namespace, ruleContent, isRunTrace, limitEvent, limitEval, isStateful, isDryRun, stream)`
  - Returns: ResultsIterator for single sensor

- `scanEvents(events, ruleName, namespace, ruleContent, isRunTrace, limitEvent, limitEval, isDryRun, stream)`
  - Replays rule against provided event list

- `validateRule(ruleContent)`
  - Returns: Validation result dict

**Return Types:**
- `ResultsIterator`: Iterable over matching events
  - Lazy evaluation, suitable for large result sets

---

### 1.6 Configs Class
**Location:** `/home/maxime/goProject/python-limacharlie/limacharlie/Configs.py`

**Purpose:** Manage Detection & Response configurations (Rules, Outputs, Responses, etc.)

**Constructor:** `Configs(oid, env, manager, isDontUseInfraService, isUseExtension)`

**Key Features:**
- Infrastructure-as-Code support (YAML-based)
- Rule management (Detection & Response rules)
- Output configuration (Syslog, S3, Splunk, etc.)
- Integrity monitoring
- File exfiltration policies
- Logging rules
- False positive rules

---

### 1.7 Search Class
**Location:** `/home/maxime/goProject/python-limacharlie/limacharlie/Search.py`

**Purpose:** Cross-organization IOC searching

**Constructor:** `Search(environments, output)`

**Valid IOC Types:**
- 'file_hash'
- 'file_name'
- 'file_path'
- 'ip'
- 'domain'
- 'user'
- 'service_name'
- 'package_name'

**Methods:**
- `query(iocType, iocName, info, isCaseInsensitive, isWithWildcards, limit, isPerIoc)`
  - Returns: Generator of results across all configured environments
  - Threading-based parallel environment querying

---

## 2. Data Structures and Return Types

### 2.1 Sensor Information
```python
{
    'sid': str,                    # Sensor UUID
    'hostname': str,               # Computer name
    'plat': int,                   # Platform constant (converted to string in getInfo())
    'arch': int,                   # Architecture constant (converted to string in getInfo())
    'last_seen': int,              # Unix timestamp
    'last_ip': str,                # Last known IP
    'is_isolated': bool,           # Network isolation status
    'should_isolate': bool,        # Desired isolation state
    'is_sealed': bool,             # Process sealing status
    'should_seal': bool,           # Desired sealing state
    'version': str,                # Sensor version
    'tags': dict,                  # Tag->TTL mapping
}
```

### 2.2 Organization Information
```python
{
    'oid': str,                    # Organization UUID
    'name': str,                   # Org name
    'description': str,            # Org description
    'plan': str,                   # Service plan
    'data_retention_days': int,    # Retention period
    'sensor_count': int,           # Number of sensors
    'features': {                  # Enabled features
        'feature_name': bool,
        ...
    },
    'urls': {                      # Service URLs
        'api': str,
        'dashboard': str,
        ...
    }
}
```

### 2.3 Detection/Alert
```python
{
    'dt': int,                     # Detection timestamp (unix seconds)
    'id': str,                     # Detection ID
    'sid': str,                    # Sensor ID
    'hostname': str,               # Sensor hostname
    'cat': str,                    # Category/Rule name
    'md5': str,                    # Process hash (some cases)
    'source': str,                 # Rule source
    'level': int,                  # Severity level
    'reason': str,                 # Rule description
    'data': dict,                  # Event data (varies by rule)
}
```

### 2.4 Historic Events
```python
{
    'routing': {
        'event_type': str,         # 'WinExec', 'ChildProcess', etc.
        'event_id': int,           # Event type ID
        'event_time': int,         # Timestamp (unix seconds)
        'parent': str,             # Parent process path
        'hostname': str,
    },
    'event': {
        # Event-type specific fields
        # Examples:
        'COMMAND_LINE': str,       # For process creation
        'IMAGE_PATH': str,         # For process execution
        'HASH': str,               # Process hash (sometimes)
        'PATH': str,               # File path
        'USER_NAME': str,          # User executing action
        ...
    }
}
```

Wrapped with `_enhancedDict` providing:
- `.getOne(path)`: Get single value at path (e.g., "event/COMMAND_LINE")
- `.getAll(path)`: Get all values matching path (supports wildcards)

### 2.5 Batch Object Information Results
```python
{
    'last_1_days': {
        'file_name': {
            'file.exe': 5,         # Sensor count
            'other.dll': 2,
        },
        'ip': {
            '192.168.1.1': 3,
        },
    },
    'last_7_days': {...},
    'last_30_days': {...},
}
```

### 2.6 Job/Task Response
```python
{
    'job_id': str,                 # Job/Task ID
    'status': str,                 # 'pending', 'in_progress', 'complete', 'error'
    'result': dict,                # Response data
    'error': str,                  # Error message if failed
    'received': bool,              # Whether sensor acknowledged
}
```

---

## 3. MCP Tool Mappings

The lc-mcp-server implements these SDK methods as MCP tools:

### 3.1 Sensor Management Tools

**Tool: `list_sensors`**
- Maps to: `Manager.sensors()`, `Manager.getSensorsWithHostname()`, `Manager.getSensorsWithIp()`
- Parameters: limit, with_hostname_prefix, with_ip, selector, with_tags
- Returns: `{"sensors": [sensor_info_dicts]}`

**Tool: `get_sensor_info`**
- Maps to: `Manager.sensor()`, `Sensor.getInfo()`, `Sensor.isOnline()`, `Sensor.getTags()`
- Parameters: sid (sensor UUID)
- Returns: `{"sensor": {detailed_sensor_dict}}`

**Tool: `get_online_sensors`**
- Maps to: `Manager.getAllOnlineSensors()`
- Returns: `{"sensors": [sid_strings]}`

### 3.2 Organization Management Tools

**Tool: `list_user_orgs`**
- Maps to: `Manager.userAccessibleOrgs()`
- Returns: `{"orgs": {"orgs": [oid_list], "names": {oid: name_map}}}`
- Note: User-level operation, no OID required

**Tool: `get_org_info`**
- Maps to: `Manager.getOrgInfo()`
- Returns: `{"org": {org_dict}}`

**Tool: `create_org`**
- Maps to: `Manager.createNewOrg()`
- Parameters: name, location, template
- Returns: `{"org": {new_org_dict}}`
- Note: User-level operation, requires UID authentication

### 3.3 IOC/Object Search Tools

**Tool: `batch_search_iocs`**
- Maps to: `Manager.getBatchObjectInformation()`
- Input transformation: List[dict] -> Dict[str, List[str]]
  - From: `[{"type": "hash", "name": "abc123", "info": "summary"}]`
  - To: `{"hash": ["abc123"]}`
- Returns: `{"results": {time_range: {obj_type: {obj_name: count}}}}`

### 3.4 Administrative Tools

**Tool: `get_usage_stats`**
- Maps to: `Manager.getUsageStats()`
- Returns: `{"stats": {usage_dict}}`

**Tool: `get_org_invoice_url`**
- Maps to: `Billing.getOrgInvoiceURL()`
- Parameters: year, month, format
- Returns: `{"invoice": {"url": str}}`

---

## 4. Authentication and Context Management

### 4.1 Manager Authentication Hierarchy
1. **OAuth (Preferred)**
   - Uses Firebase JWT tokens
   - Auto-renewal on expiry
   - Multi-factor authentication support
   - Credentials: `~/.limacharlie` with oauth dict

2. **API Key**
   - Traditional UUID-based key
   - Long-lived, requires secure storage
   - No auto-renewal

3. **Pre-generated JWT**
   - Direct token passing
   - Useful for short-lived operations

### 4.2 SDK Context Management (in MCP Server)

**Context-based SDK Retrieval:**
```python
def get_sdk_from_context(ctx: Context) -> Manager | None:
    """
    Extracts auth info from context and creates SDK.
    
    In UID mode (x-lc-uid header):
      - Returns None
      - Wrapper creates per-tool SDK with OID
      
    In normal mode:
      - Creates and returns SDK instance
      - OAuth token validation (if MCP OAuth enabled)
      - API key fallback
    """
```

**Authentication Methods in MCP Server:**
1. Normal mode: Single OID + API Key/OAuth
2. UID mode: Multi-org with per-tool OID specification
3. OAuth: Firebase identity + refresh tokens
4. UID Auth context: Stored in contextvars for multi-org operations

---

## 5. API Utilities and Base Methods

### 5.1 HTTP Verbs (from utils.py)
```python
GET = 'GET'       # Data retrieval
POST = 'POST'     # Data submission/creation
DELETE = 'DELETE' # Resource deletion
PUT = 'PUT'       # Full resource replacement
PATCH = 'PATCH'   # Partial resource update
HEAD = 'HEAD'     # Metadata only
```

### 5.2 Base API Call Pattern

**Method:** `Manager._apiCall(endpoint, method, params, queryParams, altRoot)`

**Behavior:**
- Routes through JWT authentication layer
- Handles HTTP 401 (token refresh)
- Supports query parameters (URL-encoded)
- Supports request body (JSON-encoded)
- Handles HTTP 429 (quota exceeded) with optional retry
- Compresses data with zlib for large payloads
- Returns parsed JSON response

### 5.3 Enhanced Dictionary Features

Events and complex responses wrapped with `_enhancedDict`:
```python
event.getOne('event/COMMAND_LINE')  # Get single value
event.getAll('event/*')              # Get all fields in event
event.getAll('*/hostname')           # Get hostname from any level
```

---

## 6. Special Features

### 6.1 Interactive Mode
**Purpose:** Real-time task tracking without polling

**Setup:**
```python
manager = Manager(oid, api_key, is_interactive=True, inv_id='investigation-uuid')
sensor = manager.sensor(sid)

future = sensor.request('process list')  # Returns FutureResults
responses = future.getNewResponses(timeout=30)
```

**Components:**
- Spout: WebSocket connection for event streaming
- FutureResults: Thread-safe promise pattern
- Investigation ID: Correlation ID across task submissions

### 6.2 Pagination Handling
**Cursor-based pagination:**
- Historic events: continuation_token in response
- Sensors: continuation_token in response
- Detections: next_cursor in response

**Automatic iteration:**
```python
for event in sensor.getHistoricEvents(start, end):
    # Generator automatically handles pagination
    pass
```

### 6.3 Compressed Data Handling
**Large result sets:**
- Compressed with zlib + base64 encoding
- Automatically unwrapped by `Manager._unwrap()`
- Used for: events, detections, audit logs

### 6.4 Time Range Parameters
- Unix timestamps in **seconds** (not milliseconds)
- All historic queries: `start` (inclusive) to `end` (inclusive)
- Typical windows: 1 day, 7 days, 30 days

---

## 7. Error Handling

### 7.1 Exception Types

**LcApiException:**
```python
class LcApiException(Exception):
    def __init__(self, message, code=None):
        self.message = message
        self.code = code  # HTTP status code
```

**Common error codes:**
- 401: Unauthorized (JWT expired, invalid API key)
- 403: Forbidden (insufficient permissions)
- 404: Not found (invalid OID, SID, resource)
- 429: Too many requests (quota exceeded)
- 500+: Server errors

### 7.2 Retry Behavior
- `isRetryQuotaErrors=True`: Automatic retry on HTTP 429
- JWT expiry: Automatic refresh on HTTP 401
- Rate limiting: Configurable backoff

---

## 8. Key Implementation Details

### 8.1 SDK Version
Current: 4.10.2

### 8.2 Configuration File Format
Location: `~/.limacharlie` (YAML)

**API Key format:**
```yaml
oid: "your-org-uuid"
uid: "your-user-uuid"  # Optional
api_key: "your-api-key-uuid"
env:
  default:
    oid: "org-uuid"
    api_key: "key-uuid"
  production:
    oid: "prod-org-uuid"
    api_key: "prod-key-uuid"
```

**OAuth format:**
```yaml
uid: "your-user-uuid"
oauth:
  id_token: "firebase-jwt"
  refresh_token: "firebase-refresh"
  provider: "google"  # or "microsoft"
```

### 8.3 Platform Detection
```python
PLATFORM_MAP = {
    0x10000000: 'windows',
    0x20000000: 'linux',
    0x30000000: 'macos',
    0x40000000: 'ios',
    0x50000000: 'android',
    0x60000000: 'chromeos',
}

ARCHITECTURE_MAP = {
    0x00000001: 'x86',
    0x00000002: 'x64',
    0x00000003: 'arm',
    0x00000004: 'arm64',
    0x00000005: 'alpine64',
    0x00000006: 'chrome',
}
```

### 8.4 Root Endpoints
- **Main API:** `https://api.limacharlie.io/v1`
- **JWT Service:** `https://jwt.limacharlie.io`
- **Billing API:** `https://billing.limacharlie.io`
- **Replay Engine:** Various regional endpoints

---

## Summary

The python-limacharlie SDK provides:

1. **Object-oriented abstraction** over REST APIs (Manager, Sensor, Billing, etc.)
2. **Flexible authentication** (API key, OAuth, JWT, multi-org)
3. **Streaming and pagination** for large result sets
4. **Real-time task tracking** via interactive mode
5. **Cross-cutting features** (investigation IDs, compression, retry logic)
6. **Type-safe data structures** with helper methods for event navigation

The MCP server wraps these into a tool interface, mapping each tool to one or more SDK methods and transforming input/output formats as needed.

