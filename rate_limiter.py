"""
Rate Limiter for OAuth Endpoints

Provides DoS protection for OAuth endpoints using Redis-backed rate limiting.
Limits are applied per IP address to prevent:
- Authorization code enumeration
- Credential stuffing attacks
- OAuth state exhaustion
- Token endpoint abuse
"""

import os
import logging
import time
from typing import Optional
from starlette.requests import Request
from starlette.responses import JSONResponse


class RedisRateLimiter:
    """
    Redis-backed rate limiter with sliding window algorithm.

    SECURITY: Protects OAuth endpoints from abuse by limiting requests per IP.
    """

    def __init__(self, redis_client, requests_per_minute: int, window_size: int = 60):
        """
        Initialize rate limiter.

        Args:
            redis_client: Redis client instance (from oauth_state_manager)
            requests_per_minute: Maximum requests allowed per minute
            window_size: Time window in seconds (default 60)
        """
        self.redis_client = redis_client
        self.requests_per_minute = requests_per_minute
        self.window_size = window_size
        self.enabled = True

        # Load Lua script for atomic rate limit check
        # Uses sorted set with timestamp scores for sliding window
        self.rate_limit_script = self.redis_client.register_script("""
            local key = KEYS[1]
            local limit = tonumber(ARGV[1])
            local window = tonumber(ARGV[2])
            local now = tonumber(ARGV[3])
            local min_time = now - window

            -- Remove old entries outside the window
            redis.call('ZREMRANGEBYSCORE', key, '-inf', min_time)

            -- Count current requests in window
            local count = redis.call('ZCARD', key)

            if count < limit then
                -- Allow request: add to sorted set with current timestamp
                redis.call('ZADD', key, now, now)
                redis.call('EXPIRE', key, window)
                return {1, limit - count - 1}  -- {allowed, remaining}
            else
                -- Deny request: over limit
                return {0, 0}
            end
        """)

        logging.info(f"Rate limiter initialized: {requests_per_minute} requests per {window_size}s")

    def get_client_ip(self, request: Request) -> str:
        """
        Extract client IP from request.

        Checks X-Forwarded-For header first (for reverse proxy scenarios),
        falls back to direct client IP.

        Args:
            request: Starlette Request object

        Returns:
            Client IP address string
        """
        # Check X-Forwarded-For for proxied requests
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take first IP (client) from comma-separated list
            return forwarded.split(",")[0].strip()

        # Fall back to direct client IP
        client = request.client
        if client:
            return client.host

        # Default fallback (should never happen)
        return "unknown"

    def check_rate_limit(self, request: Request, endpoint_name: str) -> tuple[bool, int]:
        """
        Check if request is within rate limit.

        Args:
            request: Starlette Request object
            endpoint_name: Name of endpoint (for separate limits per endpoint)

        Returns:
            Tuple of (allowed: bool, remaining_requests: int)
        """
        if not self.enabled:
            return True, self.requests_per_minute

        try:
            client_ip = self.get_client_ip(request)
            key = f"rate_limit:{endpoint_name}:{client_ip}"
            now = int(time.time())

            # Execute atomic rate limit check
            result = self.rate_limit_script(
                keys=[key],
                args=[self.requests_per_minute, self.window_size, now]
            )

            allowed = bool(result[0])
            remaining = int(result[1])

            if not allowed:
                logging.warning(
                    f"Rate limit exceeded for {client_ip} on {endpoint_name}: "
                    f"{self.requests_per_minute} requests/{self.window_size}s"
                )

            return allowed, remaining

        except Exception as e:
            # SECURITY: Fail open on Redis errors to avoid DoS
            # (rate limiting failure shouldn't break the service)
            logging.error(f"Rate limit check failed: {e}, allowing request")
            return True, self.requests_per_minute

    def create_rate_limit_response(self, retry_after: int = 60) -> JSONResponse:
        """
        Create 429 Too Many Requests response.

        Args:
            retry_after: Seconds until client can retry

        Returns:
            JSONResponse with 429 status
        """
        return JSONResponse(
            status_code=429,
            content={
                "error": "too_many_requests",
                "error_description": f"Rate limit exceeded. Please retry after {retry_after} seconds."
            },
            headers={
                "Retry-After": str(retry_after),
                "X-RateLimit-Limit": str(self.requests_per_minute),
                "X-RateLimit-Remaining": "0",
                "X-RateLimit-Reset": str(int(time.time()) + retry_after)
            }
        )


# Rate limit configurations for different endpoint types
OAUTH_RATE_LIMITS = {
    # Authorization endpoint: moderate limit (users clicking login)
    "authorize": {"requests_per_minute": 10, "window_size": 60},

    # Callback endpoint: moderate limit (redirects from OAuth provider)
    "oauth_callback": {"requests_per_minute": 10, "window_size": 60},

    # Token endpoint: higher limit (legitimate refresh token usage)
    "token": {"requests_per_minute": 20, "window_size": 60},

    # Register endpoint: low limit (rare operation)
    "register": {"requests_per_minute": 5, "window_size": 60},

    # Revoke endpoint: moderate limit
    "revoke": {"requests_per_minute": 10, "window_size": 60},

    # Introspect endpoint: higher limit (may be called frequently)
    "introspect": {"requests_per_minute": 30, "window_size": 60}
}


def create_rate_limiter(redis_client, endpoint_name: str) -> Optional[RedisRateLimiter]:
    """
    Create a rate limiter for a specific endpoint.

    Args:
        redis_client: Redis client instance
        endpoint_name: Name of the endpoint (must be in OAUTH_RATE_LIMITS)

    Returns:
        RedisRateLimiter instance or None if endpoint not found
    """
    config = OAUTH_RATE_LIMITS.get(endpoint_name)
    if not config:
        logging.warning(f"No rate limit config for endpoint: {endpoint_name}")
        return None

    return RedisRateLimiter(
        redis_client=redis_client,
        requests_per_minute=config["requests_per_minute"],
        window_size=config["window_size"]
    )


async def rate_limit_middleware(request: Request, call_next, rate_limiter: RedisRateLimiter, endpoint_name: str):
    """
    Middleware to enforce rate limiting on requests.

    Args:
        request: Starlette Request object
        call_next: Next handler in the chain
        rate_limiter: RedisRateLimiter instance
        endpoint_name: Name of the endpoint being accessed

    Returns:
        Response from handler or 429 Too Many Requests
    """
    allowed, remaining = rate_limiter.check_rate_limit(request, endpoint_name)

    if not allowed:
        return rate_limiter.create_rate_limit_response()

    # Add rate limit headers to successful response
    response = await call_next(request)
    response.headers["X-RateLimit-Limit"] = str(rate_limiter.requests_per_minute)
    response.headers["X-RateLimit-Remaining"] = str(remaining)
    response.headers["X-RateLimit-Reset"] = str(int(time.time()) + rate_limiter.window_size)

    return response
