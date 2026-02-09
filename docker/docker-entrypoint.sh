#!/bin/sh
set -e

# Load configuration from JSON file if it exists
if [ -f "/app/config.json" ] && [ -f "/app/docker/parse-config.js" ]; then
    # Use Node.js to generate shell-safe export commands
    eval $(node /app/docker/parse-config.js /app/config.json)
fi

# Helper function for safe logging (prevents stdio mode corruption)
log_message() {
    [ "$MCP_MODE" != "stdio" ] && echo "$@"
}

# Environment variable validation
if [ "$MCP_MODE" = "http" ] && [ -z "$AUTH_TOKEN" ] && [ -z "$AUTH_TOKEN_FILE" ]; then
    log_message "ERROR: AUTH_TOKEN or AUTH_TOKEN_FILE is required for HTTP mode" >&2
    exit 1
fi

# Validate AUTH_TOKEN_FILE if provided
if [ -n "$AUTH_TOKEN_FILE" ] && [ ! -f "$AUTH_TOKEN_FILE" ]; then
    log_message "ERROR: AUTH_TOKEN_FILE specified but file not found: $AUTH_TOKEN_FILE" >&2
    exit 1
fi

# Database path configuration - respect NODE_DB_PATH if set
if [ -n "$NODE_DB_PATH" ]; then
    # Basic validation - must end with .db
    case "$NODE_DB_PATH" in
        *.db) ;;
        *) log_message "ERROR: NODE_DB_PATH must end with .db" >&2; exit 1 ;;
    esac
    
    # Use the path as-is (Docker paths should be absolute anyway)
    DB_PATH="$NODE_DB_PATH"
else
    DB_PATH="/app/data/nodes.db"
fi

DB_DIR=$(dirname "$DB_PATH")

# Ensure database directory exists with correct ownership
if [ ! -d "$DB_DIR" ]; then
    log_message "Creating database directory: $DB_DIR"
    if [ "$(id -u)" = "0" ]; then
        # Create as root but immediately fix ownership
        mkdir -p "$DB_DIR" && chown nodejs:nodejs "$DB_DIR"
    else
        mkdir -p "$DB_DIR"
    fi
fi

# OAuth database migrations (if enabled)
if [ "$ENABLE_OAUTH" = "true" ]; then
    log_message "Running OAuth database migrations..."

    # Ensure data directory exists with proper permissions
    if [ ! -d "/app/data" ]; then
        mkdir -p /app/data 2>/dev/null || {
            log_message "WARNING: Cannot create /app/data directory (permission denied)" >&2
            log_message "This is likely due to docker-compose 'user:' override." >&2
            log_message "Solution: Remove 'user: 1000:1000' from docker-compose or run as root" >&2
            exit 1
        }
    fi

    # Verify directory is writable
    if [ ! -w "/app/data" ]; then
        log_message "ERROR: /app/data directory is not writable" >&2
        log_message "Current user: $(id)" >&2
        log_message "Directory permissions: $(ls -ld /app/data)" >&2
        log_message "Solution: Remove 'user:' override from docker-compose or run as root" >&2
        exit 1
    fi

    # Run migrations using Node.js script (no CLI dependency needed)
    if [ -f "/app/docker/run-oauth-migrations.js" ]; then
        cd /app && node docker/run-oauth-migrations.js || {
            log_message "WARNING: OAuth migrations failed, OAuth features may not work" >&2
        }
    else
        log_message "WARNING: OAuth migration script not found, skipping migrations" >&2
    fi

    # Create admin user if credentials provided
    if [ -n "$OAUTH_ADMIN_EMAIL" ] && [ -n "$OAUTH_ADMIN_PASSWORD" ]; then
        if [ -f "/app/docker/create-admin-user.js" ]; then
            log_message "Creating OAuth admin user..."
            cd /app && node docker/create-admin-user.js || {
                log_message "ERROR: Admin user creation failed" >&2
                exit 1
            }
        else
            log_message "WARNING: Admin user creation script not found" >&2
        fi
    fi

    # Fix permissions on auth database if running as root
    if [ "$(id -u)" = "0" ] && [ -f "/app/data/auth.db" ]; then
        chown nodejs:nodejs /app/data/auth.db
    fi
fi

# Custom auth table migrations (user_instances)
if [ -f "/app/docker/run-auth-migrations.js" ]; then
    log_message "Running auth custom table migrations..."
    cd /app && node docker/run-auth-migrations.js || {
        log_message "WARNING: Auth custom table migrations failed" >&2
    }
fi

# Database validation helper function
validate_database() {
    local db_path="$1"
    # Simple validation: check if nodes table exists using sqlite3 or node
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$db_path" "SELECT COUNT(*) FROM nodes LIMIT 1;" >/dev/null 2>&1
        return $?
    else
        # Fallback: check file size (pre-built DB should be ~70MB)
        if [ -f "$db_path" ]; then
            db_size=$(stat -c%s "$db_path" 2>/dev/null || stat -f%z "$db_path" 2>/dev/null || echo "0")
            # If less than 1MB, it's likely corrupted or empty
            if [ "$db_size" -lt 1048576 ]; then
                return 1
            fi
        fi
        return 0
    fi
}

# Database initialization with file locking to prevent race conditions
DB_NEEDS_INIT=0
if [ ! -f "$DB_PATH" ]; then
    log_message "Database not found at $DB_PATH"
    DB_NEEDS_INIT=1
elif ! validate_database "$DB_PATH"; then
    log_message "Database at $DB_PATH is invalid or corrupted"
    DB_NEEDS_INIT=1
fi

if [ "$DB_NEEDS_INIT" = "1" ]; then
    # Ensure lock directory exists before attempting to create lock
    mkdir -p "$DB_DIR"

    # Check if flock is available
    if command -v flock >/dev/null 2>&1; then
        # Use a lock file to prevent multiple containers from initializing simultaneously
        LOCK_FILE="$DB_DIR/.db.lock"

        # Ensure we can create the lock file - fix permissions if running as root
        if [ "$(id -u)" = "0" ] && [ ! -w "$DB_DIR" ]; then
            chown nodejs:nodejs "$DB_DIR" 2>/dev/null || true
            chmod 755 "$DB_DIR" 2>/dev/null || true
        fi

        # Try to create lock file with proper error handling
        if touch "$LOCK_FILE" 2>/dev/null; then
            (
                flock -x 200
                # Double-check inside the lock
                if [ ! -f "$DB_PATH" ] || ! validate_database "$DB_PATH"; then
                    # Try to copy from pre-built template first (fast)
                    if [ -f "/app/data-template/nodes.db" ]; then
                        log_message "Copying pre-built database from template..."
                        cp /app/data-template/nodes.db "$DB_PATH" || {
                            log_message "ERROR: Failed to copy database template" >&2
                            exit 1
                        }
                        log_message "Database initialized from template successfully"
                    else
                        # Fallback to rebuild (slow, ~2 minutes)
                        log_message "Template not found, rebuilding database (this may take 2-3 minutes)..."
                        cd /app && NODE_DB_PATH="$DB_PATH" node dist/scripts/rebuild.js || {
                            log_message "ERROR: Database initialization failed" >&2
                            exit 1
                        }
                    fi
                fi
            ) 200>"$LOCK_FILE"
        else
            log_message "WARNING: Cannot create lock file, proceeding without file locking"
            # Fallback without locking
            if [ ! -f "$DB_PATH" ] || ! validate_database "$DB_PATH"; then
                if [ -f "/app/data-template/nodes.db" ]; then
                    log_message "Copying pre-built database from template..."
                    cp /app/data-template/nodes.db "$DB_PATH" || {
                        log_message "ERROR: Failed to copy database template" >&2
                        exit 1
                    }
                else
                    log_message "Template not found, rebuilding database..."
                    cd /app && NODE_DB_PATH="$DB_PATH" node dist/scripts/rebuild.js || {
                        log_message "ERROR: Database initialization failed" >&2
                        exit 1
                    }
                fi
            fi
        fi
    else
        # Fallback without locking (log warning)
        log_message "WARNING: flock not available, database initialization may have race conditions"
        if [ ! -f "$DB_PATH" ] || ! validate_database "$DB_PATH"; then
            if [ -f "/app/data-template/nodes.db" ]; then
                log_message "Copying pre-built database from template..."
                cp /app/data-template/nodes.db "$DB_PATH" || {
                    log_message "ERROR: Failed to copy database template" >&2
                    exit 1
                }
            else
                log_message "Template not found, rebuilding database..."
                cd /app && NODE_DB_PATH="$DB_PATH" node dist/scripts/rebuild.js || {
                    log_message "ERROR: Database initialization failed" >&2
                    exit 1
                }
            fi
        fi
    fi
fi

# Fix permissions if running as root (for development)
if [ "$(id -u)" = "0" ]; then
    log_message "Running as root, fixing permissions..."
    chown -R nodejs:nodejs "$DB_DIR"
    # Also ensure /app/data exists for backward compatibility
    if [ -d "/app/data" ]; then
        chown -R nodejs:nodejs /app/data
    fi
    # Switch to nodejs user with proper exec chain for signal propagation
    # Build the command to execute
    if [ $# -eq 0 ]; then
        # No arguments provided, use default CMD from Dockerfile
        set -- node /app/dist/mcp/index.js
    fi
    # Export all needed environment variables
    export MCP_MODE="$MCP_MODE"
    export NODE_DB_PATH="$NODE_DB_PATH"
    export AUTH_TOKEN="$AUTH_TOKEN"
    export AUTH_TOKEN_FILE="$AUTH_TOKEN_FILE"
    
    # Ensure AUTH_TOKEN_FILE has restricted permissions for security
    if [ -n "$AUTH_TOKEN_FILE" ] && [ -f "$AUTH_TOKEN_FILE" ]; then
        chmod 600 "$AUTH_TOKEN_FILE" 2>/dev/null || true
        chown nodejs:nodejs "$AUTH_TOKEN_FILE" 2>/dev/null || true
    fi
    # Use exec with su-exec for proper signal handling (Alpine Linux)
    # su-exec advantages:
    # - Proper signal forwarding (critical for container shutdown)
    # - No intermediate shell process
    # - Designed for privilege dropping in containers
    if command -v su-exec >/dev/null 2>&1; then
        exec su-exec nodejs "$@"
    else
        # Fallback to su with preserved environment
        # Use safer approach to prevent command injection
        exec su -p nodejs -s /bin/sh -c 'exec "$0" "$@"' -- sh -c 'exec "$@"' -- "$@"
    fi
fi

# Handle special commands
if [ "$1" = "n8n-mcp" ] && [ "$2" = "serve" ]; then
    # Set HTTP mode for "n8n-mcp serve" command
    export MCP_MODE="http"
    shift 2  # Remove "n8n-mcp serve" from arguments
    set -- node /app/dist/mcp/index.js "$@"
fi

# Export NODE_DB_PATH so it's visible to child processes
if [ -n "$DB_PATH" ]; then
    export NODE_DB_PATH="$DB_PATH"
fi

# Execute the main command directly with exec
# This ensures our Node.js process becomes PID 1 and receives signals directly
if [ "$MCP_MODE" = "stdio" ]; then
    # Debug: Log to stderr to check if wrapper exists
    if [ "$DEBUG_DOCKER" = "true" ]; then
        echo "MCP_MODE is stdio, checking for wrapper..." >&2
        ls -la /app/dist/mcp/stdio-wrapper.js >&2 || echo "Wrapper not found!" >&2
    fi
    
    if [ -f "/app/dist/mcp/stdio-wrapper.js" ]; then
        # Use the stdio wrapper for clean JSON-RPC output
        # exec replaces the shell with node process as PID 1
        exec node /app/dist/mcp/stdio-wrapper.js
    else
        # Fallback: run with explicit environment
        exec env MCP_MODE=stdio DISABLE_CONSOLE_OUTPUT=true LOG_LEVEL=error node /app/dist/mcp/index.js
    fi
else
    # HTTP mode or other
    if [ $# -eq 0 ]; then
        # No arguments provided, use default
        exec node /app/dist/mcp/index.js
    else
        exec "$@"
    fi
fi