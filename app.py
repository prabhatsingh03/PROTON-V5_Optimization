from flask import Flask, request, jsonify, render_template, send_from_directory, send_file, g, redirect, url_for, flash
from datetime import datetime, timedelta, date, timezone
import warnings
import os
import io
import zipfile  
import json
import pandas as pd
import math
import hashlib
from deep_translator import GoogleTranslator
import razorpay
import hmac
import uuid
try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:  # pragma: no cover - optional dependency
    mysql = None
    MySQLError = Exception
import threading
import functools
import logging
from google import genai
from flask_jwt_extended import JWTManager, create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt, get_jwt_header, verify_jwt_in_request
from flask_jwt_extended.exceptions import JWTExtendedException, NoAuthorizationError, InvalidHeaderError
import re  # For regex validation
import secrets  # For secure token generation
import unicodedata  # For transliteration of non-ASCII characters
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib import colors
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT
from io import BytesIO
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from cryptography.fernet import Fernet
from dotenv import load_dotenv
import bleach
from werkzeug.security import safe_join
import atexit
import signal
try:
    from apscheduler.schedulers.background import BackgroundScheduler
    from apscheduler.triggers.cron import CronTrigger
    APSCHEDULER_AVAILABLE = True
except ImportError:
    APSCHEDULER_AVAILABLE = False
    BackgroundScheduler = None
    CronTrigger = None
from config import (
    DB_TYPE,
    MYSQL_HOST,
    MYSQL_PORT,
    MYSQL_USER,
    MYSQL_PASSWORD,
    MYSQL_PRIMARY_DATABASE,
    MYSQL_CHARSET,
    MYSQL_POOL_SIZE,
    MYSQL_POOL_RECYCLE,
    SMTP_FROM_EMAIL,
    SMTP_FROM_NAME,
    SMTP_HOST,
    SMTP_PASSWORD,
    SMTP_PORT,
    SMTP_USERNAME,
    OTP_EXPIRY_MINUTES,
    OTP_MAX_ATTEMPTS,
    RESET_TOKEN_EXPIRY_HOURS,
    SUPERADMIN_EMAIL,
    SUPERADMIN_PASSWORD,
    GEMINI_API_KEY,
    CHATBOT_GEMINI_API_KEY,
)
from utils.db_utils import (
    convert_query_placeholders,
    execute_primary_query,
    execute_primary_transaction,
    get_primary_db_connection,
    get_db_connection as base_get_db_connection,
    get_tenant_db_name,
)
from utils.email_service import (
    send_otp_email, 
    send_password_reset_email,
    send_payment_success_email,
    send_payment_failed_email,
    send_subscription_activated_email
)
DEV_MODE = os.getenv('DEV_MODE', 'false').lower() == 'true'
load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=24)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024

# CORS configuration
CORS(
    app,
    origins=os.environ.get('ALLOWED_ORIGINS', 'http://protonv5.simonindia.ai').split(','),
    methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allow_headers=['Content-Type', 'Authorization', 'X-Org-ID'],
    expose_headers=['Content-Disposition'],
    supports_credentials=True,
    max_age=3600
)

# Limiter configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["1000 per hour"],
    storage_uri=os.environ.get('RATE_LIMIT_STORAGE', 'memory://'),
    strategy="fixed-window"
)

def get_user_id_for_rate_limit():
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        return claims.get('user_id', get_remote_address())
    except Exception:
        return get_remote_address()

@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        "status": "error",
        "error_code": "RATE_LIMIT_EXCEEDED",
        "message": "Too many requests. Please try again later.",
        "retry_after": getattr(e, 'description', None)
    }), 429

@app.errorhandler(413)
def request_entity_too_large(error):
    return jsonify({
        "status": "error",
        "error_code": "REQUEST_TOO_LARGE",
        "message": "Request size exceeds limit (50 MB)"
    }), 413

# NOTE:
# Historically the application used a single 'proton.db' file (DATABASE_FILE).
# The platform has since migrated to:
#   - a primary metadata database: MYSQL_PRIMARY_DATABASE (e.g. 'proton_primary')
#   - per-tenant organization databases under the 'databases' directory.
# To avoid accidentally recreating 'proton.db', all generic helpers are now
# wired to MYSQL_PRIMARY_DATABASE instead of a separate DATABASE_FILE constant.

# Tenant Management Configuration Constants
TENANT_DB_PREFIX = 'org_'
TENANT_DB_EXTENSION = '.db'
MAX_CONNECTIONS_PER_DB = 5
CONNECTION_TIMEOUT = 30
ORG_DB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'databases')

# --- DB API Configuration ---
DB_API_PREFIX = '/db-api'
EXPECTED_TENANT_TABLES = [
    'users',
    'projects',
    'activity_logs',
    'tasks',
    'task_notes',
    'task_comments',
    'task_comment_attachments',
    'task_dependencies'
]
EXPECTED_TENANT_INDEXES = [
    'idx_tasks_project_id',
    'idx_tasks_parent_id',
    'idx_activity_logs_project',
    'idx_task_notes_task',
    'idx_task_dependencies_task',
    'idx_task_dependencies_depends',
    'idx_task_comments_task',
    'idx_comment_attachments_comment'
]

# Validation Configuration
MIN_PASSWORD_LENGTH = 8
MIN_ORG_NAME_LENGTH = 2
MAX_ORG_NAME_LENGTH = 100

# User Roles
ROLE_SUPER_ADMIN = 'super_admin'
ROLE_ORG_ADMIN = 'org_admin'
ROLE_ORG_USER = 'org_user'
ROLE_CLIENT = 'client'

# Valid roles for user creation by Org Admin
ORG_ADMIN_CREATABLE_ROLES = [ROLE_ORG_ADMIN, ROLE_ORG_USER]

# Maximum org admins allowed (hard limit for all plans)
MAX_ORG_ADMINS = 100

# Maximum user count allowed for subscriptions (prevents calculation errors)
MAX_USER_COUNT = 1000

# Valid user statuses
USER_STATUS_PENDING = 'pending'
USER_STATUS_APPROVED = 'approved'
USER_STATUS_ACTIVE = 'active'
USER_STATUS_SUSPENDED = 'suspended'
USER_STATUS_REJECTED = 'rejected'
USER_STATUS_LOCKED = 'locked'  # Set when OTP max-attempt lockout triggers

# SuperAdmin Configuration
SUPERADMIN_SECRET_KEY = os.environ.get('SUPERADMIN_SECRET_KEY', '')
if not SUPERADMIN_SECRET_KEY:
    print("WARNING: SUPERADMIN_SECRET_KEY not set. SuperAdmin signup will be disabled.")
VERIFICATION_TOKEN_EXPIRY_HOURS = 24
TRIAL_PERIOD_DAYS = 7
EMAIL_REGEX = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
ORG_NAME_REGEX = r'^[a-zA-Z0-9 _-]+$'
PASSWORD_REGEX = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$'

# Plan Limit Resource Types
RESOURCE_TYPE_PROJECT = 'project'
RESOURCE_TYPE_ADMIN = 'admin'
RESOURCE_TYPE_FILE = 'file'
RESOURCE_TYPE_AI_PROMPT = 'ai_prompt'

# Plan Limit Error Code
ERROR_CODE_PLAN_LIMIT_EXCEEDED = 'PLAN_LIMIT_EXCEEDED'

# Usage Warning Threshold (percentage)
USAGE_WARNING_THRESHOLD = 80

# Unlimited Plan Indicator
UNLIMITED_LIMIT = 999999

# AI Prompt Tracking Actions
AI_ACTION_TASK_UPDATE = 'task_risk_assessment'
AI_ACTION_TRANSLATION = 'translation'
AI_ACTION_CHATBOT = 'chatbot_query'

# --- In-memory cache for org usage ---
ORG_USAGE_CACHE = {}

def sanitize_text_input(text, max_length=1000, allow_html=False):
    if text is None:
        return ''
    value = str(text).strip()
    if len(value) > max_length:
        value = value[:max_length]
    if allow_html:
        value = bleach.clean(value, tags=['b', 'i', 'u', 'a'], strip=True)
    else:
        value = bleach.clean(value, tags=[], strip=True)
    return value

def sanitize_json_input(json_data, allowed_keys=None, max_length=None):
    if not isinstance(json_data, dict):
        return {}
    if max_length is None:
        try:
            ml = MAX_INPUT_LENGTH
        except Exception:
            ml = 10000
    else:
        ml = max_length
    result = {}
    keys = allowed_keys if allowed_keys is not None else json_data.keys()
    for k in keys:
        if k in json_data:
            v = json_data[k]
            if isinstance(v, str):
                result[k] = sanitize_text_input(v, max_length=ml)
            elif isinstance(v, dict):
                result[k] = sanitize_json_input(v, None, ml)
            elif isinstance(v, list):
                result[k] = [sanitize_text_input(x, max_length=ml) if isinstance(x, str) else x for x in v]
            else:
                result[k] = v
    return result

def validate_and_sanitize_project_name(project_name):
    name = sanitize_text_input(project_name, max_length=100, allow_html=False)
    if not name or len(name) < 2 or len(name) > 100:
        return (False, name, 'Project name must be 2-100 characters.')
    if not re.match(r'^[a-zA-Z0-9 _-]{2,100}$', name):
        return (False, name, 'Project name contains invalid characters.')
    return (True, name, '')

def validate_and_sanitize_task_id(task_id):
    tid = sanitize_text_input(task_id, max_length=64, allow_html=False)
    if not re.match(r'^[0-9]+(\.[0-9]+)*$', tid):
        return (False, tid, 'Invalid task ID format.')
    return (True, tid, '')

def sanitize_timestamp_for_db(ts_input):
    """
    Convert a timestamp string (which might be in RFC 1123, ISO 8601, or other formats)
    into a MySQL-compatible 'YYYY-MM-DD HH:MM:SS' string.
    Falls back to current time if parsing fails or input is empty.
    """
    if not ts_input:
        return datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # If it's already a datetime object
    if isinstance(ts_input, datetime):
        return ts_input.strftime('%Y-%m-%d %H:%M:%S')
        
    ts_str = str(ts_input).strip()
    
    # Attempt to parse common formats
    potential_formats = [
        '%Y-%m-%d %H:%M:%S',      # Standard MySQL
        '%a, %d %b %Y %H:%M:%S %Z', # RFC 1123 (e.g. Wed, 24 Dec 2025 14:13:44 GMT)
        '%Y-%m-%dT%H:%M:%S',      # ISO 8601
        '%Y-%m-%dT%H:%M:%S.%f',   # ISO 8601 with millis
        '%Y-%m-%d',               # Date only
    ]
    
    parsed_dt = None
    for fmt in potential_formats:
        try:
            parsed_dt = datetime.strptime(ts_str, fmt)
            break
        except ValueError:
            continue
            
    if parsed_dt:
        return parsed_dt.strftime('%Y-%m-%d %H:%M:%S')
    
    # Fallback: try using dateutil if available (usually more robust), 
    # but here we'll just log and default to now() to prevent crash.
    print(f"Warning: Could not parse timestamp '{ts_str}'. Defaulting to NOW.")
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

# SuperAdmin API Configuration
SUPERADMIN_DEFAULT_PAGE_SIZE = 50
SUPERADMIN_MAX_PAGE_SIZE = 100
AUDIT_LOG_DEFAULT_PAGE_SIZE = 100
BILLING_METRICS_CACHE_TTL = 3600  # 1 hour in seconds

# File Storage Configuration
UPLOAD_FOLDER = 'uploads'
MAX_FILES_PER_UPLOAD = 5
MAX_FILE_SIZE_MB = 10
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
ALLOWED_FILE_EXTENSIONS = {'.pdf', '.doc', '.docx', '.xls', '.xlsx', '.png', '.jpg', '.jpeg', '.txt', '.csv'}

# File Access Audit Actions
FILE_ACTION_UPLOADED = 'file_uploaded'
FILE_ACTION_DOWNLOADED = 'file_downloaded'
FILE_ACTION_ATTACHMENTS_DOWNLOADED = 'attachments_downloaded'
FILE_ACTION_DELETED = 'file_deleted'

# Allowed sort fields for each endpoint
ORG_SORT_FIELDS = ['name', 'created_at', 'status', 'user_count']
USER_SORT_FIELDS = ['email', 'created_at', 'role', 'status']
SUBSCRIPTION_SORT_FIELDS = ['created_at', 'start_date', 'plan_type', 'status']
AUDIT_LOG_SORT_FIELDS = ['timestamp', 'action', 'org_id', 'user_id']

# Cache for SuperAdmin billing metrics (TTL: 1 hour)
BILLING_METRICS_CACHE = {}
APP_START_TIME = datetime.now(timezone.utc)

# Security Configuration
FORCE_HTTPS = os.environ.get('FORCE_HTTPS', 'false').lower() == 'true'
ALLOWED_ORIGINS = os.environ.get('ALLOWED_ORIGINS', 'https://protonv5.simonindia.ai')
ENCRYPTION_KEY = os.environ.get('ENCRYPTION_KEY', '')
APP_VERSION = os.environ.get('APP_VERSION', '1.0.0')

# Rate Limiting Configuration
RATE_LIMIT_STORAGE = os.environ.get('RATE_LIMIT_STORAGE', 'memory://')
RATE_LIMIT_LOGIN = "5 per minute"
RATE_LIMIT_SIGNUP = "3 per hour"
RATE_LIMIT_API = "100 per minute"
RATE_LIMIT_FILE_UPLOAD = "10 per minute"

# Input Validation
MAX_INPUT_LENGTH = 10000
MAX_JSON_SIZE = 1048576

# Security Headers
HSTS_MAX_AGE = 31536000
# Base CSP policy - connect-src for API calls
# NOTE: Include external AI providers used directly from the browser (e.g. Gemini).
CSP_CONNECT_SRC = "https://api.razorpay.com https://unpkg.com https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com https://fonts.gstatic.com https://generativelanguage.googleapis.com"
# Add localhost for local development (allows browser console testing and API calls from same origin)
# Note: 'self' should allow same-origin, but explicit localhost helps with browser console and fetch API
# In production, set DEV_MODE=false to disable this
if DEV_MODE or os.environ.get('FLASK_ENV', '').lower() == 'development':
    CSP_CONNECT_SRC += " http://localhost:5125 http://127.0.0.1:5125 http://localhost:5000 http://127.0.0.1:5000 ws://localhost:5125 ws://127.0.0.1:5125"
# Also allow if running on localhost (for easier local testing without setting DEV_MODE)
# This is safe because 'self' already allows same-origin, this just makes it explicit
CSP_CONNECT_SRC += " http://localhost:5125 http://127.0.0.1:5125"

CSP_POLICY = f"default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com https://checkout.razorpay.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net https://cdn.dhtmlx.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdn.dhtmlx.com; font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self' {CSP_CONNECT_SRC} https://cdn.dhtmlx.com; frame-src https://*.razorpay.com https://checkout.razorpay.com https://api.razorpay.com"

def invalidate_billing_metrics_cache():
    try:
        BILLING_METRICS_CACHE.clear()
    except Exception:
        pass

RAZORPAY_PLAN_IDS = {}

def get_razorpay_plan_id(plan_type):
    """Return stored Razorpay plan_id for given plan_type or None.
    Tries cache; falls back to Primary DB table `razorpay_plans` and caches result.
    """
    pid = RAZORPAY_PLAN_IDS.get(plan_type)
    if pid:
        return pid
    try:
        create_sql = (
            "CREATE TABLE IF NOT EXISTS razorpay_plans (plan_type VARCHAR(191) PRIMARY KEY, razorpay_plan_id TEXT)"
            if DB_TYPE.lower() == "mysql"
            else "CREATE TABLE IF NOT EXISTS razorpay_plans (plan_type TEXT PRIMARY KEY, razorpay_plan_id TEXT)"
        )
        execute_primary_query(create_sql)
        row = execute_primary_query("SELECT razorpay_plan_id FROM razorpay_plans WHERE plan_type = ?", (plan_type,), fetch_one=True)
        if row and row[0]:
            RAZORPAY_PLAN_IDS[plan_type] = row[0]
            return row[0]
    except Exception:
        pass
    return None

def format_razorpay_amount(amount_in_rupees):
    """Convert rupees to paise (int)."""
    return int(round(float(amount_in_rupees) * 100))

def format_rupees_from_paise(amount_in_paise):
    """Convert paise to rupees (float)."""
    return (amount_in_paise or 0) / 100.0

def normalize_plan_type(plan_type):
    """Normalize plan type for backward compatibility. Maps 'si_plus' to 'plus'."""
    if plan_type == 'si_plus':
        return 'plus'
    return plan_type

def get_subscription_display_name(plan_type):
    """User-friendly plan name for display. Supports both 'si_plus' and 'plus' for backward compatibility."""
    return {'basic': 'Basic Plan', 'si_plus': 'Plus Plan', 'plus': 'Plus Plan', 'pro': 'Pro Plan'}.get(plan_type, plan_type)

def calculate_subscription_amount(plan_type, user_count, billing_cycle):
    """
    Calculate total amount in paise for subscription based on plan and users.
    
    New Pricing Model:
    - Base price includes specified number of admins (5 for Basic, 10 for Plus, 100 for Pro)
    - Additional admins cost ₹500/month each (50000 paise)
    - Pro plan: if user_count > 100, apply custom pricing (base + 500 per extra user beyond 100)
    
    Parameters:
        plan_type (str): Plan type ('basic', 'plus', 'si_plus', or 'pro')
        user_count (int): Number of users/admins
        billing_cycle (str): 'monthly' or 'yearly'
    
    Returns:
        int: Total amount in paise
    """
    # Normalize plan type for backward compatibility
    plan_type = normalize_plan_type(plan_type)
    
    # Get base plan amount
    base = RAZORPAY_PLANS.get(plan_type, {}).get('amount', 0)
    if base == 0:
        # Fallback to old behavior if plan not found
        return 0
    
    # Get billing multiplier
    mult = 12 if billing_cycle == 'yearly' else 1
    
    # Ensure user_count is at least 1
    user_count = max(1, int(user_count))
    
    # Get plan limits to determine included admin count
    try:
        limits = get_plan_limits(plan_type) or {}
        included_users = limits.get('max_users', 0)
    except Exception:
        # Fallback: use safe default map for included users
        default_included = {'basic': 5, 'plus': 10, 'pro': 100}.get(plan_type, 0)
        included_users = default_included
    
    # If still no included_users found, return base price only (no per-user multiplication)
    if included_users == 0:
        return base * mult
    
    # Special handling for Pro plan with custom pricing beyond 100 users
    if plan_type == 'pro':
        if user_count > 100:
            # Base price covers up to 100 users
            # Extra users beyond 100: (user_count - 100) * 50000
            extra_users = user_count - 100
            extra_cost = extra_users * 50000  # ₹500 per user in paise
            total = (base + extra_cost) * mult
            return total
        else:
            # For Pro plan with <= 100 users, return base price only
            return base * mult
    
    # For Basic and Plus plans
    # Calculate extra admins beyond included count
    extra_admins = max(0, user_count - included_users)
    
    # Calculate extra admin cost: ₹500 per admin in paise
    extra_cost = extra_admins * 50000
    
    # Total = (Base Price + Extra Cost) * Billing Multiplier
    total = (base + extra_cost) * mult
    
    return total

def generate_invoice_number(org_id, transaction_id):
	"""Generate unique invoice number for transaction."""
	year = datetime.now().year
	try:
		org_num = int(org_id)
	except Exception:
		org_num = 0
	try:
		txn_num = int(transaction_id)
	except Exception:
		txn_num = 0
	return f"INV-{org_num:04d}-{txn_num:06d}-{year}"

def get_tenant_db_filename(org_id):
    """Generate tenant database absolute file path from organization ID.
    
    Creates a human-readable database filename using the organization's first name
    and a timestamp for uniqueness. Falls back to sequential naming if org lookup fails.
    
    Args:
        org_id (int): Organization ID
        
    Returns:
        str: Absolute database file path (e.g., "/path/to/databases/zuari_20251103_105929.db")
        
    Naming Convention:
        - Format: {org_first_word}_{timestamp}.db
        - org_first_word: First word of organization name, sanitized (lowercase, alphanumeric only)
        - timestamp: YYYYmmdd_HHMMSS format
        - Collision handling: Appends _{org_id} if filename already exists
        
    Examples:
        - "Zuari Industries" -> zuari_20251103_105929.db
        - "ABC Corp" -> abc_20251103_105930.db
        - "123 Company" -> org_123_20251103_105931.db (prefixed because starts with number)
    """
    # Ensure the databases directory exists
    os.makedirs(ORG_DB_DIR, exist_ok=True)
    
    # Step 1: Query organization name from primary.db
    try:
        org_row = execute_primary_query(
            "SELECT name FROM organizations WHERE id = ?",
            params=(org_id,),
            fetch_one=True
        )
        org_name = org_row[0] if org_row and org_row[0] else None
    except Exception as e:
        print(f"[DB-FILENAME] Error querying org name for org_id={org_id}: {e}")
        org_name = None
    
    # Step 2: Extract and sanitize first word
    if org_name:
        # Split by spaces and take first word
        words = org_name.strip().split()
        first_word = words[0] if words else 'org'
        
        # Limit length to prevent excessively long filenames
        first_word = first_word[:20]
        
        # Transliterate non-ASCII characters to ASCII equivalents
        # Normalize to NFKD form (decomposed) and encode to ASCII, ignoring errors
        first_word = unicodedata.normalize('NFKD', first_word).encode('ascii', 'ignore').decode('ascii')
        
        # Sanitize: lowercase and remove non-alphanumeric
        sanitized = re.sub(r'[^a-z0-9]', '', first_word.lower())
        
        # Handle empty result after sanitization
        if not sanitized:
            sanitized = 'org'
        
        # Handle names starting with numbers (prefix with 'org_')
        if sanitized[0].isdigit():
            sanitized = f'org_{sanitized}'
    else:
        # Fallback if org name query failed
        sanitized = 'org'
    
    # Step 3: Generate timestamp
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    
    # Step 4: Construct filename
    filename = f"{sanitized}_{timestamp}.db"
    full_path = os.path.join(ORG_DB_DIR, filename)
    
    # Step 5: Handle collisions (rare with timestamp, but possible)
    if os.path.exists(full_path):
        print(f"[DB-FILENAME] Collision detected for {filename}, appending org_id={org_id}")
        filename = f"{sanitized}_{timestamp}_{org_id}.db"
        full_path = os.path.join(ORG_DB_DIR, filename)
    
    print(f"[DB-FILENAME] Generated filename for org_id={org_id}: {filename}")
    return full_path

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key-change-in-production-min-256-bits')
app.config['JWT_ALGORITHM'] = 'HS256'
app.config['JWT_DECODE_ALGORITHMS'] = ['HS256']
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)
app.config['JWT_TOKEN_LOCATION'] = ['headers']
app.config['JWT_HEADER_NAME'] = 'Authorization'
app.config['JWT_HEADER_TYPE'] = 'Bearer'
app.config['JWT_ERROR_MESSAGE_KEY'] = 'message'

# Initialize JWT
jwt = JWTManager(app)

# In-memory token blocklist for revoked tokens
# Note: In production, use Redis with TTL matching token expiration
revoked_tokens = set()

# Encryption cipher initialization
_EK = ENCRYPTION_KEY
if _EK:
    cipher_suite = Fernet(_EK.encode() if isinstance(_EK, str) else _EK)
else:
    cipher_suite = None
    print("WARNING: ENCRYPTION_KEY not set. Database paths will not be encrypted.")

def encrypt_db_path(db_file_path):
    try:
        if not cipher_suite:
            return db_file_path
        encrypted = cipher_suite.encrypt(db_file_path.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"[SECURITY] Encryption failed: {e}")
        return db_file_path

def decrypt_db_path(encrypted_path):
    try:
        if not cipher_suite:
            return encrypted_path
        if not encrypted_path:
            return None
        decrypted = cipher_suite.decrypt(encrypted_path.encode())
        return decrypted.decode()
    except Exception as e:
        print(f"[SECURITY] Decryption failed: {e}")
        raise

def encrypt_otp(otp_code):
    """Encrypt OTP codes using the shared cipher suite."""
    try:
        if otp_code is None:
            return None
        if not cipher_suite:
            print("WARNING: cipher_suite not initialized; storing OTP in plaintext.")
            return otp_code
        value = otp_code if isinstance(otp_code, str) else str(otp_code)
        encrypted = cipher_suite.encrypt(value.encode())
        return encrypted.decode()
    except Exception as exc:
        print(f"[SECURITY] OTP encryption failed: {exc}")
        return None

def decrypt_otp(encrypted_otp):
    """Decrypt OTP codes and gracefully handle missing/invalid cipher data."""
    try:
        if encrypted_otp is None:
            return None
        if not cipher_suite:
            print("WARNING: cipher_suite not initialized; returning OTP as-is.")
            return encrypted_otp
        decrypted = cipher_suite.decrypt(encrypted_otp.encode())
        return decrypted.decode()
    except Exception as exc:
        print(f"[SECURITY] OTP decryption failed: {exc}")
        return None

# HTTPS enforcement
@app.before_request
def redirect_to_https():
    try:
        if request.path == '/api/health':
            return None
        if not FORCE_HTTPS:
            return None
        host = request.host or ''
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            return None
        if request.headers.get('X-Forwarded-Proto', request.scheme) == 'http':
            return redirect(request.url.replace('http://', 'https://', 1), code=301)
    except Exception:
        return None

@app.after_request
def add_security_headers(response):
    try:
        response.headers['Strict-Transport-Security'] = f'max-age={HSTS_MAX_AGE}; includeSubDomains'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        response.headers['Content-Security-Policy'] = CSP_POLICY
    except Exception:
        pass
    return response

# Secure Credential Management
def get_decrypted_credential(env_var_name, default=''):
	"""
	Get decrypted credential from environment variables.
	
	Supports both plain-text (for backward compatibility) and encrypted credentials.
	For encrypted credentials, the environment variable should be prefixed with 'ENCRYPTED_'
	and the value should be a base64-encoded encrypted string.
	
	Production Recommendation:
	Use a dedicated secret management service like:
	- AWS Secrets Manager
	- Azure Key Vault
	- HashiCorp Vault
	- Google Cloud Secret Manager
	
	Args:
		env_var_name: Name of the environment variable
		default: Default value if not found
		
	Returns:
		Decrypted credential string
	"""
	# Try encrypted version first
	encrypted_var = f"ENCRYPTED_{env_var_name}"
	encrypted_value = os.environ.get(encrypted_var, '')
	
	if encrypted_value and ENCRYPTION_KEY:
		try:
			import base64
			from cryptography.fernet import Fernet
			# Ensure key is properly formatted
			if len(ENCRYPTION_KEY) == 32:
				# If key is 32 bytes, encode it as base64 for Fernet
				key = base64.urlsafe_b64encode(ENCRYPTION_KEY.encode()[:32])
			else:
				key = ENCRYPTION_KEY.encode()
			cipher = Fernet(key)
			decrypted = cipher.decrypt(encrypted_value.encode()).decode()
			return decrypted
		except Exception as e:
			print(f"WARNING: Failed to decrypt {env_var_name}: {e}")
			print(f"WARNING: Falling back to plain-text credential")
	
	# Fall back to plain-text
	return os.environ.get(env_var_name, default)

# Razorpay Configuration - Load credentials securely
# Razorpay Configuration - Load credentials securely
# SECURITY NOTE: In production, use AWS Secrets Manager, Azure Key Vault, or HashiCorp Vault
# For encrypted credentials, set ENCRYPTED_RAZORPAY_KEY_ID, ENCRYPTED_RAZORPAY_KEY_SECRET, etc.
RAZORPAY_KEY_ID = get_decrypted_credential('RAZORPAY_KEY_ID', '')
RAZORPAY_KEY_SECRET = get_decrypted_credential('RAZORPAY_KEY_SECRET', '')
RAZORPAY_WEBHOOK_SECRET = get_decrypted_credential('RAZORPAY_WEBHOOK_SECRET', '')

# Validate that credentials are not accidentally logged or exposed
if RAZORPAY_KEY_SECRET and os.environ.get("WERKZEUG_RUN_MAIN") == "true":
	print("Razorpay credentials loaded (key_id: {}..., secret: [REDACTED])".format(RAZORPAY_KEY_ID[:10] if RAZORPAY_KEY_ID else 'none'))

# Initialize Razorpay client (only if credentials are provided)
razorpay_client = None
if RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET:
	razorpay_client = razorpay.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET))
	if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
		print("Razorpay client initialized successfully")
else:
	if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
		print("WARNING: Razorpay credentials not configured. Payment features will be disabled.")

if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
    print(f"MySQL Connection Pool Size per Tenant: {MYSQL_POOL_SIZE}")

# Validate SMTP configuration and print status
if SMTP_USERNAME and SMTP_PASSWORD:
	if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
		print("SMTP email service configured successfully")
else:
	if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
		print("WARNING: SMTP credentials not configured. Email features (OTP, password reset) will be disabled.")

# PRICING MODEL (Updated November 2025)
# 
# Base Plan Pricing:
# - Basic: ₹1,700/month - Includes up to 5 users, 1 project, 20 files/project, 10 AI prompts/week
# - Plus: ₹2,600/month - Includes up to 10 users, 10 projects, 100 files/project, 100 AI prompts/week
# - Pro: ₹4,300/month - Unlimited resources (custom pricing beyond 100 users)
#
# Extra User Pricing:
# - All plans: ₹500/month per additional user beyond plan limit
# - Pro plan: ₹500/month per user beyond 100 users
#
# Calculation Logic:
# - Base price includes specified number of users (5 for Basic, 10 for Plus, 100 for Pro)
# - Additional users are charged at ₹500/month each
# - Total = Base Price + (Extra Users × ₹500) × Billing Multiplier
# - Billing Multiplier: 1 for monthly, 12 for yearly
#
# Implementation Notes:
# - Amounts in RAZORPAY_PLANS are in paise (1 INR = 100 paise)
# - calculate_subscription_amount() handles extra user pricing logic
# - Plan limits are defined in plan_limits table (see seed_plan_limits())
# - Both 'si_plus' and 'plus' are supported for backward compatibility
#
# TODO: Verify Razorpay plan creation with new pricing model
# - Test subscription creation with base amounts
# - Implement addon/custom charge logic for extra users
# - Update webhook handlers to process addon charges
# - Document Razorpay plan IDs for each pricing tier

# Razorpay Plan Configuration (amounts in paise - INR smallest unit)
RAZORPAY_PLANS = {
	'basic': {
		'period': 'monthly',
		'interval': 1,
		'amount': 170000,
		'currency': 'INR',
		'name': 'PROTON Basic Plan',
		'description': '1 project, up to 5 admins (₹500/extra admin), 20 files/project, 10 AI prompts/week'
	},
	'si_plus': {
		'period': 'monthly',
		'interval': 1,
		'amount': 260000,
		'currency': 'INR',
		'name': 'PROTON SI+ Plan',
		'description': '10 projects, up to 10 admins (₹500/extra admin), 100 files/project, 100 AI prompts/week, S-Curve dashboards'
	},
	'plus': {
		'period': 'monthly',
		'interval': 1,
		'amount': 260000,
		'currency': 'INR',
		'name': 'PROTON Plus Plan',
		'description': '10 projects, up to 10 admins (₹500/extra admin), 100 files/project, 100 AI prompts/week, S-Curve dashboards'
	},
	'pro': {
		'period': 'monthly',
		'interval': 1,
		'amount': 430000,
		'currency': 'INR',
		'name': 'PROTON Pro Plan',
		'description': 'Unlimited projects/admins/files/prompts (custom pricing beyond 100 users), SSO, API access, audit logs'
	}
}

# Razorpay Subscription Statuses
RAZORPAY_STATUS_CREATED = 'created'
RAZORPAY_STATUS_AUTHENTICATED = 'authenticated'
RAZORPAY_STATUS_ACTIVE = 'active'
RAZORPAY_STATUS_PAUSED = 'paused'
RAZORPAY_STATUS_HALTED = 'halted'
RAZORPAY_STATUS_CANCELLED = 'cancelled'
RAZORPAY_STATUS_COMPLETED = 'completed'
RAZORPAY_STATUS_EXPIRED = 'expired'

# Invoicing / Tax Configuration (adjust in production as needed)
TAX_ENABLED = False
TAX_RATE = 0.0  # e.g., 0.18 for 18%
COMPANY_NAME = 'PROTON'
COMPANY_FROM_NAME = 'Simon India'
COMPANY_SUPPORT_EMAIL = 'support@proton.simonindia.ai'
COMPANY_ADDRESS = ''
COMPANY_GSTIN = ''

# Required Environment Variables for Razorpay Integration:
# - RAZORPAY_KEY_ID: Your Razorpay API Key ID (from Razorpay Dashboard)
# - RAZORPAY_KEY_SECRET: Your Razorpay API Key Secret (keep secure, never commit)
# - RAZORPAY_WEBHOOK_SECRET: Webhook secret for signature verification (from Razorpay Dashboard)
# 
# To set environment variables:
# - Development: Create .env file or set in terminal: export RAZORPAY_KEY_ID="rzp_test_..."
# - Production: Set in hosting platform environment variables (Heroku, AWS, etc.)

@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    """Check if a JWT token is in the blocklist (revoked)."""
    jti = jwt_payload.get('jti')
    return jti in revoked_tokens


# --- Tenant Context Management ---

class TenantConnectionPool:
    """Manage database connections for tenant MySQL databases."""

    def __init__(self, db_type=DB_TYPE, max_connections_per_db=MAX_CONNECTIONS_PER_DB):
        self._db_type = "mysql"
        self._connections = {}
        self._pool_names = {}
        self._lock = threading.Lock()
        self._max_connections_per_db = max_connections_per_db

    def _is_connection_valid(self, conn):
        try:
            if conn.is_connected():
                # Use buffered cursor and consume results to avoid "Unread result found" errors
                cur = conn.cursor(buffered=True)
                cur.execute("SELECT 1")
                cur.fetchall()  # Consume the result
                cur.close()
                return True
        except Exception:
            return False
        return False

    def get_connection(self, org_id=None, database_name=None, db_file_path=None):
        """Get a MySQL database connection for the specified tenant database."""
        # Use MySQL connector's built-in connection pooling
        db_name = database_name or (get_tenant_db_name(org_id) if org_id is not None else MYSQL_PRIMARY_DATABASE)
        pool_name = f"{db_name}_pool"
        
        try:
            # Let MySQL connector handle the pooling - it will reuse connections automatically
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=db_name,
                charset=MYSQL_CHARSET,
                autocommit=False,
                use_pure=True,
                pool_name=pool_name,
                pool_size=MYSQL_POOL_SIZE,
                pool_reset_session=True,
                consume_results=True,
            )
            return conn
            
        except mysql.connector.Error as e:
            raise

    def close_connection(self, identifier):
        """Close and remove a specific database connection by identifier."""
        with self._lock:
            keys_to_close = [k for k in self._connections.keys() if k[0] == identifier]
            for key in keys_to_close:
                try:
                    self._connections[key].close()
                except Exception:
                    pass
                del self._connections[key]

    def close_all(self):
        """Close all connections in the pool."""
        with self._lock:
            for conn in self._connections.values():
                try:
                    conn.close()
                except Exception:
                    pass
            self._connections.clear()


# Global connection pool instance
tenant_pool = TenantConnectionPool()


# --- Custom Exception Classes ---

class TenantDatabaseError(Exception):
    """Raised when tenant database cannot be accessed or doesn't exist."""
    def __init__(self, org_id, db_file_path, message="Tenant database error"):
        self.org_id = org_id
        self.db_file_path = db_file_path
        super().__init__(f"{message}: org_id={org_id}, db_path={db_file_path}")


class TenantResolutionError(Exception):
    """Raised when tenant cannot be resolved from JWT or Primary DB."""
    def __init__(self, org_id, message="Tenant resolution error"):
        self.org_id = org_id
        super().__init__(f"{message}: org_id={org_id}")


class SubscriptionInactiveError(Exception):
    """Raised when organization's subscription is not active."""
    def __init__(self, org_id, subscription_status, message="Subscription inactive"):
        self.org_id = org_id
        self.subscription_status = subscription_status
        super().__init__(f"{message}: org_id={org_id}, status={subscription_status}")

class SubscriptionStateMachine:
    """State machine for subscription status transitions.
    
    Defines valid subscription statuses and allowed transitions between them.
    This ensures business logic integrity and prevents invalid state changes.
    """
    # All valid subscription statuses
    STATUS_TRIAL = 'trial'
    STATUS_CREATED = 'created'
    STATUS_AUTHENTICATED = 'authenticated'
    STATUS_ACTIVE = 'active'
    STATUS_PAUSED = 'paused'
    STATUS_PENDING_CANCELLATION = 'pending_cancellation'
    STATUS_HALTED = 'halted'
    STATUS_CANCELLED = 'cancelled'
    STATUS_EXPIRED = 'expired'
    STATUS_COMPLETED = 'completed'
    STATUS_ABANDONED = 'abandoned'
    STATUS_PAST_DUE = 'past_due'
    
    # Valid transitions: {from_status: [to_status1, to_status2, ...]}
    VALID_TRANSITIONS = {
        STATUS_TRIAL: [STATUS_ACTIVE, STATUS_CANCELLED, STATUS_EXPIRED],
        STATUS_CREATED: [STATUS_AUTHENTICATED, STATUS_ACTIVE, STATUS_ABANDONED, STATUS_CANCELLED],
        STATUS_AUTHENTICATED: [STATUS_ACTIVE, STATUS_CANCELLED, STATUS_ABANDONED],
        STATUS_ACTIVE: [STATUS_PAUSED, STATUS_CANCELLED, STATUS_HALTED, STATUS_COMPLETED, STATUS_PENDING_CANCELLATION, STATUS_PAST_DUE],
        STATUS_PAUSED: [STATUS_ACTIVE, STATUS_CANCELLED],
        STATUS_PENDING_CANCELLATION: [STATUS_CANCELLED, STATUS_ACTIVE],  # Can reactivate before cancellation
        STATUS_HALTED: [STATUS_CANCELLED, STATUS_ACTIVE],  # Can be reactivated
        STATUS_PAST_DUE: [STATUS_ACTIVE, STATUS_CANCELLED, STATUS_HALTED],
        # Terminal states - no transitions allowed
        STATUS_CANCELLED: [],
        STATUS_EXPIRED: [],
        STATUS_COMPLETED: [],
        STATUS_ABANDONED: []
    }
    
    # Terminal states that cannot transition to any other state
    TERMINAL_STATES = {STATUS_CANCELLED, STATUS_EXPIRED, STATUS_COMPLETED, STATUS_ABANDONED}
    
    @classmethod
    def is_valid_transition(cls, current_status, new_status):
        """Check if a transition from current_status to new_status is valid.
        
        Args:
            current_status: Current subscription status
            new_status: Desired new subscription status
            
        Returns:
            bool: True if transition is valid, False otherwise
        """
        if not current_status or not new_status:
            return False
        
        # Same status is always valid (no-op)
        if current_status == new_status:
            return True
        
        # Check if current status is in our transition map
        if current_status not in cls.VALID_TRANSITIONS:
            # Unknown status - allow transition but log warning
            return True  # Permissive for backward compatibility
        
        # Check if transition is allowed
        allowed_transitions = cls.VALID_TRANSITIONS.get(current_status, [])
        return new_status in allowed_transitions
    
    @classmethod
    def get_allowed_transitions(cls, current_status):
        """Get list of allowed transitions from current status.
        
        Args:
            current_status: Current subscription status
            
        Returns:
            list: List of allowed status values
        """
        if not current_status:
            return []
        
        return cls.VALID_TRANSITIONS.get(current_status, [])
    
    @classmethod
    def is_terminal_state(cls, status):
        """Check if a status is a terminal state (cannot transition).
        
        Args:
            status: Subscription status to check
            
        Returns:
            bool: True if status is terminal, False otherwise
        """
        return status in cls.TERMINAL_STATES

def validate_subscription_transition(org_id, current_status, new_status, user_id=None, context=None):
    """Validate and log subscription status transition.
    
    Args:
        org_id: Organization ID
        current_status: Current subscription status
        new_status: Desired new subscription status
        user_id: User ID making the change (optional)
        context: Additional context for logging (optional dict)
        
    Returns:
        tuple: (is_valid: bool, error_message: str or None)
        
    Raises:
        ValueError: If transition is invalid (for strict enforcement)
    """
    if not SubscriptionStateMachine.is_valid_transition(current_status, new_status):
        # Log security incident
        try:
            details = json.dumps({
                "org_id": org_id,
                "current_status": current_status,
                "attempted_status": new_status,
                "allowed_transitions": SubscriptionStateMachine.get_allowed_transitions(current_status),
                "context": context or {}
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, user_id, 'subscription_invalid_transition_attempt', details)
            )
        except Exception:
            pass
        
        error_msg = f"Invalid subscription transition: {current_status} -> {new_status}. Allowed transitions: {SubscriptionStateMachine.get_allowed_transitions(current_status)}"
        return False, error_msg
    
    return True, None


# --- Database Management ---

# NOTE: The legacy single-tenant initialization previously created a separate
# 'proton.db' file via a DATABASE_FILE constant. The platform now uses:
#   - MYSQL_PRIMARY_DATABASE for global/metadata tables
#   - per-tenant org_<org_id>.db files for tenant data.
# If initialize_database() is ever invoked again (e.g. in a maintenance
# script), it should operate on MYSQL_PRIMARY_DATABASE so that no new
# 'proton.db' file is ever created.

def initialize_database():
    """Initialize the MySQL database with all required tables and indexes."""
    try:
        admin_conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            charset=MYSQL_CHARSET,
            autocommit=True,
        )
        admin_cursor = admin_conn.cursor()
        admin_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{MYSQL_PRIMARY_DATABASE}` CHARACTER SET {MYSQL_CHARSET} COLLATE utf8mb4_unicode_ci"
        )
        admin_cursor.close()
        admin_conn.close()
        conn = base_get_db_connection(MYSQL_PRIMARY_DATABASE)
        create_tenant_schema(conn)
        conn.commit()
        conn.close()
        print("MySQL database initialized successfully")
    except MySQLError as e:
        print(f"Error initializing MySQL database: {e}")
        raise
def create_tenant_schema(conn):
    """Create all tenant tables and indexes on an open MySQL connection.
    
    Args:
        conn: Open MySQL connection.
    
    Returns:
        bool: True on success
    """
    cursor = conn.cursor()
    if DB_TYPE.lower() == "mysql":
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INT AUTO_INCREMENT PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password VARCHAR(255) NOT NULL,
                role VARCHAR(50) NOT NULL,
                status VARCHAR(50) NOT NULL,
                INDEX idx_users_email (email)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS projects (
                id INT AUTO_INCREMENT PRIMARY KEY,
                name VARCHAR(255) UNIQUE NOT NULL,
                client_access_code VARCHAR(255) UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_projects_name (name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INT AUTO_INCREMENT PRIMARY KEY,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_email VARCHAR(255),
                project_id INT,
                action VARCHAR(255),
                details TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                INDEX idx_activity_logs_project (project_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS tasks (
                id VARCHAR(191) PRIMARY KEY,
                project_id INT NOT NULL,
                parent_task_id VARCHAR(191),
                wbs VARCHAR(255),
                task_name VARCHAR(255),
                planned_start_date DATE,
                planned_end_date DATE,
                predecessor_string TEXT,
                original_duration_days VARCHAR(50),
                weightage DECIMAL(10,2) DEFAULT 0,
                actual_start_date DATE,
                actual_end_date DATE,
                progress DECIMAL(5,2) DEFAULT 0,
                status VARCHAR(50) DEFAULT 'Not Started',
                is_critical TINYINT(1) DEFAULT 0,
                is_client_deliverable TINYINT(1) DEFAULT 0,
                delay_weather_days INT DEFAULT 0,
                delay_contractor_days INT DEFAULT 0,
                delay_client_days INT DEFAULT 0,
                is_expanded TINYINT(1) DEFAULT 1,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                INDEX idx_tasks_project_id (project_id),
                INDEX idx_tasks_parent_id (parent_task_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_notes (
                id INT AUTO_INCREMENT PRIMARY KEY,
                task_id VARCHAR(191) NOT NULL,
                text TEXT,
                timestamp TIMESTAMP,
                source VARCHAR(50),
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                INDEX idx_task_notes_task (task_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_comments (
                id VARCHAR(191) PRIMARY KEY,
                task_id VARCHAR(191) NOT NULL,
                admin_comment TEXT,
                client_status VARCHAR(50),
                admin_seen TINYINT(1) DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                INDEX idx_task_comments_task (task_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_comment_attachments (
                id INT AUTO_INCREMENT PRIMARY KEY,
                comment_id VARCHAR(191) NOT NULL,
                file_path TEXT NOT NULL,
                org_id INT,
                project_name VARCHAR(255),
                task_id VARCHAR(191),
                uploaded_by VARCHAR(255),
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (comment_id) REFERENCES task_comments(id) ON DELETE CASCADE,
                INDEX idx_comment_attachments_comment (comment_id),
                INDEX idx_attachments_org_id (org_id),
                INDEX idx_attachments_project (project_name),
                INDEX idx_attachments_org_project (org_id, project_name)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_dependencies (
                id INT AUTO_INCREMENT PRIMARY KEY,
                task_id VARCHAR(191) NOT NULL,
                depends_on_task_id VARCHAR(191) NOT NULL,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY (depends_on_task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                UNIQUE(task_id, depends_on_task_id),
                INDEX idx_task_dependencies_task (task_id),
                INDEX idx_task_dependencies_depends (depends_on_task_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
            """
        )
    else:
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL,
                status TEXT NOT NULL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                client_access_code TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS activity_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_email TEXT,
                project_id INTEGER,
                action TEXT,
                details TEXT,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id TEXT PRIMARY KEY,
                project_id INTEGER NOT NULL,
                parent_task_id TEXT,
                wbs TEXT,
                task_name TEXT,
                planned_start_date DATE,
                planned_end_date DATE,
                predecessor_string TEXT,
                original_duration_days TEXT,
                weightage REAL DEFAULT 0,
                actual_start_date DATE,
                actual_end_date DATE,
                progress REAL DEFAULT 0,
                status TEXT DEFAULT 'Not Started',
                is_critical BOOLEAN DEFAULT 0,
                is_client_deliverable BOOLEAN DEFAULT 0,
                delay_weather_days INTEGER DEFAULT 0,
                delay_contractor_days INTEGER DEFAULT 0,
                delay_client_days INTEGER DEFAULT 0,
                is_expanded BOOLEAN DEFAULT 1,
                FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                FOREIGN KEY (parent_task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                text TEXT,
                timestamp TIMESTAMP,
                source TEXT,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_comments (
                id TEXT PRIMARY KEY,
                task_id TEXT NOT NULL,
                admin_comment TEXT,
                client_status TEXT,
                admin_seen BOOLEAN DEFAULT 0,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_comment_attachments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                comment_id TEXT NOT NULL,
                file_path TEXT NOT NULL,
                org_id INTEGER,
                project_name TEXT,
                task_id TEXT,
                uploaded_by TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (comment_id) REFERENCES task_comments(id) ON DELETE CASCADE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS task_dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id TEXT NOT NULL,
                depends_on_task_id TEXT NOT NULL,
                FOREIGN KEY (task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                FOREIGN KEY (depends_on_task_id) REFERENCES tasks(id) ON DELETE CASCADE,
                UNIQUE(task_id, depends_on_task_id)
            )
        ''')
        
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_project_id ON tasks(project_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_tasks_parent_id ON tasks(parent_task_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_activity_logs_project ON activity_logs(project_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_task_notes_task ON task_notes(task_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_task_dependencies_task ON task_dependencies(task_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_task_dependencies_depends ON task_dependencies(depends_on_task_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_task_comments_task ON task_comments(task_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_comment_attachments_comment ON task_comment_attachments(comment_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attachments_org_id ON task_comment_attachments(org_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attachments_project ON task_comment_attachments(project_name)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_attachments_org_project ON task_comment_attachments(org_id, project_name)')
    return True

def initialize_primary_database():
    """Initialize the Primary MySQL Database with all required tables and indexes for multi-tenancy."""
    try:
        admin_conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            charset=MYSQL_CHARSET,
            autocommit=True,
        )
        admin_cursor = admin_conn.cursor()
        admin_cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS `{MYSQL_PRIMARY_DATABASE}` CHARACTER SET {MYSQL_CHARSET} COLLATE utf8mb4_unicode_ci"
        )
        admin_cursor.close()
        admin_conn.close()
        conn = base_get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor()
    
        if DB_TYPE.lower() == "mysql":
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS organizations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    name VARCHAR(255) UNIQUE NOT NULL,
                    domain VARCHAR(255),
                    db_file_path VARCHAR(255) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status VARCHAR(50) NOT NULL,
                    INDEX idx_orgs_name (name)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password VARCHAR(255) NOT NULL,
                    role VARCHAR(50) NOT NULL,
                    org_id INT,
                    status VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verification_token VARCHAR(255),
                    verification_expires_at TIMESTAMP,
                    is_email_verified TINYINT(1) DEFAULT 0,
                    otp_code VARCHAR(255),
                    otp_expires_at TIMESTAMP,
                    otp_attempts INT DEFAULT 0,
                    otp_verified TINYINT(1) DEFAULT 0,
                    reset_token VARCHAR(255),
                    reset_token_expires_at TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    INDEX idx_users_org_id (org_id),
                    INDEX idx_users_org_role_status (org_id, role, status),
                    INDEX idx_users_email (email),
                    INDEX idx_users_verification_token (verification_token),
                    INDEX idx_users_reset_token (reset_token)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    org_id INT NOT NULL,
                    plan_type VARCHAR(50) NOT NULL,
                    razorpay_subscription_id VARCHAR(255),
                    status VARCHAR(50) NOT NULL,
                    start_date DATE NOT NULL,
                    end_date DATE,
                    billing_cycle VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    INDEX idx_subscriptions_org_id (org_id),
                    INDEX idx_subscriptions_status (status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS billing_transactions (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    org_id INT NOT NULL,
                    razorpay_payment_id VARCHAR(255),
                    amount DECIMAL(12,2) NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    INDEX idx_billing_org_id (org_id),
                    UNIQUE KEY idx_billing_payment_id (razorpay_payment_id)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS payment_requests (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    org_id INT NOT NULL,
                    request_id VARCHAR(255) UNIQUE NOT NULL,
                    subscription_id VARCHAR(255),
                    plan_type VARCHAR(50) NOT NULL,
                    user_count INT NOT NULL,
                    billing_cycle VARCHAR(50) NOT NULL,
                    status VARCHAR(50) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    INDEX idx_payment_requests_request_id (request_id),
                    INDEX idx_payment_requests_org_id (org_id),
                    INDEX idx_payment_requests_status (status),
                    INDEX idx_payment_requests_org_status (org_id, status)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )
        
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    org_id INT,
                    user_id INT,
                    action VARCHAR(255) NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
                    INDEX idx_audit_logs_org_id (org_id),
                    INDEX idx_audit_logs_user_id (user_id),
                    INDEX idx_audit_logs_timestamp (timestamp),
                    INDEX idx_audit_logs_action (action)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS plan_limits (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    plan_type VARCHAR(50) UNIQUE NOT NULL,
                    max_projects INT NOT NULL,
                    max_org_admins INT NOT NULL,
                    max_users INT NOT NULL,
                    max_files_per_project INT NOT NULL,
                    max_ai_prompts_per_week INT NOT NULL
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
                """
            )

            try:
                cursor.execute(
                    "CREATE INDEX idx_audit_logs_ai_prompts ON audit_logs(org_id, action, timestamp)"
                )
            except MySQLError:
                # Index may already exist; ignore duplicate errors
                pass
        else:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS organizations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    domain TEXT,
                    db_file_path TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT NOT NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    email TEXT UNIQUE NOT NULL,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    org_id INTEGER,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    verification_token TEXT,
                    verification_expires_at TIMESTAMP,
                    is_email_verified BOOLEAN DEFAULT 0,
                    otp_code TEXT,
                    otp_expires_at TIMESTAMP,
                    otp_attempts INTEGER DEFAULT 0,
                    otp_verified BOOLEAN DEFAULT 0,
                    reset_token TEXT,
                    reset_token_expires_at TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS subscriptions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL,
                    plan_type TEXT NOT NULL,
                    razorpay_subscription_id TEXT,
                    status TEXT NOT NULL,
                    start_date DATE NOT NULL,
                    end_date DATE,
                    billing_cycle TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS billing_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL,
                    razorpay_payment_id TEXT UNIQUE,
                    amount REAL NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            ''')

            cursor.execute('''
                CREATE TABLE IF NOT EXISTS payment_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER NOT NULL,
                    request_id TEXT UNIQUE NOT NULL,
                    subscription_id TEXT,
                    plan_type TEXT NOT NULL,
                    user_count INTEGER NOT NULL,
                    billing_cycle TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    org_id INTEGER,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (org_id) REFERENCES organizations(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plan_limits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plan_type TEXT UNIQUE NOT NULL,
                    max_projects INTEGER NOT NULL,
                    max_org_admins INTEGER NOT NULL,
                    max_users INTEGER NOT NULL,
                    max_files_per_project INTEGER NOT NULL,
                    max_ai_prompts_per_week INTEGER NOT NULL
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_org_id ON users(org_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_org_role_status ON users(org_id, role, status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_verification_token ON users(verification_token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_users_reset_token ON users(reset_token)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscriptions_org_id ON subscriptions(org_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_subscriptions_status ON subscriptions(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_billing_org_id ON billing_transactions(org_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_org_id ON audit_logs(org_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action)')
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_logs_ai_prompts ON audit_logs(org_id, action, timestamp) WHERE action = 'ai_prompt_used'")
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payment_requests_request_id ON payment_requests(request_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payment_requests_org_id ON payment_requests(org_id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payment_requests_status ON payment_requests(status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_payment_requests_org_status ON payment_requests(org_id, status)')
        
        conn.commit()
        conn.close()
        print("Primary MySQL database initialized successfully")
        
    except MySQLError as e:
        print(f"Error initializing primary MySQL database: {e}")
        raise

def migrate_schema_versioning():
    """Create schema_migrations table to track which migrations have been run."""
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor()
        
        # Create schema_migrations table if it doesn't exist
        if DB_TYPE.lower() == "mysql":
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    migration_name VARCHAR(255) UNIQUE NOT NULL,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    INDEX idx_migration_name (migration_name)
                )
            """)
        else:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS schema_migrations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    migration_name TEXT UNIQUE NOT NULL,
                    executed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_migration_name ON schema_migrations(migration_name)")
        
        conn.commit()
        conn.close()
        print("Schema migrations table initialized successfully")
        
    except Exception as e:
        print(f"Error creating schema_migrations table: {e}")
        # Don't raise - allow application to continue
        try:
            conn.close()
        except Exception:
            pass

def has_migration_run(migration_name):
    """Check if a migration has already been run."""
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor()
        
        if DB_TYPE.lower() == "mysql":
            cursor.execute("SELECT COUNT(*) FROM schema_migrations WHERE migration_name = %s", (migration_name,))
        else:
            cursor.execute("SELECT COUNT(*) FROM schema_migrations WHERE migration_name = ?", (migration_name,))
        
        result = cursor.fetchone()
        count = result[0] if result else 0
        
        conn.close()
        return count > 0
        
    except Exception as e:
        # If table doesn't exist or query fails, assume migration hasn't run
        print(f"Warning: Could not check migration status for '{migration_name}': {e}")
        try:
            conn.close()
        except Exception:
            pass
        return False

def mark_migration_complete(migration_name):
    """Mark a migration as complete."""
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor()
        
        if DB_TYPE.lower() == "mysql":
            cursor.execute("""
                INSERT INTO schema_migrations (migration_name) 
                VALUES (%s)
                ON DUPLICATE KEY UPDATE migration_name = VALUES(migration_name)
            """, (migration_name,))
        else:
            cursor.execute("""
                INSERT OR IGNORE INTO schema_migrations (migration_name) 
                VALUES (?)
            """, (migration_name,))
        
        conn.commit()
        conn.close()
        print(f"Migration '{migration_name}' marked as complete")
        
    except Exception as e:
        print(f"Warning: Could not mark migration '{migration_name}' as complete: {e}")
        try:
            conn.close()
        except Exception:
            pass

def seed_plan_limits():
    """Seed the plan limits table with default values for each pricing plan."""
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor(dictionary=True) if DB_TYPE.lower() == "mysql" else conn.cursor()
        
        # Migration: Check for column existence and migrate if needed
        cursor.execute("SHOW COLUMNS FROM plan_limits")
        columns = [row["Field"] if isinstance(row, dict) else row[0] for row in cursor.fetchall()]

        has_max_org_admins = 'max_org_admins' in columns
        has_max_users = 'max_users' in columns
        has_max_admins = 'max_admins' in columns
        
        if not has_max_org_admins:
            print("Migrating plan_limits: Adding max_org_admins column...")
            alter_stmt = "ALTER TABLE plan_limits ADD COLUMN max_org_admins INT DEFAULT 2" if DB_TYPE.lower() == "mysql" else "ALTER TABLE plan_limits ADD COLUMN max_org_admins INTEGER DEFAULT 2"
            cursor.execute(alter_stmt)
        
        if not has_max_users:
            print("Migrating plan_limits: Adding max_users column...")
            alter_stmt = "ALTER TABLE plan_limits ADD COLUMN max_users INT DEFAULT 2" if DB_TYPE.lower() == "mysql" else "ALTER TABLE plan_limits ADD COLUMN max_users INTEGER DEFAULT 2"
            cursor.execute(alter_stmt)
            
            if has_max_admins:
                print("Migrating plan_limits: Copying max_admins values to max_users...")
                cursor.execute("UPDATE plan_limits SET max_users = max_admins WHERE max_users = 2")
        
        if not has_max_org_admins or has_max_admins:
            cursor.execute("UPDATE plan_limits SET max_org_admins = 2 WHERE max_org_admins IS NULL OR max_org_admins != 2")
        
        conn.commit()
        
        cursor.execute("SELECT COUNT(*) FROM plan_limits")
        count_row = cursor.fetchone()
        count = count_row[0] if isinstance(count_row, (list, tuple)) else (count_row.get('COUNT(*)') if isinstance(count_row, dict) else 0)
        
        if count == 0:
            insert_stmt = """
                INSERT INTO plan_limits (plan_type, max_projects, max_org_admins, max_users, max_files_per_project, max_ai_prompts_per_week)
                VALUES (%s, %s, %s, %s, %s, %s)
            """ if DB_TYPE.lower() == "mysql" else """
                INSERT INTO plan_limits (plan_type, max_projects, max_org_admins, max_users, max_files_per_project, max_ai_prompts_per_week)
                VALUES (?, ?, ?, ?, ?, ?)
            """
            cursor.execute(insert_stmt, ('basic', 1, 5, 5, 20, 10))
            cursor.execute(insert_stmt, ('si_plus', 10, 10, 10, 100, 100))
            cursor.execute(insert_stmt, ('plus', 10, 10, 10, 100, 100))
            cursor.execute(insert_stmt, ('pro', 999999, 999999, 999999, 999999, 999999))
            
            conn.commit()
            print("Plan limits seeded successfully")
        else:
            print("Plan limits already exist, skipping seed")
        
        conn.close()
        
    except MySQLError as e:
        print(f"Error seeding plan limits: {e}")
        raise

def migrate_plan_limits_to_new_pricing():
    migration_name = "migrate_plan_limits_to_new_pricing"
    if has_migration_run(migration_name):
        return
    """Update existing plan_limits records to match new pricing structure without requiring database reset."""
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor(dictionary=True) if DB_TYPE.lower() == "mysql" else conn.cursor()
        
        if DB_TYPE.lower() == "mysql":
            cursor.execute("SELECT max_users FROM plan_limits WHERE plan_type=%s", ('basic',))
        else:
            cursor.execute("SELECT max_users FROM plan_limits WHERE plan_type='basic'")
        result = cursor.fetchone()
        max_users_basic = None
        if isinstance(result, dict):
            max_users_basic = result.get('max_users')
        elif result:
            max_users_basic = result[0]
        
        if result and max_users_basic == 2:
            print("Migrating plan_limits to new pricing structure...")
            
            cursor.execute("UPDATE plan_limits SET max_users=5, max_org_admins=5 WHERE plan_type=%s" if DB_TYPE.lower() == "mysql" else "UPDATE plan_limits SET max_users=5, max_org_admins=5 WHERE plan_type='basic'", ('basic',) if DB_TYPE.lower() == "mysql" else ())
            print("Updated Basic plan limits: 5 users, 5 org_admins")
            
            cursor.execute("UPDATE plan_limits SET max_org_admins=999999 WHERE plan_type=%s" if DB_TYPE.lower() == "mysql" else "UPDATE plan_limits SET max_org_admins=999999 WHERE plan_type='pro'", ('pro',) if DB_TYPE.lower() == "mysql" else ())
            print("Updated Pro plan limits: unlimited org_admins")
            
            if DB_TYPE.lower() == "mysql":
                cursor.execute(
                    """
                    INSERT INTO plan_limits (plan_type, max_projects, max_org_admins, max_users, max_files_per_project, max_ai_prompts_per_week)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    ON DUPLICATE KEY UPDATE plan_type=VALUES(plan_type)
                    """,
                    ('plus', 10, 2, 10, 100, 100)
                )
            else:
                cursor.execute('''
                    INSERT INTO plan_limits (plan_type, max_projects, max_org_admins, max_users, max_files_per_project, max_ai_prompts_per_week)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(plan_type) DO NOTHING
                ''', ('plus', 10, 2, 10, 100, 100))
            print("Added Plus plan limits")
            
            conn.commit()
            print("Plan limits migration completed successfully")
            mark_migration_complete(migration_name)
        else:
            print("Plan limits already migrated, skipping migration")
            mark_migration_complete(migration_name)
        
        conn.close()
        
    except MySQLError as e:
        print(f"Error migrating plan limits: {e}")
        # Don't raise - allow application to continue even if migration fails
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass

def migrate_users_table_for_auth_features():
    """Ensure users table has OTP and reset token columns plus supporting index."""
    migration_name = "migrate_users_table_for_auth_features"
    if has_migration_run(migration_name):
        return
    
    try:
        conn = get_db_connection(MYSQL_PRIMARY_DATABASE)
        cursor = conn.cursor(dictionary=True) if DB_TYPE.lower() == "mysql" else conn.cursor()

        cursor.execute("SHOW COLUMNS FROM users")
        columns = [row["Field"] if isinstance(row, dict) else row[0] for row in cursor.fetchall()]

        migrations = []

        if 'otp_code' not in columns:
            migrations.append(("otp_code", "TEXT"))
        if 'otp_expires_at' not in columns:
            migrations.append(("otp_expires_at", "TIMESTAMP"))
        if 'otp_attempts' not in columns:
            migrations.append(("otp_attempts", "INT DEFAULT 0" if DB_TYPE.lower() == "mysql" else "INTEGER DEFAULT 0"))
        if 'otp_verified' not in columns:
            migrations.append(("otp_verified", "TINYINT(1) DEFAULT 0" if DB_TYPE.lower() == "mysql" else "BOOLEAN DEFAULT 0"))
        if 'reset_token' not in columns:
            migrations.append(("reset_token", "TEXT"))
        if 'reset_token_expires_at' not in columns:
            migrations.append(("reset_token_expires_at", "TIMESTAMP"))

        for column_name, definition in migrations:
            print(f"Migrating users table: Adding {column_name} column...")
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {definition}")

        print("Ensuring idx_users_reset_token exists...")
        # MySQL doesn't support IF NOT EXISTS for CREATE INDEX
        try:
            cursor.execute('CREATE INDEX idx_users_reset_token ON users(reset_token)')
        except MySQLError as index_error:
            # Index might already exist, which is fine
            if "duplicate" in str(index_error).lower() or "already exists" in str(index_error).lower():
                print("Index idx_users_reset_token already exists, skipping...")
            else:
                raise

        conn.commit()

        if migrations:
            print("Users table migration completed successfully.")
            mark_migration_complete(migration_name)
        else:
            print("Users table already up to date; no migration needed.")

        conn.close()
    except MySQLError as exc:
        print(f"Warning: Users table migration failed: {exc}")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass
    except Exception as exc:
        print(f"Warning: Users table migration encountered unexpected error: {exc}")
        try:
            conn.rollback()
            conn.close()
        except Exception:
            pass

def migrate_organizations_table_for_tour():
    """Ensure organizations table has tour_seen column."""
    migration_name = "migrate_organizations_table_for_tour"
    if has_migration_run(migration_name):
        return
    
    conn = None
    cursor = None
    try:
        conn = get_primary_db_connection()
        cursor = conn.cursor(buffered=True)

        # Check if organizations table exists first
        cursor.execute("SHOW TABLES LIKE 'organizations'")
        table_exists = cursor.fetchone() is not None

        if not table_exists:
            print("Warning: Organizations table does not exist, skipping migration.")
            return

        # Get column information
        cursor.execute("DESCRIBE organizations")
        columns = [row[0] for row in cursor.fetchall()]

        if 'tour_seen' not in columns:
            print("Migrating organizations table: Adding tour_seen column...")
            if DB_TYPE.lower() == "mysql":
                cursor.execute("ALTER TABLE organizations ADD COLUMN tour_seen BOOLEAN DEFAULT 0")
            else:
                cursor.execute("ALTER TABLE organizations ADD COLUMN tour_seen BOOLEAN DEFAULT 0")
            conn.commit()
            print("Organizations table migration completed successfully.")
            mark_migration_complete(migration_name)
        else:
            print("Organizations table already up to date; no migration needed.")
            mark_migration_complete(migration_name)

    except MySQLError as exc:
        print(f"Warning: Organizations table migration failed: {exc}")
        try:
            if conn:
                conn.rollback()
        except Exception:
            pass
    except Exception as exc:
        print(f"Warning: Organizations table migration encountered unexpected error: {exc}")
        try:
            if conn:
                conn.rollback()
        except Exception:
            pass
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def migrate_billing_transactions_unique_constraint():
    """Ensure billing_transactions table has UNIQUE constraint on razorpay_payment_id."""
    migration_name = "migrate_billing_transactions_unique_constraint"
    if has_migration_run(migration_name):
        return
    
    conn = None
    cursor = None
    try:
        conn = get_primary_db_connection()
        cursor = conn.cursor(buffered=True)

        # Check if billing_transactions table exists first
        if DB_TYPE.lower() == "mysql":
            cursor.execute("SHOW TABLES LIKE 'billing_transactions'")
            table_exists = cursor.fetchone() is not None
        else:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_transactions'")
            table_exists = cursor.fetchone() is not None

        if not table_exists:
            print("Warning: billing_transactions table does not exist, skipping migration.")
            return

        # Check if unique constraint/index already exists
        constraint_exists = False
        if DB_TYPE.lower() == "mysql":
            cursor.execute("""
                SELECT COUNT(*) FROM INFORMATION_SCHEMA.STATISTICS 
                WHERE TABLE_SCHEMA = DATABASE() 
                AND TABLE_NAME = 'billing_transactions' 
                AND INDEX_NAME = 'idx_billing_payment_id' 
                AND NON_UNIQUE = 0
            """)
            constraint_exists = cursor.fetchone()[0] > 0
        else:
            # SQLite: Check if unique index exists
            cursor.execute("SELECT sql FROM sqlite_master WHERE type='index' AND name='idx_billing_payment_id'")
            index_info = cursor.fetchone()
            if index_info and 'UNIQUE' in (index_info[0] or '').upper():
                constraint_exists = True

        if not constraint_exists:
            print("Migrating billing_transactions table: Adding UNIQUE constraint on razorpay_payment_id...")
            if DB_TYPE.lower() == "mysql":
                # Check for existing duplicates before adding constraint
                cursor.execute("""
                    SELECT razorpay_payment_id, COUNT(*) as cnt 
                    FROM billing_transactions 
                    WHERE razorpay_payment_id IS NOT NULL 
                    GROUP BY razorpay_payment_id 
                    HAVING cnt > 1
                """)
                duplicates = cursor.fetchall()
                if duplicates:
                    print(f"Warning: Found {len(duplicates)} duplicate payment IDs. Keeping first occurrence of each.")
                    # Keep the first occurrence (lowest id) of each duplicate
                    for payment_id, count in duplicates:
                        cursor.execute("""
                            DELETE t1 FROM billing_transactions t1
                            INNER JOIN billing_transactions t2 
                            WHERE t1.razorpay_payment_id = t2.razorpay_payment_id
                            AND t1.razorpay_payment_id = %s
                            AND t1.id > t2.id
                        """, (payment_id,))
                    conn.commit()
                
                cursor.execute("CREATE UNIQUE INDEX idx_billing_payment_id ON billing_transactions(razorpay_payment_id)")
            else:
                # SQLite: Create unique index
                cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_billing_payment_id ON billing_transactions(razorpay_payment_id)")
            
            conn.commit()
            print("billing_transactions table migration completed successfully.")
            mark_migration_complete(migration_name)
        else:
            print("billing_transactions table already has UNIQUE constraint; no migration needed.")
            mark_migration_complete(migration_name)

    except MySQLError as exc:
        print(f"Warning: billing_transactions table migration failed: {exc}")
        try:
            if conn:
                conn.rollback()
        except Exception:
            pass
    except Exception as exc:
        print(f"Warning: billing_transactions table migration encountered unexpected error: {exc}")
        try:
            if conn:
                conn.rollback()
        except Exception:
            pass
    finally:
        if cursor:
            try:
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass

def migrate_billing_transactions_retry_tracking():
    """Add retry_attempts and last_retry_at columns to billing_transactions table."""
    migration_name = "migrate_billing_transactions_retry_tracking"
    if has_migration_run(migration_name):
        return
    
    conn = None
    cursor = None
    try:
        conn = get_primary_db_connection()
        cursor = conn.cursor(buffered=True)

        # Check if billing_transactions table exists first
        if DB_TYPE.lower() == "mysql":
            cursor.execute("SHOW TABLES LIKE 'billing_transactions'")
            table_exists = cursor.fetchone() is not None
        else:
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='billing_transactions'")
            table_exists = cursor.fetchone() is not None

        if not table_exists:
            print("Warning: billing_transactions table does not exist, skipping migration.")
            return

        # Check existing columns
        if DB_TYPE.lower() == "mysql":
            cursor.execute("SHOW COLUMNS FROM billing_transactions")
            columns = [row[0] for row in cursor.fetchall()]
        else:
            cursor.execute("PRAGMA table_info(billing_transactions)")
            columns = [row[1] for row in cursor.fetchall()]

        # Add retry_attempts column if it doesn't exist
        if 'retry_attempts' not in columns:
            print("Migrating billing_transactions table: Adding retry_attempts column...")
            if DB_TYPE.lower() == "mysql":
                cursor.execute("ALTER TABLE billing_transactions ADD COLUMN retry_attempts INT DEFAULT 0")
            else:
                cursor.execute("ALTER TABLE billing_transactions ADD COLUMN retry_attempts INTEGER DEFAULT 0")
            conn.commit()
            print("✓ Added retry_attempts column")

        # Add last_retry_at column if it doesn't exist
        if 'last_retry_at' not in columns:
            print("Migrating billing_transactions table: Adding last_retry_at column...")
            if DB_TYPE.lower() == "mysql":
                cursor.execute("ALTER TABLE billing_transactions ADD COLUMN last_retry_at TIMESTAMP NULL")
            else:
                cursor.execute("ALTER TABLE billing_transactions ADD COLUMN last_retry_at TIMESTAMP")
            conn.commit()
            print("✓ Added last_retry_at column")
        
        # Mark migration as complete if any columns were added, or if columns already exist
        if 'retry_attempts' in columns and 'last_retry_at' in columns:
            mark_migration_complete(migration_name)
        elif 'retry_attempts' not in columns or 'last_retry_at' not in columns:
            # Columns were added, mark as complete
            mark_migration_complete(migration_name)

    except MySQLError as e:
        print(f"Error migrating billing_transactions retry tracking: {e}")
        if conn:
            conn.rollback()
    except Exception as e:
        print(f"Unexpected error in migrate_billing_transactions_retry_tracking: {e}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def get_db_connection(database_name=None):
    """Return a connection to the configured primary database."""
    target = database_name or (MYSQL_PRIMARY_DATABASE)
    return base_get_db_connection(target)


def execute_query(query, params=None, fetch_one=False, fetch_all=False, commit=True, return_lastrowid=False):
    """Generic function to execute database queries with proper error handling."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        normalized_query = convert_query_placeholders(query, DB_TYPE)
        if DB_TYPE.lower() == "mysql":
            # Use buffered tuple cursor for consistent row[0] access
            cursor = conn.cursor(buffered=True)
        else:
            cursor = conn.cursor()

        if params:
            cursor.execute(normalized_query, params)
        else:
            cursor.execute(normalized_query)

        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            if return_lastrowid or (normalized_query.strip().upper().startswith('INSERT') and cursor.lastrowid is not None):
                result = cursor.lastrowid
            else:
                result = cursor.rowcount

        if commit:
            conn.commit()

        return result

    except MySQLError as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"Database error: {e}")
        raise
    finally:
        if cursor:
            try:
                # Consume any remaining results to prevent "Unread result found" errors
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def get_tenant_db_connection():
    """Return a database connection to the current tenant's organization database."""
    if not hasattr(g, 'tenant_db_path') or not g.tenant_db_path:
        org_id = getattr(g, 'org_id', None)
        raise TenantDatabaseError(org_id, None, "Tenant context missing for tenant DB connection")
    
    try:
        if DB_TYPE.lower() == "mysql":
            # Use MySQL connector's built-in pooling directly
            db_name = g.tenant_db_path
            pool_name = f"{db_name}_pool"
            
            conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=db_name,
                charset=MYSQL_CHARSET,
                autocommit=False,
                use_pure=True,
                pool_name=pool_name,
                pool_size=MYSQL_POOL_SIZE,
                pool_reset_session=True,
                consume_results=True,
            )
            
            # print(f"[DB-POOL] Tenant connection obtained: {db_name} (Pool: {pool_name})")
            return conn
        else:
            # This should not happen in MySQL-only mode
            return tenant_pool.get_connection(
                org_id=getattr(g, 'org_id', None),
                db_file_path=g.tenant_db_path,
            )
    except MySQLError as e:
        org_id = getattr(g, 'org_id', None)
        db_path = getattr(g, 'tenant_db_path', None)
        
        
        raise TenantDatabaseError(org_id, db_path, f"Database connection failed: {e}")


def execute_tenant_query(query, params=None, fetch_one=False, fetch_all=False, commit=True, return_lastrowid=False, as_dict=False):
    """Execute queries on the tenant's database with proper error handling.
    
    Args:
        as_dict: If True, returns dict results with column names (for JSON serialization).
                 If False (default), returns tuples for consistent row[0] access.
    """
    conn = None
    cursor = None
    try:
        conn = get_tenant_db_connection()
        normalized_query = convert_query_placeholders(query, DB_TYPE)
        if DB_TYPE.lower() == "mysql":
            # Use buffered cursor; dictionary mode when as_dict=True for JSON serialization
            cursor = conn.cursor(buffered=True, dictionary=as_dict)
        else:
            cursor = conn.cursor()

        if params:
            cursor.execute(normalized_query, params)
        else:
            cursor.execute(normalized_query)

        if fetch_one:
            result = cursor.fetchone()
        elif fetch_all:
            result = cursor.fetchall()
        else:
            if return_lastrowid or (normalized_query.strip().upper().startswith('INSERT') and cursor.lastrowid is not None):
                result = cursor.lastrowid
            else:
                result = cursor.rowcount

        if commit:
            conn.commit()

        return result

    except MySQLError as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        org_id = getattr(g, 'org_id', None)
        db_path = getattr(g, 'tenant_db_path', None)
        print(f"Tenant database error: {e}")
        raise TenantDatabaseError(org_id, db_path, f"Query execution failed: {e}")
    finally:
        if cursor:
            try:
                # Consume any remaining results to prevent "Unread result found" errors
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                # For MySQL, close() returns connection to pool
                conn.close()
            except Exception:
                pass


def execute_many(query, params_list):
    """Execute multiple statements in a batch operation."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        normalized_query = convert_query_placeholders(query, DB_TYPE)
        if DB_TYPE.lower() == "mysql":
            cursor = conn.cursor(buffered=True)
        else:
            cursor = conn.cursor()
        cursor.executemany(normalized_query, params_list)
        conn.commit()
        return True
    except MySQLError as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"Database error in execute_many: {e}")
        raise
    finally:
        if cursor:
            try:
                # Consume any remaining results to prevent "Unread result found" errors
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def execute_transaction(operations):
    """Execute multiple operations in a single transaction."""
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        if DB_TYPE.lower() == "mysql":
            conn.start_transaction()
            cursor = conn.cursor(buffered=True)
        else:
            cursor = conn.cursor()

        for query, params in operations:
            normalized_query = convert_query_placeholders(query, DB_TYPE)
            if params:
                cursor.execute(normalized_query, params)
            else:
                cursor.execute(normalized_query)

        conn.commit()
        return True
    except MySQLError as e:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"Database error in transaction: {e}")
        return False
    finally:
        if cursor:
            try:
                # Consume any remaining results to prevent "Unread result found" errors
                try:
                    cursor.fetchall()
                except Exception:
                    pass
                cursor.close()
            except Exception:
                pass
        if conn:
            try:
                conn.close()
            except Exception:
                pass


def prepare_query_for_db(query, params=None):
    """Convert query placeholders for the configured database."""
    return convert_query_placeholders(query, DB_TYPE), params

def dict_to_row(row):
    """Convert database row objects to dictionaries for JSON serialization."""
    if row is None:
        return None
    if isinstance(row, dict):
        return row
    # Handle MySQL tuple results by pairing with placeholder keys if needed
    if isinstance(row, tuple):
        # When caller expects explicit keys, they should not use dict_to_row without context.
        # Here we fallback to positional keys to avoid tuple->dict errors.
        return {str(idx): val for idx, val in enumerate(row)}
    if hasattr(row, "keys"):
        return dict(row)
    return {str(idx): val for idx, val in enumerate(row)}

def get_tenant_db_path(org_id):
    """Resolve database file path for a given organization ID.
    
    Args:
        org_id (int): Organization ID
        
    Returns:
        str: Normalized absolute database file path
        
    Raises:
        TenantResolutionError: If organization not found or inactive
        MySQLError: If database query fails
    """
    try:
        result_raw = execute_primary_query(
            "SELECT db_file_path, status FROM organizations WHERE id = ?",
            params=(org_id,),
            fetch_one=True
        )
        if not result_raw:
            print(f"[TENANT-DB-PATH] Organization not found for org_id={org_id}")
            raise TenantResolutionError(org_id, "Organization not found")
        
        if isinstance(result_raw, dict):
            db_file_path = result_raw.get('db_file_path')
            status = result_raw.get('status')
        elif hasattr(result_raw, "keys"):
            _tmp = dict(result_raw)
            db_file_path = _tmp.get('db_file_path')
            status = _tmp.get('status')
        else:
            db_file_path = result_raw[0] if len(result_raw) > 0 else None
            status = result_raw[1] if len(result_raw) > 1 else None
        
        # print(f"[TENANT-DB-PATH] Query result for org_id={org_id}: db_file_path={db_file_path}, status={status}")
        # print(f"[TENANT-DB-PATH] Organization status check for org_id={org_id}: status={status}, expected='active'")
        if status != 'active':
            raise TenantResolutionError(org_id, f"Organization status is {status}, not active")
        
        # Check for invalid db_file_path values (empty, whitespace-only, or 'pending')
        if not db_file_path or not db_file_path.strip() or db_file_path.strip().lower() == 'pending':
            print(f"[TENANT-DB-PATH] Invalid db_file_path for org_id={org_id}: '{db_file_path}' (empty, whitespace, or 'pending')")
            raise TenantResolutionError(org_id, "Database file path is not provisioned")

        # MySQL path: treat stored value as database name
        if DB_TYPE.lower() == "mysql":
            db_name = str(db_file_path).strip()
            # print(f"[TENANT-DB-PATH] Resolved MySQL database name for org_id={org_id}: {db_name}")
            return db_name
        
        # Decrypt path if needed; raise error if decryption fails
        original_length = len(db_file_path) if db_file_path else 0
        try:
            decrypted = decrypt_db_path(db_file_path)
            db_file_path = decrypted
            print(f"[TENANT-DB-PATH] Decryption result for org_id={org_id}: original_length={original_length}, decrypted_length={len(db_file_path) if db_file_path else 0}")
        except Exception as e:
            print(f"[TENANT-DB-PATH] Decryption failed for org_id={org_id}, db_file_path length={original_length}: {e}")
            raise TenantResolutionError(org_id, "Failed to decrypt db_file_path")
        
        # Normalize the path: resolve relative paths or filenames to absolute paths
        if not db_file_path:
            raise TenantResolutionError(org_id, "Database file path is empty")
        
        # Check if path is absolute
        if os.path.isabs(db_file_path):
            # Path is already absolute - check if it exists
            print(f"[TENANT-DB-PATH] File exists check for org_id={org_id}: path={db_file_path}, exists={os.path.exists(db_file_path)}")
            if os.path.exists(db_file_path):
                print(f"[TENANT-DB-PATH] Resolved path for org_id={org_id}: {db_file_path}")
                return db_file_path
            else:
                # Absolute path doesn't exist - resolve using just filename relative to ORG_DB_DIR
                # This handles cases where the stored absolute path is incorrect or outdated
                filename = os.path.basename(db_file_path)
                fallback_path = os.path.join(ORG_DB_DIR, filename)
                resolved_path = os.path.abspath(fallback_path)
                print(f"[TENANT-DB-PATH] Using fallback path for org_id={org_id}: original={db_file_path}, fallback={resolved_path}")
                # Return the fallback path (where the file should be), even if it doesn't exist yet
                # validate_tenant_context() will catch if the file doesn't exist
                return resolved_path
        else:
            # Path is relative - extract just the filename and resolve it relative to ORG_DB_DIR
            # This handles cases like "org_1.db" or "databases/org_1.db" by using only the filename
            filename = os.path.basename(db_file_path)
            resolved_path = os.path.join(ORG_DB_DIR, filename)
            resolved_path = os.path.abspath(resolved_path)
            print(f"[TENANT-DB-PATH] Resolved path for org_id={org_id}: {resolved_path}")
            return resolved_path
        
    except MySQLError as e:
        raise TenantResolutionError(org_id, f"Database query failed: {e}")


def validate_tenant_context():
    """Validate that tenant context is properly set up.
    
    Returns:
        bool: True if tenant context is valid, False otherwise
    """
    try:
        # Check if g attributes exist
        if not hasattr(g, 'org_id') or not hasattr(g, 'tenant_db_path'):
            return False
        
        # Check if org_id exists
        if g.org_id is None:
            return False
        
        # Check if tenant_db_path exists
        if g.tenant_db_path is None:
            return False

        # For MySQL, tenant_db_path holds the database name, no filesystem checks
        if DB_TYPE.lower() == "mysql":
            return True
        
        # Check if tenant database file exists on filesystem
        if not os.path.exists(g.tenant_db_path):
            return False
        
        return True
        
    except (AttributeError, OSError):
        return False


def resolve_tenant():
    """Extract tenant information from JWT token and store in Flask's g object.
    
    This middleware function runs before every request to populate tenant context.
    It extracts JWT claims and resolves the tenant database path from Primary DB.
    """
    try:
        # Initialize g attributes to None
        g.org_id = None
        g.role = None
        g.plan = None
        g.user_id = None
        g.email = None
        g.tenant_db_path = None
        g.subscription_active = None
        g.subscription_status = None
        
        # Attempt to verify JWT if present (no branching; optional=True)
        verify_jwt_in_request(optional=True)
        
        # Extract JWT claims; if no JWT present, get_jwt will raise RuntimeError
        try:
            claims = get_jwt()
        except RuntimeError:
            # No JWT present; leave g as initialized and return
            print(f"[TENANT-RESOLUTION] No JWT token present in request to {request.path}")
            return
        
        # Store claims in g object
        g.org_id = claims.get('org_id')
        g.role = claims.get('role')
        g.plan = claims.get('plan')
        g.user_id = claims.get('user_id')
        g.email = claims.get('email')
        
        # Log extracted claims
        # print(f"[TENANT-RESOLUTION] JWT claims extracted: org_id={g.org_id}, role={g.role}, user_id={g.user_id}, email={g.email}")
        
        # Resolve tenant database path if org_id exists
        if g.org_id is not None:
            try:
                # Use centralized helper for org db path
                db_file_path = get_tenant_db_path(g.org_id)
                g.tenant_db_path = db_file_path
                
                # Check subscription status - PRIORITIZE ACTIVE PLANS
                # First, check if there is ANY active/valid subscription
                # This prevents a recent "abandoned" upgrade attempt from blocking an existing "active" plan
                active_status_query = """
                    SELECT status, plan_type FROM subscriptions 
                    WHERE org_id = ? 
                    AND status IN ('active', 'trial', 'authenticated', 'created', 'paused', 'pending_cancellation')
                    ORDER BY id DESC LIMIT 1
                """
                subscription_result_raw = execute_primary_query(
                    active_status_query,
                    params=(g.org_id,),
                    fetch_one=True
                )
                
                # If no active plan found, get the absolute latest status (which might be abandoned, expired, cancelled)
                if not subscription_result_raw:
                    subscription_result_raw = execute_primary_query(
                        "SELECT status, plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
                        params=(g.org_id,),
                        fetch_one=True
                    )
                
                subscription_status = None
                fresh_plan_type = None
                if subscription_result_raw:
                    if isinstance(subscription_result_raw, dict):
                        subscription_status = subscription_result_raw.get('status')
                        fresh_plan_type = subscription_result_raw.get('plan_type')
                    elif hasattr(subscription_result_raw, "keys"):
                        subscription_status = dict(subscription_result_raw).get('status')
                        fresh_plan_type = dict(subscription_result_raw).get('plan_type')
                    else:
                        if len(subscription_result_raw) >= 2:
                            subscription_status = subscription_result_raw[0]
                            fresh_plan_type = subscription_result_raw[1]
                        elif len(subscription_result_raw) > 0:
                            # Fallback if query didn't return 2 columns for some reason (unlikely with this change)
                            subscription_status = subscription_result_raw[0]
                
                if subscription_status is not None:
                    g.subscription_status = subscription_status
                    if fresh_plan_type:
                        g.plan = fresh_plan_type
                        # print(f"[MIDDLEWARE] Updated g.plan to {g.plan} from DB")
                    
                    # Set subscription active flag with enhanced status checks
                    ALLOWED_SUBSCRIPTION_STATUSES = ['active', 'trial', 'authenticated', 'created', 'paused', 'pending_cancellation']
                    BLOCKED_SUBSCRIPTION_STATUSES = ['halted', 'cancelled', 'expired', 'abandoned']
                    if subscription_status in ALLOWED_SUBSCRIPTION_STATUSES:
                        g.subscription_active = True
                    elif subscription_status in BLOCKED_SUBSCRIPTION_STATUSES:
                        g.subscription_active = False
                        print(f"[MIDDLEWARE] Access blocked for org_id={g.org_id}, subscription_status={subscription_status}")
                    else:
                        g.subscription_active = False
                        print(f"[MIDDLEWARE] Unknown subscription status: {subscription_status}")
                else:
                    g.subscription_status = None
                    g.subscription_active = False
            except TenantResolutionError as e:
                # Organization not found or inactive
                print(f"[TENANT-RESOLUTION] Tenant resolution error for org_id={g.org_id}: {e}")
                g.tenant_db_path = None
                g.subscription_active = False
                g.subscription_status = None
            except MySQLError as e:
                print(f"[TENANT-RESOLUTION] Database error resolving tenant for org_id={g.org_id}: {e}")
                g.tenant_db_path = None
                g.subscription_active = False
                g.subscription_status = None
        else:
            # SuperAdmin or client - no tenant context needed
            g.tenant_db_path = None
            g.subscription_active = None
            g.subscription_status = None
        
        # Warn if org_admin or org_user has NULL org_id
        if g.org_id is None and g.role in [ROLE_ORG_ADMIN, ROLE_ORG_USER]:
            print(f"[TENANT-RESOLUTION] WARNING: User {g.email} (role={g.role}) has NULL org_id - this user cannot access tenant resources")
        
        # Log successful tenant resolution
        print(f"[TENANT-RESOLUTION] Tenant resolved for {request.path}: org_id={g.org_id}, role={g.role}, db_path={g.tenant_db_path}, subscription_active={g.subscription_active}")
        
    # Do not catch JWT-specific exceptions here; JWT callbacks handle those.
    except Exception as e:
        # Any other error
        print(f"Tenant resolution failed: {e}")
        g.org_id = None
        g.role = None
        g.plan = None
        g.user_id = None
        g.email = None
        g.tenant_db_path = None
        g.subscription_active = None
        g.subscription_status = None


# Register the middleware to run before every request
@app.before_request
def before_request():
    resolve_tenant()

# --- Helper Functions for Authentication ---

def wants_html_response():
    """Determine if the current request should receive an HTML response.
    
    Returns True only when:
    - The request targets a non-API route (not starting with '/api')
    - The request clearly prefers HTML (text/html in Accept header)
    
    This ensures that API requests always receive JSON responses, regardless
    of Accept header, while HTML routes can receive redirects on auth failures.
    
    Returns:
        bool: True if request should receive HTML response, False otherwise
    """
    # API routes always return JSON, never redirect
    if request.path.startswith('/api'):
        return False
    
    # Check if request prefers HTML
    accept_header = request.headers.get('Accept', '')
    if 'text/html' in accept_header:
        return True
    
    # Also check accept_mimetypes for compatibility
    if hasattr(request, 'accept_mimetypes') and 'text/html' in request.accept_mimetypes:
        return True
    
    return False

# --- Decorators for Access Control ---
#
# AUTHENTICATION ARCHITECTURE:
#
# HTML Routes (/, /home, /dashboard, etc.):
#   - No server-side authentication decorators
#   - Publicly accessible
#   - Client-side JavaScript validates JWT tokens from localStorage
#   - Redirects to / if authentication fails
#
# API Routes (/api/*):
#   - Protected by decorators (@role_required, @tenant_required, etc.)
#   - Returns JSON error responses for API clients
#   - Redirects to / for browser requests (defense-in-depth)
#
# This dual strategy ensures:
#   - Fast page loads (no server-side auth delay)
#   - Secure API access (server-side validation)
#   - Good UX (redirects vs JSON errors for browsers)
#
# Note: All decorators detect HTML requests using Accept header and redirect
# to / instead of returning JSON errors. This provides defense-in-depth if
# decorators are accidentally applied to HTML routes.

def tenant_required(fn):
    """Decorator to protect routes that require tenant context.
    
    This decorator ensures that the request has a valid JWT token with org_id
    and that the tenant database path is resolved.
    
    HTML requests (browser navigation) are redirected to / on authentication
    or tenant context failure. API requests receive JSON error responses.
    
    Args:
        fn: The route function to protect
        
    Returns:
        function: Wrapped function with tenant validation
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # First validate JWT token
        try:
            verify_jwt_in_request()
        except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError):
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource.',
                'error_code': 'AUTHENTICATION_REQUIRED'
            }), 401
        except Exception as e:
            # Log unexpected errors and return 500
            print(f"Unexpected error in tenant_required decorator: {e}")
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred.',
                'error_code': 'INTERNAL_ERROR'
            }), 500
        
        # Check tenant context - allow SuperAdmin to bypass
        if not validate_tenant_context():
            # Allow SuperAdmin to bypass tenant requirement
            if hasattr(g, 'role') and g.role == ROLE_SUPER_ADMIN:
                # SuperAdmin operates on Primary DB, no tenant context needed
                return fn(*args, **kwargs)
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'Organization context required',
                'message': 'Organization context required. Please ensure you are logged in with a valid organization account.',
                'error_code': 'TENANT_CONTEXT_REQUIRED'
            }), 403
        
        # Call the original function
        return fn(*args, **kwargs)
    
    return wrapper


def superadmin_required(fn):
    """Decorator to protect routes that only SuperAdmin can access.
    
    This decorator ensures that the request has a valid JWT token and that
    the user role is 'super_admin'.
    
    HTML requests (browser navigation) are redirected to / on authentication
    or authorization failure. API requests receive JSON error responses.
    
    Args:
        fn: The route function to protect
        
    Returns:
        function: Wrapped function with SuperAdmin validation
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # First validate JWT token
        try:
            verify_jwt_in_request()
        except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError):
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource.',
                'error_code': 'AUTHENTICATION_REQUIRED'
            }), 401
        except Exception as e:
            # Log unexpected errors and return 500
            print(f"Unexpected error in superadmin_required decorator: {e}")
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred.',
                'error_code': 'INTERNAL_ERROR'
            }), 500
        
        # Check SuperAdmin role
        if not hasattr(g, 'role') or g.role != 'super_admin':
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'SuperAdmin access required',
                'message': 'SuperAdmin access required. You do not have permission to access this resource.',
                'error_code': 'SUPERADMIN_REQUIRED'
            }), 403
        
        # Call the original function
        return fn(*args, **kwargs)
    
    return wrapper


def role_required(allowed_roles):
    """Decorator to protect routes that require specific roles.
    
    This decorator ensures that the request has a valid JWT token and that
    the user role is in the allowed roles list.
    
    HTML requests (browser navigation) are redirected to / on authentication
    or authorization failure. API requests receive JSON error responses with
    specific error codes (AUTHENTICATION_REQUIRED, ROLE_REQUIRED).
    
    Args:
        allowed_roles (list): List of allowed role strings to check against
        
    Returns:
        function: Decorator function
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            # First validate JWT token
            try:
                verify_jwt_in_request()
            except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError):
                # Check if this is an HTML request and redirect instead of returning JSON
                if wants_html_response():
                    return redirect('/')
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please log in to access this resource.',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
            except Exception as e:
                # Log unexpected errors and return 500
                print(f"Unexpected error in role_required decorator: {e}")
                return jsonify({
                    'error': 'Internal server error',
                    'message': 'An unexpected error occurred.',
                    'error_code': 'INTERNAL_ERROR'
                }), 500
            
            # Check role authorization
            if not hasattr(g, 'role') or g.role not in allowed_roles:
                # Check if this is an HTML request and redirect instead of returning JSON
                if wants_html_response():
                    return redirect('/')
                return jsonify({
                    'error': 'Access denied',
                    'message': f"Access denied. Required roles: {', '.join(allowed_roles)}",
                    'error_code': 'ROLE_REQUIRED'
                }), 403
            
            # Call the original function
            return fn(*args, **kwargs)
        
        return wrapper
    return decorator


def require_https_payment(fn):
    """Decorator to enforce HTTPS on payment endpoints regardless of FORCE_HTTPS setting.
    
    This decorator ensures PCI-DSS compliance by requiring HTTPS for all payment-related
    operations. It checks the request scheme and X-Forwarded-Proto header.
    
    Localhost and 127.0.0.1 are exempted for local development.
    
    Args:
        fn: The route function to protect
        
    Returns:
        function: Wrapped function with HTTPS enforcement
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # Allow localhost for development
        host = request.host or ''
        if host.startswith('localhost') or host.startswith('127.0.0.1'):
            return fn(*args, **kwargs)
        
        # Check if request is over HTTPS
        scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
        if scheme != 'https':
            return jsonify({
                'status': 'error',
                'error_code': 'HTTPS_REQUIRED',
                'message': 'This endpoint requires HTTPS connection for security compliance'
            }), 403
        
        return fn(*args, **kwargs)
    
    return wrapper


def subscription_required(fn):
    """Decorator to protect routes that require active subscription.
    
    This decorator ensures that the request has a valid tenant context and
    that the organization's subscription is active.
    
    HTML requests (browser navigation) are redirected to / on authentication
    or tenant context failure. Subscription inactive errors are handled by the
    global error handler. SuperAdmin users bypass subscription checks.
    
    Args:
        fn: The route function to protect
        
    Returns:
        function: Wrapped function with subscription validation
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        # Validate JWT
        try:
            verify_jwt_in_request()
        except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError):
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'Authentication required',
                'message': 'Please log in to access this resource.',
                'error_code': 'AUTHENTICATION_REQUIRED'
            }), 401
        except Exception as e:
            # Log unexpected errors and return 500
            print(f"Unexpected error in subscription_required decorator: {e}")
            return jsonify({
                'error': 'Internal server error',
                'message': 'An unexpected error occurred.',
                'error_code': 'INTERNAL_ERROR'
            }), 500
        # SuperAdmin bypass
        if hasattr(g, 'role') and g.role == ROLE_SUPER_ADMIN:
            return fn(*args, **kwargs)

        # Validate tenant context
        if not validate_tenant_context():
            # Check if this is an HTML request and redirect instead of returning JSON
            if wants_html_response():
                return redirect('/')
            return jsonify({
                'error': 'Organization context required',
                'message': 'Organization context required. Please ensure you are logged in with a valid organization account.',
                'error_code': 'TENANT_CONTEXT_REQUIRED'
            }), 403
        
        # Check subscription status
        # Note: SubscriptionInactiveError is raised here and handled by the global
        # error handler at handle_subscription_inactive_error(). The error handler
        # currently always returns JSON, but subscription checks are typically on
        # API routes, so this is acceptable.
        if not hasattr(g, 'subscription_active') or not g.subscription_active:
            org_id = getattr(g, 'org_id', 'Unknown')
            subscription_status = getattr(g, 'subscription_status', 'Unknown')
            raise SubscriptionInactiveError(org_id, subscription_status)
        
        # Call the original function
        return fn(*args, **kwargs)
    
    return wrapper


# --- Global Error Handlers ---

# Plan limit validation decorator
def check_plan_limit(resource_type):
    """Decorator to enforce subscription plan limits on resource-creating actions.
    
    HTML requests (browser navigation) are redirected to / on authentication failure.
    Plan limit exceeded errors always return JSON (since they only occur on API routes
    that create resources). SuperAdmin users bypass all plan limit checks.
    
    Args:
        resource_type (str): One of 'project', 'admin', 'file', 'ai_prompt'
    """
    def decorator(fn):
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):
            try:
                # Ensure auth context is present
                verify_jwt_in_request()
            except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError):
                # Check if this is an HTML request and redirect instead of returning JSON
                if wants_html_response():
                    return redirect('/')
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'Please log in to access this resource.',
                    'error_code': 'AUTHENTICATION_REQUIRED'
                }), 401
            except Exception as e:
                # Log unexpected errors and return 500
                print(f"Unexpected error in check_plan_limit decorator: {e}")
                return jsonify({
                    'error': 'Internal server error',
                    'message': 'An unexpected error occurred.',
                    'error_code': 'INTERNAL_ERROR'
                }), 500

            # Super admin bypass
            if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
                return fn(*args, **kwargs)

            org_id = getattr(g, 'org_id', None)
            plan_type = getattr(g, 'plan', None)

            # Fail-open if tenant context missing
            if org_id is None:
                return fn(*args, **kwargs)

            limits = get_plan_limits(plan_type)
            if not limits:
                return fn(*args, **kwargs)

            def over_limit(current_value, limit_value):
                if limit_value is None or limit_value >= UNLIMITED_LIMIT:
                    return False
                return current_value >= limit_value

            try:
                if resource_type == RESOURCE_TYPE_PROJECT:
                    current = get_current_project_count(org_id)
                    limit_val = limits.get('max_projects', UNLIMITED_LIMIT)
                elif resource_type == RESOURCE_TYPE_ADMIN:
                    current = get_current_admin_count(org_id)
                    limit_val = limits.get('max_users', UNLIMITED_LIMIT)
                elif resource_type == RESOURCE_TYPE_FILE:
                    # Extract project name from request (form or json)
                    project_name = (request.form.get('project') or
                                    request.form.get('project_name') or
                                    (request.get_json(silent=True) or {}).get('project') or
                                    (request.get_json(silent=True) or {}).get('project_name'))
                    if not project_name:
                        return jsonify({'status': 'error', 'message': 'Project is required'}), 400
                    current = get_project_file_count(project_name, org_id)
                    limit_val = limits.get('max_files_per_project', UNLIMITED_LIMIT)
                elif resource_type == RESOURCE_TYPE_AI_PROMPT:
                    current = get_weekly_ai_prompt_count(org_id)
                    limit_val = limits.get('max_ai_prompts_per_week', UNLIMITED_LIMIT)
                else:
                    return fn(*args, **kwargs)

                if over_limit(current, limit_val):
                    suggestion = get_upgrade_suggestion(plan_type, resource_type)
                    message = format_limit_error_message(resource_type, current, limit_val, plan_type)
                    # Log violation (best effort)
                    try:
                        execute_primary_query(
                            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                            params=(org_id, getattr(g, 'user_id', None), 'plan_limit_exceeded', json.dumps({
                                'resource_type': resource_type,
                                'current_usage': current,
                                'limit': limit_val,
                                'plan': plan_type
                            }))
                        )
                    except Exception:
                        pass

                    # Note: Plan limit exceeded errors always return JSON since they only occur
                    # on API routes that create resources (projects, admins, files, AI prompts).
                    # HTML routes don't create resources, so this scenario won't occur for HTML requests.
                    return jsonify({
                        'status': 'error',
                        'error_code': ERROR_CODE_PLAN_LIMIT_EXCEEDED,
                        'message': message,
                        'resource_type': resource_type,
                        'current_usage': current,
                        'limit': limit_val,
                        'plan': plan_type,
                        'upgrade_required': True,
                        'suggested_plan': suggestion['suggested_plan'] if suggestion else None,
                        'upgrade_url': suggestion['upgrade_url'] if suggestion else '/upgrade'
                    }), 403

                return fn(*args, **kwargs)
            except Exception as e:
                # Fail-open on transient errors
                print(f"Plan limit check error for {resource_type}: {e}")
                return fn(*args, **kwargs)

        return wrapper
    return decorator


@app.errorhandler(TenantDatabaseError)
def handle_tenant_database_error(error):
    """Handle tenant database access errors."""
    print(f"Tenant database error: {error}")
    return jsonify({
        'error': 'Database access error',
        'message': 'Unable to access organization database. Please contact support.',
        'error_code': 'TENANT_DB_ERROR'
    }), 500


@app.errorhandler(TenantResolutionError)
def handle_tenant_resolution_error(error):
    """Handle tenant resolution errors."""
    print(f"Tenant resolution error: {error}")
    return jsonify({
        'error': 'Organization not found',
        'message': 'Organization not found or inactive. Please contact support.',
        'error_code': 'TENANT_NOT_FOUND'
    }), 404

# --- JWT Error Handlers ---
#
# DUAL AUTHENTICATION STRATEGY:
#
# The application uses a dual authentication strategy:
#   - Server-side for API routes: Decorators (@role_required, @tenant_required, etc.)
#     validate JWT tokens and return JSON errors for API clients or redirect HTML requests
#   - Client-side for HTML routes: JavaScript in templates validates JWT tokens from
#     localStorage and redirects to / if authentication fails
#
# HOW DECORATORS AND JWT HANDLERS WORK TOGETHER:
#
# 1. Decorator-protected routes (API routes):
#    - Decorators catch JWT exceptions in their try-except blocks FIRST
#    - They detect HTML requests via Accept header and redirect to /
#    - They return JSON errors for API requests
#    - JWT error handlers are rarely reached for decorator-protected routes
#
# 2. Non-decorator routes (HTML routes):
#    - JWT validation may occur outside decorators (edge cases)
#    - JWT error handlers catch these exceptions
#    - They detect HTML requests and redirect to /
#    - They return JSON errors for API requests
#
# HTML vs JSON RESPONSE DECISION LOGIC:
#
# All decorators and JWT handlers use the centralized wants_html_response() helper
# to detect HTML requests. This helper ensures:
#   - API routes (starting with '/api') always return JSON, never redirect
#   - Non-API routes that prefer HTML are redirected to / on auth failures
#   - Non-API routes that prefer JSON receive JSON error responses
#
# If HTML request detected:
#   - Redirect to / (landing page) for re-authentication
#
# If API request detected:
#   - Return JSON error response with appropriate error code
#
# This ensures consistent authentication experience across all route types.

@jwt.invalid_token_loader
def on_invalid_token(reason):
    """Handle invalid JWT token errors.
    
    This handler is reached when JWT validation fails OUTSIDE of decorator-protected
    routes. Decorator-protected routes handle JWT errors in their own try-except blocks
    before this handler is triggered. The HTML detection logic here serves as a fallback
    for edge cases.
    """
    print(f"Invalid token: {reason}")
    # Check if this is an HTML request and redirect instead of returning JSON
    if wants_html_response():
        return redirect('/')
    return jsonify({
        'error': 'Invalid token',
        'message': 'Invalid authentication token. Please log in again.',
        'error_code': 'INVALID_TOKEN'
    }), 401


@jwt.revoked_token_loader
def on_revoked_token(jwt_header, jwt_payload):
    """Handle revoked JWT token errors.
    
    This handler is reached when a revoked token is used OUTSIDE of decorator-protected
    routes. Decorator-protected routes handle JWT errors in their own try-except blocks
    before this handler is triggered. HTML detection ensures consistent behavior.
    """
    print("Revoked token used")
    # Check if this is an HTML request and redirect instead of returning JSON
    if wants_html_response():
        return redirect('/')
    return jsonify({
        'error': 'Token revoked',
        'message': 'This token has been revoked. Please log in again.',
        'error_code': 'TOKEN_REVOKED'
    }), 401


@jwt.expired_token_loader
def on_expired_token(jwt_header, jwt_payload):
    """Handle expired JWT token errors.
    
    This handler is reached when an expired token is used OUTSIDE of decorator-protected
    routes. Decorator-protected routes handle JWT errors in their own try-except blocks
    before this handler is triggered. HTML requests are redirected to / for re-authentication.
    API requests receive JSON with error code TOKEN_EXPIRED.
    """
    print("Expired token used")
    # Check if this is an HTML request and redirect instead of returning JSON
    if wants_html_response():
        return redirect('/')
    return jsonify({
        'error': 'Token expired',
        'message': 'Authentication token has expired. Please refresh your token or log in again.',
        'error_code': 'TOKEN_EXPIRED'
    }), 401


@jwt.unauthorized_loader
def on_missing_token(reason):
    """Handle missing or unauthorized JWT token errors.
    
    This handler handles missing or unauthorized tokens. It includes HTML detection
    logic and redirect behavior. Decorator-protected routes handle JWT errors in
    their own try-except blocks before this handler is triggered, but this serves
    as a fallback for edge cases.
    """
    print(f"Missing/unauthorized token: {reason}")
    # Check if this is an HTML request and redirect instead of returning JSON
    if wants_html_response():
        return redirect('/')
    return jsonify({
        'error': 'Authentication required',
        'message': 'Authorization token is missing or invalid.',
        'error_code': 'AUTHENTICATION_REQUIRED'
    }), 401


@app.errorhandler(SubscriptionInactiveError)
def handle_subscription_inactive_error(error):
    """Handle subscription inactive errors.
    
    This error is raised by the @subscription_required decorator when an organization's
    subscription is inactive. HTML requests are redirected to / for re-authentication.
    API requests receive JSON error responses. This error typically occurs on API routes
    that require active subscriptions, so HTML detection provides defense-in-depth.
    """
    print(f"Subscription inactive error: {error}")
    # Check if this is an HTML request and redirect instead of returning JSON
    if wants_html_response():
        return redirect('/')
    return jsonify({
        'error': 'Subscription inactive',
        'message': 'Your organization\'s subscription is inactive. Please contact your administrator.',
        'error_code': 'SUBSCRIPTION_INACTIVE'
    }), 403


# Razorpay error handlers
@app.errorhandler(razorpay.errors.BadRequestError)
def handle_razorpay_bad_request(error):
    print(f"Razorpay BadRequestError: {error}")
    return jsonify({
        'error': 'Invalid payment request',
        'message': 'Invalid payment request. Please check your details.',
        'error_code': 'RAZORPAY_BAD_REQUEST'
    }), 400


@app.errorhandler(razorpay.errors.ServerError)
def handle_razorpay_server_error(error):
    print(f"Razorpay ServerError: {error}")
    return jsonify({
        'error': 'Payment service unavailable',
        'message': 'Payment service temporarily unavailable. Please try again later.',
        'error_code': 'RAZORPAY_SERVER_ERROR'
    }), 503


@app.errorhandler(razorpay.errors.SignatureVerificationError)
def handle_signature_verification_error(error):
    print(f"Razorpay SignatureVerificationError: {error}")
    return jsonify({
        'error': 'Invalid signature',
        'message': 'Payment verification failed. Please contact support.',
        'error_code': 'INVALID_SIGNATURE'
    }), 400

def seed_super_admin():
    """Seed the initial super admin user if no users exist.
    
    DISABLED: Use /api/superadmin/signup endpoint instead for self-service SuperAdmin creation.
    This function is kept for reference but disabled to prevent hardcoded credentials.
    """
    # DISABLED: Rely on /api/superadmin/signup with SUPERADMIN_SECRET_KEY instead
    # This prevents hardcoded credentials and ensures proper database usage
    print("WARNING: seed_super_admin() is disabled. Use /api/superadmin/signup endpoint instead.")
    return
    
    # Legacy code (disabled):
    # try:
    #     # Check if any users exist in Primary DB
    #     result = execute_primary_query("SELECT COUNT(*) as count FROM users", fetch_one=True)
    #     if result and result[0] > 0:
    #         return  # Users already exist
    #     
    #     # Use environment variables for initial SuperAdmin credentials if available
    #     super_admin_email = os.environ.get('INITIAL_SUPERADMIN_EMAIL', '')
    #     super_admin_password_raw = os.environ.get('INITIAL_SUPERADMIN_PASSWORD', '')
    #     
    #     if not super_admin_email or not super_admin_password_raw:
    #         print("WARNING: INITIAL_SUPERADMIN_EMAIL and INITIAL_SUPERADMIN_PASSWORD not set. Skipping seed.")
    #         return
    #     
    #     super_admin_password = hash_password(super_admin_password_raw)
    #     
    #     # Insert super admin user into Primary DB with org_id=NULL
    #     execute_primary_query(
    #         "INSERT INTO users (email, password, role, org_id, status, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)",
    #         (super_admin_email, super_admin_password, ROLE_SUPER_ADMIN, None, 'approved', 1)
    #     )
    #     print("Super admin user seeded successfully")
    #     


def auto_create_superadmin_from_env():
    """
    Automatically create a SuperAdmin user from environment credentials.

    This helper reads SUPERADMIN_EMAIL and SUPERADMIN_PASSWORD from the environment,
    validates both values, and creates the SuperAdmin account if it does not exist.
    The function is idempotent (safe to call multiple times) and logs both success
    and failure events to audit_logs for traceability.
    """
    email = (os.environ.get('SUPERADMIN_EMAIL') or SUPERADMIN_EMAIL or "").strip()
    password_raw = os.environ.get('SUPERADMIN_PASSWORD') or SUPERADMIN_PASSWORD or ""

    if not email or not password_raw:
        print("[AUTO-SUPERADMIN] Skipping automatic provisioning: SUPERADMIN_EMAIL or SUPERADMIN_PASSWORD not set.")
        return

    if not validate_email_format(email):
        print(f"[AUTO-SUPERADMIN] WARNING: Invalid SUPERADMIN_EMAIL '{email}'. Automatic provisioning skipped.")
        return

    password_valid, password_error = validate_password_strength(password_raw)
    if not password_valid:
        print(f"[AUTO-SUPERADMIN] WARNING: {password_error}. Automatic provisioning skipped.")
        return

    def log_auto_provision(action, payload, *, user_id=None):
        """Best-effort audit logging for auto provisioning events."""
        try:
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (None, user_id, action, json.dumps(payload)),
                commit=True
            )
        except Exception:
            pass

    try:
        existing_user = execute_primary_query(
            "SELECT id FROM users WHERE email = ?",
            (email,),
            fetch_one=True
        )

        if existing_user:
            existing_user_id = None
            try:
                existing_user_id = existing_user["id"]
            except (TypeError, KeyError, IndexError):
                try:
                    existing_user_id = existing_user[0]
                except (TypeError, IndexError):
                    existing_user_id = existing_user

            print(f"[AUTO-SUPERADMIN] SuperAdmin account for {email} already exists (user_id={existing_user_id}). Skipping creation.")
            return

        hashed_password = hash_password(password_raw)
        user_id = execute_primary_query(
            "INSERT INTO users (email, password, role, org_id, status, is_email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            (email, hashed_password, ROLE_SUPER_ADMIN, None, 'approved', 1),
            return_lastrowid=True
        )

        log_auto_provision(
            'superadmin_auto_created',
            {
                "email": email,
                "created_by": "environment_variables",
                "timestamp": datetime.now().isoformat(),
            },
            user_id=user_id
        )

        print(f"[AUTO-SUPERADMIN] SuperAdmin account auto-created for {email} (user_id={user_id}).")

    except mysql.connector.IntegrityError as exc:
        print(f"[AUTO-SUPERADMIN] WARNING: Integrity error while auto-creating SuperAdmin: {exc}")
        log_auto_provision(
            'superadmin_auto_create_failed',
            {
                "email": email,
                "error": str(exc),
                "timestamp": datetime.now().isoformat(),
                "reason": "integrity_error",
            }
        )
    except MySQLError as exc:
        print(f"[AUTO-SUPERADMIN] ERROR: Database error while auto-creating SuperAdmin: {exc}")
        log_auto_provision(
            'superadmin_auto_create_failed',
            {
                "email": email,
                "error": str(exc),
                "timestamp": datetime.now().isoformat(),
                "reason": "database_error",
            }
        )
    except Exception as exc:
        print(f"[AUTO-SUPERADMIN] ERROR: Unexpected error during SuperAdmin auto-creation: {exc}")
        log_auto_provision(
            'superadmin_auto_create_failed',
            {
                "email": email,
                "error": str(exc),
                "timestamp": datetime.now().isoformat(),
                "reason": "unexpected_error",
            }
        )

# --- Helper Functions ---

def sanitize(obj):
    """
    MODIFIED: Recursively replace NaN/NaT values with None.
    The order of checks is important to prevent the ambiguous truth value error.
    """
    # First, handle collection types (dict, list) recursively.
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    if pd.isna(obj):
        return None

    return obj

def hash_password(password):
    """Hashes a password for storing."""
    return hashlib.sha256(password.encode()).hexdigest()

def get_name_from_email(email):
    """Creates a display name from an email address."""
    try:
        name_part = email.split('@')[0]
        # Replace dots or underscores with spaces and capitalize
        return ' '.join(word.capitalize() for word in name_part.replace('.', ' ').replace('_', ' ').split())
    except:
        return "Admin" # Fallback


def validate_email_format(email):
    try:
        return bool(re.match(EMAIL_REGEX, email or ""))
    except Exception:
        return False

def validate_password_strength(password):
    if not password:
        return (False, "Password is required")
    if len(password) < MIN_PASSWORD_LENGTH:
        return (False, "Password must be at least 8 characters")
    if not re.search(r"[A-Z]", password):
        return (False, "Password must contain uppercase, lowercase, digit, and special character")
    if not re.search(r"[a-z]", password):
        return (False, "Password must contain uppercase, lowercase, digit, and special character")
    if not re.search(r"[0-9]", password):
        return (False, "Password must contain uppercase, lowercase, digit, and special character")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return (False, "Password must contain uppercase, lowercase, digit, and special character")
    return (True, "")

def validate_org_name(org_name):
    name = (org_name or "").strip()
    if not name:
        return (False, "Organization name must be 2-100 characters")
    if len(name) < MIN_ORG_NAME_LENGTH or len(name) > MAX_ORG_NAME_LENGTH:
        return (False, "Organization name must be 2-100 characters")
    if not re.match(ORG_NAME_REGEX, name):
        return (False, "Organization name contains invalid characters")
    return (True, "")

def check_user_access(user_id, require_same_org=True):
    """Centralized authorization check for user management operations.
    
    Args:
        user_id: ID of user being accessed
        require_same_org: If True, enforce org_id match for Org Admin
        
    Returns:
        Tuple (authorized: bool, user: dict, error_response: tuple)
    """
    try:
        # Query user from Primary DB
        user = execute_primary_query(
            "SELECT id, email, role, org_id, status FROM users WHERE id = ?",
            (user_id,),
            fetch_one=True
        )
        
        if not user:
            return (False, None, (jsonify({"error": "User not found"}), 404))
        
        # Convert to dictionary
        user_dict = dict_to_row(user)
        
        # SuperAdmin has full access
        if g.role == ROLE_SUPER_ADMIN:
            return (True, user_dict, None)
        
        # Org Admin checks
        if g.role == ROLE_ORG_ADMIN and require_same_org:
            # Check org_id match
            if user_dict['org_id'] != g.org_id:
                return (False, user_dict, (jsonify({"error": "Access denied. You can only view users in your organization."}), 403))
            
            # Check not super_admin
            if user_dict['role'] == ROLE_SUPER_ADMIN:
                return (False, user_dict, (jsonify({"error": "Cannot manage super_admin users"}), 403))
        
        return (True, user_dict, None)
        
    except MySQLError as e:
        print(f"Database error in check_user_access: {e}")
        return (False, None, (jsonify({"error": "Database error occurred"}), 500))

def generate_verification_token():
    return secrets.token_urlsafe(32)

def get_verification_expiry():
    return (datetime.now() + timedelta(hours=VERIFICATION_TOKEN_EXPIRY_HOURS)).strftime('%Y-%m-%d %H:%M:%S')

# --- Usage Tracking and Plan Limits Helpers ---
@functools.lru_cache(maxsize=32)
def get_plan_limits(plan_type):
    """Retrieve plan limits from Primary DB for given plan type.
    
    Args:
        plan_type (str): Plan type ('basic', 'si_plus', 'plus', 'pro')
    
    Returns:
        dict | None: Plan limits or None if not found
    """
    try:
        pt = plan_type or 'basic'
        # Normalize plan type for backward compatibility
        pt = normalize_plan_type(pt)
        row = execute_primary_query(
            "SELECT max_projects, max_org_admins, max_users, max_files_per_project, max_ai_prompts_per_week FROM plan_limits WHERE plan_type = ?",
            (pt,),
            fetch_one=True
    )
        if not row:
            return None
        return {
            'max_projects': row[0],
            'max_org_admins': row[1],
            'max_users': row[2],
            'max_files_per_project': row[3],
            'max_ai_prompts_per_week': row[4]
        }
    except Exception as e:
        print(f"Error fetching plan limits: {e}")
        return None


def get_current_project_count(org_id):
    """Count projects in tenant DB using context-bound connection (legacy)."""
    try:
        row = execute_tenant_query("SELECT COUNT(*) FROM projects", fetch_one=True)
        return int(row[0] if row else 0)
    except Exception as e:
        print(f"Error counting projects for org {org_id}: {e}")
        return 0

def get_project_count_for_org(org_id):
    """Count projects for a specific organization by opening its tenant MySQL database directly."""
    try:
        db_name = get_tenant_db_name(org_id)
        conn = mysql.connector.connect(
            host=MYSQL_HOST,
            port=MYSQL_PORT,
            user=MYSQL_USER,
            password=MYSQL_PASSWORD,
            database=db_name,
            charset=MYSQL_CHARSET,
        )
        try:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM projects")
            r = cur.fetchone()
            return int(r[0]) if r and r[0] is not None else 0
        finally:
            conn.close()
    except Exception as e:
        print(f"Error counting projects for org {org_id}: {e}")
        return 0


def get_current_admin_count(org_id):
    """Count active org users (org_admin + org_user) in Primary DB for org."""
    try:
        row = execute_primary_query(
            "SELECT COUNT(*) FROM users WHERE org_id = ? AND role IN ('org_admin','org_user') AND status IN ('approved','active')",
            (org_id,),
            fetch_one=True
        )
        return int(row[0] if row else 0)
    except Exception as e:
        print(f"Error counting users for org {org_id}: {e}")
        return 0


def get_current_org_admin_count(org_id):
    """Count only users with role='org_admin' in the organization."""
    try:
        row = execute_primary_query(
            "SELECT COUNT(*) FROM users WHERE org_id = ? AND role = 'org_admin' AND status IN ('approved','active')",
            (org_id,),
            fetch_one=True
        )
        return int(row[0] if row else 0)
    except Exception as e:
        print(f"Error counting org admins for org {org_id}: {e}")
        return 0


def get_project_file_count(project_name, org_id):
    """Count files for a project using org_id and project_name (index-optimized)."""
    try:
        # Prefer new columns if available
        row = execute_tenant_query(
            "SELECT COUNT(*) FROM task_comment_attachments WHERE project_name = ? AND org_id = ?",
            (project_name, org_id),
            fetch_one=True
        )
        if row is not None:
            return int(row[0] if row and row[0] is not None else 0)
    except Exception:
        # Fallback to legacy join-based counting for backward compatibility
        try:
            project_id = execute_tenant_query(
                "SELECT id FROM projects WHERE name = ?",
                (project_name,),
                fetch_one=True
            )
            if not project_id:
                return 0
            pid = project_id[0]
            row = execute_tenant_query(
                """
                SELECT COUNT(a.id)
                FROM task_comment_attachments a
                JOIN task_comments c ON c.id = a.comment_id
                JOIN tasks t ON t.id = c.task_id
                WHERE t.project_id = ?
                """,
                (pid,),
                fetch_one=True
            )
            return int(row[0]) if row and row[0] is not None else 0
        except Exception as e2:
            print(f"Error counting files for project {project_name} (org {org_id}): {e2}")
            return 0


def get_secure_file_path(org_id, project_name, task_id, filename):
    """Construct and validate a secure absolute file path under UPLOAD_FOLDER.

    Raises ValueError for invalid inputs or SecurityError for traversal attempts.
    """
    if org_id is None:
        raise ValueError('Organization context required')
    if not project_name or not task_id or not filename:
        raise ValueError('Missing required path components')

    from werkzeug.utils import secure_filename as _secure_filename

    sanitized_filename = _secure_filename(filename)
    # Basic traversal checks
    if any(x in sanitized_filename for x in ('..', '/', '\\')):
        raise ValueError('Invalid filename')

    base_root = os.path.abspath(UPLOAD_FOLDER)
    target_path = os.path.join(base_root, str(org_id), project_name, str(task_id), sanitized_filename)
    normalized_path = os.path.normpath(target_path)

    if not normalized_path.startswith(base_root):
        raise ValueError('Invalid file path')

    return normalized_path


def log_file_access(action, org_id, project_name, task_id, filename, details=None):
    """Insert an audit log entry for file operations into Primary DB.

    Fails gracefully if logging encounters an error.
    """
    try:
        payload = {
            'project_name': project_name,
            'task_id': task_id,
            'filename': filename,
            'user_email': getattr(g, 'email', None),
            'user_role': getattr(g, 'role', None),
        }
        if details:
            try:
                payload.update(details)
            except Exception:
                pass
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, getattr(g, 'user_id', None), action, json.dumps(payload)),
            commit=True
        )
    except Exception as _:
        # Do not block file operation on logging issues
        pass

def get_weekly_ai_prompt_count(org_id):
    """Count AI prompts used in last 7 days from Primary DB audit_logs."""
    try:
        if DB_TYPE.lower() == "mysql":
            query = "SELECT COUNT(*) FROM audit_logs WHERE org_id = ? AND action = 'ai_prompt_used' AND timestamp >= DATE_SUB(NOW(), INTERVAL 7 DAY)"
        else:
            query = "SELECT COUNT(*) FROM audit_logs WHERE org_id = ? AND action = 'ai_prompt_used' AND timestamp >= datetime('now','-7 days')"
        row = execute_primary_query(
            query,
            (org_id,),
            fetch_one=True
        )
        if isinstance(row, dict):
            count = next(iter(row.values())) if row else 0
        elif hasattr(row, "keys"):
            _tmp = dict(row)
            count = next(iter(_tmp.values())) if _tmp else 0
        else:
            count = row[0] if row else 0
        return int(count or 0)
    except Exception as e:
        print(f"Error counting weekly AI prompts for org {org_id}: {e}")
        return 0


def track_ai_prompt_usage(org_id, user_id, prompt_type, details=None):
    """Track AI prompt usage in audit_logs (Primary DB)."""
    try:
        payload = {
            'prompt_type': prompt_type,
            'endpoint': request.path,
            'additional_info': details
        }
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, 'ai_prompt_used', ?)",
            (org_id, user_id, json.dumps(payload)),
            commit=True
        )
        return True
    except Exception as e:
        print(f"Error tracking AI prompt usage: {e}")
        return False


def get_org_usage_stats(org_id, plan_type):
    """Aggregate org usage and compute percentages and at-limit flags."""
    limits = get_plan_limits(plan_type) or {}
    max_projects = limits.get('max_projects', UNLIMITED_LIMIT)
    max_users = limits.get('max_users', UNLIMITED_LIMIT)
    max_files = limits.get('max_files_per_project', UNLIMITED_LIMIT)
    max_prompts = limits.get('max_ai_prompts_per_week', UNLIMITED_LIMIT)

    projects_used = get_current_project_count(org_id)
    admins_used = get_current_admin_count(org_id)
    prompts_used = get_weekly_ai_prompt_count(org_id)

    def pct(cur, lim):
        if lim >= UNLIMITED_LIMIT:
            return 0
        if lim == 0:
            return 0
        return round((cur / lim) * 100, 2)

    data = {
        'plan_type': plan_type,
        'limits': {
            'projects': max_projects,
            'users': max_users,
            'files_per_project': max_files,
            'ai_prompts_per_week': max_prompts
        },
        'usage': {
            'projects': projects_used,
            'users': admins_used,
            'ai_prompts_this_week': prompts_used
        },
        'percentage': {
            'projects': pct(projects_used, max_projects),
            'users': pct(admins_used, max_users),
            'ai_prompts': pct(prompts_used, max_prompts)
        },
        'at_limit': {
            'projects': projects_used >= max_projects and max_projects < UNLIMITED_LIMIT,
            'users': admins_used >= max_users and max_users < UNLIMITED_LIMIT,
            'ai_prompts': prompts_used >= max_prompts and max_prompts < UNLIMITED_LIMIT
        }
    }
    return data
def get_upgrade_suggestion(current_plan, resource_type):
    """Suggest the next plan tier for upgrade, if applicable."""
    # Normalize plan type for comparison
    current_plan = normalize_plan_type(current_plan)
    plan_chain = ['basic', 'plus', 'pro']
    if current_plan not in plan_chain:
        current_plan = 'basic'
    idx = plan_chain.index(current_plan)
    if idx >= len(plan_chain) - 1:
        return None
    next_plan = plan_chain[idx + 1]
    next_limits = get_plan_limits(next_plan) or {}
    cur_limits = get_plan_limits(current_plan) or {}
    mapping = {
        RESOURCE_TYPE_PROJECT: ('max_projects', 'projects'),
        RESOURCE_TYPE_ADMIN: ('max_users', 'users'),
        RESOURCE_TYPE_FILE: ('max_files_per_project', 'files_per_project'),
        RESOURCE_TYPE_AI_PROMPT: ('max_ai_prompts_per_week', 'ai_prompts_per_week')
    }
    key, _ = mapping.get(resource_type, ('max_projects', 'projects'))
    return {
        'current_plan': current_plan,
        'suggested_plan': next_plan,
        'current_limit': cur_limits.get(key),
        'new_limit': next_limits.get(key),
        'price_difference': None,
        'upgrade_url': f"/upgrade?plan={next_plan}"
    }


def format_limit_error_message(resource_type, current_usage, limit, plan_type):
    """Generate user-friendly error messages for plan limit exceeded."""
    # Normalize plan type for comparison
    plan_type = normalize_plan_type(plan_type)
    
    if resource_type == RESOURCE_TYPE_PROJECT:
        if limit >= UNLIMITED_LIMIT:
            return "Project creation allowed."
        return f"Project limit reached ({current_usage}/{limit}). Upgrade to Plus plan for 10 projects." if plan_type == 'basic' else f"Project limit reached ({current_usage}/{limit}). Upgrade to Pro plan for unlimited projects."
    if resource_type == RESOURCE_TYPE_ADMIN:
        if limit >= UNLIMITED_LIMIT:
            return "User creation allowed."
        return f"User limit reached ({current_usage}/{limit}). Upgrade to Plus to add more team members." if plan_type == 'basic' else f"User limit reached ({current_usage}/{limit}). Upgrade to Pro to add unlimited team members."
    if resource_type == RESOURCE_TYPE_FILE:
        if limit >= UNLIMITED_LIMIT:
            return "File upload allowed."
        return f"File limit reached for this project ({current_usage}/{limit}). Upgrade to Plus for 100 files per project." if plan_type == 'basic' else f"File limit reached for this project ({current_usage}/{limit}). Upgrade to Pro for unlimited files."
    if resource_type == RESOURCE_TYPE_AI_PROMPT:
        if limit >= UNLIMITED_LIMIT:
            return "AI prompt allowed."
        return f"You've reached your weekly AI prompt limit ({current_usage}/{limit}). Upgrade to Plus for 100 prompts per week." if plan_type == 'basic' else f"You've reached your weekly AI prompt limit ({current_usage}/{limit}). Upgrade to Pro for unlimited prompts."
    return "Plan limit reached."


# --- SuperAdmin Billing Metrics Helpers ---
def calculate_mrr():
    """Calculate Monthly Recurring Revenue (MRR) across active subscriptions in rupees."""
    try:
        subs = execute_primary_query("SELECT org_id, plan_type FROM subscriptions WHERE status = 'active'", fetch_all=True)
        total = 0.0
        if subs:
            for row in subs:
                org_id = row[0]
                plan_type = row[1]
                users_row = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND status IN ('approved','active')", (org_id,), fetch_one=True)
                user_count = int(users_row[0]) if users_row else 1
                monthly_paise = calculate_subscription_amount(plan_type, user_count, 'monthly')
                total += (monthly_paise / 100.0)
        return round(total, 2)
    except Exception as e:
        print(f"calculate_mrr error: {e}")
        return 0.0

def calculate_churn_rate(start_date, end_date):
    """Calculate churn rate (%) in given period using cancelled vs active at start."""
    try:
        cancelled_row = execute_primary_query(
            "SELECT COUNT(*) FROM subscriptions WHERE status = 'cancelled' AND date(end_date) BETWEEN ? AND ?",
            (start_date, end_date), fetch_one=True
        )
        cancelled = int(cancelled_row[0]) if cancelled_row else 0
        active_start_row = execute_primary_query(
            "SELECT COUNT(*) FROM subscriptions WHERE status = 'active' AND (start_date IS NULL OR date(start_date) <= ?)",
            (start_date,), fetch_one=True
        )
        active_start = int(active_start_row[0]) if active_start_row else 0
        if active_start == 0:
            return 0.0
        return round((cancelled / active_start) * 100.0, 2)
    except Exception as e:
        print(f"calculate_churn_rate error: {e}")
        return 0.0

def get_revenue_by_period(start_date, end_date, group_by='month'):
    """Return list of {period, revenue} grouped by day/month from billing_transactions."""
    try:
        if DB_TYPE.lower() == "mysql":
            if group_by == 'day':
                query = "SELECT DATE(created_at) as period, SUM(amount) FROM billing_transactions WHERE status = 'success' AND DATE(created_at) BETWEEN ? AND ? GROUP BY DATE(created_at) ORDER BY period"
            else:
                query = "SELECT DATE_FORMAT(created_at, '%Y-%m') as period, SUM(amount) FROM billing_transactions WHERE status = 'success' AND DATE(created_at) BETWEEN ? AND ? GROUP BY DATE_FORMAT(created_at, '%Y-%m') ORDER BY period"
        else:
            if group_by == 'day':
                query = "SELECT date(created_at) as period, SUM(amount) FROM billing_transactions WHERE status = 'success' AND date(created_at) BETWEEN ? AND ? GROUP BY date(created_at) ORDER BY period"
            else:
                query = "SELECT strftime('%Y-%m', created_at) as period, SUM(amount) FROM billing_transactions WHERE status = 'success' AND date(created_at) BETWEEN ? AND ? GROUP BY strftime('%Y-%m', created_at) ORDER BY period"
        rows = execute_primary_query(query, (start_date, end_date), fetch_all=True)
        out = []
        if rows:
            for r in rows:
                out.append({"period": r[0], "revenue": float(r[1] or 0.0)})
        return out
    except Exception as e:
        print(f"get_revenue_by_period error: {e}")
        return []

def get_project_id_by_name(project_name):
    """Query the projects table to get the project ID by name."""
    try:
        result = execute_tenant_query("SELECT id FROM projects WHERE name = ?", (project_name,), fetch_one=True)
        if result:
            return result[0]
        return None
    except Exception as e:
        print(f"Error getting project ID: {e}")
        return None


def get_project_ai_insights(project_id):
    """Fetch stored AI insights JSON for a given project_id, if any."""
    try:
        # Ensure table exists
        execute_tenant_query(
            """
            CREATE TABLE IF NOT EXISTS project_ai_insights (
                project_id INTEGER PRIMARY KEY,
                insights_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            commit=True
        )
        row = execute_tenant_query(
            "SELECT insights_json, updated_at FROM project_ai_insights WHERE project_id = ?",
            (project_id,),
            fetch_one=True
        )
        if not row:
            return None
        return {
            "insights": json.loads(row[0]),
            "updated_at": row[1],
        }
    except Exception as e:
        print(f"Error fetching project AI insights for project_id={project_id}: {e}")
        return None


def upsert_project_ai_insights(project_id, insights_obj):
    """Insert or update stored AI insights JSON for a given project_id."""
    try:
        # Ensure table exists
        execute_tenant_query(
            """
            CREATE TABLE IF NOT EXISTS project_ai_insights (
                project_id INTEGER PRIMARY KEY,
                insights_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
            """,
            commit=True
        )
        updated_at = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        insights_json = json.dumps(insights_obj or {})
        if DB_TYPE.lower() == "mysql":
            execute_tenant_query(
                """
                INSERT INTO project_ai_insights (project_id, insights_json, updated_at)
                VALUES (?, ?, ?)
                ON DUPLICATE KEY UPDATE
                    insights_json = VALUES(insights_json),
                    updated_at = VALUES(updated_at)
                """,
                (project_id, insights_json, updated_at),
                commit=True
            )
        else:
            execute_tenant_query(
                """
                INSERT INTO project_ai_insights (project_id, insights_json, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(project_id) DO UPDATE SET
                    insights_json = excluded.insights_json,
                    updated_at = excluded.updated_at
                """,
                (project_id, insights_json, updated_at),
                commit=True
            )
        return True
    except Exception as e:
        print(f"Error upserting project AI insights for project_id={project_id}: {e}")
        return False
def load_tasks_from_db(project_id):
    """Load all tasks for a project and reconstruct the hierarchical structure."""
    conn = None
    try:
        # Load all tasks for the project
        tasks_result = execute_tenant_query("SELECT * FROM tasks WHERE project_id = ? ORDER BY wbs", (project_id,), fetch_all=True)
        if not tasks_result:
            return []
        
        # Get column names for mapping without opening a new pooled connection
        if DB_TYPE.lower() == "mysql":
            pragma_cols = execute_tenant_query("SHOW COLUMNS FROM tasks", fetch_all=True)
            columns = [row[0] for row in pragma_cols] if pragma_cols else []
        else:
            # This should not happen in MySQL-only mode
            columns = []
        
        # Convert to list of dictionaries
        tasks = []
        for row in tasks_result:
            task_dict = dict(zip(columns, row))
            tasks.append(task_dict)
            # #region agent log
            if len(tasks) == 1:
                import json as _json
                with open(r'd:\Digital Transformation\PROTON\Productization\PROTON-V5_Optimization\.cursor\debug.log', 'a', encoding='utf-8') as _f:
                    _f.write(_json.dumps({
                        "sessionId": "debug-session",
                        "runId": "dates-run1",
                        "hypothesisId": "H1",
                        "location": "app.py:load_tasks_from_db:raw_row",
                        "message": "First DB task row date types",
                        "data": {
                            "planned_start_date": str(task_dict.get("planned_start_date")),
                            "planned_start_date_type": str(type(task_dict.get("planned_start_date"))),
                            "planned_end_date": str(task_dict.get("planned_end_date")),
                            "planned_end_date_type": str(type(task_dict.get("planned_end_date"))),
                            "actual_start_date": str(task_dict.get("actual_start_date")),
                            "actual_start_date_type": str(type(task_dict.get("actual_start_date"))),
                            "actual_end_date": str(task_dict.get("actual_end_date")),
                            "actual_end_date_type": str(type(task_dict.get("actual_end_date")))
                        },
                        "timestamp": int(datetime.now().timestamp() * 1000)
                    }) + "\n")
            # #endregion
        
        # Bulk load all associated data to avoid N+1 queries
        task_ids = [task['id'] for task in tasks]
        if not task_ids:
            return []
        
        # Create placeholders for the IN clause
        placeholders = ','.join(['?' for _ in task_ids])
        
        # Load all notes for all tasks
        notes_result = execute_tenant_query(f"SELECT task_id, text, timestamp, source FROM task_notes WHERE task_id IN ({placeholders}) ORDER BY task_id, id", task_ids, fetch_all=True)
        notes_by_task = {}
        for note in notes_result:
            task_id = note[0]
            if task_id not in notes_by_task:
                notes_by_task[task_id] = []
            notes_by_task[task_id].append({'text': note[1], 'timestamp': note[2], 'source': note[3]})
        
        # Load all comments for all tasks
        comments_result = execute_tenant_query(f"SELECT id, task_id, admin_comment, client_status, admin_seen, timestamp FROM task_comments WHERE task_id IN ({placeholders}) ORDER BY task_id, timestamp", task_ids, fetch_all=True)
        comments_by_task = {}
        comment_ids = []
        for comment in comments_result:
            comment_id = comment[0]
            task_id = comment[1]
            comment_ids.append(comment_id)
            if task_id not in comments_by_task:
                comments_by_task[task_id] = []
            comments_by_task[task_id].append({
                'id': comment_id,
                'adminComment': comment[2],
                'clientStatus': comment[3],
                'adminSeen': comment[4],
                'timestamp': comment[5],
                'attachments': []  # Will be populated below
            })
        
        # Load all attachments for all comments
        attachments_by_comment = {}
        if comment_ids:
            comment_placeholders = ','.join(['?' for _ in comment_ids])
            attachments_result = execute_tenant_query(f"SELECT comment_id, file_path FROM task_comment_attachments WHERE comment_id IN ({comment_placeholders})", comment_ids, fetch_all=True)
            for attachment in attachments_result:
                comment_id = attachment[0]
                if comment_id not in attachments_by_comment:
                    attachments_by_comment[comment_id] = []
                attachments_by_comment[comment_id].append({'filePath': attachment[1]})
        
        # Load all dependencies for all tasks
        deps_result = execute_tenant_query(f"SELECT task_id, depends_on_task_id FROM task_dependencies WHERE task_id IN ({placeholders})", task_ids, fetch_all=True)
        deps_by_task = {}
        for dep in deps_result:
            task_id = dep[0]
            if task_id not in deps_by_task:
                deps_by_task[task_id] = []
            deps_by_task[task_id].append(dep[1])
        
        # Associate data with each task
        for task in tasks:
            task_id = task['id']
            
            # Set notes
            task['notes'] = notes_by_task.get(task_id, [])
            
            # Set comments with attachments
            task['clientComments'] = []
            for comment in comments_by_task.get(task_id, []):
                comment_id = comment['id']
                comment['attachments'] = attachments_by_comment.get(comment_id, [])
                task['clientComments'].append(comment)
            
            # Set dependencies
            task['dependencies'] = deps_by_task.get(task_id, [])
            
            # Convert snake_case to camelCase for JSON compatibility
            # Convert snake_case to camelCase and ensure dates are strings
            task['taskName'] = task.pop('task_name', '')
            
            p_start = task.pop('planned_start_date', None)
            task['plannedStartDate'] = str(p_start) if p_start else None
            
            p_end = task.pop('planned_end_date', None)
            task['plannedEndDate'] = str(p_end) if p_end else None
            
            task['predecessorString'] = task.pop('predecessor_string', '')
            task['originalDurationDays'] = task.pop('original_duration_days', 0)
            
            a_start = task.pop('actual_start_date', None)
            task['actualStartDate'] = str(a_start) if a_start else None
            
            a_end = task.pop('actual_end_date', None)
            task['actualEndDate'] = str(a_end) if a_end else None
            
            task['isCritical'] = task.pop('is_critical', False)
            task['isClientDeliverable'] = task.pop('is_client_deliverable', False)
            task['delayWeatherDays'] = task.pop('delay_weather_days', 0)
            task['delayContractorDays'] = task.pop('delay_contractor_days', 0)
            task['delayClientDays'] = task.pop('delay_client_days', 0)
            task['isExpanded'] = task.pop('is_expanded', False)
            task['subtasks'] = []  # Will be populated by build_task_hierarchy_from_flat_list
            # #region agent log
            if task_id == tasks[0].get('id'):
                import json as _json
                with open(r'd:\Digital Transformation\PROTON\Productization\PROTON-V5_Optimization\.cursor\debug.log', 'a', encoding='utf-8') as _f:
                    _f.write(_json.dumps({
                        "sessionId": "debug-session",
                        "runId": "dates-run1",
                        "hypothesisId": "H1",
                        "location": "app.py:load_tasks_from_db:mapped",
                        "message": "First task after snake->camel mapping date types",
                        "data": {
                            "plannedStartDate": str(task.get("plannedStartDate")),
                            "plannedStartDate_type": str(type(task.get("plannedStartDate"))),
                            "plannedEndDate": str(task.get("plannedEndDate")),
                            "plannedEndDate_type": str(type(task.get("plannedEndDate"))),
                            "actualStartDate": str(task.get("actualStartDate")),
                            "actualStartDate_type": str(type(task.get("actualStartDate"))),
                            "actualEndDate": str(task.get("actualEndDate")),
                            "actualEndDate_type": str(type(task.get("actualEndDate")))
                        },
                        "timestamp": int(datetime.now().timestamp() * 1000)
                    }) + "\n")
            # #endregion
            
            # NOTE: Do NOT remove project_id and parent_task_id here - they are needed for hierarchy reconstruction
        
        # Build the hierarchy first
        hierarchy = build_task_hierarchy_from_flat_list(tasks)
        
        # Now scrub DB-only fields from the hierarchy
        def scrub_db_fields_recursive(task_list):
            for task in task_list:
                # Remove DB-only fields that should not be exposed in API responses
                task.pop('project_id', None)
                task.pop('parent_task_id', None)
                
                # Recursively scrub subtasks
                if 'subtasks' in task and task['subtasks']:
                    scrub_db_fields_recursive(task['subtasks'])
        
        scrub_db_fields_recursive(hierarchy)
        
        return hierarchy
        
    except Exception as e:
        print(f"Error loading tasks from database: {e}")
        return []
    finally:
        # Pooled connection is managed by the pool; do not close here
        conn = None

def save_tasks_to_db(project_id, tasks, conn=None):
    """Save the entire task hierarchy to the database."""
    internal_conn = None
    cursor = None
    try:
        # If no connection provided, create one and manage the transaction
        if conn is None:
            internal_conn = get_tenant_db_connection()
            conn = internal_conn
            manage_transaction = True
        else:
            manage_transaction = False

        # Create cursor for MySQL
        if DB_TYPE.lower() == "mysql":
            cursor = conn.cursor(buffered=True)
            if manage_transaction:
                conn.start_transaction()
        else:
            cursor = conn.cursor()
            if manage_transaction:
                conn.execute("BEGIN TRANSACTION")
        
        try:
            # Delete all existing tasks for the project (cascades to notes, comments, dependencies)
            if DB_TYPE.lower() == "mysql":
                cursor.execute("DELETE FROM tasks WHERE project_id = %s", (project_id,))
            else:
                conn.execute("DELETE FROM tasks WHERE project_id = ?", (project_id,))

            # Flatten the task hierarchy
            flat_tasks = flatten_task_hierarchy(tasks)

            # Prepare batch data for insertion
            tasks_data = []
            notes_data = []
            comments_data = []
            attachments_data = []
            dependencies_data = []

            # Resolve project_name for attachment rows using the same transaction connection
            if DB_TYPE.lower() == "mysql":
                cursor.execute("SELECT name FROM projects WHERE id = %s", (project_id,))
                project_name_row = cursor.fetchone()
            else:
                project_name_row = conn.execute("SELECT name FROM projects WHERE id = ?", (project_id,)).fetchone()
            resolved_project_name = project_name_row[0] if project_name_row else None
            
            for task_dict, parent_id in flat_tasks:
                # Convert camelCase to snake_case for database
                task_data = (
                    task_dict['id'],
                    project_id,
                    parent_id,
                    task_dict.get('wbs', ''),
                    task_dict.get('taskName', ''),
                    task_dict.get('plannedStartDate', None),
                    task_dict.get('plannedEndDate', None),
                    task_dict.get('predecessorString', ''),
                    task_dict.get('originalDurationDays', 0),
                    task_dict.get('weightage', 0),
                    task_dict.get('actualStartDate', None),
                    task_dict.get('actualEndDate', None),
                    task_dict.get('progress', 0),
                    task_dict.get('status', ''),
                    task_dict.get('isCritical', False),
                    task_dict.get('isClientDeliverable', False),
                    task_dict.get('delayWeatherDays', 0),
                    task_dict.get('delayContractorDays', 0),
                    task_dict.get('delayClientDays', 0),
                    task_dict.get('isExpanded', False)
                )
                tasks_data.append(task_data)
                
                # Prepare notes data
                for note in task_dict.get('notes', []):
                    notes_data.append((
                        task_dict['id'],
                        note.get('text', ''),
                        sanitize_timestamp_for_db(note.get('timestamp')),
                        note.get('source', '')
                    ))
                
                # Prepare comments data
                for comment in task_dict.get('clientComments', []):
                    comment_id = comment.get('id')
                    # Generate UUID if comment doesn't have an ID
                    if not comment_id:
                        comment_id = str(uuid.uuid4())
                        comment['id'] = comment_id  # Update the comment with the new ID
                    comments_data.append((
                        comment_id,
                        task_dict['id'],
                        comment.get('adminComment', ''),
                        comment.get('clientStatus', ''),
                        comment.get('adminSeen', False),
                        sanitize_timestamp_for_db(comment.get('timestamp'))
                    ))
                    
                    # Prepare attachments data for this comment
                    for attachment in comment.get('attachments', []):
                        attachments_data.append((
                            comment_id,
                            attachment.get('filePath', ''),
                            getattr(g, 'org_id', None),
                            resolved_project_name,
                            task_dict['id'],
                            getattr(g, 'email', None)
                        ))
                
                # Prepare dependencies data
                for dep_id in task_dict.get('dependencies', []):
                    dependencies_data.append((
                        task_dict['id'],
                        dep_id
                    ))
            
            # Insert all data
            if tasks_data:
                if DB_TYPE.lower() == "mysql":
                    cursor.executemany("""
                        INSERT INTO tasks (id, project_id, parent_task_id, wbs, task_name, planned_start_date,
                                        planned_end_date, predecessor_string, original_duration_days, weightage,
                                        actual_start_date, actual_end_date, progress, status, is_critical,
                                        is_client_deliverable, delay_weather_days, delay_contractor_days,
                                        delay_client_days, is_expanded)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, tasks_data)
                else:
                    conn.executemany("""
                        INSERT INTO tasks (id, project_id, parent_task_id, wbs, task_name, planned_start_date,
                                        planned_end_date, predecessor_string, original_duration_days, weightage,
                                        actual_start_date, actual_end_date, progress, status, is_critical,
                                        is_client_deliverable, delay_weather_days, delay_contractor_days,
                                        delay_client_days, is_expanded)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, tasks_data)
            
            if notes_data:
                if DB_TYPE.lower() == "mysql":
                    cursor.executemany("""
                        INSERT INTO task_notes (task_id, text, timestamp, source)
                        VALUES (%s, %s, %s, %s)
                    """, notes_data)
                else:
                    conn.executemany("""
                        INSERT INTO task_notes (task_id, text, timestamp, source)
                        VALUES (?, ?, ?, ?)
                    """, notes_data)
            
            if comments_data:
                if DB_TYPE.lower() == "mysql":
                    cursor.executemany("""
                        INSERT INTO task_comments (id, task_id, admin_comment, client_status, admin_seen, timestamp)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, comments_data)
                else:
                    conn.executemany("""
                        INSERT INTO task_comments (id, task_id, admin_comment, client_status, admin_seen, timestamp)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, comments_data)
            
            if attachments_data:
                if DB_TYPE.lower() == "mysql":
                    cursor.executemany("""
                        INSERT INTO task_comment_attachments (comment_id, file_path, org_id, project_name, task_id, uploaded_by)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, attachments_data)
                else:
                    conn.executemany("""
                        INSERT INTO task_comment_attachments (comment_id, file_path, org_id, project_name, task_id, uploaded_by)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, attachments_data)
            
            if dependencies_data:
                if DB_TYPE.lower() == "mysql":
                    cursor.executemany("""
                        INSERT INTO task_dependencies (task_id, depends_on_task_id)
                        VALUES (%s, %s)
                    """, dependencies_data)
                else:
                    conn.executemany("""
                        INSERT INTO task_dependencies (task_id, depends_on_task_id)
                        VALUES (?, ?)
                    """, dependencies_data)
            
            if manage_transaction:
                conn.commit()

            return True

        except Exception as e:
            if manage_transaction:
                conn.rollback()
            raise e

    except Exception as e:
        print(f"Error saving tasks to database: {e}")
        return False
    finally:
        # Close cursor if it was created for MySQL
        if cursor and DB_TYPE.lower() == "mysql":
            try:
                cursor.close()
            except Exception:
                pass
        # Do not close pooled tenant connections; let the pool manage lifecycle
        internal_conn = None

def flatten_task_hierarchy(tasks, parent_id=None):
    """Recursive helper to flatten the nested task structure into a list of tuples."""
    result = []
    for task in tasks:
        result.append((task, parent_id))
        if 'subtasks' in task and task['subtasks']:
            result.extend(flatten_task_hierarchy(task['subtasks'], task['id']))
    return result

def build_task_hierarchy_from_flat_list(flat_tasks):
    """Helper to reconstruct the nested hierarchy from a flat list of tasks."""
    # Create a dictionary to store tasks by their ID
    task_dict = {}
    root_tasks = []
    
    # First pass: create all task objects
    for task in flat_tasks:
        task['subtasks'] = []
        task_dict[task['id']] = task
    
    # Second pass: build the hierarchy
    for task in flat_tasks:
        parent_id = task.get('parent_task_id')
        if parent_id is None:
            # This is a root task
            root_tasks.append(task)
        else:
            # This is a child task
            if parent_id in task_dict:
                task_dict[parent_id]['subtasks'].append(task)
    
    return root_tasks



def log_activity(user_email, project_name, action, details):
    """Logs an admin's action to the activity log database."""
    try:
        # Resolve project_name to project_id if provided
        project_id = None
        if project_name:
            project_id = get_project_id_by_name(project_name)
        
        # Compute timestamp string with 'YYYY-MM-DD HH:MM:SS' format for consistent lexicographic ordering
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Insert log entry into activity_logs table
        execute_tenant_query(
            "INSERT INTO activity_logs (timestamp, user_email, project_id, action, details) VALUES (?, ?, ?, ?, ?)",
            (ts, user_email, project_id, action, details)
        )
        return True
    except MySQLError as e:
        print(f"Error logging activity: {e}")
        return False


def log_primary_activity(email, action, details, org_id=None, user_id=None):
    """Logs authentication/authorization actions to primary.db's audit_logs.

    This function is intended for operations that occur before tenant context
    is established (e.g., signup, login, logout, approval, rejection).
    It writes to the centralized audit_logs table in the primary database and
    intentionally sets org_id and user_id to None.
    """
    try:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Ensure the actor email is included in the details string for auditing
        details_with_email = details if (email and (str(email) in (details or ""))) else f"{details} [email: {email}]"
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details, timestamp) VALUES (?, ?, ?, ?, ?)",
            (org_id, user_id, action, details_with_email, ts)
        )
        return True
    except MySQLError as e:
        print(f"Error logging primary activity: {e}")
        return False


def tasks_differ(old_task, new_task):
    """
    Efficient field-level comparison of task objects to replace json.dumps() comparison.
    Compares only the relevant fields that indicate a task has been modified.
    """
    # Core task fields that indicate meaningful changes
    core_fields = {
        'taskName', 'wbs', 'plannedStartDate', 'plannedEndDate', 
        'actualStartDate', 'actualEndDate', 'progress', 'weightage', 
        'status', 'isCritical', 'isClientDeliverable', 'isExpanded',
        'delayWeatherDays', 'delayContractorDays', 'delayClientDays',
        'predecessorString', 'originalDurationDays'
    }
    
    # Compare core fields
    for field in core_fields:
        if old_task.get(field) != new_task.get(field):
            return True
    
    # Compare notes (simplified comparison - just check count and basic content)
    old_notes = old_task.get('notes', [])
    new_notes = new_task.get('notes', [])
    if len(old_notes) != len(new_notes):
        return True
    
    # Compare notes content (check if any note text changed)
    for old_note, new_note in zip(old_notes, new_notes):
        if (old_note.get('text') != new_note.get('text') or 
            old_note.get('source') != new_note.get('source')):
            return True
    
    # Compare client comments (simplified comparison)
    old_comments = old_task.get('clientComments', [])
    new_comments = new_task.get('clientComments', [])
    if len(old_comments) != len(new_comments):
        return True
    
    # Compare comments content
    for old_comment, new_comment in zip(old_comments, new_comments):
        if (old_comment.get('adminComment') != new_comment.get('adminComment') or
            old_comment.get('clientStatus') != new_comment.get('clientStatus') or
            old_comment.get('adminSeen') != new_comment.get('adminSeen')):
            return True
    
    # Compare dependencies
    old_deps = old_task.get('dependencies', [])
    new_deps = new_task.get('dependencies', [])
    if set(old_deps) != set(new_deps):
        return True
    
    # Compare subtasks recursively
    old_subtasks = old_task.get('subtasks', [])
    new_subtasks = new_task.get('subtasks', [])
    if len(old_subtasks) != len(new_subtasks):
        return True
    
    for old_sub, new_sub in zip(old_subtasks, new_subtasks):
        if tasks_differ(old_sub, new_sub):
            return True
    
    return False

def needs_progress_recalculation(old_data, new_data):
    """
    Check if progress recalculation is needed by comparing relevant fields.
    Returns True if progress, weightage, or task structure changed.
    """
    # Fields that don't require progress recalculation
    non_progress_fields = {
        'notes', 'clientComments', 'delayWeatherDays', 
        'delayContractorDays', 'delayClientDays', 
        'isClientDeliverable', 'isCritical', 'isExpanded'
    }
    
    def compare_tasks_recursive(old_task, new_task):
        # Check if progress or weightage changed
        if (old_task.get('progress', 0) != new_task.get('progress', 0) or
            old_task.get('weightage', 0) != new_task.get('weightage', 0)):
            return True
        
        # Check if subtasks structure changed
        old_subtasks = old_task.get('subtasks', [])
        new_subtasks = new_task.get('subtasks', [])
        
        if len(old_subtasks) != len(new_subtasks):
            return True
        
        # Check if any subtask needs recalculation
        for old_sub, new_sub in zip(old_subtasks, new_subtasks):
            if compare_tasks_recursive(old_sub, new_sub):
                return True
        
        return False
    
    # Compare each task
    if len(old_data) != len(new_data):
        return True
    
    for old_task, new_task in zip(old_data, new_data):
        if compare_tasks_recursive(old_task, new_task):
            return True
    
    return False

@app.route('/api/toggle_all_client_deliverables', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
@subscription_required
def toggle_all_client_deliverables():
    project_name = request.args.get('project')
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    payload = request.get_json()
    should_select_all = payload.get('should_select_all', False)
    user_email = payload.get('user_email')

    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # Load existing tasks
        project_tasks = load_tasks_from_db(project_id)
        if project_tasks is None:
            return jsonify({"status": "error", "message": "Could not read project data"}), 500

        def set_deliverable_recursively(task_list, status):
            for task in task_list:
                task['isClientDeliverable'] = status
                if task.get('subtasks'):
                    set_deliverable_recursively(task['subtasks'], status)

        set_deliverable_recursively(project_tasks, should_select_all)
        
        final_data = sanitize(project_tasks)

        # Save to database
        if not save_tasks_to_db(project_id, final_data):
            return jsonify({"status": "error", "message": "Failed to save data"}), 500
        
        # --- Logging ---
        action_log = "All tasks marked for client view." if should_select_all else "All tasks removed from client view."
        if user_email:
            log_activity(user_email, project_name, "Bulk Edit", action_log)

        return jsonify({"status": "success", "message": "All tasks updated successfully."})

    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error toggling client deliverables: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error toggling client deliverables: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

def recalculate_progress_recursively(tasks):
    """
    MODIFIED: Recursively calculates parent progress based on weighted child progress.
    """
    for task in tasks:
        if task.get('subtasks') and len(task['subtasks']) > 0:
            # First, recurse to ensure children are calculated
            task['subtasks'] = recalculate_progress_recursively(task['subtasks'])
            
            # Now, calculate this task's progress
            total_weight = 0
            weighted_progress_sum = 0
            for subtask in task['subtasks']:
                # MODIFIED: Use 0.0 as the default and fix logic to handle 0 weightage correctly.
                weight = float(subtask.get('weightage', 0.0))
                progress = float(subtask.get('progress', 0) or 0)
                total_weight += weight
                weighted_progress_sum += progress * weight
            
            if total_weight > 0:
                task['progress'] = round(weighted_progress_sum / total_weight, 2)
            else:
                task['progress'] = 0 # Avoid division by zero
    return tasks

def reindex_wbs_recursively(task_list, prefix=''):
    """Recursively re-indexes WBS numbers for a list of tasks."""
    for i, task in enumerate(task_list):
        new_wbs = f"{prefix}{i + 1}"
        task['wbs'] = new_wbs
        if task.get('subtasks'):
            task['subtasks'] = reindex_wbs_recursively(task['subtasks'], prefix=f"{new_wbs}.")
    return task_list



@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/add_task', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
def add_task():
    project_name = sanitize_text_input(request.args.get('project') or '', max_length=100)
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    payload = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['newTask','context','user_email'])
    new_task_data = payload.get('newTask') or {}
    context = payload.get('context') or {}
    user_email = payload.get('user_email')

    if not new_task_data or not context:
        return jsonify({"status": "error", "message": "New task data and context are required."}), 400

    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # Load existing tasks
        project_tasks = load_tasks_from_db(project_id) or []

        new_task = {
            "id": str(uuid.uuid4()),
            "wbs": "", # WBS will be assigned
            "taskName": sanitize_text_input(new_task_data.get('taskName') or 'New Task', max_length=200, allow_html=False),
            "plannedStartDate": new_task_data.get('plannedStartDate') or None,
            "plannedEndDate": new_task_data.get('plannedEndDate') or None,
            "predecessorString": "",
            "originalDurationDays": "1",
            "weightage": 0,
            "actualStartDate": None,
            "actualEndDate": None,
            "progress": 0,
            "status": "Not Started",
            "notes": [],
            "isClientDeliverable": False,
            "isCritical": False,
            "dependencies": [],
            "clientComments": [],
            "delayWeatherDays": 0,
            "delayContractorDays": 0,
            "delayClientDays": 0,
            "isExpanded": True,
            "subtasks": []
        }

        mode = context.get('mode')
        target_task_id = (context.get('task') or {}).get('id')

        if mode == 'child':
            def find_and_add_subtask(task_list, parent_id):
                for task in task_list:
                    if task.get('id') == parent_id:
                        if 'subtasks' not in task or task['subtasks'] is None:
                            task['subtasks'] = []
                        task['subtasks'].append(new_task)
                        task['isExpanded'] = True
                        return True
                    if task.get('subtasks') and find_and_add_subtask(task['subtasks'], parent_id):
                        return True
                return False
            find_and_add_subtask(project_tasks, target_task_id)
        
        else: # Sibling mode
            def find_and_add_sibling(task_list, sibling_id):
                for i, task in enumerate(task_list):
                    if task.get('id') == sibling_id:
                        task_list.insert(i + 1, new_task)
                        return True
                    if task.get('subtasks') and find_and_add_sibling(task['subtasks'], sibling_id):
                        return True
                return False
            if not find_and_add_sibling(project_tasks, target_task_id):
                 project_tasks.append(new_task) # Fallback to add at the end

        # Re-index all WBS numbers to ensure consistency
        final_tasks = reindex_wbs_recursively(project_tasks)
        final_tasks = recalculate_progress_recursively(final_tasks)
        
        # Save to database
        if not save_tasks_to_db(project_id, sanitize(final_tasks)):
            return jsonify({"status": "error", "message": "Failed to save data"}), 500

        log_activity(sanitize_text_input(user_email or ''), project_name, "Task Added", f"Task '{new_task['taskName']}' was created.")
        
        return jsonify({"status": "success", "updatedTasks": final_tasks})

    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in add_task: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error in add_task: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500
@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/delete_task', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
@subscription_required
def delete_task():
    project_name = request.args.get('project')
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    payload = request.get_json()
    task_id_to_delete = payload.get('taskId')
    user_email = payload.get('user_email')
    
    if not task_id_to_delete:
        return jsonify({"status": "error", "message": "Task ID is required."}), 400

    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # Load existing tasks
        project_tasks = load_tasks_from_db(project_id) or []
        
        task_name_to_log = "Unknown Task"
        
        def find_and_delete_task(task_list, task_id):
            nonlocal task_name_to_log
            task_to_remove = None
            for task in task_list:
                if task.get('id') == task_id:
                    task_to_remove = task
                    break
            
            if task_to_remove:
                task_name_to_log = task_to_remove.get('taskName', 'Unknown Task')
                task_list.remove(task_to_remove)
                return True

            for task in task_list:
                if task.get('subtasks') and find_and_delete_task(task['subtasks'], task_id):
                    return True
            return False

        if not find_and_delete_task(project_tasks, task_id_to_delete):
            return jsonify({"status": "error", "message": "Task not found."}), 404

        # Re-index WBS and recalculate progress
        final_tasks = reindex_wbs_recursively(project_tasks)
        final_tasks = recalculate_progress_recursively(final_tasks)

        # Save to database
        if not save_tasks_to_db(project_id, sanitize(final_tasks)):
            return jsonify({"status": "error", "message": "Failed to save data"}), 500
        
        log_activity(user_email, project_name, "Task Deleted", f"Task '{task_name_to_log}' was deleted.")

        return jsonify({"status": "success", "updatedTasks": final_tasks})

    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in delete_task: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error in delete_task: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

def find_and_update_task(task_list, task_id, updates):
    """A helper function to find a task by ID in a nested list and update it."""
    for task in task_list:
        if task.get('id') == task_id:
            if 'clientComments' in updates:
                # Create a dictionary of original comments for quick lookup
                original_comments = {c.get('id'): c for c in task.get('clientComments', [])}
                updated_comments_list = updates['clientComments']

                # Scenario 1: A new comment is added by the admin (array gets longer)
                if len(updated_comments_list) > len(original_comments):
                    latest_comment = updated_comments_list[-1]
                    if 'adminComment' in latest_comment and 'clientStatus' not in latest_comment:
                        latest_comment['clientStatus'] = None # Explicitly set as pending for client

                # Scenario 2: An existing comment is updated by the client (array length is the same)
                else:
                    for comment in updated_comments_list:
                        comment_id = comment.get('id')
                        original_comment = original_comments.get(comment_id)
                        
                        # Check if a comment's status has changed from 'pending' (None) to a 'responded' state.
                        if original_comment and original_comment.get('clientStatus') is None and comment.get('clientStatus') is not None:
                            comment['adminSeen'] = False  # This is a new client response, so mark it as unseen for the admin.
            
            task.update(updates)
            return True, task
            
        if task.get('subtasks'):
            found, updated_task = find_and_update_task(task['subtasks'], task_id, updates)
            if found:
                return True, updated_task
    return False, None

@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/update_task', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
def update_task():
    project_name = sanitize_text_input(request.args.get('project') or '', max_length=100)
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    payload_raw = request.get_json(silent=True) or {}
    payload = sanitize_json_input(payload_raw, allowed_keys=['taskId','updatedData','user_email'])
    task_id = payload.get('taskId')
    updates_raw = payload_raw.get('updatedData') or {}
    updates = {}
    user_email = payload.get('user_email')
    # Sanitize string fields in updates
    for key, value in updates_raw.items():
        if isinstance(value, str):
            if key in ['taskName', 'status', 'predecessorString']:
                updates[key] = sanitize_text_input(value, max_length=200, allow_html=False)
            elif key in ['notes', 'clientComments']:
                updates[key] = value  # Lists will be sanitized per item if needed
            else:
                updates[key] = sanitize_text_input(value, max_length=1000, allow_html=False)
        else:
            updates[key] = value

    if not task_id or not updates:
        return jsonify({"status": "error", "message": "taskId and updatedData are required."}), 400

    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # Load existing tasks
        project_tasks = load_tasks_from_db(project_id)
        if project_tasks is None:
            return jsonify({"status": "error", "message": "Could not read project data"}), 500

        # Find the specific task and apply the new changes
        task_found, updated_task_details = find_and_update_task(project_tasks, task_id, updates)

        if not task_found:
            return jsonify({"status": "error", "message": "Task not found."}), 404

        # Log the specific modification
        if user_email and updated_task_details:
             log_activity(
                sanitize_text_input(user_email or ''),
                project_name,
                "Task Edited",
                f"Task '{updated_task_details.get('taskName')}' (WBS: {updated_task_details.get('wbs')}) was modified."
             )

        # --- Optimized Progress Recalculation ---
        # Check if the update affects progress-related fields
        progress_related_fields = {'progress', 'weightage'}
        needs_recalc = any(field in updates for field in progress_related_fields)
        
        if needs_recalc:
            final_data = sanitize(recalculate_progress_recursively(project_tasks))
        else:
            final_data = sanitize(project_tasks)

        # Save to database
        if not save_tasks_to_db(project_id, final_data):
            return jsonify({"status": "error", "message": "Failed to save data"}), 500

        return jsonify({"status": "success", "updatedTasks": final_data})

    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in update_task: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error in update_task: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

def build_task_hierarchy(df):
    """
    Builds a nested list of tasks from a DataFrame based on WBS numbers.
    MODIFIED: Now imports Actual Dates, Progress, Status, and Critical status from the CSV.
    """
    tasks_by_wbs = {}
    top_level_tasks = []

    # Map CSV columns to the keys expected by the frontend
    column_mapping = {
        # Existing mappings
        'WBS': ['WBS', 'Activity ID', 'ID'],
        'Name': ['Name', 'Task Name', 'Activity Name'],
        'Duration': ['Duration'],
        'Start_Date': ['Start', 'start', 'Start_Date'],
        'Finish_Date': ['Finish', 'finish', 'Finish_Date'],
        'Predecessors': ['Predecessors', 'predecessors'],
        'Weightage': ['Weightage', 'Weightage (%)', 'weightage'],
        'Notes': ['Notes'],
        # New mappings based on user request
        'Actual_Start_Date': ['Actual Start Date', 'Actual Start'],
        'Actual_End_Date': ['Actual End Date', 'Actual End'],
        'Progress': ['Progress(%)', 'Progress (%)', 'Progress'],
        'Status': ['Status', 'status'],
        'Is_Critical': ['Is Critical', 'Critical', 'critical']
    }

    # Normalize DataFrame columns
    for target_key, possible_names in column_mapping.items():
        for name in possible_names:
            if name in df.columns:
                df.rename(columns={name: target_key}, inplace=True)
                break
    date_columns = ['Start_Date', 'Finish_Date', 'Actual_Start_Date', 'Actual_End_Date']
    for col in date_columns:
        if col in df.columns:
            # Strategy 1: ISO Format (YYYY-MM-DD)
            parsed = pd.to_datetime(df[col], format='%Y-%m-%d', errors='coerce')
            # Strategy 2: DD-MM-YYYY
            parsed = parsed.fillna(pd.to_datetime(df[col], format='%d-%m-%Y', errors='coerce'))
            # Strategy 3: DD/MM/YYYY
            parsed = parsed.fillna(pd.to_datetime(df[col], format='%d/%m/%Y', errors='coerce'))
            # Strategy 4: MM/DD/YYYY (USA)
            parsed = parsed.fillna(pd.to_datetime(df[col], format='%m/%d/%Y', errors='coerce'))
            # Strategy 5: Flexible Fallback (dayfirst=True)
            parsed = parsed.fillna(pd.to_datetime(df[col], errors='coerce', dayfirst=True))
            # Strategy 6: Flexible Fallback (dayfirst=False)
            parsed = parsed.fillna(pd.to_datetime(df[col], errors='coerce', dayfirst=False))

            # Convert to string format, handling NaT values properly (use None for DB compatibility)
            df[col] = parsed.apply(lambda x: x.strftime('%Y-%m-%d') if pd.notna(x) else None)

    # First pass: create all task objects and map them by WBS
    for _, row in df.iterrows():
        if pd.isna(row.get('WBS')):
            continue

        wbs_str = str(row.get('WBS'))

        # Handle Weightage (existing logic)
        try:
            raw_val = row.get('Weightage', 0.0)
            weightage_val = float(raw_val) if pd.notna(raw_val) else 0.0
        except (ValueError, TypeError):
            weightage_val = 0.0

        # --- NEW: Handle Progress, Status, and Is_Critical ---

        # Progress
        progress_raw = row.get('Progress', 0)
        try:
            if pd.notna(progress_raw) and str(progress_raw).strip():
                # Try to convert to float first (handles decimals), then to int
                progress_val = int(float(progress_raw))
            else:
                progress_val = 0
        except (ValueError, TypeError):
            progress_val = 0

        # Status
        status_raw = row.get('Status', 'Not Started')
        status_val = str(status_raw) if pd.notna(status_raw) and str(status_raw).strip() else 'Not Started'

        # Is Critical
        is_critical_raw = row.get('Is_Critical')
        is_critical_bool = str(is_critical_raw).lower() in ['yes', 'true', '1', 'y']

        # Sanitize text inputs to prevent XSS
        task_name_raw = row.get('Name')
        task_name_sanitized = sanitize_text_input(task_name_raw, allow_html=False) if pd.notna(task_name_raw) else None
        
        predecessor_string_raw = row.get('Predecessors', '')
        predecessor_string_sanitized = sanitize_text_input(predecessor_string_raw, allow_html=False) if pd.notna(predecessor_string_raw) and str(predecessor_string_raw).strip() else ''
        
        notes_raw = row.get('Notes')
        notes_sanitized = []
        if pd.notna(notes_raw) and str(notes_raw).strip():
            notes_text_sanitized = sanitize_text_input(notes_raw, allow_html=False)
            # Convert ISO format to MySQL datetime format (YYYY-MM-DD HH:MM:SS)
            timestamp_value = pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S')
            notes_sanitized = [{'text': notes_text_sanitized, 'timestamp': timestamp_value, 'source': 'import'}]
        
        task = {
            'id': wbs_str,
            'wbs': wbs_str,
            'taskName': task_name_sanitized,
            'plannedStartDate': row.get('Start_Date'),
            'plannedEndDate': row.get('Finish_Date'),
            'predecessorString': predecessor_string_sanitized,
            'originalDurationDays': row.get('Duration'),
            'weightage': weightage_val,
            'notes': notes_sanitized,
            
            # --- MODIFIED: Use values from CSV ---
            'actualStartDate': row.get('Actual_Start_Date'), # defaults to None
            'actualEndDate': row.get('Actual_End_Date'),   # defaults to None
            'progress': progress_val,
            'status': status_val,
            'isCritical': is_critical_bool,
            # --- End of modifications for this block ---

            'isClientDeliverable': False, # Still defaults to False on import
            'dependencies': [],
            'clientComments': [],
            'delayWeatherDays': 0,
            'delayContractorDays': 0,
            'delayClientDays': 0,
            'isExpanded': True,
            'subtasks': []
        }
        tasks_by_wbs[task['wbs']] = task

    # Second pass: build the hierarchy by linking tasks to their parents
    sorted_wbs_keys = sorted(tasks_by_wbs.keys())
    for wbs in sorted_wbs_keys:
        task = tasks_by_wbs[wbs]
        parent_wbs = '.'.join(wbs.split('.')[:-1])
        if parent_wbs and parent_wbs in tasks_by_wbs:
            tasks_by_wbs[parent_wbs]['subtasks'].append(task)
        else:
            top_level_tasks.append(task)

    # After building hierarchy, recalculate parent progress to ensure data integrity.
    # This will use the imported progress values for leaf tasks.
    return recalculate_progress_recursively(top_level_tasks)


# --- API Endpoints ---

# Create a dedicated folder for uploads if it doesn't exist
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# In app.py

@limiter.limit(RATE_LIMIT_FILE_UPLOAD, key_func=get_user_id_for_rate_limit)
@app.route('/api/upload_document', methods=['POST'])
@subscription_required
@check_plan_limit(RESOURCE_TYPE_FILE)
def upload_document():
    # Enforce per-route request size for uploads (defense-in-depth)
    try:
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            return jsonify({"status": "error", "message": "File upload exceeds 10 MB limit"}), 413
    except Exception:
        pass
    if 'files[]' not in request.files:
        return jsonify({"status": "error", "message": "No file part in the request"}), 400

    files = request.files.getlist('files[]')
    project_name = sanitize_text_input(request.form.get('project_name') or '', max_length=100)
    task_id_raw = request.form.get('task_id') or ''
    valid_tid, task_id, tid_err = validate_and_sanitize_task_id(str(task_id_raw))
    if not valid_tid:
        return jsonify({"status": "error", "message": tid_err}), 400

    if not all([files, project_name, task_id]):
        return jsonify({"status": "error", "message": "Missing file, project name, or task ID"}), 400

    if len(files) > MAX_FILES_PER_UPLOAD:
        return jsonify({"status": "error", "message": "You have reached the limit to Upload Document"}), 400

    # Batch-aware plan limit check for per-project files
    try:
        limits = get_plan_limits(getattr(g, 'plan', None)) or {}
        current_count = get_project_file_count(project_name, getattr(g, 'org_id', None))
        max_files = limits.get('max_files_per_project', UNLIMITED_LIMIT)
        if max_files < UNLIMITED_LIMIT and (current_count + len(files)) > max_files:
            return jsonify({
                'status': 'error',
                'error_code': ERROR_CODE_PLAN_LIMIT_EXCEEDED,
                'message': f'Uploading {len(files)} files would exceed the per-project limit ({current_count}/{max_files}).'
            }), 403
    except Exception:
        pass

    # Enforce org context
    if not hasattr(g, 'org_id') or g.org_id is None:
        return jsonify({"error": "Organization context required for file uploads"}), 403

    # Validate project belongs to user's org (tenant DB)
    exists_row = execute_tenant_query("SELECT COUNT(*) FROM projects WHERE name = ?", (project_name,), fetch_one=True)
    if not exists_row or int(exists_row[0]) == 0:
        return jsonify({"error": "Project not found in your organization"}), 403

    # Validate that task_id belongs to the specified project within this org
    task_row = execute_tenant_query(
        """
        SELECT COUNT(*)
        FROM tasks t
        JOIN projects p ON p.id = t.project_id
        WHERE p.name = ? AND t.id = ?
        """,
        (project_name, task_id),
        fetch_one=True
    )
    if not task_row or int(task_row[0]) == 0:
        return jsonify({"error": "Task not found in the specified project"}), 404

    uploaded_filepaths = []
    for file in files:
        if file.filename == '':
            continue  # Skip empty file parts

        if file:
            # File type validation
            original_name = file.filename
            _, ext = os.path.splitext(original_name)
            if ext.lower() not in ALLOWED_FILE_EXTENSIONS:
                return jsonify({"status": "error", "message": "File type not allowed. Allowed types: PDF, DOC, DOCX, XLS, XLSX, PNG, JPG, JPEG, TXT, CSV"}), 400

            # File size validation
            try:
                file.stream.seek(0, os.SEEK_END)
                file_size = file.stream.tell()
                file.stream.seek(0)
            except Exception:
                file_size = 0
            if file_size > MAX_FILE_SIZE_BYTES:
                return jsonify({"status": "error", "message": f"File size exceeds limit ({MAX_FILE_SIZE_MB} MB)"}), 413

            # Create a unique filename
            from werkzeug.utils import secure_filename
            safe_name = secure_filename(original_name)
            unique_filename = f"{uuid.uuid4().hex[:8]}_{safe_name}"

            # Ensure directory exists using secure path helper
            target_path = get_secure_file_path(g.org_id, project_name, task_id, unique_filename)
            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            file.save(target_path)

            uploaded_filepaths.append(unique_filename)

    if not uploaded_filepaths:
        return jsonify({"status": "error", "message": "No valid files were uploaded"}), 400

    # Invalidate org usage cache after successful upload
    try:
        ORG_USAGE_CACHE.pop(getattr(g, 'org_id', None), None)
    except Exception:
        pass
    # Audit log
    try:
        log_file_access(FILE_ACTION_UPLOADED, g.org_id, project_name, task_id, uploaded_filepaths, details={"file_count": len(uploaded_filepaths)})
    except Exception:
        pass
    return jsonify({"status": "success", "filepaths": uploaded_filepaths}), 200

@app.route('/download_document/<project_name>/<task_id>/<filename>')
@jwt_required()
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER, ROLE_CLIENT])
def download_document(project_name, task_id, filename):
    try:
        # Determine target org_id (SuperAdmin may override via query param)
        target_org_id = getattr(g, 'org_id', None)
        if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
            query_org_id = request.args.get('org_id', type=int)
            if query_org_id:
                target_org_id = query_org_id

        if target_org_id is None and getattr(g, 'role', None) != ROLE_SUPER_ADMIN:
            return jsonify({"error": "Organization context required"}), 403

        # Sanitize filename
        from werkzeug.utils import secure_filename
        filename = secure_filename(filename)
        if any(x in filename for x in ('..', '/', '\\')):
            return jsonify({"error": "Invalid filename"}), 400

        # Validate project exists in the correct tenant DB
        if getattr(g, 'role', None) == ROLE_SUPER_ADMIN and request.args.get('org_id', type=int):
            # Validate against target org's MySQL DB
            try:
                db_name = get_tenant_db_name(target_org_id)
                conn = mysql.connector.connect(
                    host=MYSQL_HOST,
                    port=MYSQL_PORT,
                    user=MYSQL_USER,
                    password=MYSQL_PASSWORD,
                    database=db_name,
                    charset=MYSQL_CHARSET,
                )
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM projects WHERE name = %s", (project_name,))
                row = cur.fetchone()
                conn.close()
            except Exception:
                row = (0,)
        else:
            row = execute_tenant_query("SELECT COUNT(*) FROM projects WHERE name = ?", (project_name,), fetch_one=True)
        if not row or int(row[0]) == 0:
            return jsonify({"error": "Project not found"}), 404

        # Build and check path
        abs_path = get_secure_file_path(target_org_id, project_name, task_id, filename)
        if not os.path.exists(abs_path):
            return jsonify({"error": "File not found"}), 404

        # Audit log prior to send
        try:
            log_file_access(FILE_ACTION_DOWNLOADED, target_org_id, project_name, task_id, filename)
        except Exception:
            pass

        return send_from_directory(os.path.dirname(abs_path), os.path.basename(abs_path), as_attachment=True)
    except FileNotFoundError:
        return jsonify({"error": "File not found"}), 404
    except PermissionError:
        return jsonify({"error": "Access denied"}), 403
    except OSError as e:
        print(f"OS error in download_document: {e}")
        return jsonify({"error": "File system error"}), 500

@app.route('/api/documents', methods=['GET'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER, ROLE_CLIENT])
def get_documents():
    """Get list of documents for a project."""
    try:
        project_name = request.args.get('project_name')
        if not project_name:
            return jsonify({"status": "error", "message": "Project name is required"}), 400
        
        # Validate project exists in tenant DB
        project_exists = execute_tenant_query(
            "SELECT COUNT(*) FROM projects WHERE name = ?",
            (project_name,),
            fetch_one=True
        )
        if not project_exists or int(project_exists[0]) == 0:
            return jsonify({"status": "error", "message": "Project not found"}), 404
        
        # Get org_id for file path resolution
        org_id = getattr(g, 'org_id', None)
        if org_id is None:
            return jsonify({"status": "error", "message": "Organization context required"}), 403
        
        # Get project storage path (using same pattern as get_secure_file_path)
        base_root = os.path.abspath(UPLOAD_FOLDER)
        project_storage = os.path.join(base_root, str(org_id), project_name)
        
        documents = []
        if os.path.exists(project_storage):
            # Walk through project storage directory
            for root, dirs, files in os.walk(project_storage):
                for filename in files:
                    file_path = os.path.join(root, filename)
                    # Extract task_id from path (format: project_name/task_id/filename)
                    rel_path = os.path.relpath(file_path, project_storage)
                    path_parts = rel_path.split(os.sep)
                    task_id = path_parts[0] if len(path_parts) > 1 else 'general'
                    
                    try:
                        file_stat = os.stat(file_path)
                        documents.append({
                            'filename': filename,
                            'size': file_stat.st_size,
                            'upload_date': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                            'task_id': task_id
                        })
                    except OSError:
                        continue
        
        return jsonify({
            "status": "success",
            "documents": documents
        })
    except Exception as e:
        app.logger.error(f'Error getting documents: {str(e)}')
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/documents/<filename>', methods=['DELETE'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def delete_document(filename):
    """Delete a document file. Admin only."""
    try:
        project_name = request.args.get('project_name')
        task_id = request.args.get('task_id', 'general')
        
        if not project_name:
            return jsonify({"status": "error", "message": "Project name is required"}), 400
        
        # Sanitize filename
        from werkzeug.utils import secure_filename
        filename = secure_filename(filename)
        if any(x in filename for x in ('..', '/', '\\')):
            return jsonify({"status": "error", "message": "Invalid filename"}), 400
        
        # Validate project exists in tenant DB
        project_exists = execute_tenant_query(
            "SELECT COUNT(*) FROM projects WHERE name = ?",
            (project_name,),
            fetch_one=True
        )
        if not project_exists or int(project_exists[0]) == 0:
            return jsonify({"status": "error", "message": "Project not found"}), 404
        
        # Get org_id for file path resolution
        org_id = getattr(g, 'org_id', None)
        if org_id is None:
            return jsonify({"status": "error", "message": "Organization context required"}), 403
        
        # Build file path
        abs_path = get_secure_file_path(org_id, project_name, task_id, filename)
        
        if not os.path.exists(abs_path):
            return jsonify({"status": "error", "message": "File not found"}), 404
        
        # Delete the file
        try:
            os.remove(abs_path)
        except OSError as e:
            app.logger.error(f'Error deleting file: {str(e)}')
            return jsonify({"status": "error", "message": "Failed to delete file"}), 500
        
        return jsonify({"status": "success"})
    except Exception as e:
        app.logger.error(f'Error deleting document: {str(e)}')
        return jsonify({"status": "error", "message": str(e)}), 500

@limiter.limit(RATE_LIMIT_SIGNUP)
@app.route('/api/signup', methods=['POST'])
def admin_signup():
    data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['email','password'])
    email = sanitize_text_input(data.get('email') or '')
    password = (request.get_json(silent=True) or {}).get('password')  # do not sanitize passwords

    if not email or not password:
        return jsonify({"status": "error", "message": "Email and password are required."}), 400

    try:
        # Check if email already exists in primary database
        result = execute_primary_query("SELECT COUNT(*) FROM users WHERE email = ?", (email,), fetch_one=True)
        if result and result[0] > 0:
            return jsonify({"status": "error", "message": "This email is already registered."}), 409
        
        # Insert new admin user into primary database
        execute_primary_query(
            "INSERT INTO users (email, password, role, org_id, status) VALUES (?, ?, ?, ?, ?)",
            (email, hash_password(password), 'org_admin', None, 'pending')
        )
        
        log_primary_activity(email, "User Signup", f"New admin account created for {email}, awaiting approval.")
        return jsonify({"status": "success", "message": "Signup successful! A Super Admin has been notified to approve your account."})
        
    except mysql.connector.IntegrityError:
        return jsonify({"status": "error", "message": "This email is already registered."}), 409
    except MySQLError as e:
        print(f"Database error in signup: {e}")
        return jsonify({"status": "error", "message": "Failed to create account"}), 500

@limiter.limit(RATE_LIMIT_SIGNUP)
@app.route('/api/org/signup', methods=['POST'])
def organization_signup():
    data_raw = request.get_json(silent=True) or {}
    data = sanitize_json_input(data_raw, allowed_keys=['org_name','admin_email','admin_password','plan_type','domain'])
    org_name = sanitize_text_input((data.get('org_name') or ''), max_length=100)
    admin_email = sanitize_text_input((data.get('admin_email') or ''), max_length=255)
    admin_password = (data_raw.get('admin_password') or '')  # do not sanitize passwords
    plan_type = sanitize_text_input((data.get('plan_type') or ''), max_length=32)
    domain = sanitize_text_input((data.get('domain') or ''), max_length=255)

    print(f"[ORG-SIGNUP] Starting signup for org: {org_name}, email: {admin_email}")

    # Required fields
    if not org_name or not admin_email or not admin_password or not plan_type:
        return jsonify({"status": "error", "message": "All fields are required: org_name, admin_email, admin_password, plan_type"}), 400

    # Validate org name
    valid, err = validate_org_name(org_name)
    if not valid:
        return jsonify({"status": "error", "message": err, "field": "org_name"}), 400
    existing_org = execute_primary_query(
        "SELECT COUNT(*) FROM organizations WHERE LOWER(name) = LOWER(?)",
        params=(org_name,),
        fetch_one=True
    )
    if existing_org and existing_org[0] > 0:
        return jsonify({"status": "error", "message": "Organization name already exists", "field": "org_name"}), 409

    # Validate email
    if not validate_email_format(admin_email):
        return jsonify({"status": "error", "message": "Invalid email format", "field": "admin_email"}), 400
    existing_email = execute_primary_query(
        "SELECT COUNT(*) FROM users WHERE email = ?",
        params=(admin_email,),
        fetch_one=True
    )
    if existing_email and existing_email[0] > 0:
        return jsonify({"status": "error", "message": "Email already registered", "field": "admin_email"}), 409

    # Validate password
    valid_pw, err_pw = validate_password_strength(admin_password)
    if not valid_pw:
        return jsonify({"status": "error", "message": err_pw, "field": "admin_password"}), 400

    # Validate plan
    if plan_type not in ['basic', 'si_plus', 'plus', 'pro']:
        return jsonify({"status": "error", "message": "Invalid plan type. Must be: basic, plus, or pro", "field": "plan_type"}), 400

    org_id = None
    user_id = None
    db_file_path = None
    conn = None
    try:
        # ATOMIC TRANSACTION: All operations below execute in a single transaction.
        conn = get_primary_db_connection()
        # Configure transaction handling based on backend
        conn.start_transaction()
        print(f"[ORG-SIGNUP] Transaction started")

        # Provision org DB (participates in parent transaction)
        success, result, status_code = provision_organization_database(org_name, domain, conn=conn, manage_transaction=False)
        if not success:
            try:
                conn.rollback()
                print(f"[ORG-SIGNUP] Transaction rolled back: provisioning failed")
            except Exception:
                pass
            return jsonify(result), status_code
        org_id = result.get('org_id')
        db_file_path = result.get('db_file_path')
        print(f"[ORG-SIGNUP] Organization created: org_id={org_id}")

        cur = conn.cursor()
        # Helper to normalize placeholder style for the active backend
        def _exec(sql, params=None):
            return cur.execute(convert_query_placeholders(sql, DB_TYPE), params or ())

        # Audit log: organization created
        org_details = json.dumps({
            "org_name": org_name,
            "db_file_path": db_file_path
        })
        _exec(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, None, 'organization_created', org_details)
        )

        # Create admin user - OTP verification required before activation
        hashed_password = hash_password(admin_password)
        _exec(
            "INSERT INTO users (email, password, role, org_id, status, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)",
            (admin_email, hashed_password, 'org_admin', org_id, USER_STATUS_APPROVED, 1)
        )
        user_id = cur.lastrowid
        print(f"[ORG-SIGNUP] Admin user created: user_id={user_id}")

        # Audit log: user created
        user_details = json.dumps({
            "user_id": user_id,
            "email": admin_email,
            "role": "org_admin",
            "status": USER_STATUS_APPROVED
        })
        _exec(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, user_id, 'user_created', user_details)
        )

        # Create trial subscription
        start_date = datetime.now().strftime('%Y-%m-%d')
        end_date = (datetime.now() + timedelta(days=TRIAL_PERIOD_DAYS)).strftime('%Y-%m-%d')
        _exec(
            "INSERT INTO subscriptions (org_id, plan_type, status, start_date, end_date, billing_cycle) VALUES (?, ?, ?, ?, ?, ?)",
            (org_id, plan_type, 'trial', start_date, end_date, 'monthly')
        )
        print(f"[ORG-SIGNUP] Trial subscription created for org_id={org_id}")

        # Generate OTP for email verification
        otp_code = str(secrets.randbelow(1000000)).zfill(6)
        otp_expires_at = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
        encrypted_otp = encrypt_otp(otp_code)
        
        # Store OTP in database
        _exec(
            "UPDATE users SET otp_code = ?, otp_expires_at = ?, otp_attempts = 0, otp_verified = 0 WHERE id = ?",
            (encrypted_otp, otp_expires_at, user_id)
        )

        # Audit log: signup completed (before commit)
        details_payload = {
            "org_name": org_name,
            "admin_email": admin_email,
            "plan_type": plan_type,
            "user_status": USER_STATUS_APPROVED,
            "email_verified": True,
            "otp_required": True
        }
        details = json.dumps(details_payload)
        _exec(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, user_id, 'org_signup_completed', details)
        )

        conn.commit()
        print(f"[ORG-SIGNUP] Transaction committed successfully for org_id={org_id}")

        # Send OTP email after commit
        email_success, email_error = send_otp_email(
            to_email=admin_email,
            otp_code=otp_code,
            user_name=get_name_from_email(admin_email),
            org_id=org_id,
            user_id=user_id
        )

        if not email_success:
            try:
                details = json.dumps({
                    "email": admin_email,
                    "reason": email_error or "otp_email_failed",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (org_id, user_id, 'otp_send_failed', details)
                )
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Organization created but failed to send OTP email. Please try logging in to receive OTP."}), 500

        # Log OTP generation
        try:
            details = json.dumps({"email": admin_email, "ip_address": request.remote_addr})
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, user_id, 'otp_generated', details)
            )
        except Exception:
            pass

        # Return OTP sent response instead of JWT tokens
        # User must verify OTP via /api/auth/verify-otp to get JWT tokens
        response_body = {
            "status": "otp_sent",
            "message": "Organization created successfully! Please check your email for the OTP code to complete signup.",
            "org_id": org_id,
            "email": admin_email,
            "expires_in_minutes": OTP_EXPIRY_MINUTES
        }
        return jsonify(response_body), 201
    except mysql.connector.IntegrityError as e:
        print(f"[ORG-SIGNUP] Integrity error: {e}")
        if conn:
            try:
                conn.rollback()
                print(f"[ORG-SIGNUP] Transaction rolled back: integrity error")
            except Exception:
                pass
        # Map unique constraint on organizations.name to 409
        msg = str(e)
        if 'organizations.name' in msg or 'UNIQUE constraint failed: organizations.name' in msg:
            try:
                if db_file_path and os.path.exists(db_file_path):
                    os.remove(db_file_path)
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Organization name already exists", "field": "org_name"}), 409
        # Filesystem cleanup (other integrity errors)
        try:
            if db_file_path and os.path.exists(db_file_path):
                os.remove(db_file_path)
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Organization signup failed. Please try again."}), 500
    except (MySQLError, OSError) as e:
        print(f"[ORG-SIGNUP] Error: {e}")
        if conn:
            try:
                conn.rollback()
                print(f"[ORG-SIGNUP] Transaction rolled back: exception")
            except Exception:
                pass
        # Filesystem cleanup
        try:
            if db_file_path and os.path.exists(db_file_path):
                os.remove(db_file_path)
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Organization signup failed. Please try again."}), 500
    finally:
        if conn:
            try:
                conn.close()
            except Exception:
                pass
@app.route('/api/org/trial-status', methods=['GET'])
@jwt_required()
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def trial_status():
    """Get trial countdown information for the current organization.
    
    Returns trial status including days remaining, trial end date, and expiration status.
    SuperAdmin can check any organization's trial status by providing org_id query parameter.
    """
    try:
        # Extract organization ID from JWT token (set by tenant middleware)
        org_id = g.org_id
        
        # Allow SuperAdmin to check any organization's trial status
        if g.role == ROLE_SUPER_ADMIN:
            org_id_param = request.args.get('org_id')
            if org_id_param:
                try:
                    org_id = int(org_id_param)
                except (ValueError, TypeError):
                    return jsonify({"status": "error", "message": "Invalid org_id parameter"}), 400
        
        if not org_id:
            return jsonify({"status": "error", "message": "Organization ID not found"}), 400
        
        # Query current subscription
        subscription_result = execute_primary_query(
            "SELECT plan_type, status, start_date, end_date FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
            params=(org_id,),
            fetch_one=True
        )
        
        if not subscription_result:
            return jsonify({"status": "error", "message": "No subscription found"}), 404
        
        # Normalize subscription_result across dict/Row/tuple
        if isinstance(subscription_result, dict):
            plan_type = subscription_result.get('plan_type')
            status = subscription_result.get('status')
            start_date = subscription_result.get('start_date')
            end_date = subscription_result.get('end_date')
        elif hasattr(subscription_result, "keys"):
            _tmp = dict(subscription_result)
            plan_type = _tmp.get('plan_type')
            status = _tmp.get('status')
            start_date = _tmp.get('start_date')
            end_date = _tmp.get('end_date')
        else:
            plan_type = subscription_result[0] if len(subscription_result) > 0 else None
            status = subscription_result[1] if len(subscription_result) > 1 else None
            start_date = subscription_result[2] if len(subscription_result) > 2 else None
            end_date = subscription_result[3] if len(subscription_result) > 3 else None
        
        # Calculate trial status
        is_trial = status == 'trial'
        days_remaining = 0
        is_expired = False
        trial_end_date_value = None
        
        if is_trial and end_date:
            try:
                if isinstance(end_date, (datetime, date)):
                    trial_end_date = datetime.combine(end_date, datetime.min.time()) if isinstance(end_date, date) and not isinstance(end_date, datetime) else end_date
                else:
                    trial_end_date = datetime.strptime(str(end_date), '%Y-%m-%d')
                now = datetime.now()
                days_remaining = (trial_end_date - now).days
                is_expired = days_remaining < 0
                days_remaining = max(0, days_remaining)  # Don't return negative numbers
                trial_end_date_value = trial_end_date.strftime('%Y-%m-%d')
            except (ValueError, TypeError) as e:
                print(f"[TRIAL-STATUS] Error parsing date: {e}")
                # If date parsing fails, assume expired
                is_expired = True
                trial_end_date_value = str(end_date)
        elif not is_trial and end_date:
            # For non-trial subscriptions, use the subscription's end_date
            trial_end_date_value = end_date
            days_remaining = 0
            is_expired = False
        
        # Build response message
        if is_trial:
            if is_expired:
                message = "Your trial has expired"
            else:
                message = f"Your trial expires in {days_remaining} day{'s' if days_remaining != 1 else ''}"
        elif status == 'active':
            message = "Subscription is active"
        elif status == 'cancelled':
            message = "Subscription is cancelled"
        else:
            message = f"Subscription status: {status}"
        
        response_body = {
            "status": "success",
            "subscription_status": status,
            "is_trial": is_trial,
            "trial_end_date": trial_end_date_value,
            "days_remaining": days_remaining,
            "is_expired": is_expired,
            "plan_type": plan_type,
            "message": message
        }
        
        return jsonify(response_body), 200
        
    except MySQLError as e:
        print(f"[TRIAL-STATUS] Database error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve trial status"}), 500
    except Exception as e:
        print(f"[TRIAL-STATUS] Error: {e}")
        return jsonify({"status": "error", "message": "An error occurred while retrieving trial status"}), 500

# --- SuperAdmin Signup (Self-Service) ---

@limiter.limit("1 per hour")
@app.route('/api/superadmin/signup', methods=['POST'])
def superadmin_signup():
    """Self-service SuperAdmin signup endpoint with secret key validation.
    
    This endpoint allows authorized personnel to create SuperAdmin accounts
    using a secret key. SuperAdmin accounts have full platform access and
    bypass all subscription/payment requirements.
    
    Security:
    - Secret key validation (SUPERADMIN_SECRET_KEY from environment)
    - Rate limited: 1 attempt per hour per IP
    - All attempts logged to audit_logs (success and failure)
    - No email verification needed (secret key serves as verification)
    - Account created with status='approved' (immediately active)
    """
    data = request.get_json(silent=True) or {}
    email = sanitize_text_input((data.get('email') or ''), max_length=255)
    password = (data.get('password') or '')  # do not sanitize passwords
    secret_key = (data.get('secret_key') or '').strip()  # do not sanitize secret key
    
    # Required fields validation
    if not email or not password or not secret_key:
        return jsonify({"status": "error", "message": "All fields required: email, password, secret_key"}), 400
    
    # Secret key validation (critical security check)
    if not SUPERADMIN_SECRET_KEY:
        try:
            details = json.dumps({"email": email, "reason": "secret_key_not_configured", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'superadmin_signup_failed', details))
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Invalid secret key. SuperAdmin signup not authorized."}), 403
    
    # Use constant-time comparison to prevent timing attacks
    if not hmac.compare_digest(secret_key, SUPERADMIN_SECRET_KEY):
        # Log failed attempt for security monitoring
        try:
            details = json.dumps({"email": email, "reason": "invalid_secret_key", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'superadmin_signup_failed', details))
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Invalid secret key. SuperAdmin signup not authorized."}), 403
    
    # Email format validation
    if not validate_email_format(email):
        return jsonify({"status": "error", "message": "Invalid email format", "field": "email"}), 400
    
    # Password strength validation
    valid_pw, err_pw = validate_password_strength(password)
    if not valid_pw:
        return jsonify({"status": "error", "message": err_pw, "field": "password"}), 400
    
    try:
        # Check email uniqueness in Primary DB
        existing_email = execute_primary_query(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            params=(email,),
            fetch_one=True
        )
        if existing_email and existing_email[0] > 0:
            return jsonify({"status": "error", "message": "Email already registered", "field": "email"}), 409
        
        # Hash password
        hashed_password = hash_password(password)
        
        # Create SuperAdmin user in Primary DB
        # Critical: org_id=NULL (SuperAdmin is not tied to any organization)
        user_id = execute_primary_query(
            "INSERT INTO users (email, password, role, org_id, status, is_email_verified, created_at) VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
            params=(email, hashed_password, ROLE_SUPER_ADMIN, None, 'approved', 1),
            return_lastrowid=True
        )
        
        # Log successful signup
        try:
            details = json.dumps({"email": email, "created_by": "self-service", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, user_id, 'superadmin_signup_completed', details))
        except Exception:
            pass
        
        return jsonify({
            "status": "success",
            "message": "SuperAdmin account created successfully. You can now log in.",
            "user_id": user_id,
            "email": email
        }), 201
        
    except mysql.connector.IntegrityError:
        return jsonify({"status": "error", "message": "Email already registered", "field": "email"}), 409
    except MySQLError as e:
        # Log error
        try:
            details = json.dumps({"email": email, "error": str(e), "ip_address": request.remote_addr})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'superadmin_signup_failed', details))
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Failed to create SuperAdmin account. Please try again."}), 500
    except Exception as e:
        # Log unexpected errors
        try:
            details = json.dumps({"email": email, "error": str(e), "ip_address": request.remote_addr})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'superadmin_signup_failed', details))
        except Exception:
            pass
        return jsonify({"status": "error", "message": "An unexpected error occurred. Please try again."}), 500

# --- Razorpay Payment Integration ---

# In-memory mapping for created Razorpay plans (cached; persisted in DB)
RAZORPAY_PLAN_IDS = {}

@app.route('/api/razorpay/plans', methods=['POST'])
@superadmin_required
def create_razorpay_plans():
	"""
	Create Razorpay subscription plans for available tiers (SuperAdmin only).
	
	New Pricing Model Mapping:
	- Base plans include specified number of users (5 for Basic, 10 for Plus, 100 for Pro)
	- Razorpay plans are created with base amounts (₹1700, ₹2600, ₹4300)
	- Extra users beyond plan limits are charged at ₹500/month each
	- For Pro plan: custom pricing applies beyond 100 users
	- Extra users are handled via addons or custom charges (see calculate_subscription_amount function)
	
	Note: The actual subscription amount is calculated by calculate_subscription_amount() which
	includes base price + extra user charges. Razorpay plan creation here only sets up the base plans.
	"""
	if razorpay_client is None:
		try:
			details = json.dumps({"error": "client_not_configured"})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, getattr(g, 'user_id', None), 'razorpay_plan_error', details))
		except Exception:
			pass
		return jsonify({"status": "error", "message": "Razorpay not configured"}), 503

	body = request.get_json(silent=True) or {}
	# Default to ['basic','plus','pro'] - 'si_plus' is a legacy alias only needed during migration
	requested = body.get('plan_types') or ['basic', 'plus', 'pro']
	
	# Normalize and de-duplicate requested plans to avoid creating duplicate plans
	normalized_requested = []
	seen = set()
	for plan_type in requested:
		normalized = normalize_plan_type(plan_type)
		if normalized not in seen:
			normalized_requested.append(normalized)
			seen.add(normalized)
	
	created = {}
	for plan_type in normalized_requested:
		cfg = RAZORPAY_PLANS.get(plan_type)
		if not cfg:
			continue
		try:
			# Razorpay Plan Creation API format per documentation:
			# https://razorpay.com/docs/api/payments/subscriptions/create-plan/
			# Format: period, interval, item{name, amount, currency, description}
			plan_data = {
				'period': cfg['period'],
				'interval': cfg['interval'],
				'item': {
					'name': cfg['name'],
					'amount': cfg['amount'],  # Amount in paise: ₹1,700 = 170,000 paise
					'currency': cfg['currency'],  # 'INR' - per Razorpay docs, can be empty string or currency code
					'description': cfg['description']
				}
			}
			print(f"[RAZORPAY] Creating plan for {plan_type} using Razorpay API...")
			print(f"[RAZORPAY] Plan data: {plan_data}")
			print(f"[RAZORPAY] API endpoint: POST /v1/plans")
			rz_plan = razorpay_client.plan.create(plan_data, timeout=10)
			plan_id = rz_plan.get('id')
			print(f"[RAZORPAY] Plan created successfully: {plan_id}")
			RAZORPAY_PLAN_IDS[plan_type] = plan_id
			try:
				execute_primary_query("CREATE TABLE IF NOT EXISTS razorpay_plans (plan_type TEXT PRIMARY KEY, razorpay_plan_id TEXT)")
				execute_primary_query("INSERT INTO razorpay_plans (plan_type, razorpay_plan_id) VALUES (?, ?) ON CONFLICT(plan_type) DO UPDATE SET razorpay_plan_id = excluded.razorpay_plan_id", (plan_type, plan_id))
			except Exception:
				pass
			created[plan_type] = plan_id
			try:
				details = json.dumps({"plan_type": plan_type, "razorpay_plan_id": plan_id, "amount": cfg['amount'], "currency": cfg['currency']})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, getattr(g, 'user_id', None), 'razorpay_plan_created', details))
			except Exception:
				pass
		except razorpay.errors.BadRequestError as e:
			error_msg = str(e)
			print(f"[RAZORPAY] BadRequestError for {plan_type}: {error_msg}")
			print(f"[RAZORPAY] RECOMMENDATION: Create plans manually in Razorpay Dashboard")
			print(f"[RAZORPAY] Then use: python add_plan_ids.py to store Plan IDs")
			try:
				details = json.dumps({"plan_type": plan_type, "error": error_msg, "plan_data": plan_data})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, getattr(g, 'user_id', None), 'razorpay_plan_error', details))
			except Exception:
				pass
			# Provide helpful error message
			if "URL was not found" in error_msg or "not found" in error_msg.lower():
				return jsonify({
					"status": "error", 
					"message": "Razorpay plan creation API unavailable. Please create plans manually in Razorpay Dashboard and use 'python add_plan_ids.py' to store Plan IDs. See RAZORPAY_PLAN_SETUP.md for instructions.",
					"error": error_msg, 
					"plan_type": plan_type,
					"solution": "manual_setup_required"
				}), 400
			return jsonify({"status": "error", "message": "Invalid plan data", "error": error_msg, "plan_type": plan_type}), 400
		except razorpay.errors.ServerError as e:
			error_msg = str(e)
			print(f"[RAZORPAY] ServerError for {plan_type}: {error_msg}")
			try:
				details = json.dumps({"plan_type": plan_type, "error": error_msg})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, getattr(g, 'user_id', None), 'razorpay_plan_error', details))
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Payment service error", "error": error_msg, "plan_type": plan_type}), 500
		except Exception as e:
			error_msg = str(e)
			error_type = type(e).__name__
			print(f"[RAZORPAY] Unexpected error for {plan_type} ({error_type}): {error_msg}")
			import traceback
			traceback.print_exc()
			try:
				details = json.dumps({"plan_type": plan_type, "error": error_msg, "error_type": error_type})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, getattr(g, 'user_id', None), "razorpay_plan_error", details))
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Failed to create plan", "error": error_msg, "error_type": error_type, "plan_type": plan_type}), 500

	return jsonify({"status": "success", "message": "Razorpay plans created successfully", "plans": created}), 201


@app.route('/api/razorpay/subscription/create', methods=['POST'])
@require_https_payment
@limiter.limit("5 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def create_razorpay_subscription():
	"""Create a Razorpay subscription for organization upgrade."""
	if razorpay_client is None:
		return jsonify({"status": "error", "message": "Razorpay not configured"}), 503

	data = request.get_json(silent=True) or {}
	plan_type = (data.get('plan_type') or '').strip()
	user_count = int(data.get('user_count') or 1)
	billing_cycle = (data.get('billing_cycle') or 'monthly').strip()
	primary_conn = None
	primary_cursor = None

	if plan_type not in ['basic', 'si_plus', 'plus', 'pro']:
		return jsonify({"status": "error", "message": "Invalid plan type"}), 400
	
	# Validate user_count range
	if user_count < 1:
		return jsonify({"status": "error", "message": "User count must be at least 1"}), 400
	if user_count > MAX_USER_COUNT:
		return jsonify({"status": "error", "message": f"User count cannot exceed {MAX_USER_COUNT}"}), 400

	org_id = data.get('org_id') if getattr(g, 'role', None) == ROLE_SUPER_ADMIN else getattr(g, 'org_id', None)
	if not org_id:
		return jsonify({"status": "error", "message": "Missing org context"}), 400

	# Normalize plan type for lookups and ID fetches
	plan_type_normalized = normalize_plan_type(plan_type)

	# Check current subscription
	current = execute_primary_query(
		"SELECT status, razorpay_subscription_id FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
		(org_id,),
		fetch_one=True
	)
	if current:
		status, existing_sub = current
		if status == 'active' and existing_sub:
			return jsonify({"status": "error", "message": "Subscription already active"}), 409

	# Use normalized plan type for plan ID lookup
	plan_id = get_razorpay_plan_id(plan_type_normalized)
	if not plan_id:
		return jsonify({"status": "error", "message": "Razorpay plan not configured. Contact administrator."}), 500

	# Compute included_users and extra_users
	limits = get_plan_limits(plan_type_normalized) or {}
	included_users = limits.get('max_users', 0)
	extra_users = max(0, user_count - included_users)

	# Create base subscription with quantity=1
	# total_count: For yearly, set to 12. For monthly, set to 360 (30 years) - max allowed for UPI payments
	# Razorpay requires total_count to be at least 1, but UPI has a 30-year limit
	subscription_data = {
		'plan_id': plan_id,
		'customer_notify': 1,
		'quantity': 1,
		'total_count': 12 if billing_cycle == 'yearly' else 360,  # 360 months = 30 years (max for UPI)
		'notes': {
			'org_id': str(org_id),
			'plan_type': plan_type,
			'created_by': getattr(g, 'email', None) or ''
		}
	}
	try:
		rz_sub = razorpay_client.subscription.create(subscription_data, timeout=10)
		sub_id = rz_sub.get('id')
		
		# Create addons for extra users if needed
		if extra_users > 0:
			try:
				addon_amount = extra_users * 50000  # ₹500 per extra user in paise
				addon_data = {
					'item': {
						'name': 'Extra Users',
						'amount': 50000,
						'currency': 'INR'
					},
					'quantity': extra_users
				}
				razorpay_client.subscription.createAddon(sub_id, addon_data, timeout=10)
			except Exception as e:
				print(f"Error creating addon for subscription {sub_id}: {e}")
				# Continue even if addon creation fails
		
		# Update subscription row
		res = execute_primary_query(
			"UPDATE subscriptions SET razorpay_subscription_id = ?, status = ?, plan_type = ? WHERE org_id = ? AND status = ?",
			(sub_id, RAZORPAY_STATUS_CREATED, plan_type, org_id, 'trial')
		)
		try:
			updated = getattr(res, 'rowcount', None)
		except Exception:
			updated = None
		if not updated:
			execute_primary_query(
				"INSERT INTO subscriptions (org_id, plan_type, status, razorpay_subscription_id, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?)",
				(org_id, plan_type, RAZORPAY_STATUS_CREATED, sub_id, None, None)
			)
		# Audit
		try:
			details = json.dumps({"org_id": org_id, "plan_type": plan_type, "razorpay_subscription_id": sub_id, "user_count": user_count, "included_users": included_users, "extra_users": extra_users})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'razorpay_subscription_created', details))
		except Exception:
			pass
		
		# Calculate total amount using calculate_subscription_amount
		amount = calculate_subscription_amount(plan_type, user_count, billing_cycle)
		
		# Build description without per-user phrasing
		plan_display = get_subscription_display_name(plan_type)
		if extra_users > 0:
			description = f"{plan_display} (Base + {extra_users} extra user{'s' if extra_users > 1 else ''})"
		else:
			description = f"{plan_display} (Base plan)"
		
		return jsonify({
			"status": "success",
			"subscription_id": sub_id,
			"razorpay_key_id": RAZORPAY_KEY_ID,
			"amount": amount,
			"currency": "INR",
			"name": "PROTON Subscription",
			"description": description,
			"prefill": {"email": getattr(g, 'email', None) or '', "contact": ''}
		}), 201
	except razorpay.errors.BadRequestError as e:
		return jsonify({"status": "error", "message": "Invalid request", "error": str(e)}), 400
	except razorpay.errors.ServerError as e:
		return jsonify({"status": "error", "message": "Payment service unavailable", "error": str(e)}), 500


@app.route('/api/razorpay/subscription/verify', methods=['POST'])
@require_https_payment
@limiter.limit("10 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def verify_razorpay_subscription():
	"""Verify payment signature after successful Razorpay Checkout and activate subscription."""
	if razorpay_client is None:
		return jsonify({"status": "error", "message": "Razorpay not configured"}), 503

	data = request.get_json(silent=True) or {}
	rz_sub_id = data.get('razorpay_subscription_id')
	rz_payment_id = data.get('razorpay_payment_id')
	rz_signature = data.get('razorpay_signature')
	if not (rz_sub_id and rz_payment_id and rz_signature):
		return jsonify({"status": "error", "message": "Missing required fields"}), 400

	params = {
		'razorpay_subscription_id': rz_sub_id,
		'razorpay_payment_id': rz_payment_id,
		'razorpay_signature': rz_signature
	}
	try:
		razorpay_client.utility.verify_subscription_payment_signature(params)
	except razorpay.errors.SignatureVerificationError:
		return jsonify({"status": "error", "message": "Invalid payment signature"}), 400

	try:
		subscription = razorpay_client.subscription.fetch(rz_sub_id)
		payment = razorpay_client.payment.fetch(rz_payment_id)
		sub_row = execute_primary_query("SELECT org_id, plan_type, billing_cycle FROM subscriptions WHERE razorpay_subscription_id = ?", (rz_sub_id,), fetch_one=True)
		if not sub_row:
			return jsonify({"status": "error", "message": "Subscription not found"}), 404
		org_id, plan_type, billing_cycle = sub_row
		# Enforce org ownership unless SuperAdmin
		if getattr(g, 'role', None) != ROLE_SUPER_ADMIN and org_id != getattr(g, 'org_id', None):
			try:
				details = json.dumps({"attempting_org_id": getattr(g, 'org_id', None), "subscription_org_id": org_id, "subscription_id": rz_sub_id})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (getattr(g, 'org_id', None), getattr(g, 'user_id', None), 'subscription_cross_org_verification_attempt', details))
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Forbidden"}), 403
		
		# Get current admin count to calculate expected amount (MUST be before fraud detection)
		try:
			admin_count_row = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND role IN ('org_admin', 'super_admin')", (org_id,), fetch_one=True)
			user_count = admin_count_row[0] if admin_count_row else 1
		except Exception:
			user_count = 1
		
		expected_amount_paise = calculate_subscription_amount(plan_type, user_count, billing_cycle or 'monthly')
		expected_amount_rupees = expected_amount_paise / 100.0
		
		# Verify payment amount matches expected amount
		actual_amount_rupees = (payment.get('amount', 0) or 0) / 100.0
		
		# Fraud detection check
		try:
			from utils.fraud_detection import FraudDetector
			fraud_analysis = FraudDetector.analyze_payment(
				org_id=org_id,
				user_id=getattr(g, 'user_id', None),
				payment_id=rz_payment_id,
				expected_amount=expected_amount_rupees,
				actual_amount=actual_amount_rupees
			)
			
			# Log fraud analysis
			if fraud_analysis["fraud_score"] > 0:
				try:
					details = json.dumps({
						"fraud_score": fraud_analysis["fraud_score"],
						"risk_level": fraud_analysis["risk_level"],
						"risk_factors": fraud_analysis["risk_factors"],
						"payment_id": rz_payment_id,
						"org_id": org_id
					})
					execute_primary_query(
						"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
						(org_id, getattr(g, 'user_id', None), 'fraud_analysis', details)
					)
				except Exception:
					pass
			
			# Block high-risk payments
			if fraud_analysis["recommendation"] == "block":
				return jsonify({
					"status": "error",
					"message": "Payment flagged for review due to security concerns",
					"error_code": "FRAUD_DETECTED"
				}), 403
		except Exception as e:
			print(f"[FRAUD] Fraud detection error: {e}")
			# Continue with payment if fraud detection fails
		
		# Allow 1 rupee tolerance for rounding differences
		if abs(actual_amount_rupees - expected_amount_rupees) > 1.0:
			# Log security incident - amount mismatch
			try:
				details = json.dumps({
					"org_id": org_id,
					"subscription_id": rz_sub_id,
					"payment_id": rz_payment_id,
					"expected_amount": expected_amount_rupees,
					"actual_amount": actual_amount_rupees,
					"plan_type": plan_type,
					"user_count": user_count,
					"billing_cycle": billing_cycle
				})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'payment_amount_mismatch_security_incident', details))
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Payment amount verification failed"}), 400
		
		# Activate subscription and record payment atomically
		start_at = subscription.get('start_at')
		start_date_val = datetime.fromtimestamp(start_at).strftime('%Y-%m-%d') if start_at else datetime.now().strftime('%Y-%m-%d')
		
		# Get current subscription status for validation
		current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
		current_status = current_sub[0] if current_sub else None
		
		# Validate transition to 'active'
		is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'active', user_id=getattr(g, 'user_id', None), context={"subscription_id": rz_sub_id, "payment_id": rz_payment_id})
		if not is_valid:
			try:
				details = json.dumps({"org_id": org_id, "current_status": current_status, "attempted_status": "active", "error": error_msg, "subscription_id": rz_sub_id})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_invalid_transition_blocked', details))
			except Exception:
				pass
			return jsonify({"status": "error", "message": error_msg}), 400
		
		# Check if payment already exists (idempotency check)
		existing_payment = execute_primary_query(
			"SELECT id FROM billing_transactions WHERE razorpay_payment_id = ?",
			(rz_payment_id,),
			fetch_one=True
		)
		
		if existing_payment:
			# Payment already recorded - just update subscription status (idempotent)
			execute_primary_query(
				"UPDATE subscriptions SET status = 'active', start_date = ?, end_date = NULL WHERE org_id = ?",
				(start_date_val, org_id)
			)
			try:
				details = json.dumps({"org_id": org_id, "payment_id": rz_payment_id, "reason": "duplicate_payment_idempotent"})
				execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'payment_duplicate_idempotent', details))
			except Exception:
				pass
		else:
			# Use transaction to ensure atomicity
			try:
				execute_primary_transaction([
					{
						"query": "UPDATE subscriptions SET status = 'active', start_date = ?, end_date = NULL WHERE org_id = ?",
						"params": (start_date_val, org_id)
					},
					{
						"query": "INSERT INTO billing_transactions (org_id, razorpay_payment_id, amount, status) VALUES (?, ?, ?, ?)",
						"params": (org_id, rz_payment_id, actual_amount_rupees, 'success')
					}
				])
			except mysql.connector.IntegrityError:
				# Duplicate payment ID (race condition) - check again and handle gracefully
				existing_payment = execute_primary_query(
					"SELECT id FROM billing_transactions WHERE razorpay_payment_id = ?",
					(rz_payment_id,),
					fetch_one=True
				)
				if existing_payment:
					# Payment was inserted by another request - just update subscription
					execute_primary_query(
						"UPDATE subscriptions SET status = 'active', start_date = ?, end_date = NULL WHERE org_id = ?",
						(start_date_val, org_id)
					)
					try:
						details = json.dumps({"org_id": org_id, "payment_id": rz_payment_id, "reason": "duplicate_payment_race_condition"})
						execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'payment_duplicate_race_condition', details))
					except Exception:
						pass
				else:
					# Different integrity error - re-raise
					raise
		
		invalidate_billing_metrics_cache()
		try:
			details = json.dumps({"org_id": org_id, "subscription_id": rz_sub_id, "payment_id": rz_payment_id, "amount": actual_amount_rupees, "expected_amount": expected_amount_rupees})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_payment_verified', details))
		except Exception:
			pass
		
		# Send email notifications
		try:
			user_email = getattr(g, 'email', None)
			user_name = getattr(g, 'name', None)
			if user_email:
				# Send payment success email
				send_payment_success_email(
					to_email=user_email,
					payment_id=rz_payment_id,
					amount=actual_amount_rupees,
					plan_type=plan_type,
					billing_cycle=billing_cycle or 'monthly',
					payment_date=start_date_val,
					user_name=user_name,
					org_id=org_id,
					user_id=getattr(g, 'user_id', None)
				)
				# Send subscription activated email
				next_billing = None
				if billing_cycle == 'yearly':
					start_dt = datetime.strptime(start_date_val, '%Y-%m-%d')
					next_billing = (start_dt + timedelta(days=365)).strftime('%Y-%m-%d')
				elif billing_cycle == 'monthly':
					start_dt = datetime.strptime(start_date_val, '%Y-%m-%d')
					next_billing = (start_dt + timedelta(days=30)).strftime('%Y-%m-%d')
				
				send_subscription_activated_email(
					to_email=user_email,
					plan_type=plan_type,
					billing_cycle=billing_cycle or 'monthly',
					start_date=start_date_val,
					next_billing_date=next_billing,
					user_name=user_name,
					org_id=org_id,
					user_id=getattr(g, 'user_id', None)
				)
		except Exception as e:
			print(f"[EMAIL] Failed to send payment notification emails: {e}")
			# Don't fail the payment if email fails
		
		# Invalidate usage cache
		try:
			ORG_USAGE_CACHE.pop(org_id, None)
		except Exception:
			pass
		return jsonify({"status": "success", "message": "Payment verified successfully. Your subscription is now active!", "subscription_status": "active"})
	except razorpay.errors.BadRequestError as e:
		# Log Razorpay API error
		try:
			details = json.dumps({
				"error_type": "razorpay_bad_request",
				"error": str(e),
				"subscription_id": rz_sub_id,
				"payment_id": rz_payment_id
			})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (getattr(g, 'org_id', None), getattr(g, 'user_id', None), 'payment_verification_error', details))
		except Exception:
			pass
		return jsonify({"status": "error", "message": "Invalid payment request"}), 400
	except razorpay.errors.ServerError as e:
		# Log Razorpay server error
		try:
			details = json.dumps({
				"error_type": "razorpay_server_error",
				"error": str(e),
				"subscription_id": rz_sub_id,
				"payment_id": rz_payment_id
			})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (getattr(g, 'org_id', None), getattr(g, 'user_id', None), 'payment_verification_error', details))
		except Exception:
			pass
		return jsonify({"status": "error", "message": "Payment service temporarily unavailable"}), 502
	except Exception as e:
		# Log unexpected error with full context
		import traceback
		error_trace = traceback.format_exc()
		try:
			details = json.dumps({
				"error_type": "unexpected_error",
				"error": str(e),
				"error_class": type(e).__name__,
				"subscription_id": rz_sub_id,
				"payment_id": rz_payment_id,
				"trace": error_trace[:1000]  # Limit trace length
			})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (getattr(g, 'org_id', None), getattr(g, 'user_id', None), 'payment_verification_critical_error', details))
		except Exception:
			pass
		print(f"[PAYMENT VERIFICATION ERROR] {type(e).__name__}: {e}")
		print(error_trace)
		return jsonify({"status": "error", "message": "Failed to verify payment"}), 500


@app.route('/api/razorpay/webhooks', methods=['POST'])
@require_https_payment
@limiter.limit("100 per minute", key_func=lambda: request.remote_addr)
def razorpay_webhooks():
	"""Handle Razorpay webhook events for subscription lifecycle and payments."""
	if not RAZORPAY_WEBHOOK_SECRET:
		try:
			details = json.dumps({"event": request.headers.get('X-Razorpay-Event-Id'), "error": "webhook_secret_missing"})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'webhook_config_error', details))
		except Exception:
			pass
		return jsonify({"status": "error", "message": "Razorpay webhook not configured"}), 503
	webhook_signature = request.headers.get('X-Razorpay-Signature')
	if not webhook_signature:
		return jsonify({"status": "error", "message": "Missing signature"}), 400
	webhook_body = request.get_data()
	expected_signature = hmac.new(
		RAZORPAY_WEBHOOK_SECRET.encode('utf-8'),
		webhook_body,
		hashlib.sha256
	).hexdigest()
	if not hmac.compare_digest(webhook_signature, expected_signature):
		return jsonify({"status": "error", "message": "Invalid signature"}), 400

	# Idempotency: ensure we don't process the same event twice
	event_id = request.headers.get('X-Razorpay-Event-Id')
	try:
		execute_primary_query("CREATE TABLE IF NOT EXISTS webhook_events (id TEXT PRIMARY KEY, received_at TEXT)")
		if event_id:
			existing = execute_primary_query("SELECT id FROM webhook_events WHERE id = ?", (event_id,), fetch_one=True)
			if existing:
				return jsonify({"status": "success"})
	except Exception:
		pass

	data = request.get_json(silent=True) or {}
	event_type = data.get('event')
	payload = data.get('payload', {})
	sub_entity = payload.get('subscription', {}).get('entity', {})
	pay_entity = payload.get('payment', {}).get('entity', {})
	subscription_id = sub_entity.get('id')
	if not subscription_id:
		return jsonify({"status": "error", "message": "Missing subscription_id"}), 400

	org_row = execute_primary_query("SELECT org_id FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
	if not org_row:
		try:
			details = json.dumps({"subscription_id": subscription_id, "event": data.get('event')})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'subscription_webhook_unknown_subscription', details))
		except Exception:
			pass
		# Return 200 to avoid retries
		return jsonify({"status": "success"})
	org_id = org_row[0]

	try:
		if event_type == 'subscription.authenticated':
			# Get current status for validation
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'authenticated', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
				# Continue anyway for webhook - log but don't block
			else:
				execute_primary_query("UPDATE subscriptions SET status = 'authenticated' WHERE razorpay_subscription_id = ?", (subscription_id,))
		elif event_type == 'subscription.activated':
			start_at = sub_entity.get('start_at')
			# Get current status for validation
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'active', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
				# Continue anyway for webhook - log but don't block
			else:
				# Atomic Swap: Activate new plan AND cancel any other 'active' or 'trial' plans for this org
				try:
					# 1. Activate the new subscription
					execute_primary_query("UPDATE subscriptions SET status = 'active', start_date = ? WHERE razorpay_subscription_id = ?", (datetime.fromtimestamp(start_at).strftime('%Y-%m-%d') if start_at else None, subscription_id))
					
					# 2. Cancel any OTHER active/trial subscriptions for this org to prevent duplicates
					# We use the org_id we resolved earlier
					# Note: Cancelling other subscriptions is a business rule, not a state transition validation
					execute_primary_query(
						"UPDATE subscriptions SET status = 'cancelled', end_date = ? WHERE org_id = ? AND razorpay_subscription_id != ? AND status IN ('active', 'trial', 'authenticated')",
						(datetime.now().strftime('%Y-%m-%d'), org_id, subscription_id)
					)
					print(f"[WEBHOOK] Atomic swap completed for org {org_id}. New subscription {subscription_id} active.")
				except Exception as e:
					print(f"[WEBHOOK] Error during atomic swap: {e}")
		elif event_type == 'subscription.charged':
			payment_id = pay_entity.get('id')
			amount = (pay_entity.get('amount', 0) or 0) / 100.0
			try:
				execute_primary_query("INSERT INTO billing_transactions (org_id, razorpay_payment_id, amount, status) VALUES (?, ?, ?, ?)", (org_id, payment_id, amount, 'success'))
				invalidate_billing_metrics_cache()
			except mysql.connector.IntegrityError:
				# Duplicate payment ID - already processed (idempotent)
				try:
					details = json.dumps({"org_id": org_id, "payment_id": payment_id, "event": event_type, "reason": "duplicate_payment_idempotent"})
					execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, None, 'webhook_duplicate_payment_ignored', details))
				except Exception:
					pass
				# Continue processing - payment already recorded
		elif event_type == 'subscription.paused':
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'paused', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
			else:
				execute_primary_query("UPDATE subscriptions SET status = 'paused' WHERE razorpay_subscription_id = ?", (subscription_id,))
		elif event_type == 'subscription.cancelled':
			ended_at = sub_entity.get('ended_at')
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'cancelled', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
			else:
				execute_primary_query("UPDATE subscriptions SET status = 'cancelled', end_date = ? WHERE razorpay_subscription_id = ?", (datetime.fromtimestamp(ended_at).strftime('%Y-%m-%d') if ended_at else None, subscription_id))
		elif event_type == 'subscription.halted':
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'halted', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
			else:
				execute_primary_query("UPDATE subscriptions SET status = 'halted' WHERE razorpay_subscription_id = ?", (subscription_id,))
		elif event_type == 'subscription.completed':
			current_sub = execute_primary_query("SELECT status FROM subscriptions WHERE razorpay_subscription_id = ?", (subscription_id,), fetch_one=True)
			current_status = current_sub[0] if current_sub else None
			is_valid, error_msg = validate_subscription_transition(org_id, current_status, 'completed', context={"event": event_type, "subscription_id": subscription_id})
			if not is_valid:
				print(f"[WEBHOOK] Invalid transition attempt: {error_msg}")
			else:
				execute_primary_query("UPDATE subscriptions SET status = 'completed' WHERE razorpay_subscription_id = ?", (subscription_id,))
		elif event_type == 'payment.failed':
			payment_id = pay_entity.get('id')
			amount = (pay_entity.get('amount', 0) or 0) / 100.0
			failure_reason = pay_entity.get('error_description') or pay_entity.get('error_code') or 'Payment processing failed'
			try:
				execute_primary_query("INSERT INTO billing_transactions (org_id, razorpay_payment_id, amount, status) VALUES (?, ?, ?, ?)", (org_id, payment_id, amount, 'failed'))
				invalidate_billing_metrics_cache()
				
				# Send payment failed email notification
				try:
					user_row = execute_primary_query("SELECT u.email, u.name FROM users u JOIN subscriptions s ON u.org_id = s.org_id WHERE s.org_id = ? AND u.role IN ('org_admin', 'super_admin') LIMIT 1", (org_id,), fetch_one=True)
					if user_row:
						user_email, user_name = user_row[0], user_row[1]
						send_payment_failed_email(
							to_email=user_email,
							payment_id=payment_id,
							amount=amount,
							payment_date=datetime.now().strftime('%Y-%m-%d'),
							failure_reason=failure_reason,
							user_name=user_name,
							org_id=org_id
						)
				except Exception as e:
					print(f"[EMAIL] Failed to send payment failed notification: {e}")
			except mysql.connector.IntegrityError:
				# Duplicate payment ID - already processed (idempotent)
				try:
					details = json.dumps({"org_id": org_id, "payment_id": payment_id, "event": event_type, "reason": "duplicate_payment_idempotent"})
					execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, None, 'webhook_duplicate_payment_ignored', details))
				except Exception:
					pass
				# Continue processing - payment already recorded
		# Audit log
		try:
			details = json.dumps({"org_id": org_id, "event": event_type, "subscription_id": subscription_id, "payment_id": pay_entity.get('id')})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, None, 'subscription_webhook_received', details))
		except Exception:
			pass
		# Invalidate cache
		try:
			ORG_USAGE_CACHE.pop(org_id, None)
		except Exception:
			pass
		try:
			if event_id:
				execute_primary_query("INSERT OR IGNORE INTO webhook_events (id, received_at) VALUES (?, ?)", (event_id, datetime.now().isoformat()))
		except Exception:
			pass
		return jsonify({"status": "success", "message": "Webhook processed successfully"}), 200
	except MySQLError as e:
		# Database error - retryable, return 500 so Razorpay retries
		import traceback
		error_trace = traceback.format_exc()
		try:
			details = json.dumps({
				"org_id": org_id,
				"event": event_type,
				"error_type": "database_error",
				"error": str(e),
				"error_class": type(e).__name__,
				"trace": error_trace[:1000]
			})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, None, 'subscription_webhook_database_error', details))
		except Exception:
			pass
		print(f"[WEBHOOK] Database error processing webhook: {e}")
		return jsonify({"status": "error", "message": "Database error processing webhook"}), 500
	except Exception as e:
		# Processing error - retryable, return 500 so Razorpay retries
		import traceback
		error_trace = traceback.format_exc()
		try:
			details = json.dumps({
				"org_id": org_id,
				"event": event_type,
				"error_type": "processing_error",
				"error": str(e),
				"error_class": type(e).__name__,
				"trace": error_trace[:1000]
			})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, None, 'subscription_webhook_processing_error', details))
		except Exception:
			pass
		print(f"[WEBHOOK] Processing error: {e}")
		print(error_trace)
		return jsonify({"status": "error", "message": "Error processing webhook"}), 500


# --- Subscription & Billing Management ---

@app.route('/api/org/subscription', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_organization_subscription():
	"""Retrieve current subscription details for organization.

	Returns comprehensive subscription information including plan type,
	status, billing cycle, next billing date, and usage statistics.
	"""
	try:
		org_id = getattr(g, 'org_id', None)
		if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
			q_org_id = request.args.get('org_id', type=int)
			if q_org_id:
				org_id = q_org_id
		if not org_id:
			return jsonify({"status": "error", "message": "Organization context missing"}), 400

		# Prioritize Active/Trial/Authenticated subscriptions over Created/Abandoned
		# This ensures we show the actual active plan even if a newer "created" (abandoned) attempt exists
		row = execute_primary_query(
			"""
			SELECT id, org_id, plan_type, razorpay_subscription_id, status, start_date, end_date, billing_cycle 
			FROM subscriptions 
			WHERE org_id = ? 
			ORDER BY 
				CASE 
					WHEN status IN ('active', 'trial', 'authenticated') THEN 1 
					WHEN status = 'paused' THEN 2
					WHEN status = 'past_due' THEN 3
					WHEN status = 'created' THEN 4
					ELSE 5 
				END ASC,
				id DESC 
			LIMIT 1
			""",
			(org_id,),
			fetch_one=True
		)
		if not row:
			return jsonify({"status": "error", "message": "No subscription found for this organization"}), 404

		sub_id, s_org_id, plan_type, rz_sub_id, status, start_date, end_date, billing_cycle = row
		if getattr(g, 'role', None) != ROLE_SUPER_ADMIN and s_org_id != getattr(g, 'org_id', None):
			return jsonify({"status": "error", "message": "Forbidden"}), 403

		next_billing_date = None
		quantity = None
		if rz_sub_id and razorpay_client is not None:
			try:
				rz = razorpay_client.subscription.fetch(rz_sub_id)
				charge_at = rz.get('charge_at')
				quantity = rz.get('quantity')
				if charge_at:
					next_billing_date = datetime.fromtimestamp(charge_at).strftime('%Y-%m-%d')
			except Exception as _:
				pass

		plan_limits = get_plan_limits(plan_type) or {}
		usage_stats = None
		try:
			usage_stats = get_org_usage_stats(org_id, plan_type)
		except Exception:
			usage_stats = None

		# Get current user count for pricing breakdown
		current_user_count = 0
		try:
			current_user_count = get_current_admin_count(org_id)
		except Exception:
			pass

		# Calculate pricing breakdown
		pricing_breakdown = None
		try:
			included_users = plan_limits.get('max_users', 0)
			extra_users = max(0, current_user_count - included_users)
			base_price = RAZORPAY_PLANS.get(plan_type, {}).get('amount', 0) / 100.0  # Convert paise to rupees
			extra_user_rate = 500.0  # ₹500 per extra user
			extra_user_cost = extra_users * extra_user_rate
			
			# For Pro plan, base covers up to 100 users
			if plan_type == 'pro' and current_user_count > 100:
				included_users = 100
				extra_users = current_user_count - 100
				extra_user_cost = extra_users * extra_user_rate
			
			total_monthly_cost = base_price + extra_user_cost
			next_billing_amount = calculate_subscription_amount(plan_type, current_user_count, billing_cycle or 'monthly') / 100.0
			
			pricing_breakdown = {
				"base_price": base_price,
				"included_users": included_users,
				"current_users": current_user_count,
				"extra_users": extra_users,
				"extra_user_rate": extra_user_rate,
				"extra_user_cost": extra_user_cost,
				"total_monthly_cost": total_monthly_cost,
				"billing_cycle": billing_cycle or 'monthly',
				"next_billing_amount": next_billing_amount
			}
		except Exception:
			pass

		days_remaining = None
		if status == 'trial' and end_date:
			try:
				end_dt = datetime.strptime(end_date, '%Y-%m-%d') if isinstance(end_date, str) else end_date
				days_remaining = (end_dt - datetime.now()).days
			except Exception:
				pass

		resp = {
			"status": "success",
			"subscription": {
				"id": sub_id,
				"org_id": s_org_id,
				"plan_type": plan_type,
				"plan_display_name": get_subscription_display_name(plan_type),
				"status": status,
				"billing_cycle": billing_cycle,
				"start_date": start_date,
				"end_date": end_date,
				"next_billing_date": next_billing_date,
				"user_count": quantity,
				"amount_per_cycle": (calculate_subscription_amount(plan_type, quantity or current_user_count or 1, billing_cycle or 'monthly') / 100.0),
				"razorpay_subscription_id": rz_sub_id,
				"is_trial": status == 'trial',
				"trial_days_remaining": days_remaining if status == 'trial' else None,
				"can_upgrade": status in ['active', 'trial'] and plan_type != 'pro',
				"can_cancel": status in ['active', 'authenticated'],
				"can_pause": status == 'active' and rz_sub_id is not None,
				"plan_limits": plan_limits
			},
			"plan_limits": plan_limits,
			"current_usage": usage_stats,
			"pricing_breakdown": pricing_breakdown
		}

		try:
			details = json.dumps({"org_id": org_id, "subscription_id": rz_sub_id, "plan_type": plan_type})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_viewed', details))
		except Exception:
			pass

		return jsonify(resp)
	except Exception as e:
		print(f"/api/org/subscription error: {e}")
		return jsonify({"status": "error", "message": "Failed to retrieve subscription"}), 500


@app.route('/api/org/subscription/upgrade', methods=['POST'])
@require_https_payment
@limiter.limit("5 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def upgrade_subscription():
	data = request.get_json(silent=True) or {}
	if razorpay_client is None:
		return jsonify({"status": "error", "message": "Razorpay not configured"}), 503

	org_id = data.get('org_id') if getattr(g, 'role', None) == ROLE_SUPER_ADMIN else getattr(g, 'org_id', None)
	if not org_id:
		return jsonify({"status": "error", "message": "Organization context missing"}), 400

	new_plan_type = (data.get('new_plan_type') or '').strip()
	user_count = int(data.get('user_count') or 0)
	billing_cycle = (data.get('billing_cycle') or 'monthly').strip()
	primary_conn = None
	primary_cursor = None
	idempotency_key = (data.get('idempotency_key') or '').strip()
	if idempotency_key:
		try:
			uuid.UUID(idempotency_key)
		except ValueError:
			return jsonify({"status": "error", "message": "Invalid idempotency key format"}), 400
	else:
		idempotency_key = str(uuid.uuid4())
	if new_plan_type not in ['basic', 'si_plus', 'plus', 'pro']:
		return jsonify({"status": "error", "message": "Invalid plan type"}), 400
	
	# Validate user_count range (if provided, before deriving from current users)
	if user_count > 0:
		if user_count < 1:
			return jsonify({"status": "error", "message": "User count must be at least 1"}), 400
		if user_count > MAX_USER_COUNT:
			return jsonify({"status": "error", "message": f"User count cannot exceed {MAX_USER_COUNT}"}), 400

	# Normalize new_plan_type for plan comparisons and Razorpay plan ID lookup
	new_plan_type_normalized = normalize_plan_type(new_plan_type)

	def parse_timestamp(ts_value):
		if not ts_value:
			return None
		try:
			return datetime.fromisoformat(ts_value)
		except Exception:
			pass
		for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d'):
			try:
				return datetime.strptime(ts_value, fmt)
			except Exception:
				continue
		return None

	payment_request = execute_primary_query(
		"SELECT id, subscription_id, status, plan_type, user_count, billing_cycle, created_at FROM payment_requests WHERE request_id = ? AND org_id = ?",
		(idempotency_key, org_id),
		fetch_one=True
	)
	if payment_request:
		_, pr_subscription_id, pr_status, pr_plan_type, pr_user_count, pr_cycle, pr_created_at = payment_request
		details_payload = {
			"request_id": idempotency_key,
			"org_id": org_id,
			"existing_status": pr_status,
			"plan_type": pr_plan_type,
			"user_count": pr_user_count,
			"billing_cycle": pr_cycle
		}
		created_dt = parse_timestamp(pr_created_at)
		if pr_status == 'completed' and pr_subscription_id:
			try:
				execute_primary_query(
					"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
					(org_id, getattr(g, 'user_id', None), 'payment_request_duplicate_completed', json.dumps(details_payload))
				)
			except Exception:
				pass
			resp = jsonify({
				"status": "success",
				"message": "Subscription upgrade already processed. No additional payment required.",
				"subscription_id": pr_subscription_id,
				"request_id": idempotency_key,
				"requires_payment": False,
				"idempotent_replay": True,
				"razorpay_key_id": RAZORPAY_KEY_ID
			})
			return resp, 200
		if pr_status == 'processing':
			try:
				execute_primary_query(
					"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
					(org_id, getattr(g, 'user_id', None), 'payment_request_duplicate_processing', json.dumps(details_payload))
				)
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Payment already in progress. Please wait.", "request_id": idempotency_key}), 409
		if pr_status == 'pending' and created_dt and datetime.now() - created_dt < timedelta(minutes=5):
			try:
				execute_primary_query(
					"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
					(org_id, getattr(g, 'user_id', None), 'payment_request_duplicate_recent', json.dumps(details_payload))
				)
			except Exception:
				pass
			return jsonify({"status": "error", "message": "Recent payment request exists. Please try again shortly.", "request_id": idempotency_key}), 409

	# Prioritize Active/Trial/Authenticated subscriptions for upgrade comparison
	current = execute_primary_query(
		"""
		SELECT id, plan_type, status, razorpay_subscription_id, billing_cycle 
		FROM subscriptions 
		WHERE org_id = ? 
		ORDER BY 
			CASE 
				WHEN status IN ('active', 'trial', 'authenticated') THEN 1 
				WHEN status = 'paused' THEN 2
				WHEN status = 'past_due' THEN 3
				ELSE 4 
			END ASC,
			id DESC 
		LIMIT 1
		""", 
		(org_id,), 
		fetch_one=True
	)
	if not current:
		return jsonify({"status": "error", "message": "No active subscription to upgrade"}), 404
	old_id, old_plan, old_status, old_rz_sub, old_cycle = current
	# Normalize plan types for comparison
	old_plan_normalized = normalize_plan_type(old_plan)
	plan_order = ['basic', 'plus', 'pro']
	if old_plan_normalized in plan_order and new_plan_type_normalized in plan_order and plan_order.index(new_plan_type_normalized) <= plan_order.index(old_plan_normalized):
		return jsonify({"status": "error", "message": "Please contact support for downgrades or same plan"}), 400

	pending_subscription = execute_primary_query(
		"SELECT id, razorpay_subscription_id, plan_type, created_at FROM subscriptions WHERE org_id = ? AND status = 'created' ORDER BY id DESC LIMIT 1",
		(org_id,),
		fetch_one=True
	)
	if pending_subscription:
		_, pending_rz_sub, pending_plan, pending_created_at = pending_subscription
		pending_created_dt = parse_timestamp(pending_created_at)
		if pending_created_dt and datetime.now() - pending_created_dt < timedelta(minutes=10):
			try:
				execute_primary_query(
					"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
					(org_id, getattr(g, 'user_id', None), 'subscription_upgrade_blocked_pending_exists', json.dumps({
						"request_id": idempotency_key,
						"pending_subscription_id": pending_rz_sub,
						"pending_plan": pending_plan
					}))
				)
			except Exception:
				pass
			return jsonify({
				"status": "error",
				"message": "A subscription upgrade is already pending payment. Please complete or cancel it first.",
				"subscription_id": pending_rz_sub,
				"request_id": idempotency_key
			}), 409

	# Cancel old Razorpay subscription if present and not trial
	if old_rz_sub and old_status in ['active', 'authenticated']:
		try:
			razorpay_client.subscription.cancel(old_rz_sub, {"cancel_at_cycle_end": 0})
		except Exception as _:
			pass

	# Use normalized plan type for plan ID lookup
	plan_id = get_razorpay_plan_id(new_plan_type_normalized)
	if not plan_id:
		print(f"[UPGRADE] ERROR: Plan ID not found for {new_plan_type_normalized}")
		return jsonify({"status": "error", "message": "Plan not configured in Razorpay. Contact administrator."}), 500

	if user_count <= 0:
		# derive current active users
		user_row = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND role IN ('org_admin','org_user') AND status IN ('approved','active')", (org_id,), fetch_one=True)
		user_count = int(user_row[0]) if user_row else 1

	# Derive included_users and compute extra_users
	limits = get_plan_limits(new_plan_type_normalized) or {}
	included_users = limits.get('max_users', 0)
	extra_users = max(0, user_count - included_users)

	# Get or create Razorpay customer
	# First, try to get customer email from organization or current user
	user_email = getattr(g, 'email', None) or ''
	if not user_email:
		# Try to get from organization
		org_row = execute_primary_query("SELECT name, email FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
		if org_row:
			user_email = org_row[1] or org_row[0] or f"org_{org_id}@proton.local"
		else:
			user_email = f"org_{org_id}@proton.local"
	
	# Create or get customer
	customer_id = None
	try:
		# Try to find existing customer by email
		customers = razorpay_client.customer.all({'email': user_email, 'count': 1})
		if customers and customers.get('items') and len(customers['items']) > 0:
			customer_id = customers['items'][0]['id']
			print(f"[UPGRADE] Found existing customer: {customer_id}")
		else:
			# Create new customer
			customer_data = {
				'name': getattr(g, 'name', None) or f"Organization {org_id}",
				'email': user_email,
				'contact': getattr(g, 'contact', None) or '',
				'notes': {
					'org_id': str(org_id)
				}
			}
			customer = razorpay_client.customer.create(customer_data)
			customer_id = customer['id']
			print(f"[UPGRADE] Created new customer: {customer_id}")
	except Exception as e:
		print(f"[UPGRADE] Warning: Could not create/fetch customer: {e}")
		# Continue without customer_id - some Razorpay configurations allow this

	# Create base subscription with quantity=1
	# total_count: For yearly, set to 12. For monthly, set to 360 (30 years) - max allowed for UPI payments
	# Razorpay requires total_count to be at least 1, but UPI has a 30-year limit
	subscription_data = {
		'plan_id': plan_id,
		'customer_notify': 1,
		'quantity': 1,
		'total_count': 12 if billing_cycle == 'yearly' else 360,  # 360 months = 30 years (max for UPI)
		'notes': {
			'org_id': str(org_id),
			'plan_type': new_plan_type,
			'upgraded_from': old_plan,
			'upgraded_by': getattr(g, 'email', '')
		}
	}
	
	# Add customer_id if available
	if customer_id:
		subscription_data['customer_id'] = customer_id
	
	print(f"[UPGRADE] Creating subscription with data: {subscription_data}")
	print(f"[UPGRADE] Plan ID: {plan_id}, Org ID: {org_id}, New Plan: {new_plan_type}, User Count: {user_count}, Customer ID: {customer_id}")

	def run_primary_transaction(statements):
		nonlocal primary_conn, primary_cursor
		if primary_conn is None:
			primary_conn = get_primary_db_connection()
			primary_cursor = primary_conn.cursor()
		try:
			if DB_TYPE.lower() == 'mysql':
				primary_cursor.execute("START TRANSACTION")
			else:
				primary_cursor.execute("BEGIN IMMEDIATE")
			for sql, params in statements:
				primary_cursor.execute(convert_query_placeholders(sql, DB_TYPE), params)
			primary_conn.commit()
		except Exception:
			if primary_conn:
				primary_conn.rollback()
			raise

	def close_primary_conn():
		nonlocal primary_conn
		if primary_conn:
			try:
				primary_conn.close()
			except Exception:
				pass
			primary_conn = None

	run_primary_transaction([
		(
			"INSERT INTO payment_requests (org_id, request_id, plan_type, user_count, billing_cycle, status) VALUES (?, ?, ?, ?, ?, 'pending')",
			(org_id, idempotency_key, new_plan_type, user_count, billing_cycle)
		)
	])
	try:
		execute_primary_query(
			"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
			(org_id, getattr(g, 'user_id', None), 'payment_request_created', json.dumps({
				"request_id": idempotency_key,
				"plan_type": new_plan_type,
				"user_count": user_count,
				"billing_cycle": billing_cycle
			}))
		)
	except Exception:
		pass

	run_primary_transaction([
		(
			"UPDATE payment_requests SET status = 'processing', updated_at = CURRENT_TIMESTAMP WHERE request_id = ?",
			(idempotency_key,)
		)
	])

	try:
		rz_sub = razorpay_client.subscription.create(subscription_data)
		new_sub_id = rz_sub.get('id')
		
		# Create addons for extra users if needed
		if extra_users > 0:
			try:
				addon_data = {
					'item': {
						'name': 'Extra Users',
						'amount': 50000,
						'currency': 'INR'
					},
					'quantity': extra_users
				}
				razorpay_client.subscription.createAddon(new_sub_id, addon_data)
			except Exception as e:
				print(f"Error creating addon for subscription {new_sub_id}: {e}")
				# Continue even if addon creation fails
		
		# DB update atomically in Primary DB
		start_date = datetime.now().strftime('%Y-%m-%d')
		run_primary_transaction([
			# REMOVED: Premature cancellation of old plan. Old plan remains active until new one is activated via webhook.
			(
				"INSERT INTO subscriptions (org_id, plan_type, razorpay_subscription_id, status, start_date, billing_cycle) VALUES (?, ?, ?, 'created', ?, ?)",
				(org_id, new_plan_type, new_sub_id, start_date, billing_cycle)
			),
			(
				"UPDATE payment_requests SET subscription_id = ?, status = 'completed', updated_at = CURRENT_TIMESTAMP WHERE request_id = ?",
				(new_sub_id, idempotency_key)
			)
		])
		try:
			execute_primary_query(
				"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
				(org_id, getattr(g, 'user_id', None), 'payment_request_completed', json.dumps({
					"request_id": idempotency_key,
					"subscription_id": new_sub_id,
					"plan_type": new_plan_type,
					"user_count": user_count,
					"billing_cycle": billing_cycle
				}))
			)
		except Exception:
			pass
		try:
			details = json.dumps({"org_id": org_id, "old_plan": old_plan, "new_plan": new_plan_type, "razorpay_subscription_id": new_sub_id, "user_count": user_count, "included_users": included_users, "extra_users": extra_users})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_upgraded', details))
		except Exception:
			pass
		try:
			ORG_USAGE_CACHE.pop(org_id, None)
		except Exception:
			pass
		
		# Calculate amount using calculate_subscription_amount
		amount = calculate_subscription_amount(new_plan_type, user_count, billing_cycle)
		
		response = jsonify({
			"status": "success",
			"message": "Subscription upgraded successfully. Please complete payment.",
			"subscription_id": new_sub_id,
			"razorpay_key_id": RAZORPAY_KEY_ID,
			"amount": amount,
			"currency": "INR",
			"requires_payment": True,
			"request_id": idempotency_key
		})
		close_primary_conn()
		return response, 201
	except razorpay.errors.BadRequestError as e:
		try:
			run_primary_transaction([
				(
					"UPDATE payment_requests SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE request_id = ?",
					(idempotency_key,)
				)
			])
			execute_primary_query(
				"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
				(org_id, getattr(g, 'user_id', None), 'payment_request_failed', json.dumps({
					"request_id": idempotency_key,
					"reason": "razorpay_bad_request",
					"error": str(e)
				}))
			)
		except Exception:
			pass
		error_msg = str(e)
		print(f"[UPGRADE] Razorpay BadRequestError: {error_msg}")
		if hasattr(e, 'error'):
			print(f"[UPGRADE] Error details: {e.error}")
		# Provide more specific error message
		if "plan" in error_msg.lower() or "plan_id" in error_msg.lower():
			error_message = f"Invalid plan configuration: {error_msg}. Please contact support."
		elif "customer" in error_msg.lower():
			error_message = f"Customer information issue: {error_msg}. Please contact support."
		else:
			error_message = f"Invalid request to Razorpay: {error_msg}"
		close_primary_conn()
		return jsonify({"status": "error", "message": error_message, "error": error_msg, "details": str(e.error) if hasattr(e, 'error') else None}), 400
	except razorpay.errors.ServerError as e:
		try:
			run_primary_transaction([
				(
					"UPDATE payment_requests SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE request_id = ?",
					(idempotency_key,)
				)
			])
			execute_primary_query(
				"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
				(org_id, getattr(g, 'user_id', None), 'payment_request_failed', json.dumps({
					"request_id": idempotency_key,
					"reason": "razorpay_server_error",
					"error": str(e)
				}))
			)
		except Exception:
			pass
		print(f"[UPGRADE] Razorpay ServerError: {e}")
		close_primary_conn()
		return jsonify({"status": "error", "message": "Razorpay server error", "error": str(e)}), 502
	except Exception as e:
		try:
			run_primary_transaction([
				(
					"UPDATE payment_requests SET status = 'failed', updated_at = CURRENT_TIMESTAMP WHERE request_id = ?",
					(idempotency_key,)
				)
			])
			execute_primary_query(
				"INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
				(org_id, getattr(g, 'user_id', None), 'payment_request_failed', json.dumps({
					"request_id": idempotency_key,
					"reason": "unexpected_error",
					"error": str(e)
				}))
			)
		except Exception:
			pass
		print(f"[UPGRADE] Exception: {type(e).__name__}: {e}")
		import traceback
		traceback.print_exc()
		close_primary_conn()
		return jsonify({"status": "error", "message": "Upgrade failed", "error": str(e)}), 500


@app.route('/api/org/subscription/cancel', methods=['POST'])
@require_https_payment
@limiter.limit("10 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def cancel_subscription():
	data = request.get_json(silent=True) or {}
	cancel_at_cycle_end = bool(data.get('cancel_at_cycle_end', True))
	reason = (data.get('reason') or '').strip()
	org_id = data.get('org_id') if getattr(g, 'role', None) == ROLE_SUPER_ADMIN else getattr(g, 'org_id', None)
	if not org_id:
		return jsonify({"status": "error", "message": "Organization context missing"}), 400

	row = execute_primary_query("SELECT id, plan_type, status, razorpay_subscription_id FROM subscriptions WHERE org_id = ? AND status IN ('active','authenticated','trial') ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
	if not row:
		return jsonify({"status": "error", "message": "No active subscription to cancel"}), 404
	sub_id, plan_type, status, rz_sub_id = row

	if status in ['active','authenticated'] and rz_sub_id and razorpay_client is not None:
		try:
			payload = {'cancel_at_cycle_end': 1 if cancel_at_cycle_end else 0}
			razorpay_client.subscription.cancel(rz_sub_id, payload, timeout=10)
		except Exception as _:
			pass

	if cancel_at_cycle_end:
		new_status = 'pending_cancellation'
		is_valid, error_msg = validate_subscription_transition(org_id, status, new_status, user_id=getattr(g, 'user_id', None), context={"subscription_id": rz_sub_id, "action": "cancel_at_cycle_end"})
		if not is_valid:
			return jsonify({"status": "error", "message": error_msg}), 400
		execute_primary_query("UPDATE subscriptions SET status = 'pending_cancellation' WHERE id = ?", (sub_id,))
		message = "Subscription will be cancelled at the end of current billing cycle"
		access_until = None
	else:
		new_status = 'cancelled'
		is_valid, error_msg = validate_subscription_transition(org_id, status, new_status, user_id=getattr(g, 'user_id', None), context={"subscription_id": rz_sub_id, "action": "cancel_immediate"})
		if not is_valid:
			return jsonify({"status": "error", "message": error_msg}), 400
		end_dt = datetime.now().strftime('%Y-%m-%d')
		execute_primary_query("UPDATE subscriptions SET status = 'cancelled', end_date = ? WHERE id = ?", (end_dt, sub_id))
		message = "Subscription cancelled immediately. Access will be restricted."
		access_until = end_dt

	try:
		details = json.dumps({"plan_type": plan_type, "razorpay_subscription_id": rz_sub_id, "cancel_at_cycle_end": cancel_at_cycle_end, "reason": reason})
		execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_cancelled', details))
	except Exception:
		pass
	try:
		ORG_USAGE_CACHE.pop(org_id, None)
	except Exception:
		pass
	return jsonify({"status": "success", "message": message, "cancelled_at": datetime.now().strftime('%Y-%m-%d'), "access_until": access_until})


@app.route('/api/razorpay/subscription/abandon', methods=['POST'])
@require_https_payment
@limiter.limit("10 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def abandon_subscription():
    """
    Handle abandoned subscription attempts (e.g. user closed modal).
    """
    data = request.get_json(silent=True) or {}
    subscription_id = data.get('subscription_id')
    
    if not subscription_id:
        return jsonify({"status": "error", "message": "Subscription ID required"}), 400
        
    org_id = getattr(g, 'org_id', None)
    
    try:
        # Define transaction helper locally
        primary_conn = None
        primary_cursor = None

        def close_primary_conn():
            nonlocal primary_conn
            if primary_conn:
                try:
                    primary_conn.close()
                except Exception:
                    pass
                primary_conn = None

        def run_primary_transaction(statements):
            nonlocal primary_conn, primary_cursor
            if primary_conn is None:
                primary_conn = get_primary_db_connection()
                primary_cursor = primary_conn.cursor()
            try:
                if DB_TYPE.lower() == 'mysql':
                    primary_cursor.execute("START TRANSACTION")
                else:
                    primary_cursor.execute("BEGIN IMMEDIATE")
                for sql, params in statements:
                    primary_cursor.execute(convert_query_placeholders(sql, DB_TYPE), params)
                primary_conn.commit()
            except Exception:
                if primary_conn:
                    primary_conn.rollback()
                raise

        # Find the subscription
        row = execute_primary_query(
            "SELECT id, status, plan_type FROM subscriptions WHERE razorpay_subscription_id = ? AND org_id = ?", 
            (subscription_id, org_id), 
            fetch_one=True
        )
        
        if not row:
            close_primary_conn()
            return jsonify({"status": "error", "message": "Subscription not found"}), 404
            
        sub_id, status, plan_type = row
        
        # Only abandon if it's in 'created' state or 'authenticated' (but not active)
        if status in ['created', 'pending']:
            # Validate transition to 'abandoned'
            is_valid, error_msg = validate_subscription_transition(org_id, status, 'abandoned', user_id=getattr(g, 'user_id', None), context={"subscription_id": subscription_id, "action": "abandon"})
            if not is_valid:
                return jsonify({"status": "error", "message": error_msg}), 400
            try:
                run_primary_transaction([
                    (
                        "UPDATE subscriptions SET status = 'abandoned' WHERE id = ?",
                        (sub_id,)
                    ),
                    (
                        "UPDATE payment_requests SET status = 'abandoned', updated_at = CURRENT_TIMESTAMP WHERE subscription_id = ?",
                        (subscription_id,)
                    )
                ])
                
                # Log it
                try:
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (org_id, getattr(g, 'user_id', None), 'payment_abandoned', json.dumps({
                            "subscription_id": subscription_id,
                            "plan_type": plan_type
                        }))
                    )
                except Exception:
                    pass
            finally:
                close_primary_conn()
                
            return jsonify({"status": "success", "message": "Subscription abandoned"})
            
        elif status == 'active':
             close_primary_conn()
             return jsonify({"status": "error", "message": "Cannot abandon active subscription"}), 400
        else:
             # Already in some other state, just ignore
             close_primary_conn()
             return jsonify({"status": "success", "message": "Subscription already in terminal state"})

    except Exception as e:
        print(f"[ABANDON] Error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500
@app.route('/api/org/subscription/pause', methods=['POST'])
@require_https_payment
@limiter.limit("10 per minute", key_func=get_user_id_for_rate_limit)
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def pause_subscription():
	if razorpay_client is None:
		return jsonify({"status": "error", "message": "Razorpay not configured"}), 503
	data = request.get_json(silent=True) or {}
	reason = (data.get('reason') or '').strip()
	pause_duration = int(data.get('pause_duration') or 1)
	org_id = data.get('org_id') if getattr(g, 'role', None) == ROLE_SUPER_ADMIN else getattr(g, 'org_id', None)
	if not org_id:
		return jsonify({"status": "error", "message": "Organization context missing"}), 400

	row = execute_primary_query("SELECT id, status, razorpay_subscription_id, plan_type, billing_cycle FROM subscriptions WHERE org_id = ? AND status = 'active' ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
	if not row:
		return jsonify({"status": "error", "message": "No active subscription to pause"}), 404
	sub_id, status, rz_sub_id, plan_type, billing_cycle = row
	if not rz_sub_id:
		return jsonify({"status": "error", "message": "Trial subscriptions cannot be paused"}), 400

	try:
		razorpay_client.subscription.pause(rz_sub_id, {'pause_at': 'now'})
		# Validate transition to 'paused'
		is_valid, error_msg = validate_subscription_transition(org_id, status, 'paused', user_id=getattr(g, 'user_id', None), context={"subscription_id": rz_sub_id, "action": "pause"})
		if not is_valid:
			return jsonify({"status": "error", "message": error_msg}), 400
		execute_primary_query("UPDATE subscriptions SET status = 'paused' WHERE id = ?", (sub_id,))
		# Compute resume date locally based on billing_cycle and pause_duration
		resume_date = None
		try:
			base = datetime.now()
			if (billing_cycle or 'monthly') == 'yearly':
				resume_year = base.year + pause_duration
				resume_date = base.replace(year=resume_year).strftime('%Y-%m-%d')
			else:
				# monthly: approximate by adding 30 days per cycle
				resume = base + timedelta(days=30 * pause_duration)
				resume_date = resume.strftime('%Y-%m-%d')
		except Exception:
			resume_date = None
		try:
			details = json.dumps({"plan_type": plan_type, "razorpay_subscription_id": rz_sub_id, "reason": reason, "pause_duration": pause_duration, "resume_date": resume_date})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'subscription_paused', details))
		except Exception:
			pass
		try:
			ORG_USAGE_CACHE.pop(org_id, None)
		except Exception:
			pass
		return jsonify({"status": "success", "message": "Subscription paused successfully.", "paused_at": datetime.now().strftime('%Y-%m-%d'), "resume_date": resume_date})
	except Exception as e:
		return jsonify({"status": "error", "message": "Failed to pause subscription", "error": str(e)}), 500


@app.route('/api/org/billing/history', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def get_billing_history():
	try:
		org_id = getattr(g, 'org_id', None)
		if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
			q_org_id = request.args.get('org_id', type=int)
			if q_org_id:
				org_id = q_org_id
		if not org_id:
			return jsonify({"status": "error", "message": "Organization context missing"}), 400

		page = request.args.get('page', default=1, type=int)
		limit = request.args.get('limit', default=50, type=int)
		status = request.args.get('status', default=None, type=str)
		start_date = request.args.get('start_date', default=None, type=str)
		end_date = request.args.get('end_date', default=None, type=str)
		if page < 1 or limit < 1 or limit > 100:
			return jsonify({"status": "error", "message": "Invalid pagination parameters"}), 400

		conditions = ["org_id = ?"]
		params = [org_id]
		if status:
			conditions.append("status = ?")
			params.append(status)
		if start_date:
			conditions.append("date(created_at) >= ?")
			params.append(start_date)
		if end_date:
			conditions.append("date(created_at) <= ?")
			params.append(end_date)
		where_clause = " AND ".join(conditions)

		total_row = execute_primary_query(f"SELECT COUNT(*) FROM billing_transactions WHERE {where_clause}", tuple(params), fetch_one=True)
		total_count = int(total_row[0]) if total_row else 0
		offset = (page - 1) * limit
		rows = execute_primary_query(f"SELECT id, org_id, razorpay_payment_id, amount, status, created_at FROM billing_transactions WHERE {where_clause} ORDER BY created_at DESC LIMIT ? OFFSET ?", tuple(params + [limit, offset]), fetch_all=True)

		transactions = []
		if rows:
			for r in rows:
				columns = ['id', 'org_id', 'razorpay_payment_id', 'amount', 'status', 'created_at']
				trx = dict(zip(columns, r))
				trx['currency'] = 'INR'
				trx['created_at'] = trx.get('created_at')
				trx['invoice_available'] = (trx.get('status') == 'success')
				trx['invoice_url'] = f"/api/org/billing/invoice/{trx['id']}" if trx['invoice_available'] else None
				# Attach latest known plan type
				plan_row = execute_primary_query("SELECT plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
				trx['subscription_plan'] = plan_row[0] if plan_row else None
				transactions.append(trx)

		# Summary
		sum_paid_row = execute_primary_query(f"SELECT IFNULL(SUM(amount),0), MAX(created_at) FROM billing_transactions WHERE {where_clause} AND status = 'success'", tuple(params), fetch_one=True)
		total_paid = float(sum_paid_row[0]) if sum_paid_row else 0.0
		last_payment_date = (sum_paid_row[1] if sum_paid_row else None)
		failed_count_row = execute_primary_query(f"SELECT COUNT(*) FROM billing_transactions WHERE {where_clause} AND status = 'failed'", tuple(params), fetch_one=True)
		total_failed = int(failed_count_row[0]) if failed_count_row else 0

		total_pages = math.ceil(total_count / limit) if limit else 1
		resp = {
			"status": "success",
			"transactions": transactions,
			"pagination": {
				"page": page,
				"limit": limit,
				"total_count": total_count,
				"total_pages": total_pages,
				"has_next": page < total_pages,
				"has_prev": page > 1
			},
			"summary": {
				"total_paid": total_paid,
				"total_failed": total_failed,
				"last_payment_date": last_payment_date
			}
		}
		try:
			details = json.dumps({"org_id": org_id, "page": page, "limit": limit})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'billing_history_viewed', details))
		except Exception:
			pass
		return jsonify(resp)
	except Exception as e:
		print(f"/api/org/billing/history error: {e}")
		return jsonify({"status": "error", "message": "Failed to retrieve billing history"}), 500


@app.route('/api/org/billing/invoice/<int:transaction_id>', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def download_invoice(transaction_id):
	try:
		trx_row = execute_primary_query("SELECT id, org_id, razorpay_payment_id, amount, status, created_at FROM billing_transactions WHERE id = ?", (transaction_id,), fetch_one=True)
		if not trx_row:
			return jsonify({"status": "error", "message": "Transaction not found"}), 404
		
		# Convert tuple to dictionary
		trx = {
			'id': trx_row[0],
			'org_id': trx_row[1],
			'razorpay_payment_id': trx_row[2],
			'amount': trx_row[3],
			'status': trx_row[4],
			'created_at': trx_row[5]
		}
		
		org_id = trx['org_id']
		if getattr(g, 'role', None) != ROLE_SUPER_ADMIN and org_id != getattr(g, 'org_id', None):
			return jsonify({"status": "error", "message": "Forbidden"}), 403
		if trx['status'] != 'success':
			return jsonify({"status": "error", "message": "Invoice not available for failed/pending transactions"}), 400

		org = execute_primary_query("SELECT name, domain FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
		org_name, org_domain = (org[0], org[1]) if org else (f"Org {org_id}", '')
		admin_row = execute_primary_query("SELECT email FROM users WHERE org_id = ? AND role = 'org_admin' ORDER BY id LIMIT 1", (org_id,), fetch_one=True)
		admin_email = admin_row[0] if admin_row else ''

		invoice_number = generate_invoice_number(org_id, transaction_id)
		invoice_date = trx.get('created_at') or datetime.now().strftime('%Y-%m-%d')
		payment_date = invoice_date
		plan_row = execute_primary_query("SELECT plan_type, billing_cycle, razorpay_subscription_id FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
		plan_type = plan_row[0] if plan_row else 'basic'
		billing_cycle = plan_row[1] if plan_row and len(plan_row) > 1 else 'monthly'
		plan_display = get_subscription_display_name(plan_type)
		plan_type_normalized = normalize_plan_type(plan_type)
		
		# Get current user count for pricing breakdown
		uc = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND role IN ('org_admin','org_user') AND status IN ('approved','active')", (org_id,), fetch_one=True)
		user_count = int(uc[0]) if uc else 1
		
		# Calculate pricing breakdown using calculate_subscription_amount and get_plan_limits
		limits = get_plan_limits(plan_type_normalized) or {}
		included_users = limits.get('max_users', 0)
		extra_users = max(0, user_count - included_users)
		
		# For Pro plan, base covers up to 100 users
		if plan_type_normalized == 'pro' and user_count > 100:
			included_users = 100
			extra_users = user_count - 100
		
		base_price = RAZORPAY_PLANS.get(plan_type_normalized, {}).get('amount', 0) / 100.0  # Convert paise to rupees
		extra_user_rate = 500.0  # ₹500 per extra user
		extra_user_cost = extra_users * extra_user_rate
		
		subtotal = round(float(trx['amount'] or 0), 2)
		# Apply tax only if enabled and configured; otherwise treat stored amount as final gross total
		tax_rate_val = float(TAX_RATE) if (TAX_ENABLED and TAX_RATE is not None) else 0.0
		gst_amount = round(subtotal * tax_rate_val, 2) if tax_rate_val > 0 else 0.0
		total_amount = round(subtotal + gst_amount, 2)

		buffer = BytesIO()
		doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
		elements = []
		styles = getSampleStyleSheet()
		# Custom styles
		title_style = ParagraphStyle('CustomTitle', parent=styles['Heading1'], fontSize=24, textColor=colors.HexColor('#2c3e50'), alignment=TA_RIGHT, spaceAfter=20)
		header_style = ParagraphStyle('HeaderStyle', parent=styles['Normal'], fontSize=10, textColor=colors.HexColor('#7f8c8d'), alignment=TA_RIGHT)
		
		# Logo and Header Table
		logo_path = os.path.join(app.root_path, 'static', 'logo.png')
		header_data = []
		if os.path.exists(logo_path):
			img = Image(logo_path, width=1.5*inch, height=0.5*inch)
			img.hAlign = 'LEFT'
			header_data = [[img, Paragraph("INVOICE", title_style)]]
		else:
			header_data = [[Paragraph("PROTON", styles['Heading1']), Paragraph("INVOICE", title_style)]]
		
		header_table = Table(header_data, colWidths=[3*inch, 3*inch])
		header_table.setStyle(TableStyle([
			('VALIGN', (0,0), (-1,-1), 'TOP'),
			('ALIGN', (0,0), (0,0), 'LEFT'),
			('ALIGN', (1,0), (1,0), 'RIGHT'),
		]))
		elements.append(header_table)
		elements.append(Spacer(1, 10))

		# Invoice Details (Right Aligned under Title)
		details_data = [
			[Paragraph(f"<b>Invoice #:</b> {invoice_number}", header_style)],
			[Paragraph(f"<b>Date:</b> {str(invoice_date)}", header_style)],
			[Paragraph(f"<b>Transaction ID:</b> {trx['razorpay_payment_id']}", header_style)]
		]
		details_table = Table(details_data, colWidths=[6*inch])
		details_table.setStyle(TableStyle([('ALIGN', (0,0), (-1,-1), 'RIGHT')]))
		elements.append(details_table)
		elements.append(Spacer(1, 30))

		# Billing Details
		billing_data = [
			[Paragraph("<b>Bill To:</b>", styles['Normal']), Paragraph("<b>Bill From:</b>", styles['Normal'])],
			[Paragraph(f"{org_name}<br/>{org_domain or ''}<br/>{admin_email}", styles['Normal']), 
			 Paragraph(f"{COMPANY_NAME}<br/>{COMPANY_FROM_NAME}<br/>{COMPANY_SUPPORT_EMAIL}", styles['Normal'])]
		]
		billing_table = Table(billing_data, colWidths=[3*inch, 3*inch])
		billing_table.setStyle(TableStyle([
			('VALIGN', (0,0), (-1,-1), 'TOP'),
			('LINEBELOW', (0,0), (-1,0), 1, colors.HexColor('#ecf0f1')),
			('PADDING', (0,0), (-1,-1), 6),
		]))
		elements.append(billing_table)
		elements.append(Spacer(1, 30))

		# Items Table
		data = [['Description', 'Quantity', 'Unit Price', 'Amount']]
		# Base Plan Item
		data.append([
			f"{plan_display} Subscription ({billing_cycle.title()})",
			"1",
			f"Rs. {base_price:,.2f}",
			f"Rs. {base_price:,.2f}"
		])
		
		# Extra Users Item
		if extra_users > 0:
			data.append([
				f"Additional Users ({extra_users} x Rs. {extra_user_rate})",
				str(extra_users),
				f"Rs. {extra_user_rate:,.2f}",
				f"Rs. {extra_user_cost:,.2f}"
			])
			
		# Total Row Calculation
		data.append(['', '', 'Subtotal:', f"Rs. {subtotal:,.2f}"])
		if gst_amount > 0:
			data.append(['', '', f"GST ({int(tax_rate_val*100)}%):", f"Rs. {gst_amount:,.2f}"])
		data.append(['', '', 'Total:', f"Rs. {total_amount:,.2f}"])

		t = Table(data, colWidths=[3*inch, 1*inch, 1*inch, 1.5*inch])
		t.setStyle(TableStyle([
			('BACKGROUND', (0,0), (-1,0), colors.HexColor('#f8f9fa')),
			('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#2c3e50')),
			('ALIGN', (0,0), (-1,-1), 'LEFT'),
			('ALIGN', (1,0), (-1,-1), 'CENTER'),   # Qty centered
			('ALIGN', (2,0), (-1,-1), 'RIGHT'),  # Price right
			('ALIGN', (3,0), (-1,-1), 'RIGHT'),  # Amount right
			('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
			('FONTSIZE', (0,0), (-1,-1), 10),
			('BOTTOMPADDING', (0,0), (-1,-1), 8),
			('TOPPADDING', (0,0), (-1,-1), 8),
			('GRID', (0,0), (-1,-2), 0.5, colors.HexColor('#ecf0f1')), # Grid for items
			('LINEABOVE', (0,-1), (-1,-1), 1, colors.HexColor('#bdc3c7')), # Total line
			('FONTNAME', (0,-1), (-1,-1), 'Helvetica-Bold'), # Total bold
			('TEXTCOLOR', (2,-1), (-1,-1), colors.HexColor('#2c3e50')),
			('BACKGROUND', (0,-1), (-1,-1), colors.HexColor('#f8f9fa')), # Total bg
		]))
		elements.append(t)
		
		# Footer
		elements.append(Spacer(1, 40))
		elements.append(Paragraph("Thank you for your business!", ParagraphStyle('Footer', parent=styles['Normal'], alignment=TA_CENTER, textColor=colors.HexColor('#7f8c8d'))))
		elements.append(Spacer(1, 24))

		elements.append(Paragraph("Payment Information", styles['Heading2']))
		payment_data = [
			['Payment Method:', 'Razorpay'],
			['Payment Status:', 'Paid'],
			['Payment Date:', str(payment_date)]
		]
		payment_table = Table(payment_data, colWidths=[2*inch, 4*inch])
		elements.append(payment_table)
		elements.append(Spacer(1, 24))

		# Bill From details and compliance fields
		if TAX_ENABLED and COMPANY_GSTIN:
			elements.append(Paragraph(f"GSTIN: {COMPANY_GSTIN}", styles['Normal']))
		if COMPANY_ADDRESS:
			elements.append(Paragraph(COMPANY_ADDRESS, styles['Normal']))

		footer_text = f"Thank you for your business! For support, contact {COMPANY_SUPPORT_EMAIL}"
		elements.append(Paragraph(footer_text, styles['Normal']))

		doc.build(elements)
		pdf_data = buffer.getvalue()
		buffer.close()

		try:
			details = json.dumps({"transaction_id": transaction_id, "amount": trx['amount'], "invoice_number": invoice_number})
			execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (org_id, getattr(g, 'user_id', None), 'invoice_downloaded', details))
		except Exception:
			pass

		from flask import make_response
		response = make_response(pdf_data)
		response.headers['Content-Type'] = 'application/pdf'
		response.headers['Content-Disposition'] = f'attachment; filename="invoice_{invoice_number}.pdf"'
		return response
	except Exception as e:
		print(f"/api/org/billing/invoice error: {e}")
		return jsonify({"status": "error", "message": "Failed to generate invoice"}), 500


# --- User Management for Organization Admins ---

@app.route('/api/org/users', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def get_org_users():
    """List all users within the organization.
    
    Authorization:
        - SuperAdmin: Can view all users across all organizations
        - Org Admin: Can view users in their organization only
        - Org User: Access denied (403)
    
    Query Parameters:
        role (optional): Filter by role (org_admin, org_user)
        status (optional): Filter by status (approved, pending, suspended)
    
    Returns:
        JSON response with list of users (excluding passwords)
    
    Raises:
        403 Forbidden: If user lacks required role
        500 Internal Server Error: If database query fails
    """
    try:
        # Check user role from g.role
        if g.role == ROLE_SUPER_ADMIN:
            # SuperAdmin can view all users across all organizations
            users = execute_primary_query(
                "SELECT id, email, role, org_id, status, created_at, is_email_verified FROM users ORDER BY created_at DESC",
                fetch_all=True
            )
        elif g.role == ROLE_ORG_ADMIN:
            # Org Admin can only view users in their organization
            users = execute_primary_query(
                "SELECT id, email, role, org_id, status, created_at, is_email_verified FROM users WHERE org_id = ? ORDER BY created_at DESC",
                (g.org_id,),
                fetch_all=True
            )
        else:
            return jsonify({"error": "Access denied"}), 403
        
        # Convert results to list of dictionaries
        columns = ['id', 'email', 'role', 'org_id', 'status', 'created_at', 'is_email_verified']
        user_list = [dict(zip(columns, user)) for user in users] if users else []
        
        return jsonify({"status": "success", "users": user_list})
        
    except MySQLError as e:
        print(f"Database error in get_org_users: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve users"}), 500


# --- Org Usage Endpoint ---
@app.route('/api/org/usage', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_org_usage():
    try:
        # Determine org context
        org_id = getattr(g, 'org_id', None)
        plan_type = getattr(g, 'plan', None)
        if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
            # Allow SuperAdmin to override org_id via query param
            q_org_id = request.args.get('org_id', type=int)
            if q_org_id:
                org_id = q_org_id

        if not org_id:
            return jsonify({'status': 'error', 'message': 'Organization context missing'}), 400

        # Basic 5-minute cache by org_id
        now = datetime.now()
        cached = ORG_USAGE_CACHE.get(org_id)
        if cached and (now - cached['ts']).total_seconds() < 300:
            return jsonify({'status': 'success', **cached['data']}), 200

        data = get_org_usage_stats(org_id, plan_type)

        # Optionally enrich with files_by_project for admins
        try:
            if getattr(g, 'role', None) in (ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN):
                # Use execute_tenant_query instead of execute_query since projects table is in tenant DB
                projects = execute_tenant_query("SELECT name FROM projects ORDER BY name", fetch_all=True)
                files_by_project = {}
                if projects:
                    for row in projects:
                        pname = row[0]
                        files_by_project[pname] = get_project_file_count(pname, org_id)
                data['files_by_project'] = files_by_project
        except Exception as e:
            # Silently fail - files_by_project is optional enrichment
            print(f"[ORG-USAGE] Optional files_by_project enrichment failed: {e}")
            pass

        # Simple subscription echo
        data['subscription'] = {
            'plan': plan_type
        }

        # Cache result
        ORG_USAGE_CACHE[org_id] = {'ts': now, 'data': data}

        return jsonify({'status': 'success', **data}), 200
    except PermissionError:
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    except Exception as e:
        print(f"/api/org/usage error: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to compute usage'}), 500

@app.route('/api/org/tour-seen', methods=['POST'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def mark_tour_seen():
    try:
        data = request.get_json()
        org_id = data.get('orgId') if data else None

        if not org_id:
            return jsonify({'status': 'error', 'message': 'Organization ID is required'}), 400

        try:
            org_id = int(org_id)
        except (ValueError, TypeError):
            return jsonify({'status': 'error', 'message': 'Invalid organization ID'}), 400

        # For non-SuperAdmin users, verify org_id matches their org
        user_role = getattr(g, 'role', None)
        user_org_id = getattr(g, 'org_id', None)
        if user_role != ROLE_SUPER_ADMIN:
            if org_id != user_org_id:
                return jsonify({'status': 'error', 'message': 'Access denied'}), 403

        # Validate that the organization exists
        org_exists = execute_primary_query(
            "SELECT id FROM organizations WHERE id = ?",
            (org_id,),
            fetch_one=True
        )
        if not org_exists:
            return jsonify({'status': 'error', 'message': 'Organization not found'}), 404

        # Update tour_seen flag
        result = execute_primary_query(
            "UPDATE organizations SET tour_seen = 1 WHERE id = ?",
            (org_id,),
            commit=True
        )

        if result == 0:
            return jsonify({'status': 'error', 'message': 'Organization not found'}), 404

        # Log the action in audit_logs
        try:
            user_id = getattr(g, 'user_id', None)
            user_email = getattr(g, 'email', None)
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, user_id, 'tour_completed', json.dumps({
                    'user_email': user_email,
                    'timestamp': datetime.now().isoformat()
                })),
                commit=True
            )
        except Exception as audit_error:
            # Best effort audit logging - don't fail the request if audit fails
            print(f"Warning: Failed to log tour completion in audit_logs: {audit_error}")

        return jsonify({'status': 'success', 'message': 'Tour marked as seen'}), 200
    except PermissionError:
        return jsonify({'status': 'error', 'message': 'Access denied'}), 403
    except MySQLError as e:
        print(f"/api/org/tour-seen database error: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to update tour status'}), 500
    except Exception as e:
        print(f"/api/org/tour-seen error: {e}")
        return jsonify({'status': 'error', 'message': 'Failed to update tour status'}), 500

@app.route('/api/org/tour-seen', methods=['GET'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_tour_seen():
    try:
        # Extract org_id from tenant context (populated by tenant_required decorator)
        org_id = getattr(g, 'org_id', None)
        
        if not org_id:
            return jsonify({'error': 'Organization context missing'}), 400
        
        # Query Primary DB for tour_seen status
        row = execute_primary_query(
            "SELECT tour_seen FROM organizations WHERE id = ?",
            (org_id,),
            fetch_one=True
        )
        
        tour_seen = bool(row[0]) if row else False
        
        return jsonify({'tour_seen': tour_seen}), 200
    except Exception as e:
        print(f"/api/org/tour-seen GET error: {e}")
        return jsonify({'error': 'Failed to fetch tour status'}), 500

@app.route('/api/org/users', methods=['POST'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
@check_plan_limit(RESOURCE_TYPE_ADMIN)
def create_org_user():
    """Create a new user within the organization.
    
    Authorization:
        - SuperAdmin: Can create user in any organization (requires org_id in request)
        - Org Admin: Can create user in their organization only
        - Org User: Access denied (403)
    
    Request Body:
        email (required): User email address
        password (required): User password (will be hashed)
        role (required): User role - must be 'org_admin' or 'org_user'
        status (optional): User status - defaults to 'approved'
        org_id (required for SuperAdmin): Organization ID
    
    Returns:
        JSON response with created user details (excluding password)
    
    Raises:
        400 Bad Request: If validation fails
        403 Forbidden: If user lacks required role or tries to create in different org
        409 Conflict: If email already exists
        500 Internal Server Error: If database operation fails
    """
    try:
        data = request.get_json()
        email = data.get('email', '').strip()
        password = data.get('password', '')
        role = data.get('role', '').strip()
        status = data.get('status', USER_STATUS_APPROVED).strip()
        
        # Validation
        if not email or not password or not role:
            return jsonify({"status": "error", "message": "Email, password, and role are required"}), 400
        
        # Validate email format
        if not validate_email_format(email):
            return jsonify({"status": "error", "message": "Invalid email format"}), 400
        
        # Validate password strength
        is_valid, error_msg = validate_password_strength(password)
        if not is_valid:
            return jsonify({"status": "error", "message": error_msg}), 400
        
        # Validate role
        if role not in ORG_ADMIN_CREATABLE_ROLES:
            return jsonify({"status": "error", "message": "Role must be 'org_admin' or 'org_user'"}), 400
        
        # Check email uniqueness
        existing_user = execute_primary_query(
            "SELECT COUNT(*) FROM users WHERE email = ?",
            (email,),
            fetch_one=True
        )
        if existing_user and existing_user[0] > 0:
            return jsonify({"status": "error", "message": "Email already exists"}), 409
        
        # Determine target org_id
        if g.role == ROLE_SUPER_ADMIN:
            org_id = data.get('org_id')
            if not org_id:
                return jsonify({"status": "error", "message": "org_id is required for SuperAdmin"}), 400
        else:  # Org Admin
            org_id = g.org_id  # Use current user's org_id
        
        # Validate org_admin count limit (before creating user)
        if role == ROLE_ORG_ADMIN and g.role != ROLE_SUPER_ADMIN:
            limits = get_plan_limits(getattr(g, 'plan', None)) or {}
            max_org_admins = limits.get('max_org_admins', MAX_ORG_ADMINS)
            current_org_admin_count = get_current_org_admin_count(org_id)
            if current_org_admin_count >= max_org_admins:
                return jsonify({"status": "error", "message": f"Maximum {max_org_admins} org admins allowed. Please upgrade to add more admins or change existing user role."}), 403
        
        # Check for pricing warning (if adding this user will exceed plan's included users)
        pricing_warning = None
        try:
            # Get current plan and limits
            sub = execute_primary_query(
                "SELECT plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
                (org_id,),
                fetch_one=True
            )
            plan_type = sub[0] if sub else None
            if plan_type:
                limits = get_plan_limits(plan_type) or {}
                included_users = limits.get('max_users', 0)
                current_user_count = get_current_admin_count(org_id)
                new_user_count = current_user_count + 1
                
                # Check if new user count exceeds included users
                if new_user_count > included_users:
                    extra_users = new_user_count - included_users
                    additional_monthly_cost = extra_users * 500  # ₹500 per extra user
                    pricing_warning = {
                        "exceeds_limit": True,
                        "current_users": current_user_count,
                        "included_users": included_users,
                        "extra_users": extra_users,
                        "additional_monthly_cost": additional_monthly_cost,
                        "message": f"Your organization will have {new_user_count} users, exceeding your {get_subscription_display_name(plan_type)} limit of {included_users}. Additional charges of ₹{additional_monthly_cost}/month will apply."
                    }
        except Exception:
            pass  # Don't fail user creation if pricing check fails
        
        # Hash password
        hashed_password = hash_password(password)
        
        # Insert user into Primary DB
        user_id = execute_primary_query(
            "INSERT INTO users (email, password, role, org_id, status, is_email_verified) VALUES (?, ?, ?, ?, ?, ?)",
            (email, hashed_password, role, org_id, status, 1),
            return_lastrowid=True
        )
        
        # Log activity in audit_logs
        details = json.dumps({
            "created_by": g.email,
            "new_user_email": email,
            "role": role
        })
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (org_id, g.user_id, 'user_created', details)
        )
        
        # Return created user details (excluding password)
        user = execute_primary_query(
            "SELECT id, email, role, org_id, status, created_at FROM users WHERE id = ?",
            (user_id,),
            fetch_one=True
        )
        user_dict = dict_to_row(user) if user else None
        
        # Invalidate usage cache for this org
        try:
            ORG_USAGE_CACHE.pop(org_id, None)
        except Exception:
            pass

        response = {
            "status": "success",
            "message": "User created successfully",
            "user": user_dict
        }
        if pricing_warning:
            response["pricing_warning"] = pricing_warning

        return jsonify(response), 201
        
    except MySQLError as e:
        print(f"Database error in create_org_user: {e}")
        return jsonify({"status": "error", "message": "Failed to create user"}), 500

@app.route('/api/org/users/<int:user_id>', methods=['GET'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def get_org_user(user_id):
    """Retrieve details of a specific user.
    
    Authorization:
        - SuperAdmin: Can view any user
        - Org Admin: Can view users in their organization only
        - Org User: Access denied (403)
    
    Returns:
        JSON response with user details (excluding password)
    
    Raises:
        403 Forbidden: If user lacks required role or tries to access user from different org
        404 Not Found: If user not found
        500 Internal Server Error: If database query fails
    """
    try:
        # Use helper function for authorization check
        authorized, user, error_response = check_user_access(user_id, require_same_org=True)
        if not authorized:
            return error_response
        
        return jsonify({"status": "success", "user": user})
        
    except MySQLError as e:
        print(f"Database error in get_org_user: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve user"}), 500

@app.route('/api/org/users/<int:user_id>', methods=['PUT'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def update_org_user(user_id):
    """Update user details (email, status, password).
    
    Authorization:
        - SuperAdmin: Can update any user
        - Org Admin: Can update users in their organization only (except super_admin)
        - Org User: Access denied (403)
    
    Request Body (all fields optional):
        email: New email address
        password: New password (will be hashed)
        status: New status ('approved', 'suspended', 'pending')
    
    Returns:
        JSON response with updated user details
    
    Raises:
        400 Bad Request: If validation fails
        403 Forbidden: If user lacks required role or tries to update user from different org
        404 Not Found: If user not found
        409 Conflict: If new email already exists
        500 Internal Server Error: If database operation fails
    """
    try:
        # Use helper function for authorization check
        authorized, user, error_response = check_user_access(user_id, require_same_org=True)
        if not authorized:
            return error_response
        
        # Additional checks for Org Admin
        if g.role == ROLE_ORG_ADMIN:
            if user['role'] == ROLE_SUPER_ADMIN:
                return jsonify({"error": "Cannot update super_admin users"}), 403
        
        data = request.get_json()
        update_fields = []
        update_values = []
        
        # Handle email update
        if 'email' in data:
            new_email = data['email'].strip()
            if not validate_email_format(new_email):
                return jsonify({"status": "error", "message": "Invalid email format"}), 400
            
            # Check email uniqueness
            existing_user = execute_primary_query(
                "SELECT COUNT(*) FROM users WHERE email = ? AND id != ?",
                (new_email, user_id),
                fetch_one=True
            )
            if existing_user and existing_user[0] > 0:
                return jsonify({"status": "error", "message": "Email already exists"}), 409
            
            update_fields.append("email = ?")
            update_values.append(new_email)
        
        # Handle password update
        if 'password' in data:
            new_password = data['password']
            is_valid, error_msg = validate_password_strength(new_password)
            if not is_valid:
                return jsonify({"status": "error", "message": error_msg}), 400
            
            update_fields.append("password = ?")
            update_values.append(hash_password(new_password))
        
        # Handle status update
        if 'status' in data:
            new_status = data['status'].strip()
            valid_statuses = [USER_STATUS_APPROVED, USER_STATUS_SUSPENDED, USER_STATUS_PENDING, USER_STATUS_REJECTED, USER_STATUS_LOCKED]
            if new_status not in valid_statuses:
                return jsonify({"status": "error", "message": "Invalid status"}), 400
            
            update_fields.append("status = ?")
            update_values.append(new_status)
        
        if not update_fields:
            return jsonify({"status": "error", "message": "No fields to update"}), 400
        
        # Execute update
        update_values.append(user_id)
        query = f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?"
        execute_primary_query(query, tuple(update_values))
        
        # Log activity
        details = json.dumps({
            "updated_by": g.email,
            "user_email": user['email'],
            "fields_changed": list(data.keys())
        })
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (user['org_id'], g.user_id, 'user_updated', details)
        )
        
        # Fetch and return updated user
        updated_user = execute_primary_query(
            "SELECT id, email, role, org_id, status, created_at FROM users WHERE id = ?",
            (user_id,),
            fetch_one=True
        )
        user_dict = dict_to_row(updated_user) if updated_user else None
        
        return jsonify({
            "status": "success",
            "message": "User updated successfully",
            "user": user_dict
        })
        
    except MySQLError as e:
        print(f"Database error in update_org_user: {e}")
        return jsonify({"status": "error", "message": "Failed to update user"}), 500

@app.route('/api/org/users/<int:user_id>', methods=['DELETE'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def delete_org_user(user_id):
    """Delete a user from the organization.
    
    Authorization:
        - SuperAdmin: Can delete any user (except self in future)
        - Org Admin: Can delete users in their organization only (except super_admin and self)
        - Org User: Access denied (403)
    
    Returns:
        JSON response with success message
    
    Raises:
        403 Forbidden: If user lacks required role or tries to delete user from different org
        404 Not Found: If user not found
        500 Internal Server Error: If database operation fails
    """
    try:
        # Use helper function for authorization check
        authorized, user, error_response = check_user_access(user_id, require_same_org=True)
        if not authorized:
            return error_response
        
        # Additional checks for Org Admin
        if g.role == ROLE_ORG_ADMIN:
            if user['role'] == ROLE_SUPER_ADMIN:
                return jsonify({"error": "Cannot delete super_admin users"}), 403
            if user['id'] == g.user_id:
                return jsonify({"error": "Cannot delete your own account"}), 403
        
        # Delete user
        execute_primary_query("DELETE FROM users WHERE id = ?", (user_id,))
        
        # Log activity
        details = json.dumps({
            "deleted_by": g.email,
            "deleted_user_email": user['email'],
            "role": user['role']
        })
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (user['org_id'], g.user_id, 'user_deleted', details)
        )
        
        return jsonify({
            "status": "success",
            "message": "User deleted successfully"
        })
        
    except MySQLError as e:
        print(f"Database error in delete_org_user: {e}")
        return jsonify({"status": "error", "message": "Failed to delete user"}), 500
# --- SuperAdmin Dashboard API ---

@app.route('/api/superadmin/orgs', methods=['GET'])
@superadmin_required
def sa_list_orgs():
    try:
        page = request.args.get('page', default=1, type=int)
        limit = request.args.get('limit', default=SUPERADMIN_DEFAULT_PAGE_SIZE, type=int)
        if not page or page < 1 or not limit or limit < 1:
            return jsonify({"status": "error", "message": "Invalid pagination parameters"}), 400
        limit = min(SUPERADMIN_MAX_PAGE_SIZE, limit)
        status = request.args.get('status')
        plan = request.args.get('plan')
        search = (request.args.get('search') or '').strip().lower()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc').lower()
        if sort_by not in ORG_SORT_FIELDS:
            return jsonify({"status": "error", "message": "Invalid sort_by"}), 400
        if sort_order not in ['asc', 'desc']:
            return jsonify({"status": "error", "message": "Invalid sort_order"}), 400

        where = []
        params = []
        if status:
            where.append("o.status = ?")
            params.append(status)
        if search:
            where.append("LOWER(o.name) LIKE ?")
            params.append(f"%{search}%")

        join_plan = "LEFT JOIN (SELECT org_id, MAX(id) as max_id FROM subscriptions GROUP BY org_id) sm ON sm.org_id = o.id LEFT JOIN subscriptions s ON s.id = sm.max_id"
        if plan:
            where.append("(s.plan_type = ? OR s.status = 'trial')" if plan == 'trial' else "s.plan_type = ?")
            params.append(plan)
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""

        total_row = execute_primary_query(f"SELECT COUNT(*) FROM organizations o {join_plan} {where_clause}", tuple(params), fetch_one=True)
        total_count = int(total_row[0]) if total_row else 0
        offset = (page - 1) * limit
        # Support sort by user_count via subquery; project_count sorting not supported
        if sort_by == 'user_count':
            rows = execute_primary_query(
                f"SELECT o.id, o.name, o.domain, o.db_file_path, o.created_at, o.status, IFNULL(uc.cnt,0) as user_count FROM organizations o {join_plan} LEFT JOIN (SELECT org_id, COUNT(*) cnt FROM users WHERE status IN ('approved','active') GROUP BY org_id) uc ON uc.org_id = o.id {where_clause} ORDER BY user_count {sort_order} LIMIT ? OFFSET ?",
                tuple(params + [limit, offset]), fetch_all=True
            )
        else:
            rows = execute_primary_query(
                f"SELECT o.id, o.name, o.domain, o.db_file_path, o.created_at, o.status FROM organizations o {join_plan} {where_clause} ORDER BY o.{sort_by} {sort_order} LIMIT ? OFFSET ?",
                tuple(params + [limit, offset]), fetch_all=True
            )
        orgs = []
        if rows:
            for r in rows:
                o = {
                    'id': r[0],
                    'name': r[1],
                    'domain': r[2],
                    'db_file_path': r[3],
                    'created_at': r[4].isoformat() if r[4] else None,
                    'status': r[5]
                }
                org_id = o['id']
                urow = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND status IN ('approved','active')", (org_id,), fetch_one=True)
                o['user_count'] = int(urow[0]) if urow else 0
                # Project count (handle missing tenant DB gracefully)
                try:
                    o['project_count'] = get_project_count_for_org(org_id)
                except Exception:
                    o['project_count'] = 0
                sub = execute_primary_query("SELECT plan_type, status, start_date, end_date FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
                if sub:
                    o['subscription'] = {"plan_type": sub[0], "status": sub[1], "start_date": sub[2], "end_date": sub[3]}
                else:
                    o['subscription'] = None
                # Usage metrics
                try:
                    plan_type = o['subscription']['plan_type'] if o['subscription'] else None
                    o['usage'] = get_org_usage_stats(org_id, plan_type) if plan_type else None
                except Exception:
                    o['usage'] = None
                dbfp = o.get('db_file_path')
                try:
                    dbfp_dec = decrypt_db_path(dbfp) if dbfp else dbfp
                except Exception:
                    dbfp_dec = dbfp
                o['db_file_exists'] = bool(dbfp_dec and os.path.exists(dbfp_dec))
                try:
                    o['db_file_size_mb'] = round(os.path.getsize(dbfp_dec) / (1024*1024), 2) if o['db_file_exists'] else 0
                except Exception:
                    o['db_file_size_mb'] = 0
                orgs.append(o)

        total_pages = math.ceil(total_count / limit) if limit else 1
        active_row = execute_primary_query("SELECT COUNT(*) FROM organizations WHERE status = 'active'", fetch_one=True)
        active_count = int(active_row[0]) if active_row else 0
        users_row = execute_primary_query("SELECT COUNT(*) FROM users WHERE status IN ('approved','active')", fetch_one=True)
        total_users = int(users_row[0]) if users_row else 0
        rev_row = execute_primary_query("SELECT SUM(amount) FROM billing_transactions WHERE status = 'success'", fetch_one=True)
        total_revenue = float(rev_row[0]) if rev_row and rev_row[0] is not None else 0.0
        plan_counts = {"basic": 0, "si_plus": 0, "pro": 0, "trial": 0}
        p_rows = execute_primary_query("SELECT plan_type, COUNT(*) FROM (SELECT org_id, MAX(id) mid FROM subscriptions GROUP BY org_id) x JOIN subscriptions s ON s.id = x.mid GROUP BY plan_type", fetch_all=True)
        if p_rows:
            for pr in p_rows:
                if pr[0] in plan_counts:
                    plan_counts[pr[0]] = int(pr[1])
        # Trial count by latest status
        t_row = execute_primary_query("SELECT COUNT(*) FROM (SELECT org_id, MAX(id) mid FROM subscriptions GROUP BY org_id) x JOIN subscriptions s ON s.id = x.mid WHERE s.status = 'trial'", fetch_one=True)
        plan_counts['trial'] = int(t_row[0]) if t_row else plan_counts.get('trial', 0)

        try:
            details = json.dumps({"page": page, "limit": limit, "status": status, "plan": plan, "search": search})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_orgs_viewed', details))
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "organizations": orgs,
            "pagination": {"page": page, "limit": limit, "total_count": total_count, "total_pages": total_pages, "has_next": page < total_pages, "has_prev": page > 1},
            "summary": {"total_orgs": total_count, "active_orgs": active_count, "total_users": total_users, "total_revenue": total_revenue, "orgs_by_plan": plan_counts}
        })
    except Exception as e:
        print(f"/api/superadmin/orgs error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve organizations"}), 500


@app.route('/api/superadmin/orgs/<int:org_id>', methods=['GET'])
@superadmin_required
def sa_get_org(org_id):
    try:
        org = execute_primary_query("SELECT * FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404
        org_dict = dict_to_row(org)
        db_file_path = org_dict.get('db_file_path')
        try:
            db_file_path_dec = decrypt_db_path(db_file_path) if db_file_path else db_file_path
        except Exception:
            db_file_path_dec = db_file_path

        # Users stats
        total_users_row = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ?", (org_id,), fetch_one=True)
        total_users = int(total_users_row[0]) if total_users_row else 0
        by_role_rows = execute_primary_query("SELECT role, COUNT(*) FROM users WHERE org_id = ? GROUP BY role", (org_id,), fetch_all=True)
        users_by_role = {r[0]: int(r[1]) for r in by_role_rows} if by_role_rows else {}
        by_status_rows = execute_primary_query("SELECT status, COUNT(*) FROM users WHERE org_id = ? GROUP BY status", (org_id,), fetch_all=True)
        users_by_status = {r[0]: int(r[1]) for r in by_status_rows} if by_status_rows else {}
        recent_users = execute_primary_query("SELECT email, role, created_at FROM users WHERE org_id = ? ORDER BY created_at DESC LIMIT 5", (org_id,), fetch_all=True)
        recent_users_list = [dict_to_row(u) for u in recent_users] if recent_users else []

        # Projects
        project_count = get_project_count_for_org(org_id)

        # Subscriptions
        subs = execute_primary_query("SELECT * FROM subscriptions WHERE org_id = ? ORDER BY id DESC", (org_id,), fetch_all=True)
        sub_list = [dict_to_row(s) for s in subs] if subs else []
        current_subscription = sub_list[0] if sub_list else None

        # Billing
        total_paid_row = execute_primary_query("SELECT SUM(amount) FROM billing_transactions WHERE org_id = ? AND status = 'success'", (org_id,), fetch_one=True)
        total_transactions_row = execute_primary_query("SELECT COUNT(*) FROM billing_transactions WHERE org_id = ?", (org_id,), fetch_one=True)
        failed_row = execute_primary_query("SELECT COUNT(*) FROM billing_transactions WHERE org_id = ? AND status = 'failed'", (org_id,), fetch_one=True)
        last_payment_row = execute_primary_query("SELECT amount, created_at FROM billing_transactions WHERE org_id = ? AND status = 'success' ORDER BY created_at DESC LIMIT 1", (org_id,), fetch_one=True)
        billing_stats = {
            "total_paid": float(total_paid_row[0]) if total_paid_row and total_paid_row[0] is not None else 0.0,
            "total_transactions": int(total_transactions_row[0]) if total_transactions_row else 0,
            "failed_payments": int(failed_row[0]) if failed_row else 0,
            "last_payment": {"amount": (float(last_payment_row[0]) if last_payment_row else None), "date": (last_payment_row[1] if last_payment_row else None)}
        }

        # Usage metrics
        usage = None
        try:
            plan_type = current_subscription.get('plan_type') if current_subscription else None
            if plan_type:
                usage = get_org_usage_stats(org_id, plan_type)
        except Exception:
            usage = None

        try:
            details = json.dumps({"org_id": org_id})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_org_viewed', details))
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "organization": org_dict,
            "statistics": {
                "users": {"total": total_users, "by_role": users_by_role, "by_status": users_by_status, "recent": recent_users_list},
                "projects": {"total": project_count},
                "billing": billing_stats
            },
            "subscription": current_subscription,
            "subscription_history": sub_list,
            "usage": usage
        })
    except Exception as e:
        print(f"/api/superadmin/orgs/<id> GET error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve organization"}), 500


@app.route('/api/superadmin/orgs/<int:org_id>', methods=['PUT'])
@superadmin_required
def sa_update_org(org_id):
    try:
        org = execute_primary_query("SELECT * FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404
        body = request.get_json(silent=True) or {}
        name = (body.get('name') or '').strip()
        domain = (body.get('domain') or '').strip()
        status = (body.get('status') or '').strip()

        updates = []
        params = []
        old_values = dict_to_row(org)
        if name:
            # uniqueness
            exists = execute_primary_query("SELECT COUNT(*) FROM organizations WHERE LOWER(name) = LOWER(?) AND id != ?", (name, org_id), fetch_one=True)
            if exists and int(exists[0]) > 0:
                return jsonify({"status": "error", "message": "Organization name already exists"}), 409
            updates.append("name = ?")
            params.append(name)
        if domain:
            updates.append("domain = ?")
            params.append(domain)
        if status:
            if status not in ['active','suspended','deleted']:
                return jsonify({"status": "error", "message": "Invalid status"}), 400
            updates.append("status = ?")
            params.append(status)

        if not updates:
            return jsonify({"status": "error", "message": "No fields to update"}), 400

        params.append(org_id)
        execute_primary_query(f"UPDATE organizations SET {', '.join(updates)} WHERE id = ?", tuple(params))

        # Side effects
        if status in ['suspended','deleted']:
            try:
                execute_primary_query("UPDATE subscriptions SET status = 'halted' WHERE org_id = ? AND status = 'active'", (org_id,))
            except Exception:
                pass

        new_org = execute_primary_query("SELECT * FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
        try:
            details = json.dumps({"org_id": org_id, "old": old_values, "new": dict_to_row(new_org)})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_org_updated', details))
        except Exception:
            pass

        return jsonify({"status": "success", "organization": dict_to_row(new_org)})
    except Exception as e:
        print(f"/api/superadmin/orgs/<id> PUT error: {e}")
        return jsonify({"status": "error", "message": "Failed to update organization"}), 500


@app.route('/api/superadmin/orgs/<int:org_id>', methods=['DELETE'])
@superadmin_required
def sa_delete_org(org_id):
    try:
        org = execute_primary_query("SELECT * FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404
        org_row = dict_to_row(org)
        hard_delete = request.args.get('hard_delete', default=False, type=lambda v: str(v).lower() in ['1','true','yes'])

        # Log before destructive ops
        try:
            details = json.dumps({"org_id": org_id, "org_name": org_row.get('name'), "delete_type": 'hard' if hard_delete else 'soft'})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_org_deleted', details))
        except Exception:
            pass

        if not hard_delete:
            execute_primary_query("UPDATE organizations SET status = 'deleted' WHERE id = ?", (org_id,))
            try:
                execute_primary_query("UPDATE subscriptions SET status = 'cancelled' WHERE org_id = ? AND status IN ('active','authenticated')", (org_id,))
            except Exception:
                pass
            return jsonify({"status": "success", "message": "Organization marked as deleted. Data retained for recovery."})
        else:
            # Cancel Razorpay subscription if any
            try:
                sub = execute_primary_query("SELECT razorpay_subscription_id FROM subscriptions WHERE org_id = ? AND status IN ('active','authenticated') ORDER BY id DESC LIMIT 1", (org_id,), fetch_one=True)
                if sub and sub[0] and razorpay_client is not None:
                    try:
                        razorpay_client.subscription.cancel(sub[0])
                    except Exception:
                        pass
            except Exception:
                pass
            # Delete org (CASCADE)
            execute_primary_query("DELETE FROM organizations WHERE id = ?", (org_id,))
            # Delete tenant DB file
            try:
                db_path = org_row.get('db_file_path')
                if db_path and os.path.exists(db_path):
                    os.remove(db_path)
            except Exception:
                pass
            return jsonify({"status": "success", "message": "Organization permanently deleted. All data removed."})
    except Exception as e:
        print(f"/api/superadmin/orgs/<id> DELETE error: {e}")
        return jsonify({"status": "error", "message": "Failed to delete organization"}), 500


@app.route('/api/superadmin/orgs/<int:org_id>/convert-plan', methods=['PUT'])
@superadmin_required
def sa_convert_plan(org_id):
    try:
        # Validate request body
        body = request.get_json(silent=True) or {}
        plan_type = (body.get('plan_type') or '').strip().lower()
        
        # Validate plan_type
        valid_plans = ['trial', 'basic', 'si_plus', 'plus', 'pro']
        if not plan_type or plan_type not in valid_plans:
            return jsonify({"status": "error", "message": "Invalid plan type. Must be: trial, basic, plus, or pro"}), 400
        
        # Validate organization exists and is not deleted
        org = execute_primary_query("SELECT id, name, status FROM organizations WHERE id = ?", (org_id,), fetch_one=True)
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404
        
        org_row = dict_to_row(org)
        if org_row.get('status') == 'deleted':
            return jsonify({"status": "error", "message": "Cannot convert plan for deleted organization"}), 400
        
        org_name = org_row.get('name', '')
        
        # Get current subscription
        current_sub = execute_primary_query(
            "SELECT id, plan_type, status, razorpay_subscription_id, start_date, end_date FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
            (org_id,),
            fetch_one=True
        )
        
        # Store old values for audit logging
        old_plan_type = None
        old_status = None
        
        if current_sub:
            sub_row = dict_to_row(current_sub)
            old_plan_type = sub_row.get('plan_type')
            old_status = sub_row.get('status')
            sub_id = sub_row.get('id')
            
            # Idempotency check: if plan_type unchanged, return early without DB writes
            if old_plan_type is not None and plan_type == old_plan_type:
                return jsonify({
                    "status": "success",
                    "message": "Plan unchanged",
                    "subscription": {
                        "plan_type": old_plan_type,
                        "status": old_status,
                        "start_date": sub_row.get('start_date'),
                        "end_date": sub_row.get('end_date')
                    }
                })
        else:
            sub_id = None
        
        # Determine new status based on plan conversion logic
        current_date = datetime.now().strftime('%Y-%m-%d')
        
        # Update subscription based on conversion type
        if not sub_id:
            # Create new subscription if none exists
            new_status = 'trial' if plan_type == 'trial' else 'active'
            if plan_type == 'trial':
                end_date = (datetime.now() + timedelta(days=TRIAL_PERIOD_DAYS)).strftime('%Y-%m-%d')
                execute_primary_query(
                    "INSERT INTO subscriptions (org_id, plan_type, status, start_date, end_date, billing_cycle) VALUES (?, ?, ?, ?, ?, ?)",
                    (org_id, plan_type, new_status, current_date, end_date, 'monthly')
                )
                new_end_date = end_date
            else:
                execute_primary_query(
                    "INSERT INTO subscriptions (org_id, plan_type, status, start_date, billing_cycle) VALUES (?, ?, ?, ?, ?)",
                    (org_id, plan_type, new_status, current_date, 'monthly')
                )
                new_end_date = None
            new_start_date = current_date
            new_status = new_status
        elif old_plan_type == 'trial':
            # Converting FROM trial to paid plan
            execute_primary_query(
                "UPDATE subscriptions SET plan_type = ?, status = 'active', start_date = ?, end_date = NULL WHERE id = ?",
                (plan_type, current_date, sub_id)
            )
            new_start_date = current_date
            new_end_date = None
            new_status = 'active'
        elif plan_type == 'trial':
            # Converting TO trial (from paid plan)
            end_date = (datetime.now() + timedelta(days=TRIAL_PERIOD_DAYS)).strftime('%Y-%m-%d')
            execute_primary_query(
                "UPDATE subscriptions SET plan_type = 'trial', status = 'trial', start_date = ?, end_date = ? WHERE id = ?",
                (current_date, end_date, sub_id)
            )
            new_start_date = current_date
            new_end_date = end_date
            new_status = 'trial'
        else:
            # Converting between paid plans (basic ↔ si_plus ↔ pro)
            execute_primary_query(
                "UPDATE subscriptions SET plan_type = ?, status = 'active' WHERE id = ?",
                (plan_type, sub_id)
            )
            # Keep existing dates
            existing_sub = execute_primary_query(
                "SELECT start_date, end_date FROM subscriptions WHERE id = ?",
                (sub_id,),
                fetch_one=True
            )
            if existing_sub:
                new_start_date = existing_sub[0] if existing_sub[0] else current_date
                new_end_date = existing_sub[1] if existing_sub[1] else None
            else:
                new_start_date = current_date
                new_end_date = None
            new_status = 'active'
        
        # Invalidate usage cache
        ORG_USAGE_CACHE.pop(org_id, None)
        
        # Audit logging
        try:
            details = json.dumps({
                "org_id": org_id,
                "org_name": org_name,
                "old_plan": old_plan_type,
                "new_plan": plan_type,
                "old_status": old_status,
                "new_status": new_status,
                "converted_by": g.email,
                "manual_conversion": True,
                "no_payment": True
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, g.user_id, 'superadmin_plan_converted', details)
            )
        except Exception as e:
            print(f"Failed to log audit entry: {e}")
        
        # Success response
        return jsonify({
            "status": "success",
            "message": f"Plan converted successfully from {old_plan_type or 'none'} to {plan_type}",
            "subscription": {
                "plan_type": plan_type,
                "status": new_status,
                "start_date": new_start_date,
                "end_date": new_end_date
            }
        })
    except MySQLError as e:
        print(f"/api/superadmin/orgs/<id>/convert-plan PUT error (DB): {e}")
        return jsonify({"status": "error", "message": "Failed to convert plan"}), 500
    except ValueError as e:
        print(f"/api/superadmin/orgs/<id>/convert-plan PUT error (Validation): {e}")
        return jsonify({"status": "error", "message": "Invalid plan type"}), 400
    except Exception as e:
        print(f"/api/superadmin/orgs/<id>/convert-plan PUT error: {e}")
        return jsonify({"status": "error", "message": "Failed to convert plan"}), 500


@app.route('/api/superadmin/billing', methods=['GET'])
@superadmin_required
def sa_billing_metrics():
    try:
        end_date = request.args.get('end_date') or datetime.now().strftime('%Y-%m-%d')
        start_date = request.args.get('start_date') or (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        group_by = request.args.get('group_by', 'month')

        # Cache
        cache_key = f"billing_metrics_{start_date}_{end_date}_{group_by}"
        cached = BILLING_METRICS_CACHE.get(cache_key)
        if cached and (datetime.now() - cached['ts']).total_seconds() < BILLING_METRICS_CACHE_TTL:
            return jsonify(cached['data'])

        rev_row = execute_primary_query("SELECT SUM(amount) FROM billing_transactions WHERE status = 'success' AND date(created_at) BETWEEN ? AND ?", (start_date, end_date), fetch_one=True)
        total_revenue = float(rev_row[0]) if rev_row and rev_row[0] is not None else 0.0
        mrr = calculate_mrr()
        arr = round(mrr * 12.0, 2)
        churn_rate = calculate_churn_rate(start_date, end_date)

        by_plan_rows = execute_primary_query("SELECT s.plan_type, SUM(bt.amount) FROM billing_transactions bt JOIN subscriptions s ON bt.org_id = s.org_id WHERE bt.status = 'success' AND date(bt.created_at) BETWEEN ? AND ? GROUP BY s.plan_type", (start_date, end_date), fetch_all=True)
        revenue_by_plan = {}
        if by_plan_rows:
            for r in by_plan_rows:
                revenue_by_plan[r[0]] = float(r[1] or 0.0)

        series = get_revenue_by_period(start_date, end_date, group_by=group_by)

        total_tx_row = execute_primary_query("SELECT COUNT(*) FROM billing_transactions WHERE date(created_at) BETWEEN ? AND ?", (start_date, end_date), fetch_one=True)
        succ_tx_row = execute_primary_query("SELECT COUNT(*) FROM billing_transactions WHERE status = 'success' AND date(created_at) BETWEEN ? AND ?", (start_date, end_date), fetch_one=True)
        total_tx = int(total_tx_row[0]) if total_tx_row else 0
        succ_tx = int(succ_tx_row[0]) if succ_tx_row else 0
        success_rate = round((succ_tx / total_tx) * 100.0, 2) if total_tx else 0.0
        avg_row = execute_primary_query("SELECT AVG(amount) FROM billing_transactions WHERE status = 'success' AND date(created_at) BETWEEN ? AND ?", (start_date, end_date), fetch_one=True)
        avg_tx = float(avg_row[0]) if avg_row and avg_row[0] is not None else 0.0

        top_rows = execute_primary_query("SELECT o.id, o.name, SUM(bt.amount) as total_revenue FROM billing_transactions bt JOIN organizations o ON bt.org_id = o.id WHERE bt.status = 'success' GROUP BY bt.org_id ORDER BY total_revenue DESC LIMIT 10", fetch_all=True)
        top_customers = []
        if top_rows:
            for r in top_rows:
                top_customers.append({"org_id": r[0], "org_name": r[1], "total_revenue": float(r[2] or 0.0)})

        # Subscription counts
        active_count_row = execute_primary_query("SELECT COUNT(*) FROM subscriptions WHERE status = 'active'", fetch_one=True)
        trial_count_row = execute_primary_query("SELECT COUNT(*) FROM subscriptions WHERE status = 'trial'", fetch_one=True)
        churned_count_row = execute_primary_query("SELECT COUNT(*) FROM subscriptions WHERE status = 'cancelled' AND date(end_date) BETWEEN ? AND ?", (start_date, end_date), fetch_one=True)
        active_count = int(active_count_row[0]) if active_count_row else 0
        trial_count = int(trial_count_row[0]) if trial_count_row else 0
        churned_count = int(churned_count_row[0]) if churned_count_row else 0

        data = {
            "status": "success",
            "period": {"start_date": start_date, "end_date": end_date},
            "revenue": {"total": total_revenue, "mrr": mrr, "arr": arr, "by_plan": revenue_by_plan, "over_time": series, "average_transaction": avg_tx},
            "subscriptions": {"active_count": active_count, "trial_count": trial_count, "churned_count": churned_count, "churn_rate": churn_rate},
            "payments": {"total_transactions": total_tx, "successful_transactions": succ_tx, "failed_transactions": total_tx - succ_tx, "success_rate": success_rate},
            "top_customers": top_customers
        }

        try:
            details = json.dumps({"start_date": start_date, "end_date": end_date, "group_by": group_by})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_billing_viewed', details))
        except Exception:
            pass

        BILLING_METRICS_CACHE[cache_key] = {'ts': datetime.now(), 'data': data}
        return jsonify(data)
    except Exception as e:
        print(f"/api/superadmin/billing error: {e}")
        return jsonify({"status": "error", "message": "Failed to compute billing metrics"}), 500


@app.route('/api/superadmin/payments/reconcile', methods=['POST'])
@superadmin_required
def sa_reconcile_payments():
    """Reconcile payments between Razorpay and database."""
    try:
        from utils.payment_reconciliation import reconcile_payments
        
        data = request.get_json(silent=True) or {}
        org_id = data.get('org_id')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        if razorpay_client is None:
            return jsonify({"status": "error", "message": "Razorpay not configured"}), 503
        
        results = reconcile_payments(
            org_id=org_id,
            start_date=start_date,
            end_date=end_date,
            razorpay_client=razorpay_client
        )
        
        # Log reconciliation
        try:
            details = json.dumps({"org_id": org_id, "start_date": start_date, "end_date": end_date, "discrepancies": results.get("summary", {}).get("discrepancies", 0)})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'payment_reconciliation_run', details))
        except Exception:
            pass
        
        return jsonify(results)
    except Exception as e:
        print(f"/api/superadmin/payments/reconcile error: {e}")
        return jsonify({"status": "error", "message": "Reconciliation failed"}), 500


@app.route('/api/superadmin/payments/retry-failed', methods=['POST'])
@superadmin_required
def sa_retry_failed_payments():
    """Manually trigger retry for failed payments."""
    try:
        from utils.payment_retry import PaymentRetryManager, retry_failed_payments
        
        # Get payments ready for retry
        ready_payments = PaymentRetryManager.get_failed_payments_ready_for_retry()
        
        if not ready_payments:
            return jsonify({
                "status": "success",
                "message": "No payments ready for retry",
                "retried_count": 0
            })
        
        # Execute retry logic
        results = retry_failed_payments(ready_payments, razorpay_client)
        
        # Log retry execution
        try:
            details = json.dumps({
                "retried_count": results.get("retried_count", 0),
                "success_count": results.get("success_count", 0),
                "failed_count": results.get("failed_count", 0)
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (None, g.user_id, 'payment_retry_execution', details)
            )
        except Exception:
            pass
        
        return jsonify(results)
    except Exception as e:
        print(f"/api/superadmin/payments/retry-failed error: {e}")
        return jsonify({"status": "error", "message": "Payment retry failed"}), 500


@app.route('/api/superadmin/monitoring', methods=['GET'])
@superadmin_required
def sa_monitoring_dashboard():
    """Comprehensive monitoring dashboard data."""
    try:
        # System health metrics
        active_subs = execute_primary_query("SELECT COUNT(*) FROM subscriptions WHERE status = 'active'", fetch_one=True)
        active_subs_count = active_subs[0] if active_subs else 0
        
        # Payment metrics (last 24 hours)
        last_24h = (datetime.now() - timedelta(hours=24)).strftime('%Y-%m-%d %H:%M:%S')
        recent_payments = execute_primary_query(
            "SELECT COUNT(*), SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) FROM billing_transactions WHERE created_at >= ?",
            (last_24h,),
            fetch_one=True
        )
        total_recent = recent_payments[0] if recent_payments else 0
        success_recent = recent_payments[1] if recent_payments and len(recent_payments) > 1 else 0
        
        # Error rates
        error_logs_24h = execute_primary_query(
            "SELECT COUNT(*) FROM audit_logs WHERE action IN ('payment_verification_critical_error', 'subscription_webhook_processing_error', 'subscription_webhook_database_error') AND timestamp >= ?",
            (last_24h,),
            fetch_one=True
        )
        error_count = error_logs_24h[0] if error_logs_24h else 0
        
        # Fraud alerts (last 24 hours)
        fraud_alerts = execute_primary_query(
            "SELECT COUNT(*) FROM audit_logs WHERE action = 'fraud_analysis' AND JSON_EXTRACT(details, '$.fraud_score') >= 50 AND timestamp >= ?",
            (last_24h,),
            fetch_one=True
        )
        fraud_count = fraud_alerts[0] if fraud_alerts else 0
        
        # Rate limit hits
        rate_limit_hits = execute_primary_query(
            "SELECT COUNT(*) FROM audit_logs WHERE action LIKE '%rate_limit%' AND timestamp >= ?",
            (last_24h,),
            fetch_one=True
        )
        rate_limit_count = rate_limit_hits[0] if rate_limit_hits else 0
        
        # Recent security incidents
        security_incidents = execute_primary_query(
            "SELECT action, COUNT(*) as cnt FROM audit_logs WHERE action IN ('payment_amount_mismatch_security_incident', 'subscription_invalid_transition_attempt', 'subscription_cross_org_verification_attempt') AND timestamp >= ? GROUP BY action",
            (last_24h,),
            fetch_all=True
        )
        incidents = {}
        if security_incidents:
            for row in security_incidents:
                incidents[row[0]] = row[1]
        
        return jsonify({
            "status": "success",
            "metrics": {
                "subscriptions": {
                    "active": active_subs_count
                },
                "payments_24h": {
                    "total": total_recent,
                    "successful": success_recent,
                    "success_rate": round((success_recent / total_recent * 100) if total_recent > 0 else 0, 2)
                },
                "errors_24h": {
                    "count": error_count,
                    "rate": round((error_count / total_recent * 100) if total_recent > 0 else 0, 2)
                },
                "fraud_alerts_24h": fraud_count,
                "rate_limit_hits_24h": rate_limit_count,
                "security_incidents": incidents
            },
            "timestamp": datetime.now().isoformat()
        })
    except Exception as e:
        print(f"/api/superadmin/monitoring error: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch monitoring data"}), 500


@app.route('/api/superadmin/analytics/payments', methods=['GET'])
@superadmin_required
def sa_payment_analytics():
    """Enhanced payment analytics dashboard."""
    try:
        end_date = request.args.get('end_date') or datetime.now().strftime('%Y-%m-%d')
        start_date = request.args.get('start_date') or (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')
        
        # Revenue trends
        revenue_trends = get_revenue_by_period(start_date, end_date, group_by='day')
        
        # Payment method distribution (if available in future)
        # For now, all are Razorpay
        
        # Success rate by day
        if DB_TYPE.lower() == "mysql":
            success_rate_query = """
                SELECT DATE(created_at) as day,
                       COUNT(*) as total,
                       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful
                FROM billing_transactions
                WHERE DATE(created_at) BETWEEN ? AND ?
                GROUP BY DATE(created_at)
                ORDER BY day
            """
        else:
            success_rate_query = """
                SELECT date(created_at) as day,
                       COUNT(*) as total,
                       SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful
                FROM billing_transactions
                WHERE date(created_at) BETWEEN ? AND ?
                GROUP BY date(created_at)
                ORDER BY day
            """
        
        success_rates = execute_primary_query(success_rate_query, (start_date, end_date), fetch_all=True)
        success_rate_data = []
        if success_rates:
            for row in success_rates:
                total = row[1] or 0
                successful = row[2] or 0
                success_rate_data.append({
                    "date": row[0],
                    "total": total,
                    "successful": successful,
                    "rate": round((successful / total * 100) if total > 0 else 0, 2)
                })
        
        # Average transaction value trend
        avg_tx_trend = []
        for day_data in revenue_trends:
            day = day_data["period"]
            revenue = day_data["revenue"]
            # Get count for that day
            count_row = execute_primary_query(
                "SELECT COUNT(*) FROM billing_transactions WHERE DATE(created_at) = ? AND status = 'success'",
                (day,),
                fetch_one=True
            )
            count = count_row[0] if count_row else 0
            avg_tx_trend.append({
                "date": day,
                "avg_transaction": round(revenue / count, 2) if count > 0 else 0
            })
        
        # Churn analysis
        churn_rate = calculate_churn_rate(start_date, end_date)
        
        # Customer lifetime value (simplified)
        clv_rows = execute_primary_query(
            "SELECT org_id, SUM(amount) as total_revenue, COUNT(*) as transaction_count FROM billing_transactions WHERE status = 'success' AND DATE(created_at) BETWEEN ? AND ? GROUP BY org_id",
            (start_date, end_date),
            fetch_all=True
        )
        avg_clv = 0
        if clv_rows:
            total_clv = sum(float(row[1] or 0) for row in clv_rows)
            avg_clv = round(total_clv / len(clv_rows), 2) if clv_rows else 0
        
        return jsonify({
            "status": "success",
            "period": {"start_date": start_date, "end_date": end_date},
            "revenue_trends": revenue_trends,
            "success_rates": success_rate_data,
            "avg_transaction_trend": avg_tx_trend,
            "churn_rate": churn_rate,
            "customer_metrics": {
                "avg_clv": avg_clv,
                "total_customers": len(clv_rows) if clv_rows else 0
            }
        })
    except Exception as e:
        print(f"/api/superadmin/analytics/payments error: {e}")
        return jsonify({"status": "error", "message": "Failed to fetch analytics"}), 500


@app.route('/api/superadmin/users', methods=['GET'])
@superadmin_required
def sa_list_users():
    try:
        page = request.args.get('page', default=1, type=int)
        limit = request.args.get('limit', default=SUPERADMIN_DEFAULT_PAGE_SIZE, type=int)
        if not page or page < 1 or not limit or limit < 1:
            return jsonify({"status": "error", "message": "Invalid pagination parameters"}), 400
        limit = min(SUPERADMIN_MAX_PAGE_SIZE, limit)
        org_id = request.args.get('org_id', type=int)
        role = request.args.get('role')
        status = request.args.get('status')
        search = (request.args.get('search') or '').strip().lower()
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc').lower()
        if sort_by not in USER_SORT_FIELDS:
            return jsonify({"status": "error", "message": "Invalid sort_by"}), 400
        if sort_order not in ['asc', 'desc']:
            return jsonify({"status": "error", "message": "Invalid sort_order"}), 400

        where = []
        params = []
        if org_id:
            where.append("org_id = ?")
            params.append(org_id)
        if role:
            where.append("role = ?")
            params.append(role)
        if status:
            where.append("status = ?")
            params.append(status)
        if search:
            where.append("LOWER(email) LIKE ?")
            params.append(f"%{search}%")
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""

        total_row = execute_primary_query(f"SELECT COUNT(*) FROM users {where_clause}", tuple(params), fetch_one=True)
        total_count = int(total_row[0]) if total_row else 0
        offset = (page - 1) * limit
        rows = execute_primary_query(
            f"SELECT id, email, role, org_id, status, created_at, is_email_verified FROM users {where_clause} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]), fetch_all=True
        )
        users = []
        if rows:
            for r in rows:
                if isinstance(r, dict):
                    u = r
                elif hasattr(r, "keys"):
                    u = dict(r)
                else:
                    cols = ["id", "email", "role", "org_id", "status", "created_at", "is_email_verified"]
                    u = {col: r[idx] for idx, col in enumerate(cols) if idx < len(r)}
                if u.get('org_id'):
                    nrow = execute_primary_query("SELECT name FROM organizations WHERE id = ?", (u['org_id'],), fetch_one=True)
                    u['org_name'] = nrow[0] if nrow else None
                else:
                    u['org_name'] = 'Platform'
                users.append(u)

        # Summary
        by_role = {}
        r_rows = execute_primary_query("SELECT role, COUNT(*) FROM users GROUP BY role", fetch_all=True)
        if r_rows:
            for rr in r_rows:
                by_role[rr[0]] = int(rr[1])
        by_status = {}
        s_rows = execute_primary_query("SELECT status, COUNT(*) FROM users GROUP BY status", fetch_all=True)
        if s_rows:
            for sr in s_rows:
                by_status[sr[0]] = int(sr[1])

        total_pages = math.ceil(total_count / limit) if limit else 1
        try:
            details = json.dumps({"page": page, "limit": limit, "org_id": org_id, "role": role, "status": status, "search": search})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_users_viewed', details))
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "users": users,
            "pagination": {"page": page, "limit": limit, "total_count": total_count, "total_pages": total_pages, "has_next": page < total_pages, "has_prev": page > 1},
            "summary": {"by_role": by_role, "by_status": by_status, "pending_approvals": by_status.get('pending', 0)}
        })
    except Exception as e:
        print(f"/api/superadmin/users error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve users"}), 500


@app.route('/api/superadmin/users/<int:user_id>', methods=['GET'])
@superadmin_required
def sa_get_user(user_id):
    try:
        user = execute_primary_query("SELECT id, email, role, org_id, status, created_at, is_email_verified FROM users WHERE id = ?", (user_id,), fetch_one=True)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        if isinstance(user, dict):
            u = user
        elif hasattr(user, "keys"):
            u = dict(user)
        else:
            cols = ["id", "email", "role", "org_id", "status", "created_at", "is_email_verified"]
            u = {col: user[idx] for idx, col in enumerate(cols) if idx < len(user)}
        if u.get('org_id'):
            nrow = execute_primary_query("SELECT name FROM organizations WHERE id = ?", (u['org_id'],), fetch_one=True)
            u['org_name'] = nrow[0] if nrow else None
            prow = execute_primary_query("SELECT plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1", (u['org_id'],), fetch_one=True)
            u['subscription_plan'] = prow[0] if prow else None
        logs = execute_primary_query("SELECT action, details, timestamp FROM audit_logs WHERE user_id = ? ORDER BY timestamp DESC LIMIT 10", (user_id,), fetch_all=True)
        if logs:
            log_cols = ["action", "details", "timestamp"]
            recent_logs = []
            for l in logs:
                if isinstance(l, dict):
                    recent_logs.append(l)
                elif hasattr(l, "keys"):
                    recent_logs.append(dict(l))
                else:
                    recent_logs.append({col: l[idx] for idx, col in enumerate(log_cols) if idx < len(l)})
        else:
            recent_logs = []
        try:
            details = json.dumps({"user_id": user_id})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_user_viewed', details))
        except Exception:
            pass
        return jsonify({"status": "success", "user": u, "recent_audit": recent_logs})
    except Exception as e:
        print(f"/api/superadmin/users/<id> GET error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve user"}), 500


@app.route('/api/superadmin/users/<int:user_id>', methods=['PUT'])
@superadmin_required
def sa_update_user(user_id):
    try:
        user = execute_primary_query("SELECT id, email, role, org_id, status FROM users WHERE id = ?", (user_id,), fetch_one=True)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        old = dict_to_row(user)
        body = request.get_json(silent=True) or {}
        update_fields = []
        vals = []
        if 'email' in body:
            email = body.get('email','').strip()
            if not validate_email_format(email):
                return jsonify({"status": "error", "message": "Invalid email format"}), 400
            dup = execute_primary_query("SELECT COUNT(*) FROM users WHERE email = ? AND id != ?", (email, user_id), fetch_one=True)
            if dup and int(dup[0]) > 0:
                return jsonify({"status": "error", "message": "Email already exists"}), 409
            update_fields.append('email = ?'); vals.append(email)
        if 'password' in body:
            pwd = body.get('password','')
            ok, msg = validate_password_strength(pwd)
            if not ok:
                return jsonify({"status": "error", "message": msg}), 400
            update_fields.append('password = ?'); vals.append(hash_password(pwd))
        if 'role' in body:
            role = body.get('role','').strip()
            if role not in [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER]:
                return jsonify({"status": "error", "message": "Invalid role"}), 400
            update_fields.append('role = ?'); vals.append(role)
        if 'status' in body:
            st = body.get('status','').strip()
            if st not in [USER_STATUS_APPROVED, USER_STATUS_PENDING, USER_STATUS_SUSPENDED, USER_STATUS_REJECTED, USER_STATUS_LOCKED]:
                return jsonify({"status": "error", "message": "Invalid status"}), 400
            update_fields.append('status = ?'); vals.append(st)
        if 'org_id' in body:
            new_org = body.get('org_id')
            chk = execute_primary_query("SELECT id FROM organizations WHERE id = ?", (new_org,), fetch_one=True)
            if not chk:
                return jsonify({"status": "error", "message": "Organization does not exist"}), 400
            update_fields.append('org_id = ?'); vals.append(new_org)
        if not update_fields:
            return jsonify({"status": "error", "message": "No fields to update"}), 400
        vals.append(user_id)
        execute_primary_query(f"UPDATE users SET {', '.join(update_fields)} WHERE id = ?", tuple(vals))
        new_user = execute_primary_query("SELECT id, email, role, org_id, status, created_at, is_email_verified FROM users WHERE id = ?", (user_id,), fetch_one=True)
        try:
            details = json.dumps({"user_id": user_id, "old": old, "new": dict_to_row(new_user)})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_user_updated', details))
        except Exception:
            pass
        return jsonify({"status": "success", "user": dict_to_row(new_user)})
    except Exception as e:
        print(f"/api/superadmin/users/<id> PUT error: {e}")
        return jsonify({"status": "error", "message": "Failed to update user"}), 500


@app.route('/api/superadmin/users/<int:user_id>', methods=['DELETE'])
@superadmin_required
def sa_delete_user(user_id):
    try:
        if user_id == getattr(g, 'user_id', None):
            return jsonify({"status": "error", "message": "Cannot delete your own account"}), 403
        user = execute_primary_query("SELECT id, email FROM users WHERE id = ?", (user_id,), fetch_one=True)
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        execute_primary_query("DELETE FROM users WHERE id = ?", (user_id,))
        try:
            details = json.dumps({"user_id": user_id, "email": dict_to_row(user).get('email')})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_user_deleted', details))
        except Exception:
            pass
        return jsonify({"status": "success", "message": "User deleted successfully"})
    except Exception as e:
        print(f"/api/superadmin/users/<id> DELETE error: {e}")
        return jsonify({"status": "error", "message": "Failed to delete user"}), 500
@app.route('/api/superadmin/audit-logs', methods=['GET'])
@superadmin_required
def sa_audit_logs():
    try:
        page = max(1, int(request.args.get('page', 1)))
        limit = min(SUPERADMIN_MAX_PAGE_SIZE*2, max(1, int(request.args.get('limit', AUDIT_LOG_DEFAULT_PAGE_SIZE))))
        org_id = request.args.get('org_id', type=int)
        user_id = request.args.get('user_id', type=int)
        action = request.args.get('action')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        search = (request.args.get('search') or '')
        sort_order = request.args.get('sort_order', 'desc').lower()
        if sort_order not in ['asc', 'desc']:
            return jsonify({"status": "error", "message": "Invalid sort_order"}), 400

        where = []
        params = []
        if org_id:
            where.append("al.org_id = ?")
            params.append(org_id)
        if user_id:
            where.append("al.user_id = ?")
            params.append(user_id)
        if action:
            where.append("al.action = ?")
            params.append(action)
        if start_date:
            where.append("date(al.timestamp) >= ?")
            params.append(start_date)
        if end_date:
            where.append("date(al.timestamp) <= ?")
            params.append(end_date)
        if search:
            where.append("al.details LIKE ?")
            params.append(f"%{search}%")
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""

        total_row = execute_primary_query(f"SELECT COUNT(*) FROM audit_logs al {where_clause}", tuple(params), fetch_one=True)
        total_count = int(total_row[0]) if total_row else 0
        offset = (page - 1) * limit
        rows = execute_primary_query(
            f"SELECT al.id, al.org_id, al.user_id, al.action, al.details, al.timestamp, u.email as user_email, o.name as org_name FROM audit_logs al LEFT JOIN users u ON al.user_id = u.id LEFT JOIN organizations o ON al.org_id = o.id {where_clause} ORDER BY al.timestamp {sort_order} LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]), fetch_all=True
        )
        logs = []
        if rows:
            for r in rows:
                if isinstance(r, dict):
                    d = r
                elif hasattr(r, "keys"):
                    d = dict(r)
                else:
                    cols = ["id", "org_id", "user_id", "action", "details", "timestamp", "user_email", "org_name"]
                    d = {col: r[idx] for idx, col in enumerate(cols) if idx < len(r)}
                try:
                    d['details_parsed'] = json.loads(d.get('details') or '{}')
                except Exception:
                    d['details_parsed'] = d.get('details')
                logs.append(d)

        # Summary
        top_actions = []
        ta_rows = execute_primary_query("SELECT action, COUNT(*) c FROM audit_logs GROUP BY action ORDER BY c DESC LIMIT 10", fetch_all=True)
        if ta_rows:
            for tr in ta_rows:
                top_actions.append({"action": tr[0], "count": int(tr[1])})
        top_orgs = []
        to_rows = execute_primary_query("SELECT org_id, COUNT(*) c FROM audit_logs GROUP BY org_id ORDER BY c DESC LIMIT 10", fetch_all=True)
        if to_rows:
            for tr in to_rows:
                top_orgs.append({"org_id": tr[0], "count": int(tr[1])})
        if DB_TYPE.lower() == "mysql":
            recent_24h_row = execute_primary_query("SELECT COUNT(*) FROM audit_logs WHERE timestamp >= DATE_SUB(NOW(), INTERVAL 24 HOUR)", fetch_one=True)
        else:
            recent_24h_row = execute_primary_query("SELECT COUNT(*) FROM audit_logs WHERE timestamp >= datetime('now','-24 hours')", fetch_one=True)
        recent_24h = int(recent_24h_row[0]) if recent_24h_row else 0

        total_pages = math.ceil(total_count / limit) if limit else 1
        try:
            details = json.dumps({"page": page, "limit": limit, "org_id": org_id, "user_id": user_id, "action": action})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_audit_logs_viewed', details))
        except Exception:
            pass

        return jsonify({
            "status": "success",
            "logs": logs,
            "pagination": {"page": page, "limit": limit, "total_count": total_count, "total_pages": total_pages, "has_next": page < total_pages, "has_prev": page > 1},
            "summary": {"total_logs": total_count, "top_actions": top_actions, "top_orgs": top_orgs, "recent_activity_24h": recent_24h}
        })
    except Exception as e:
        print(f"/api/superadmin/audit-logs error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve audit logs"}), 500


@app.route('/api/superadmin/subscriptions', methods=['GET'])
@superadmin_required
def sa_list_subscriptions():
    try:
        page = request.args.get('page', default=1, type=int)
        limit = request.args.get('limit', default=SUPERADMIN_DEFAULT_PAGE_SIZE, type=int)
        if not page or page < 1 or not limit or limit < 1:
            return jsonify({"status": "error", "message": "Invalid pagination parameters"}), 400
        limit = min(SUPERADMIN_MAX_PAGE_SIZE, limit)
        status = request.args.get('status')
        plan_type = request.args.get('plan_type')
        org_id = request.args.get('org_id', type=int)
        sort_by = request.args.get('sort_by', 'created_at')
        sort_order = request.args.get('sort_order', 'desc').lower()
        if sort_by not in SUBSCRIPTION_SORT_FIELDS:
            return jsonify({"status": "error", "message": "Invalid sort_by"}), 400
        if sort_order not in ['asc','desc']:
            return jsonify({"status": "error", "message": "Invalid sort_order"}), 400
        # Map friendly sort key to real column (subscriptions table lacks created_at)
        sort_column = 'start_date' if sort_by == 'created_at' else sort_by

        where = []
        params = []
        if status:
            where.append("s.status = ?"); params.append(status)
        if plan_type:
            where.append("s.plan_type = ?"); params.append(plan_type)
        if org_id:
            where.append("s.org_id = ?"); params.append(org_id)
        where_clause = (" WHERE " + " AND ".join(where)) if where else ""

        total_row = execute_primary_query(f"SELECT COUNT(*) FROM subscriptions s {where_clause}", tuple(params), fetch_one=True)
        total_count = int(total_row[0]) if total_row else 0
        offset = (page - 1) * limit
        rows = execute_primary_query(
            f"SELECT s.*, o.name as org_name FROM subscriptions s LEFT JOIN organizations o ON s.org_id = o.id {where_clause} ORDER BY s.{sort_column} {sort_order} LIMIT ? OFFSET ?",
            tuple(params + [limit, offset]), fetch_all=True
        )
        subs = []
        if rows:
            for r in rows:
                if isinstance(r, dict):
                    d = r
                elif hasattr(r, "keys"):
                    d = dict(r)
                else:
                    # Columns from SELECT s.* plus org_name join column
                    base_cols = ["id", "org_id", "plan_type", "razorpay_subscription_id", "status", "start_date", "end_date", "billing_cycle", "org_name"]
                    d = {col: r[idx] for idx, col in enumerate(base_cols) if idx < len(r)}
                urow = execute_primary_query("SELECT COUNT(*) FROM users WHERE org_id = ? AND status IN ('approved','active')", (d.get('org_id'),), fetch_one=True)
                d['user_count'] = int(urow[0]) if urow else 0
                subs.append(d)

        # Summary
        by_status = {}
        s_rows = execute_primary_query("SELECT status, COUNT(*) FROM subscriptions GROUP BY status", fetch_all=True)
        if s_rows:
            for sr in s_rows:
                by_status[sr[0]] = int(sr[1])
        by_plan = {}
        p_rows = execute_primary_query("SELECT plan_type, COUNT(*) FROM subscriptions GROUP BY plan_type", fetch_all=True)
        if p_rows:
            for pr in p_rows:
                by_plan[pr[0]] = int(pr[1])

        total_pages = math.ceil(total_count / limit) if limit else 1
        try:
            details = json.dumps({"page": page, "limit": limit, "status": status, "plan_type": plan_type, "org_id": org_id})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, g.user_id, 'superadmin_subscriptions_viewed', details))
        except Exception:
            pass
        return jsonify({
            "status": "success",
            "subscriptions": subs,
            "pagination": {"page": page, "limit": limit, "total_count": total_count, "total_pages": total_pages, "has_next": page < total_pages, "has_prev": page > 1},
            "summary": {"by_status": by_status, "by_plan": by_plan}
        })
    except Exception as e:
        print(f"/api/superadmin/subscriptions error: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve subscriptions"}), 500

@app.route('/api/superadmin/diagnose-tenant', methods=['POST'])
@superadmin_required
def diagnose_tenant():
    """Diagnose tenant resolution failures for org admin users.
    
    This endpoint performs comprehensive diagnostics to identify why a user
    cannot access tenant resources. It checks user org_id, organization record,
    database path, file existence, subscription, and simulates tenant resolution.
    
    Request Body:
        email (str, optional): User email address
        org_id (int, optional): Organization ID (alternative to email)
    
    Returns:
        JSON response with detailed diagnostics and identified issues
    """
    try:
        data = request.get_json() or {}
        email = data.get('email')
        org_id = data.get('org_id', type=int)
        
        if not email and not org_id:
            return jsonify({"status": "error", "message": "Either email or org_id is required"}), 400
        
        diagnostics = {
            "user": None,
            "organization": None,
            "database_file": None,
            "subscription": None,
            "tenant_resolution": None,
            "issues": [],
            "recommended_actions": []
        }
        
        # Step 1: Query user record
        user = None
        if email:
            user_result = execute_primary_query(
                "SELECT id, email, role, org_id, status, COALESCE(is_email_verified, 1) AS is_email_verified FROM users WHERE email = ?",
                (email,),
                fetch_one=True
            )
            if user_result:
                user = dict_to_row(user_result)
        elif org_id:
            # Find first org_admin user for this org
            user_result = execute_primary_query(
                "SELECT id, email, role, org_id, status, COALESCE(is_email_verified, 1) AS is_email_verified FROM users WHERE org_id = ? AND role IN (?, ?) LIMIT 1",
                (org_id, ROLE_ORG_ADMIN, ROLE_ORG_USER),
                fetch_one=True
            )
            if user_result:
                user = dict_to_row(user_result)
        
        if not user:
            return jsonify({"status": "error", "message": "User not found"}), 404
        
        diagnostics["user"] = user
        
        # Step 2: Check user's org_id
        if user['org_id'] is None:
            diagnostics["issues"].append({
                "severity": "critical",
                "code": "USER_ORG_ID_NULL",
                "message": "User's org_id is NULL"
            })
            diagnostics["recommended_actions"].append("Run repair endpoint with action=fix_user_org_id")
        else:
            org_id = user['org_id']
        
        # Step 3: Check organization record
        if org_id:
            org_result = execute_primary_query(
                "SELECT id, name, db_file_path, status, created_at FROM organizations WHERE id = ?",
                (org_id,),
                fetch_one=True
            )
            
            if not org_result:
                diagnostics["issues"].append({
                    "severity": "critical",
                    "code": "ORG_NOT_FOUND",
                    "message": f"Organization with id={org_id} not found (orphaned user)"
                })
                diagnostics["organization"] = None
            else:
                org = dict_to_row(org_result)
                diagnostics["organization"] = {
                    "id": org['id'],
                    "name": org['name'],
                    "status": org['status'],
                    "db_file_path_encrypted": org['db_file_path'],
                    "db_file_path_decrypted": None,
                    "created_at": org['created_at']
                }
                
                # Check organization status
                if org['status'] != 'active':
                    diagnostics["issues"].append({
                        "severity": "critical",
                        "code": "ORG_STATUS_INACTIVE",
                        "message": f"Organization status is '{org['status']}', not 'active'"
                    })
                    diagnostics["recommended_actions"].append("Run repair endpoint with action=activate_organization")
                
                # Check db_file_path
                db_file_path_encrypted = org['db_file_path']
                if not db_file_path_encrypted or db_file_path_encrypted == 'pending':
                    diagnostics["issues"].append({
                        "severity": "critical",
                        "code": "DB_FILE_PATH_PENDING",
                        "message": f"Organization db_file_path is '{db_file_path_encrypted or 'NULL'}' (incomplete provisioning)"
                    })
                    diagnostics["recommended_actions"].append("Run repair endpoint with action=fix_db_file_path")
                else:
                    # Step 4: Check database path decryption
                    try:
                        db_file_path_decrypted = decrypt_db_path(db_file_path_encrypted)
                        diagnostics["organization"]["db_file_path_decrypted"] = db_file_path_decrypted
                    except Exception as e:
                        diagnostics["issues"].append({
                            "severity": "critical",
                            "code": "DB_PATH_DECRYPTION_FAILED",
                            "message": f"Failed to decrypt db_file_path: {e}"
                        })
                        db_file_path_decrypted = None
                    
                    # Step 5: Check filesystem
                    if db_file_path_decrypted:
                        if os.path.exists(db_file_path_decrypted):
                            file_size = os.path.getsize(db_file_path_decrypted)
                            diagnostics["database_file"] = {
                                "exists": True,
                                "path": db_file_path_decrypted,
                                "size_bytes": file_size
                            }
                            if file_size == 0:
                                diagnostics["issues"].append({
                                    "severity": "critical",
                                    "code": "DB_FILE_EMPTY",
                                    "message": f"Tenant database file exists but is empty (0 bytes)"
                                })
                        else:
                            diagnostics["database_file"] = {
                                "exists": False,
                                "path": db_file_path_decrypted,
                                "size_bytes": 0
                            }
                            diagnostics["issues"].append({
                                "severity": "critical",
                                "code": "DB_FILE_MISSING",
                                "message": f"Tenant database file does not exist at {db_file_path_decrypted}"
                            })
                            diagnostics["recommended_actions"].append("Run repair endpoint with action=recreate_tenant_db")
        
        # Step 6: Check subscription
        if org_id:
            sub_result = execute_primary_query(
                "SELECT plan_type, status, start_date, end_date FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
                (org_id,),
                fetch_one=True
            )
            
            if not sub_result:
                diagnostics["issues"].append({
                    "severity": "warning",
                    "code": "SUBSCRIPTION_MISSING",
                    "message": "No subscription record found for organization"
                })
                diagnostics["recommended_actions"].append("Run repair endpoint with action=create_trial_subscription")
                diagnostics["subscription"] = None
            else:
                sub = dict_to_row(sub_result)
                diagnostics["subscription"] = {
                    "plan_type": sub['plan_type'],
                    "status": sub['status'],
                    "start_date": sub['start_date'],
                    "end_date": sub['end_date']
                }
        
        # Step 7: Simulate tenant resolution
        if org_id:
            try:
                resolved_path = get_tenant_db_path(org_id)
                diagnostics["tenant_resolution"] = {
                    "success": True,
                    "resolved_path": resolved_path
                }
            except TenantResolutionError as e:
                diagnostics["tenant_resolution"] = {
                    "success": False,
                    "error": str(e),
                    "error_type": "TenantResolutionError"
                }
                diagnostics["issues"].append({
                    "severity": "critical",
                    "code": "TENANT_RESOLUTION_FAILED",
                    "message": f"Tenant resolution failed: {e}"
                })
            except Exception as e:
                diagnostics["tenant_resolution"] = {
                    "success": False,
                    "error": str(e),
                    "error_type": type(e).__name__
                }
                diagnostics["issues"].append({
                    "severity": "critical",
                    "code": "TENANT_RESOLUTION_ERROR",
                    "message": f"Unexpected error during tenant resolution: {e}"
                })
        
        # Log diagnostic run
        try:
            details = json.dumps({
                "email": email,
                "org_id": org_id,
                "user_id": user['id'] if user else None,
                "issues_count": len(diagnostics["issues"])
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (org_id, g.user_id, 'tenant_diagnostic_run', details)
            )
        except Exception:
            pass
        
        return jsonify({
            "status": "success",
            "diagnostics": diagnostics
        })
        
    except Exception as e:
        print(f"/api/superadmin/diagnose-tenant error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": "Diagnostic failed",
            "error": str(e)
        }), 500

@app.route('/api/superadmin/repair-tenant', methods=['POST'])
@superadmin_required
def repair_tenant():
    """Automatically repair common tenant resolution issues.
    
    This endpoint performs repair actions to fix tenant resolution problems
    identified by the diagnose-tenant endpoint.
    
    Request Body:
        email (str, optional): User email address
        org_id (int, optional): Organization ID (alternative to email)
        action (str, required): Repair action to perform
            - fix_user_org_id: Update user's org_id (requires target_org_id)
            - fix_db_file_path: Fix organization's db_file_path
            - recreate_tenant_db: Recreate missing tenant database file
            - activate_organization: Set organization status to 'active'
            - create_trial_subscription: Create trial subscription for organization
        target_org_id (int, optional): Required for fix_user_org_id action
        confirm (bool, optional): Required for destructive actions (recreate_tenant_db)
    
    Returns:
        JSON response with repair results
    """
    try:
        data = request.get_json() or {}
        email = data.get('email')
        org_id = data.get('org_id', type=int)
        action = data.get('action')
        target_org_id = data.get('target_org_id', type=int)
        confirm = data.get('confirm', False)
        
        if not email and not org_id:
            return jsonify({"status": "error", "message": "Either email or org_id is required"}), 400
        
        if not action:
            return jsonify({"status": "error", "message": "action is required"}), 400
        
        # Get user if email provided
        user_id = None
        if email:
            user_result = execute_primary_query(
                "SELECT id, org_id FROM users WHERE email = ?",
                (email,),
                fetch_one=True
            )
            if user_result:
                user_id = user_result[0]
                if not org_id:
                    org_id = user_result[1]
        
        # Get org_id from user if not provided
        if not org_id and user_id:
            user_result = execute_primary_query(
                "SELECT org_id FROM users WHERE id = ?",
                (user_id,),
                fetch_one=True
            )
            if user_result:
                org_id = user_result[0]
        
        # Perform repair action
        if action == 'fix_user_org_id':
            if not target_org_id:
                return jsonify({"status": "error", "message": "target_org_id is required for fix_user_org_id action"}), 400
            if not user_id:
                return jsonify({"status": "error", "message": "User not found"}), 404
            
            # Verify organization exists
            org_check = execute_primary_query(
                "SELECT id FROM organizations WHERE id = ?",
                (target_org_id,),
                fetch_one=True
            )
            if not org_check:
                return jsonify({"status": "error", "message": f"Organization with id={target_org_id} not found"}), 404
            
            # Get old org_id
            old_org_id_result = execute_primary_query(
                "SELECT org_id FROM users WHERE id = ?",
                (user_id,),
                fetch_one=True
            )
            old_org_id = old_org_id_result[0] if old_org_id_result else None
            
            # Update user org_id
            execute_primary_query(
                "UPDATE users SET org_id = ? WHERE id = ?",
                (target_org_id, user_id)
            )
            
            # Verify update
            verify_result = execute_primary_query(
                "SELECT org_id FROM users WHERE id = ?",
                (user_id,),
                fetch_one=True
            )
            verified = verify_result and verify_result[0] == target_org_id
            
            # Log repair
            try:
                details = json.dumps({
                    "user_id": user_id,
                    "old_org_id": old_org_id,
                    "new_org_id": target_org_id
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (target_org_id, g.user_id, 'tenant_repair_user_org_id', details)
                )
            except Exception:
                pass
            
            return jsonify({
                "status": "success",
                "action": "fix_user_org_id",
                "message": "User org_id updated successfully",
                "details": {
                    "user_id": user_id,
                    "old_org_id": old_org_id,
                    "new_org_id": target_org_id,
                    "verified": verified
                }
            })
        
        elif action == 'fix_db_file_path':
            if not org_id:
                return jsonify({"status": "error", "message": "org_id is required for fix_db_file_path action"}), 400
            
            # Check current db_file_path
            org_result = execute_primary_query(
                "SELECT id, name, db_file_path FROM organizations WHERE id = ?",
                (org_id,),
                fetch_one=True
            )
            if not org_result:
                return jsonify({"status": "error", "message": f"Organization with id={org_id} not found"}), 404
            
            org = dict_to_row(org_result)
            current_path = org['db_file_path']
            
            # Check if tenant DB file exists in databases directory
            db_filename = get_tenant_db_filename(org_id)
            if os.path.exists(db_filename):
                # File exists, encrypt and update
                encrypted_path = encrypt_db_path(db_filename)
                execute_primary_query(
                    "UPDATE organizations SET db_file_path = ? WHERE id = ?",
                    (encrypted_path, org_id)
                )
                
                # Verify update
                verify_result = execute_primary_query(
                    "SELECT db_file_path FROM organizations WHERE id = ?",
                    (org_id,),
                    fetch_one=True
                )
                verified = verify_result and verify_result[0] != 'pending' and verify_result[0] is not None
                
                # Log repair
                try:
                    details = json.dumps({
                        "org_id": org_id,
                        "old_path": current_path,
                        "new_path": db_filename
                    })
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (org_id, g.user_id, 'tenant_repair_db_path', details)
                    )
                except Exception:
                    pass
                
                return jsonify({
                    "status": "success",
                    "action": "fix_db_file_path",
                    "message": "Database file path updated successfully",
                    "details": {
                        "org_id": org_id,
                        "old_path": current_path,
                        "new_path": db_filename,
                        "verified": verified
                    }
                })
            else:
                # File doesn't exist, create it using provision_organization_database
                org_name = org['name']
                success, result, status_code = provision_organization_database(org_name, None)
                
                if success:
                    new_org_id = result.get('org_id')
                    new_db_path = result.get('db_file_path')
                    
                    # If new org was created, we need to update the existing org record instead
                    if new_org_id != org_id:
                        # This shouldn't happen, but handle it
                        return jsonify({
                            "status": "error",
                            "message": "New organization was created instead of updating existing one"
                        }), 500
                    
                    # Log repair
                    try:
                        details = json.dumps({
                            "org_id": org_id,
                            "old_path": current_path,
                            "new_path": new_db_path
                        })
                        execute_primary_query(
                            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                            (org_id, g.user_id, 'tenant_repair_db_path', details)
                        )
                    except Exception:
                        pass
                    
                    return jsonify({
                        "status": "success",
                        "action": "fix_db_file_path",
                        "message": "Tenant database created and path updated successfully",
                        "details": {
                            "org_id": org_id,
                            "old_path": current_path,
                            "new_path": new_db_path,
                            "verified": True
                        }
                    })
                else:
                    return jsonify(result), status_code
        
        elif action == 'recreate_tenant_db':
            if not org_id:
                return jsonify({"status": "error", "message": "org_id is required for recreate_tenant_db action"}), 400
            
            if not confirm:
                return jsonify({
                    "status": "error",
                    "message": "confirm=true is required for recreate_tenant_db action (this creates an empty database)"
                }), 400
            
            # Get organization name
            org_result = execute_primary_query(
                "SELECT id, name FROM organizations WHERE id = ?",
                (org_id,),
                fetch_one=True
            )
            if not org_result:
                return jsonify({"status": "error", "message": f"Organization with id={org_id} not found"}), 404
            
            org = dict_to_row(org_result)
            org_name = org['name']
            
            # Generate new database filename
            db_filename = get_tenant_db_filename(org_id)
            
            # Remove existing file if it exists
            if os.path.exists(db_filename):
                try:
                    os.remove(db_filename)
                except Exception:
                    pass
            
            # Legacy SQLite repair path is no longer supported in MySQL-only mode
            return jsonify({"status": "error", "message": "SQLite-based repair operations are not supported in MySQL-only mode"}), 400
        
    except Exception as e:
        print(f"/api/superadmin/repair-tenant error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({
            "status": "error",
            "message": "Repair failed",
            "error": str(e)
        }), 500

@app.route('/api/superadmin/tenant-health', methods=['GET'])
@superadmin_required
def tenant_health():
    """List all organizations with their tenant health status for proactive monitoring.
    
    Query Parameters:
        page (int, optional): Page number (default: 1)
        page_size (int, optional): Items per page (default: 50)
        status (str, optional): Filter by health status ('healthy', 'warning', 'critical', 'all'; default: 'all')
    
    Returns:
        JSON response with organizations and their health status
    """
    try:
        page = request.args.get('page', default=1, type=int)
        page_size = request.args.get('page_size', default=50, type=int)
        status_filter = request.args.get('status', default='all')
        
        if page < 1 or page_size < 1:
            return jsonify({"status": "error", "message": "Invalid pagination parameters"}), 400
        
        page_size = min(page_size, 100)  # Max 100 per page
        offset = (page - 1) * page_size
        
        # Query all organizations with related data
        query = """
            SELECT o.id, o.name, o.status, o.db_file_path, o.created_at,
                   (SELECT COUNT(*) FROM users WHERE org_id = o.id AND role = ?) as admin_count,
                   (SELECT COUNT(*) FROM users WHERE org_id = o.id) as total_user_count,
                   (SELECT plan_type FROM subscriptions WHERE org_id = o.id ORDER BY id DESC LIMIT 1) as plan_type,
                   (SELECT status FROM subscriptions WHERE org_id = o.id ORDER BY id DESC LIMIT 1) as subscription_status
            FROM organizations o
            ORDER BY o.created_at DESC
            LIMIT ? OFFSET ?
        """
        
        rows = execute_primary_query(
            query,
            (ROLE_ORG_ADMIN, page_size, offset),
            fetch_all=True
        )
        
        organizations = []
        healthy_count = 0
        warning_count = 0
        critical_count = 0
        
        for row in rows:
            org = dict_to_row(row)
            org_id = org['id']
            
            # Perform health checks
            checks = {
                "db_file_path_valid": False,
                "db_file_exists": False,
                "db_file_size_bytes": 0,
                "has_subscription": False,
                "has_admins": False
            }
            issues = []
            
            # Check db_file_path
            db_file_path_encrypted = org['db_file_path']
            db_file_path_decrypted = None
            if db_file_path_encrypted and db_file_path_encrypted != 'pending':
                checks["db_file_path_valid"] = True
                try:
                    db_file_path_decrypted = decrypt_db_path(db_file_path_encrypted)
                except Exception:
                    issues.append({
                        "code": "DB_PATH_DECRYPTION_FAILED",
                        "message": "Failed to decrypt db_file_path"
                    })
            else:
                issues.append({
                    "code": "DB_FILE_PATH_PENDING",
                    "message": f"Organization db_file_path is '{db_file_path_encrypted or 'NULL'}'"
                })
            
            # Check file existence
            if db_file_path_decrypted:
                if os.path.exists(db_file_path_decrypted):
                    checks["db_file_exists"] = True
                    file_size = os.path.getsize(db_file_path_decrypted)
                    checks["db_file_size_bytes"] = file_size
                    if file_size == 0:
                        issues.append({
                            "code": "DB_FILE_EMPTY",
                            "message": "Tenant database file is empty"
                        })
                else:
                    issues.append({
                        "code": "DB_FILE_MISSING",
                        "message": f"Tenant database file does not exist at {db_file_path_decrypted}"
                    })
            
            # Check subscription
            if org['subscription_status']:
                checks["has_subscription"] = True
            else:
                issues.append({
                    "code": "SUBSCRIPTION_MISSING",
                    "message": "No subscription found"
                })
            
            # Check admins
            if org['admin_count'] and org['admin_count'] > 0:
                checks["has_admins"] = True
            else:
                issues.append({
                    "code": "NO_ADMINS",
                    "message": "No org_admin users found"
                })
            
            # Determine health status
            if len(issues) == 0:
                health_status = "healthy"
                healthy_count += 1
            elif any(issue['code'] in ['DB_FILE_PATH_PENDING', 'DB_FILE_MISSING', 'DB_FILE_EMPTY'] for issue in issues):
                health_status = "critical"
                critical_count += 1
            else:
                health_status = "warning"
                warning_count += 1
            
            # Apply status filter
            if status_filter != 'all' and health_status != status_filter:
                continue
            
            organizations.append({
                "org_id": org_id,
                "name": org['name'],
                "status": org['status'],
                "created_at": org['created_at'],
                "health_status": health_status,
                "admin_count": org['admin_count'] or 0,
                "total_user_count": org['total_user_count'] or 0,
                "plan_type": org['plan_type'],
                "subscription_status": org['subscription_status'],
                "checks": checks,
                "issues": issues
            })
        
        # Get total count (for pagination)
        total_count_row = execute_primary_query(
            "SELECT COUNT(*) FROM organizations",
            fetch_one=True
        )
        total_count = int(total_count_row[0]) if total_count_row else 0
        
        return jsonify({
            "status": "success",
            "page": page,
            "page_size": page_size,
            "total_count": total_count,
            "organizations": organizations,
            "summary": {
                "healthy": healthy_count,
                "warning": warning_count,
                "critical": critical_count
            }
        })
        
    except Exception as e:
        print(f"/api/superadmin/tenant-health error: {e}")
        import traceback
        traceback.print_exc()
        return jsonify({"status": "error", "message": "Failed to retrieve tenant health"}), 500

@app.route('/api/org/users/<int:user_id>/role', methods=['PUT'])
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def update_user_role(user_id):
    """Update user role (separate endpoint for security and audit trail).
    
    Authorization:
        - SuperAdmin: Can change any user role
        - Org Admin: Can change roles in their organization only (except super_admin and self)
        - Org User: Access denied (403)
    
    Request Body:
        role (required): New role - must be 'org_admin' or 'org_user'
    
    Returns:
        JSON response with updated user details
    
    Raises:
        400 Bad Request: If role is invalid
        403 Forbidden: If user lacks required role or tries to change role of user from different org
        404 Not Found: If user not found
        500 Internal Server Error: If database operation fails
    """
    try:
        # Use helper function for authorization check
        authorized, user, error_response = check_user_access(user_id, require_same_org=True)
        if not authorized:
            return error_response
        
        data = request.get_json()
        new_role = data.get('role', '').strip()
        
        if not new_role:
            return jsonify({"status": "error", "message": "Role is required"}), 400
        
        # Additional checks for Org Admin
        if g.role == ROLE_ORG_ADMIN:
            if user['role'] == ROLE_SUPER_ADMIN:
                return jsonify({"error": "Cannot change super_admin role"}), 403
            if new_role == ROLE_SUPER_ADMIN:
                return jsonify({"error": "Cannot promote user to super_admin"}), 403
            if user['id'] == g.user_id:
                return jsonify({"error": "Cannot change your own role"}), 403
        
        # Validate new role
        if new_role not in ORG_ADMIN_CREATABLE_ROLES:
            return jsonify({"status": "error", "message": "Role must be 'org_admin' or 'org_user'"}), 400
        
        # Validate org_admin count limit (when changing TO org_admin)
        if new_role == ROLE_ORG_ADMIN and user['role'] != ROLE_ORG_ADMIN and g.role != ROLE_SUPER_ADMIN:
            limits = get_plan_limits(getattr(g, 'plan', None)) or {}
            max_org_admins = limits.get('max_org_admins', MAX_ORG_ADMINS)
            current_org_admin_count = get_current_org_admin_count(user['org_id'])
            if current_org_admin_count >= max_org_admins:
                return jsonify({"status": "error", "message": f"Maximum {max_org_admins} org admins allowed. Please upgrade to add more admins or change existing user role."}), 403
        
        # Check for pricing warning (if role change affects user count and exceeds plan limits)
        pricing_warning = None
        try:
            # Get current plan and limits
            sub = execute_primary_query(
                "SELECT plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
                (user['org_id'],),
                fetch_one=True
            )
            plan_type = sub[0] if sub else None
            if plan_type:
                limits = get_plan_limits(plan_type) or {}
                included_users = limits.get('max_users', 0)
                current_user_count = get_current_admin_count(user['org_id'])
                
                # If changing to org_admin, check if this exceeds limits
                if new_role == ROLE_ORG_ADMIN and user['role'] != ROLE_ORG_ADMIN:
                    # User count doesn't change, but check if already at limit
                    if current_user_count >= included_users:
                        extra_users = current_user_count - included_users + 1
                        additional_monthly_cost = extra_users * 500
                        pricing_warning = {
                            "exceeds_limit": True,
                            "current_users": current_user_count,
                            "included_users": included_users,
                            "extra_users": extra_users,
                            "additional_monthly_cost": additional_monthly_cost,
                            "message": f"Your organization has {current_user_count} users, exceeding your {get_subscription_display_name(plan_type)} limit of {included_users}. Additional charges of ₹{additional_monthly_cost}/month apply."
                        }
        except Exception:
            pass  # Don't fail role change if pricing check fails
        
        # Update role
        execute_primary_query(
            "UPDATE users SET role = ? WHERE id = ?",
            (new_role, user_id)
        )
        
        # Log activity
        details = json.dumps({
            "changed_by": g.email,
            "user_email": user['email'],
            "old_role": user['role'],
            "new_role": new_role
        })
        execute_primary_query(
            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
            (user['org_id'], g.user_id, 'user_role_changed', details)
        )
        
        # Fetch and return updated user
        updated_user = execute_primary_query(
            "SELECT id, email, role, org_id, status, created_at FROM users WHERE id = ?",
            (user_id,),
            fetch_one=True
        )
        user_dict = dict_to_row(updated_user) if updated_user else None

        # Invalidate usage cache (admins count could have changed relevance)
        try:
            ORG_USAGE_CACHE.pop(user['org_id'], None)
        except Exception:
            pass
        
        response = {
            "status": "success",
            "message": "User role updated successfully",
            "user": user_dict
        }
        if pricing_warning:
            response["pricing_warning"] = pricing_warning
        
        return jsonify(response)
        
    except MySQLError as e:
        print(f"Database error in update_user_role: {e}")
        return jsonify({"status": "error", "message": "Failed to update user role"}), 500

@app.route('/api/org/verify-email', methods=['GET'])
def verify_email():
    token = request.args.get('token')
    print(f"[EMAIL-VERIFY] Verification attempt for token: {str(token)[:8]}...")
    if not token:
        return jsonify({"status": "error", "message": "Verification token is required"}), 400
    try:
        row = execute_primary_query(
            "SELECT id, email, org_id, verification_expires_at, COALESCE(is_email_verified, 0) as is_email_verified, status FROM users WHERE verification_token = ?",
            params=(token,),
            fetch_one=True
        )
        if not row:
            return jsonify({"status": "error", "message": "Invalid verification token"}), 404
        user = dict_to_row(row)
        if int(user.get('is_email_verified', 0)) == 1:
            return jsonify({"status": "success", "message": "Email already verified. You can now log in."})

        expires_at = user.get('verification_expires_at')
        if expires_at:
            try:
                exp_dt = datetime.strptime(expires_at, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                exp_dt = datetime.fromisoformat(expires_at)
            if datetime.now() > exp_dt:
                return jsonify({"status": "error", "message": "Verification token has expired. Please request a new verification email."}), 410

        execute_primary_query(
            "UPDATE users SET is_email_verified = 1, status = 'approved', verification_token = NULL WHERE id = ?",
            params=(user['id'],)
        )

        try:
            details = json.dumps({"email": user['email']})
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                params=(user.get('org_id'), user.get('id'), 'email_verified', details)
            )
        except Exception:
            pass

        print(f"[EMAIL-VERIFY] Email verified successfully for user_id={user['id']}")
        return jsonify({"status": "success", "message": "Email verified successfully! You can now log in to your account."})
    except MySQLError as e:
        print(f"[EMAIL-VERIFY] DB error: {e}")
        return jsonify({"status": "error", "message": "Email verification failed. Please try again."}), 500

@limiter.limit(RATE_LIMIT_LOGIN)
@app.route('/api/login', methods=['POST'])
def login():
    """
    Validate admin/client credentials and initiate the appropriate login flow.

    For admin users this endpoint now performs only password validation and,
    when successful, issues a one-time passcode (OTP) via email. JWT tokens are
    no longer returned here; callers must complete the second step by invoking
    `/api/auth/verify-otp` with the emailed code to obtain access and refresh
    tokens. Clients should treat the `{"status": "otp_sent"}` response as the
    new success path. If single-step logins are still required by legacy
    consumers, they should remain on a dedicated versioned route (for example
    `/api/login/v1`) while `/api/login` stays dedicated to the two-step flow.
    Repeated invalid OTP attempts will lock the account (status `locked`) until
    an administrator resets it. Client (access-code) logins continue to behave
    as before.
    """
    data = request.get_json()
    login_type = data.get('type')
    
    try:
        if login_type == 'admin':
            email = data.get('email')
            password = data.get('password')
            
            if not email or not password:
                return jsonify({"status": "error", "message": "Email and password are required."}), 400
            
            hashed_pass = hash_password(password)
            
            # Query user from primary database
            result = execute_primary_query(
                "SELECT id, email, password, role, status, org_id, COALESCE(is_email_verified, 1) AS is_email_verified FROM users WHERE email = ? AND password = ?",
                (email, hashed_pass),
                fetch_one=True
            )
            
            if result:
                # Normalize result across mysql (tuple) and dict.
                if isinstance(result, dict):
                    user = result
                elif hasattr(result, "keys"):
                    user = dict(result)
                else:
                    cols = ["id", "email", "password", "role", "status", "org_id", "is_email_verified"]
                    user = {col: result[idx] for idx, col in enumerate(cols) if idx < len(result)}
                user_status = user.get('status')
                if user_status in (USER_STATUS_APPROVED, USER_STATUS_ACTIVE):
                    if int(user.get('is_email_verified', 1)) == 0:
                        try:
                            details = json.dumps({"email": email, "reason": "email_not_verified", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'login_failed', details))
                        except Exception:
                            pass
                        return jsonify({"status": "error", "message": "Please verify your email address before logging in. Check your inbox for the verification link."}), 403
                    
                    # Check if org_admin or org_user has valid org_id
                    if user['role'] in [ROLE_ORG_ADMIN, ROLE_ORG_USER]:
                        if user['org_id'] is None:
                            print(f"[LOGIN] WARNING: User {email} (role={user['role']}) has NULL org_id - login allowed but tenant access will fail")
                            # Log to audit_logs for tracking
                            try:
                                details = json.dumps({
                                    "email": email,
                                    "role": user['role'],
                                    "issue": "null_org_id",
                                    "ip_address": request.remote_addr
                                })
                                execute_primary_query(
                                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                                    (None, user['id'], 'login_warning_null_org_id', details)
                                )
                            except Exception:
                                pass
                    
                    otp_code = str(secrets.randbelow(1000000)).zfill(6)
                    otp_expires_at = (datetime.now() + timedelta(minutes=OTP_EXPIRY_MINUTES)).strftime('%Y-%m-%d %H:%M:%S')
                    encrypted_otp = encrypt_otp(otp_code)

                    execute_primary_query(
                        "UPDATE users SET otp_code = ?, otp_expires_at = ?, otp_attempts = 0, otp_verified = 0 WHERE id = ?",
                        (encrypted_otp, otp_expires_at, user['id'])
                    )

                    email_success, email_error = send_otp_email(
                        to_email=email,
                        otp_code=otp_code,
                        user_name=get_name_from_email(email),
                        org_id=user.get('org_id'),
                        user_id=user.get('id')
                    )

                    if not email_success:
                        try:
                            details = json.dumps({
                                "email": email,
                                "reason": email_error or "otp_email_failed",
                                "ip_address": request.remote_addr,
                                "user_agent": request.headers.get('User-Agent')
                            })
                            execute_primary_query(
                                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                                (user.get('org_id'), user.get('id'), 'otp_send_failed', details)
                            )
                        except Exception:
                            pass
                        return jsonify({"status": "error", "message": "Failed to send OTP email. Please try again."}), 500

                    try:
                        details = json.dumps({"email": email, "ip_address": request.remote_addr})
                        execute_primary_query(
                            "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                            (user.get('org_id'), user.get('id'), 'otp_generated', details)
                        )
                    except Exception:
                        pass

                    return jsonify({
                        "status": "otp_sent",
                        "message": "OTP sent to your email",
                        "email": email,
                        "expires_in_minutes": OTP_EXPIRY_MINUTES
                    })
                elif user_status == USER_STATUS_PENDING:
                    try:
                        details = json.dumps({"email": email, "reason": "account_not_approved", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                        execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'login_failed', details))
                    except Exception:
                        pass
                    return jsonify({"status": "error", "message": "Your account is pending approval."}), 403
                elif user_status == USER_STATUS_LOCKED:
                    try:
                        details = json.dumps({"email": email, "reason": "account_locked", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                        execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (user.get('org_id'), user.get('id'), 'login_failed_locked', details))
                    except Exception:
                        pass
                    return jsonify({"status": "error", "message": "Your account is locked due to repeated invalid OTP attempts. Please contact support."}), 403
                else:
                    try:
                        details = json.dumps({"email": email, "reason": f"account_status_{user_status}", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                        execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (user.get('org_id'), user.get('id'), 'login_failed_status', details))
                    except Exception:
                        pass
                    return jsonify({"status": "error", "message": "Your account is not allowed to login. Please contact support."}), 403
            try:
                details = json.dumps({"email": data.get('email'), "reason": "invalid_credentials", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'login_failed', details))
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Invalid admin credentials."}), 401

        elif login_type == 'client':
            access_code = data.get('access_code')
            
            if not access_code:
                return jsonify({"status": "error", "message": "Access code is required."}), 400
            
            # Query project from database
            result = execute_query(
                "SELECT name FROM projects WHERE client_access_code = ?",
                (access_code,),
                fetch_one=True
            )
            
            if result:
                project = dict_to_row(result)
                
                # Generate JWT tokens for client with custom claims
                additional_claims = {
                    'org_id': None,
                    'role': 'client',
                    'plan': None,
                    'email': None,
                    'user_id': None,
                    'project': project['name']
                }
                
                access_token = create_access_token(identity='client', additional_claims=additional_claims)
                refresh_token = create_refresh_token(identity='client', additional_claims=additional_claims)
                
                return jsonify({
                    "status": "success",
                    "access_token": access_token,
                    "refresh_token": refresh_token,
                    "userType": "client",
                    "project": project['name']
                })
            try:
                details = json.dumps({"reason": "invalid_client_access_code", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
                execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'login_failed', details))
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Invalid Client Access Code."}), 401
            
        try:
            details = json.dumps({"reason": "invalid_login_type", "ip_address": request.remote_addr, "user_agent": request.headers.get('User-Agent')})
            execute_primary_query("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", (None, None, 'login_failed', details))
        except Exception:
            pass
        return jsonify({"status": "error", "message": "Invalid login type."}), 400
        
    except MySQLError as e:
        print(f"Database error in login: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500

@limiter.limit("10 per minute")
@app.route('/api/auth/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json() or {}
    email = data.get('email')
    otp_code = data.get('otp_code')

    if not email or not otp_code:
        return jsonify({"status": "error", "message": "Email and OTP code are required."}), 400

    try:
        result = execute_primary_query(
            "SELECT id, email, role, status, org_id, otp_code, otp_expires_at, otp_attempts FROM users WHERE email = ?",
            (email,),
            fetch_one=True
        )

        if not result:
            return jsonify({"status": "error", "message": "User not found."}), 404

        # Normalize result across mysql (tuple) and dict.
        if isinstance(result, dict):
            user = result
        elif hasattr(result, "keys"):
            user = dict(result)
        else:
            cols = ["id", "email", "role", "status", "org_id", "otp_code", "otp_expires_at", "otp_attempts"]
            user = {col: result[idx] for idx, col in enumerate(cols) if idx < len(result)}
        user_status = user.get('status')
        if user_status not in (USER_STATUS_APPROVED, USER_STATUS_ACTIVE):
            try:
                details = json.dumps({
                    "email": email,
                    "reason": f"otp_status_block_{user_status}",
                    "ip_address": request.remote_addr
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'otp_status_blocked', details)
                )
            except Exception:
                pass

            if user_status == USER_STATUS_PENDING:
                return jsonify({"status": "error", "message": "Your account is pending approval."}), 403
            if user_status == USER_STATUS_LOCKED:
                return jsonify({"status": "error", "message": "Your account is locked due to repeated invalid OTP attempts. Please contact support."}), 403
            return jsonify({"status": "error", "message": "Your account is not allowed to login. Please contact support."}), 403

        stored_attempts = user.get('otp_attempts') or 0

        expires_at_raw = user.get('otp_expires_at')
        if not expires_at_raw:
            return jsonify({"status": "error", "message": "OTP not requested. Please login again."}), 400

        # Handle datetime values from MySQL connectors which may already be datetime objects.
        if isinstance(expires_at_raw, datetime):
            expires_at = expires_at_raw
        else:
            try:
                expires_at = datetime.strptime(expires_at_raw, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                expires_at = datetime.fromisoformat(expires_at_raw)

        if datetime.now() > expires_at:
            return jsonify({"status": "error", "message": "OTP has expired. Please request a new one."}), 400

        if stored_attempts >= OTP_MAX_ATTEMPTS:
            execute_primary_query(
                "UPDATE users SET status = ?, otp_code = NULL, otp_expires_at = NULL WHERE id = ?",
                (USER_STATUS_LOCKED, user['id'])
            )
            try:
                details = json.dumps({
                    "email": email,
                    "ip_address": request.remote_addr,
                    "attempts": stored_attempts
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'otp_max_attempts_exceeded', details)
                )
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Maximum OTP attempts exceeded. Your account is locked. Please contact support."}), 403

        decrypted_otp = decrypt_otp(user.get('otp_code')) if user.get('otp_code') else None
        if not decrypted_otp or decrypted_otp != otp_code:
            execute_primary_query(
                "UPDATE users SET otp_attempts = COALESCE(otp_attempts, 0) + 1 WHERE id = ?",
                (user['id'],)
            )
            attempts_made = stored_attempts + 1
            attempts_remaining = max(OTP_MAX_ATTEMPTS - attempts_made, 0)
            try:
                details = json.dumps({
                    "email": email,
                    "ip_address": request.remote_addr,
                    "attempts_remaining": attempts_remaining
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'otp_verification_failed', details)
                )
            except Exception:
                pass
            if attempts_remaining == 0:
                execute_primary_query(
                    "UPDATE users SET status = ?, otp_code = NULL, otp_expires_at = NULL WHERE id = ?",
                    (USER_STATUS_LOCKED, user['id'])
                )
                try:
                    details = json.dumps({
                        "email": email,
                        "ip_address": request.remote_addr,
                        "attempts": attempts_made
                    })
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (user.get('org_id'), user.get('id'), 'otp_max_attempts_exceeded', details)
                    )
                except Exception:
                    pass
                message = "Maximum OTP attempts exceeded. Your account is locked. Please contact support."
                status_code = 403
            else:
                message = f"Invalid OTP. {attempts_remaining} attempts remaining."
                status_code = 401
            return jsonify({
                "status": "error",
                "message": message,
                "attempts_remaining": attempts_remaining
            }), status_code

        execute_primary_query(
            "UPDATE users SET otp_code = NULL, otp_expires_at = NULL, otp_attempts = 0, otp_verified = 1 WHERE id = ?",
            (user['id'],)
        )

        plan = None
        if user['org_id']:
            subscription_result = execute_primary_query(
                "SELECT plan_type FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
                (user['org_id'],),
                fetch_one=True
            )
            if subscription_result:
                if isinstance(subscription_result, dict):
                    plan = subscription_result.get('plan_type')
                elif hasattr(subscription_result, "keys"):
                    plan = dict(subscription_result).get('plan_type')
                else:
                    plan = subscription_result[0] if len(subscription_result) > 0 else None

        additional_claims = {
            'org_id': user['org_id'],
            'role': user['role'],
            'plan': plan,
            'email': user['email'],
            'user_id': user['id']
        }

        access_token = create_access_token(identity=str(user['id']), additional_claims=additional_claims)
        refresh_token = create_refresh_token(identity=str(user['id']), additional_claims=additional_claims)

        try:
            details = json.dumps({"email": email, "ip_address": request.remote_addr})
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (user.get('org_id'), user.get('id'), 'otp_verification_success', details)
            )
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (user.get('org_id'), user.get('id'), 'login_success', details)
            )
        except Exception:
            pass

        log_primary_activity(email, "User Login", "Admin successfully logged in.", user.get('org_id'), user.get('id'))

        return jsonify({
            "status": "success",
            "access_token": access_token,
            "refresh_token": refresh_token,
            "userType": user['role'],
            "email": user['email'],
            "name": get_name_from_email(user['email'])
        })

    except MySQLError as e:
        print(f"Database error in verify_otp: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Error verifying OTP: {e}")
        return jsonify({"status": "error", "message": "Failed to verify OTP"}), 500

def forgot_password_rate_limit_key():
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower() or 'unknown'
    ip_addr = request.remote_addr or 'unknown'
    return f"{ip_addr}:{email}"


@limiter.limit("3 per hour", key_func=forgot_password_rate_limit_key)
@app.route('/api/auth/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()

    if not email or not validate_email_format(email):
        return jsonify({"status": "error", "message": "A valid email address is required."}), 400

    generic_response = {
        "status": "success",
        "message": "If an account exists with this email, you will receive a password reset link shortly."
    }

    try:
        result = execute_primary_query(
            "SELECT id, email, status, org_id FROM users WHERE lower(email) = ?",
            (email,),
            fetch_one=True
        )

        if not result:
            try:
                details = json.dumps({
                    "email": email,
                    "reason": "user_not_found",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (None, None, 'password_reset_requested_unknown', details)
                )
            except Exception:
                pass
            return jsonify(generic_response)

        user = dict_to_row(result)
        user_status = user.get('status')
        if user_status not in (USER_STATUS_APPROVED, USER_STATUS_ACTIVE):
            try:
                details = json.dumps({
                    "email": email,
                    "reason": f"reset_not_allowed_status_{user_status}",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'password_reset_failed', details)
                )
            except Exception:
                pass
            return jsonify(generic_response)

        reset_token = secrets.token_urlsafe(32)
        expires_at = (datetime.now() + timedelta(hours=RESET_TOKEN_EXPIRY_HOURS)).strftime('%Y-%m-%d %H:%M:%S')

        execute_primary_query(
            "UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?",
            (reset_token, expires_at, user['id'])
        )

        reset_link = f"{request.url_root}?reset_token={reset_token}"
        success, error = send_password_reset_email(
            to_email=user['email'],
            reset_link=reset_link,
            user_name=get_name_from_email(user['email']),
            org_id=user.get('org_id'),
            user_id=user.get('id')
        )

        if not success:
            try:
                details = json.dumps({
                    "email": email,
                    "reason": error or "email_send_failed",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'password_reset_failed', details)
                )
            except Exception:
                pass
            print(f"Password reset email failed for {email}: {error}")
            return jsonify(generic_response)

        try:
            details = json.dumps({
                "email": email,
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get('User-Agent'),
                "expires_at": expires_at
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (user.get('org_id'), user.get('id'), 'password_reset_requested', details)
            )
        except Exception:
            pass

        return jsonify(generic_response)

    except MySQLError as e:
        print(f"Database error in forgot_password: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Error handling forgot password: {e}")
        return jsonify({"status": "error", "message": "Failed to process request"}), 500

@limiter.limit("5 per minute")
@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json() or {}
    reset_token = (data.get('reset_token') or '').strip()
    new_password = data.get('new_password')

    if not reset_token:
        return jsonify({"status": "error", "message": "Reset token is required."}), 400

    is_valid, validation_message = validate_password_strength(new_password)
    if not is_valid:
        return jsonify({"status": "error", "message": validation_message}), 400

    try:
        result = execute_primary_query(
            "SELECT id, email, status, org_id, reset_token_expires_at FROM users WHERE reset_token = ?",
            (reset_token,),
            fetch_one=True
        )

        if not result:
            try:
                details = json.dumps({
                    "reason": "invalid_reset_token",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (None, None, 'password_reset_failed', details)
                )
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Invalid or expired reset token."}), 400

        user = dict_to_row(result)
        user_status = user.get('status')

        expires_raw = user.get('reset_token_expires_at')
        if not expires_raw:
            return jsonify({"status": "error", "message": "Invalid or expired reset token."}), 400

        try:
            expires_at = datetime.strptime(expires_raw, '%Y-%m-%d %H:%M:%S')
        except ValueError:
            expires_at = datetime.fromisoformat(expires_raw)

        if datetime.now() > expires_at:
            try:
                details = json.dumps({
                    "email": user.get('email'),
                    "reason": "reset_token_expired",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'password_reset_failed', details)
                )
            except Exception:
                pass
            try:
                execute_primary_query(
                    "UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?",
                    (user['id'],)
                )
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Invalid or expired reset token."}), 400

        if user_status not in (USER_STATUS_APPROVED, USER_STATUS_ACTIVE):
            try:
                details = json.dumps({
                    "email": user.get('email'),
                    "reason": f"reset_not_allowed_status_{user_status}",
                    "ip_address": request.remote_addr,
                    "user_agent": request.headers.get('User-Agent')
                })
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (user.get('org_id'), user.get('id'), 'password_reset_failed', details)
                )
            except Exception:
                pass
            return jsonify({"status": "error", "message": "Password reset not allowed for this account."}), 403

        hashed_password = hash_password(new_password)
        execute_primary_query(
            "UPDATE users SET password = ?, reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?",
            (hashed_password, user['id'])
        )

        try:
            details = json.dumps({
                "email": user.get('email'),
                "ip_address": request.remote_addr,
                "user_agent": request.headers.get('User-Agent')
            })
            execute_primary_query(
                "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                (user.get('org_id'), user.get('id'), 'password_reset_completed', details)
            )
        except Exception:
            pass

        return jsonify({"status": "success", "message": "Password reset successfully. You can now log in with your new password."})

    except MySQLError as e:
        print(f"Database error in reset_password: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Error resetting password: {e}")
        return jsonify({"status": "error", "message": "Failed to reset password"}), 500

@app.route('/api/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh_token():
    """Refresh access token using valid refresh token.
    
    The new access token will expire at the same time as the refresh token
    (30 days from initial login), ensuring users are logged out after 30 days
    and must re-authenticate with OTP.
    """
    try:
        current_user_id = get_jwt_identity()
        current_claims = get_jwt()
        
        # Extract existing claims
        additional_claims = {
            'org_id': current_claims.get('org_id'),
            'role': current_claims.get('role'),
            'plan': current_claims.get('plan'),
            'email': current_claims.get('email'),
            'user_id': current_claims.get('user_id'),
            'project': current_claims.get('project')
        }
        
        # Get refresh token expiry time (exp claim is Unix timestamp)
        refresh_exp = current_claims.get('exp')
        if refresh_exp:
            # Calculate remaining time until refresh token expires
            refresh_exp_datetime = datetime.fromtimestamp(refresh_exp)
            now = datetime.now(timezone.utc)
            remaining_time = refresh_exp_datetime - now
            
            # Ensure access token expires when refresh token expires (or earlier)
            # This ensures users are logged out after 30 days from initial login
            expires_delta = remaining_time if remaining_time.total_seconds() > 0 else timedelta(seconds=0)
        else:
            # Fallback to default 30 days if exp not found
            expires_delta = timedelta(days=30)
        
        # Generate new access token with same claims, expiring when refresh token expires
        new_access_token = create_access_token(
            identity=current_user_id, 
            additional_claims=additional_claims,
            expires_delta=expires_delta
        )
        
        return jsonify({
            "status": "success",
            "access_token": new_access_token
        })
        
    except Exception as e:
        print(f"Error in token refresh: {e}")
        return jsonify({"status": "error", "message": "Failed to refresh token"}), 500

@app.route('/api/logout', methods=['POST'])
@jwt_required()
def logout():
    """Revoke the current access token by adding it to blocklist."""
    try:
        jwt_data = get_jwt()
        jti = jwt_data.get('jti')
        
        # Add token to blocklist
        revoked_tokens.add(jti)
        
        # Also check for refresh token in request body if provided
        data = request.get_json()
        if data and 'refresh_token' in data:
            # Note: In production, use proper token parsing instead of this approach
            pass
        
        # Get user email from claims for logging
        user_email = jwt_data.get('email', 'Unknown')
        log_primary_activity(user_email, "User Logout", "User successfully logged out.")
        
        return jsonify({
            "status": "success",
            "message": "Successfully logged out"
        })
        
    except Exception as e:
        print(f"Error in logout: {e}")
        return jsonify({"status": "error", "message": "Failed to logout"}), 500

@app.route('/api/client_login', methods=['POST'])
def client_login():
    data = request.get_json()
    access_code = data.get('access_code')
    
    if not access_code:
        return jsonify({"status": "error", "message": "Access code is required."}), 400
    
    try:
        # Query project from database
        result = execute_query(
            "SELECT name FROM projects WHERE client_access_code = ?",
            (access_code,),
            fetch_one=True
        )
        
        if result:
            project = dict_to_row(result)
            return jsonify({"status": "success", "userType": "client", "project": project['name']})
        return jsonify({"status": "error", "message": "Invalid Client Access Code."}), 401
        
    except MySQLError as e:
        print(f"Database error in client_login: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500

@app.route('/api/pending_admins', methods=['GET'])
@superadmin_required
def get_pending_admins():
    try:
        results = execute_primary_query(
            "SELECT email, role, status FROM users WHERE status = 'pending'",
            fetch_all=True
        )
        columns = ['email', 'role', 'status']
        pending = [dict(zip(columns, row)) for row in results] if results else []
        return jsonify(pending)
    except MySQLError as e:
        print(f"Database error in get_pending_admins: {e}")
        return jsonify([])

@app.route('/api/approve_admin', methods=['POST'])
@superadmin_required
def approve_admin():
    data = request.get_json()
    email_to_approve = data.get('email')
    if not email_to_approve:
        return jsonify({"status": "error", "message": "Email is required for approval."}), 400
    
    try:
        # Update user status to approved in primary database
        rows_affected = execute_primary_query(
            "UPDATE users SET status = 'approved' WHERE email = ? AND status = 'pending'",
            (email_to_approve,)
        )
        
        if rows_affected == 0:
            return jsonify({"status": "error", "message": "User not found or already approved."}), 404
            
        log_primary_activity(email_to_approve, "Approval", f"Admin account approved for {email_to_approve}.")
        
        return jsonify({"status": "success", "message": f"Admin '{email_to_approve}' has been approved."})
        
    except MySQLError as e:
        print(f"Database error in approve_admin: {e}")
        return jsonify({"status": "error", "message": "Failed to approve admin"}), 500

@app.route('/api/reject_admin', methods=['POST'])
@superadmin_required
def reject_admin():
    data = request.get_json()
    email_to_reject = data.get('email')
    if not email_to_reject:
        return jsonify({"status": "error", "message": "Email is required for rejection."}), 400
    
    try:
        # Delete pending user from primary database
        rows_affected = execute_primary_query(
            "DELETE FROM users WHERE email = ? AND status = 'pending'",
            (email_to_reject,)
        )
        
        if rows_affected == 0:
            return jsonify({"status": "error", "message": "User not found or not in a pending state."}), 404
            
        log_primary_activity(email_to_reject, "Rejection", f"Admin account rejected for {email_to_reject}.")
        
        return jsonify({"status": "success", "message": f"Admin request for '{email_to_reject}' has been rejected and removed."})
        
    except MySQLError as e:
        print(f"Database error in reject_admin: {e}")
        return jsonify({"status": "error", "message": "Failed to reject admin"}), 500


@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/projects', methods=['GET'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_projects():
    """Get all projects. All authenticated organization users can view projects."""
    try:
        # Note: client_access_code is exposed in project list - consider security implications
        # for non-admin contexts if needed in future iterations
        results = execute_tenant_query(
            "SELECT p.id, p.name, p.client_access_code, p.created_at, COALESCE(t.progress, 0) as overall_actual_progress FROM projects p LEFT JOIN tasks t ON p.id = t.project_id AND t.wbs = '1' ORDER BY p.created_at DESC",
            fetch_all=True,
            as_dict=True  # Return dict results for JSON serialization
        )
        # For MySQL (as_dict=True), results are already dicts
        projects = []
        if results:
            for row in results:
                if isinstance(row, dict):
                    projects.append(row)
                else:
                    projects.append(dict_to_row(row))
        return jsonify(projects)
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in get_projects: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500

@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/projects', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
@subscription_required
@check_plan_limit(RESOURCE_TYPE_PROJECT)
def create_project():
    """Create a new project. Only SuperAdmin and Org Admin can create projects."""
    try:
        data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['project_name','client_access_code','user_email'])
        project_name = sanitize_text_input(data.get('project_name') or '', max_length=100)
        valid, project_name, err = validate_and_sanitize_project_name(project_name)
        if not valid:
            return jsonify({"status": "error", "message": err}), 400
        client_access_code = sanitize_text_input(data.get('client_access_code') or '', max_length=128)

        if not project_name or not client_access_code:
            return jsonify({"status": "error", "message": "Project Name and Client Access Code are required."}), 400

        def _count_from_row(row):
            if isinstance(row, dict):
                return next(iter(row.values())) if row else 0
            if hasattr(row, "keys"):
                _tmp = dict(row)
                return next(iter(_tmp.values())) if _tmp else 0
            return row[0] if row else 0

        # Check if project name already exists
        result = execute_tenant_query("SELECT COUNT(*) FROM projects WHERE name = ?", (project_name,), fetch_one=True)
        if result and _count_from_row(result) > 0:
            return jsonify({"status": "error", "message": "A project with this name already exists."}), 409
        
        # Check if access code already exists
        result = execute_tenant_query("SELECT COUNT(*) FROM projects WHERE client_access_code = ?", (client_access_code,), fetch_one=True)
        if result and _count_from_row(result) > 0:
            return jsonify({"status": "error", "message": "This client access code is already in use."}), 409

        # Insert new project
        project_id = execute_tenant_query(
            "INSERT INTO projects (name, client_access_code) VALUES (?, ?)",
            (project_name, client_access_code),
            return_lastrowid=True
        )

        # Fetch the created project to return in response
        result = execute_tenant_query(
            "SELECT id, name, client_access_code, created_at FROM projects WHERE id = ?",
            (project_id,),
            fetch_one=True,
            as_dict=True  # Return dict for JSON serialization
        )
        new_project = result if isinstance(result, dict) else (dict_to_row(result) if result else None)
        
        # Log project creation activity
        creator_email = sanitize_text_input(data.get('user_email') or '')  # Get creator email if available in request context
        log_activity(creator_email, project_name, "Project Created", f"New project '{project_name}' created successfully.")
        
        # Invalidate usage cache after project creation
        try:
            ORG_USAGE_CACHE.pop(getattr(g, 'org_id', None), None)
        except Exception:
            pass
        return jsonify({"status": "success", "message": "Project added successfully.", "project": new_project})
        
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except mysql.connector.IntegrityError as e:
        if "UNIQUE constraint failed" in str(e) and "name" in str(e):
            return jsonify({"status": "error", "message": "A project with this name already exists."}), 409
        elif "UNIQUE constraint failed" in str(e) and "client_access_code" in str(e):
            return jsonify({"status": "error", "message": "This client access code is already in use."}), 409
        else:
            return jsonify({"status": "error", "message": "Project creation failed due to constraint violation."}), 409
    except MySQLError as e:
        print(f"Database error in create_project: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500

@app.route('/api/users', methods=['GET'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def get_users():
    """Get list of organization users for adding to projects."""
    try:
        # Get users from primary DB (same pattern as /api/org/users)
        if g.role == ROLE_SUPER_ADMIN:
            users = execute_primary_query(
                "SELECT id, email, role, org_id, status, created_at FROM users ORDER BY created_at DESC",
                fetch_all=True
            )
        elif g.role == ROLE_ORG_ADMIN:
            users = execute_primary_query(
                "SELECT id, email, role, org_id, status, created_at FROM users WHERE org_id = ? ORDER BY created_at DESC",
                (g.org_id,),
                fetch_all=True
            )
        else:
            return jsonify({"status": "error", "message": "Access denied"}), 403
        
        columns = ['id', 'email', 'role', 'org_id', 'status', 'created_at']
        user_list = [dict(zip(columns, user)) for user in users] if users else []
        # Add name field (using email as name if name not available)
        for user in user_list:
            if 'name' not in user:
                user['name'] = user.get('email', 'Unknown')
        
        return jsonify({"status": "success", "users": user_list})
    except MySQLError as e:
        app.logger.error(f'Database error in get_users: {e}')
        return jsonify({"status": "error", "message": "Failed to retrieve users"}), 500

@app.route('/api/projects/<project_id>/members', methods=['GET', 'POST'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def project_members(project_id):
    """Get or add project members."""
    try:
        # Validate project exists
        project_result = execute_tenant_query(
            "SELECT id, name FROM projects WHERE name = ? OR id = ?",
            (project_id, project_id),
            fetch_one=True
        )
        if not project_result:
            return jsonify({"status": "error", "message": "Project not found"}), 404
        
        project_row = dict(zip(['id', 'name'], project_result))
        actual_project_id = project_row['id']
        project_name = project_row['name']
        
        # Ensure project_members table exists
        try:
            if DB_TYPE.lower() == "mysql":
                execute_tenant_query("""
                    CREATE TABLE IF NOT EXISTS project_members (
                        id INT AUTO_INCREMENT PRIMARY KEY,
                        project_id INT NOT NULL,
                        user_id INT NOT NULL,
                        role VARCHAR(50) NOT NULL DEFAULT 'viewer',
                        permissions TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        UNIQUE KEY uq_project_user (project_id, user_id)
                    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
                """)
            else:
                execute_tenant_query("""
                    CREATE TABLE IF NOT EXISTS project_members (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        project_id INTEGER NOT NULL,
                        user_id INTEGER NOT NULL,
                        role TEXT NOT NULL DEFAULT 'viewer',
                        permissions TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE,
                        UNIQUE(project_id, user_id)
                    )
                """)
        except MySQLError:
            pass  # Table might already exist
        
        if request.method == 'GET':
            # Get all members for this project
            members_result = execute_tenant_query("""
                SELECT pm.user_id, pm.role, pm.permissions
                FROM project_members pm
                WHERE pm.project_id = ?
            """, (actual_project_id,), fetch_all=True)
            
            members = []
            for row in (members_result or []):
                columns = ['user_id', 'role', 'permissions']
                row_dict = dict(zip(columns, row))
                user_id = int(row_dict.get('user_id')) if row_dict and row_dict.get('user_id') is not None else None
                role = row_dict.get('role', 'viewer')
                permissions = row_dict.get('permissions')
                email = row_dict.get('email')
                
                # Get user info from primary DB
                user_info_raw = execute_primary_query(
                    "SELECT email FROM users WHERE id = ?",
                    (user_id,),
                    fetch_one=True
                )
                user_info = {'email': user_info_raw[0]} if user_info_raw else None
                user_email = user_info.get('email') if user_info else email
                user_name = user_email  # Use email as name if name not available
                
                members.append({
                    'user_id': user_id,
                    'name': user_name or '',
                    'email': user_email or '',
                    'role': role or 'viewer',
                    'permissions': permissions
                })
            
            return jsonify({"status": "success", "members": members})
        
        elif request.method == 'POST':
            # Add a new member
            if g.role not in [ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN]:
                return jsonify({"status": "error", "message": "Only admins can add project members"}), 403
            
            data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['user_id', 'role', 'permissions'])
            user_id = data.get('user_id')
            role = sanitize_text_input(data.get('role') or 'viewer', max_length=50)
            permissions = data.get('permissions')
            
            if not user_id:
                return jsonify({"status": "error", "message": "user_id is required"}), 400
            
            # Validate user_id is integer
            try:
                user_id = int(user_id)
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid user_id"}), 400
            
            # Validate user exists in org
            user_check_raw = execute_primary_query(
                "SELECT id, email, org_id FROM users WHERE id = ?",
                (user_id,),
                fetch_one=True
            )
            user_check = dict(zip(['id', 'email', 'org_id'], user_check_raw))
            if not user_check:
                return jsonify({"status": "error", "message": "User not found"}), 404
            
            user_org_id = user_check.get('org_id') if isinstance(user_check, dict) else (user_check[2] if len(user_check) > 2 else None)
            if g.role == ROLE_ORG_ADMIN and user_org_id != g.org_id:
                return jsonify({"status": "error", "message": "User does not belong to your organization"}), 403
            
            # Insert or update project member
            try:
                upsert_query = """
                    INSERT INTO project_members (project_id, user_id, role, permissions)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(project_id, user_id) DO UPDATE SET
                        role = excluded.role,
                        permissions = excluded.permissions
                """ if DB_TYPE.lower() != "mysql" else """
                    INSERT INTO project_members (project_id, user_id, role, permissions)
                    VALUES (?, ?, ?, ?)
                    ON DUPLICATE KEY UPDATE
                        role = VALUES(role),
                        permissions = VALUES(permissions)
                """
                execute_tenant_query(
                    upsert_query,
                    (actual_project_id, user_id, role, json.dumps(permissions) if permissions else None)
                )
            except (mysql.connector.IntegrityError, MySQLError):
                return jsonify({"status": "error", "message": "Member already exists"}), 409
            
            return jsonify({"status": "success", "message": "Member added successfully"})
            
    except MySQLError as e:
        app.logger.error(f'Database error in project_members: {e}')
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        app.logger.error(f'Error in project_members: {str(e)}')
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/projects/<project_id>/members/<int:user_id>', methods=['DELETE'])
@app.route('/api/projects/<project_id>/members/<int:user_id>/role', methods=['PUT'])
@app.route('/api/projects/<project_id>/members/<int:user_id>/permissions', methods=['PUT'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def project_member_operations(project_id, user_id):
    """Handle DELETE, PUT role, and PUT permissions operations for project members."""
    """Delete member, update role, or update permissions."""
    try:
        # Validate project exists
        project_result_raw = execute_tenant_query(
            "SELECT id FROM projects WHERE name = ? OR id = ?",
            (project_id, project_id),
            fetch_one=True
        )
        project_result = dict_to_row(project_result_raw)
        if not project_result_raw:
            return jsonify({"status": "error", "message": "Project not found"}), 404
        
        actual_project_id = project_result.get('id') if isinstance(project_result, dict) else project_result[0]
        
        if request.method == 'DELETE':
            # Delete member
            execute_tenant_query(
                "DELETE FROM project_members WHERE project_id = ? AND user_id = ?",
                (actual_project_id, user_id)
            )
            return jsonify({"status": "success", "message": "Member removed successfully"})
        
        elif request.method == 'PUT':
            if '/role' in request.path:
                # Update role
                data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['role'])
                new_role = sanitize_text_input(data.get('role') or 'viewer', max_length=50)
                
                execute_tenant_query(
                    "UPDATE project_members SET role = ? WHERE project_id = ? AND user_id = ?",
                    (new_role, actual_project_id, user_id)
                )
                return jsonify({"status": "success", "message": "Role updated successfully"})
            
            elif '/permissions' in request.path:
                # Update permissions
                data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['permissions'])
                permissions = data.get('permissions')
                
                execute_tenant_query(
                    "UPDATE project_members SET permissions = ? WHERE project_id = ? AND user_id = ?",
                    (json.dumps(permissions) if permissions else None, actual_project_id, user_id)
                )
                return jsonify({"status": "success", "message": "Permissions updated successfully"})
        
    except MySQLError as e:
        app.logger.error(f'Database error in project_member_operations: {e}')
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        app.logger.error(f'Error in project_member_operations: {str(e)}')
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/activity_log', methods=['GET'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def get_activity_log():
    """Serves the content of the activity log database with pagination."""
    try:
        # Query the latest 100 activity log entries with project names using LEFT JOIN
        results = execute_tenant_query(
            "SELECT a.timestamp, a.user_email, p.name AS project_name, a.action, a.details FROM activity_logs a LEFT JOIN projects p ON a.project_id = p.id ORDER BY a.timestamp DESC LIMIT 100",
            fetch_all=True
        )
        
        if not results:
            return jsonify([])
        
        # Build response with project names from the JOIN
        logs = []
        for row in results:
            log_entry = {
                "timestamp": row[0],
                "user": row[1],
                "project": row[2],  # project_name from the JOIN
                "action": row[3],
                "details": row[4]
            }
            logs.append(log_entry)
        
        return jsonify(logs)
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify([])
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify([])
    except MySQLError as e:
        print(f"Database error in get_activity_log: {e}")
        return jsonify([])

@app.route('/api/activity_log/download', methods=['GET'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
def download_activity_log():
    """Downloads the complete activity log as CSV."""
    try:
        # Query all activity logs from database with project names using LEFT JOIN
        results = execute_tenant_query(
            "SELECT a.timestamp, a.user_email, p.name AS project_name, a.action, a.details FROM activity_logs a LEFT JOIN projects p ON a.project_id = p.id ORDER BY a.timestamp DESC",
            fetch_all=True
        )
        
        if not results:
            return jsonify({"status": "error", "message": "No activity log found"}), 404
        
        import csv
        import io
        
        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['Timestamp', 'User', 'Project', 'Action', 'Details'])
        
        # Write data with project names from the JOIN
        for row in results:
            writer.writerow([
                row[0],  # timestamp
                row[1],  # user_email
                row[2] or '',  # project_name from the JOIN (or empty string if NULL)
                row[3],  # action
                row[4]   # details
            ])
        
        from flask import Response
        output.seek(0)
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=activity_log.csv'}
        )
    except TenantDatabaseError as e:
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        return jsonify({"status": "error", "message": f"Database error: {str(e)}"}), 500
@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/translate', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
@check_plan_limit(RESOURCE_TYPE_AI_PROMPT)
def translate_text():
    data = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['texts','target_lang'])
    texts_to_translate = data.get('texts')
    target_lang = sanitize_text_input(data.get('target_lang') or '', max_length=16)

    if not texts_to_translate or not target_lang:
        return jsonify({"status": "error", "message": "Missing 'texts' or 'target_lang' in request"}), 400

    try:
        # Use the new library
        translated_data = {}
        for key, text in texts_to_translate.items():
            # The translate method is simpler
            translated_text = GoogleTranslator(source='auto', target=target_lang).translate(text)
            translated_data[key] = translated_text

        # Track AI usage after a successful operation
        try:
            track_ai_prompt_usage(getattr(g, 'org_id', None), getattr(g, 'user_id', None), AI_ACTION_TRANSLATION, { 'target_lang': target_lang })
            # Invalidate usage cache after AI usage
            try:
                ORG_USAGE_CACHE.pop(getattr(g, 'org_id', None), None)
            except Exception:
                pass
        except Exception:
            pass
        return jsonify({"status": "success", "translations": translated_data})
    except TenantDatabaseError as e:
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500
    
@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/gemini/generate-content', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
@check_plan_limit(RESOURCE_TYPE_AI_PROMPT)
def gemini_generate_content():
    """
    Proxy endpoint for Google Gemini generateContent API.
    Accepts a JSON body with:
      - contents: list (chat history/messages)
      - use_chatbot_key: bool (if true, use CHATBOT_GEMINI_API_KEY)
    Returns a response shaped like the Gemini API:
      { "candidates": [ { "content": { "parts": [ { "text": "..." } ] } } ] }
    """
    try:
        data = sanitize_json_input(
            request.get_json(silent=True) or {},
            allowed_keys=['contents', 'use_chatbot_key']
        )

        contents = data.get('contents')
        use_chatbot_key = bool(data.get('use_chatbot_key', False))

        if not isinstance(contents, list) or not contents:
            return jsonify({
                "status": "error",
                "message": "Invalid request: 'contents' must be a non-empty list."
            }), 400

        selected_key = CHATBOT_GEMINI_API_KEY if use_chatbot_key else GEMINI_API_KEY
        if not selected_key:
            return jsonify({
                "status": "error",
                "message": "Gemini API key not configured."
            }), 500

        try:
            client = genai.Client(api_key=selected_key)
            response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=contents,
            )

            # Extract response text safely; fall back to the older structure if needed
            response_text = getattr(response, "text", "") or ""
            if not response_text:
                try:
                    response_text = (
                        response.candidates[0].content.parts[0].text
                        if getattr(response, "candidates", None)
                        else ""
                    )
                except Exception:
                    response_text = ""

            # Track AI usage
            try:
                org_id = getattr(g, 'org_id', None)
                user_id = getattr(g, 'user_id', None)
                action = AI_ACTION_CHATBOT if use_chatbot_key else AI_ACTION_TASK_UPDATE
                track_ai_prompt_usage(org_id, user_id, action, {'model': 'gemini-2.5-flash'})
                ORG_USAGE_CACHE.pop(org_id, None)
            except Exception:
                pass

            return jsonify({
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"text": response_text}
                            ]
                        }
                    }
                ]
            }), 200
        except TenantDatabaseError:
            return jsonify({
                "status": "error",
                "message": "Unable to access organization database. Please contact support."
            }), 500
        except TenantResolutionError:
            return jsonify({
                "status": "error",
                "message": "Organization not found or inactive."
            }), 404
        except Exception as e:
            return jsonify({
                "status": "error",
                "message": str(e)
            }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e)
        }), 500


@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/projects/<project_name>/ai-insights', methods=['GET'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
def get_ai_insights_for_project(project_name):
    """Return stored AI insights for a specific project, if available."""
    try:
        if not project_name:
            return jsonify({"status": "error", "message": "Project name is required."}), 400

        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found."}), 404

        stored = get_project_ai_insights(project_id)
        if not stored:
            return jsonify({"status": "success", "insights": None, "updated_at": None}), 200

        return jsonify({
            "status": "success",
            "insights": stored.get("insights"),
            "updated_at": stored.get("updated_at"),
        }), 200
    except TenantDatabaseError as e:
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except Exception as e:
        with open("debug_error.log", "a") as f:
            f.write(f"Error in get_ai_insights_for_project (name={project_name}): {e}\n")
        print(f"Error in get_ai_insights_for_project: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/projects/<project_name>/ai-insights', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
def save_ai_insights_for_project(project_name):
    """Persist AI insights for a specific project. Called after Gemini generation on the client."""
    try:
        if not project_name:
            return jsonify({"status": "error", "message": "Project name is required."}), 400

        data = request.get_json(silent=True) or {}
        insights = data.get("insights")
        if insights is None:
            return jsonify({"status": "error", "message": "Request body must include 'insights'."}), 400

        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found."}), 404

        ok = upsert_project_ai_insights(project_id, insights)
        if not ok:
            return jsonify({"status": "error", "message": "Failed to save AI insights."}), 500

        # Invalidate usage cache (insights can affect perceived usage context)
        try:
            ORG_USAGE_CACHE.pop(getattr(g, 'org_id', None), None)
        except Exception:
            pass

        return jsonify({"status": "success"}), 200
    except TenantDatabaseError as e:
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/download_attachments/<project_name>/<task_id>/<comment_id>', methods=['GET'])
@jwt_required()
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER, ROLE_CLIENT])
def download_attachments(project_name, task_id, comment_id):
    try:
        # Explicit org_id validation and SuperAdmin override handling
        target_org_id = getattr(g, 'org_id', None)
        if getattr(g, 'role', None) == ROLE_SUPER_ADMIN:
            query_org_id = request.args.get('org_id', type=int)
            if query_org_id:
                target_org_id = query_org_id
        if target_org_id is None and getattr(g, 'role', None) != ROLE_SUPER_ADMIN:
            return jsonify({"error": "Organization context required"}), 403
        # Get project ID and load tasks from database
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"error": "Project not found"}), 404

        project_tasks = load_tasks_from_db(project_id)
        if not project_tasks:
            return jsonify({"error": "Project not found"}), 404

        task = find_task_by_id_recursive(project_tasks, task_id)
        if not task or 'clientComments' not in task:
            return jsonify({"error": "Task not found"}), 404

        comment = next((c for c in task['clientComments'] if c.get('id') == comment_id), None)
        if not comment or not comment.get('attachments'):
            return jsonify({"error": "Comment or attachments not found"}), 404
    except MySQLError as e:
        print(f"Database error in download_attachments: {e}")
        return jsonify({"error": "Database error"}), 500

    memory_file = io.BytesIO()
    with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
        for file_path in comment['attachments']:
            try:
                # Construct correct absolute paths under the upload root
                base_root = os.path.abspath(UPLOAD_FOLDER)
                org_root = os.path.normpath(os.path.join(base_root, str(target_org_id)))

                # Reject dangerous inputs
                if not file_path or file_path.startswith(os.sep) or '..' in file_path or '\\' in file_path:
                    raise ValueError('Invalid attachment path')

                if os.path.basename(file_path) == file_path:
                    # filename-only: sanitize and use secure path helper
                    from werkzeug.utils import secure_filename as _secure_filename
                    safe_name = _secure_filename(file_path)
                    full_file_path = get_secure_file_path(target_org_id, project_name, task_id, safe_name)
                else:
                    # Multi-segment path: sanitize segments and ensure within org_root
                    norm_rel = os.path.normpath(file_path)
                    parts = [p for p in norm_rel.split(os.sep) if p and p not in ('.',)]
                    from werkzeug.utils import secure_filename as _secure_filename
                    sanitized_parts = [_secure_filename(seg) for seg in parts]
                    candidate = os.path.normpath(os.path.join(org_root, *sanitized_parts))
                    if not candidate.startswith(org_root):
                        raise ValueError('Path escapes organization root')
                    full_file_path = candidate
                
                arcname = os.path.basename(file_path)
                zf.write(full_file_path, arcname)
            except FileNotFoundError:
                print(f"Warning: File not found and skipped: {full_file_path}")
                continue
            except ValueError as ve:
                print(f"Security warning: {ve}")
                continue

    memory_file.seek(0)
    zip_filename = f"attachments_{project_name.replace(' ','_')}_{task_id}_{comment_id[:8]}.zip"

    # Audit log
    try:
        log_file_access(FILE_ACTION_ATTACHMENTS_DOWNLOADED, getattr(g, 'org_id', None), project_name, task_id, None, details={"comment_id": comment_id, "file_count": len(comment['attachments'])})
    except Exception:
        pass

    return send_file(
        memory_file,
        mimetype='application/zip',
        as_attachment=True,
        download_name=zip_filename
    )

# Helper function to find a task by ID (you might need to add this if it's not already there)
def find_task_by_id_recursive(tasks, task_id):
    for task in tasks:
        # Assuming task IDs are strings, ensure consistent comparison
        if str(task.get('id')) == str(task_id):
            return task
        if task.get('subtasks'):
            found = find_task_by_id_recursive(task['subtasks'], task_id)
            if found:
                return found
    return None


# --- Database API for Organization Management ---

def provision_organization_database(org_name, domain=None, conn=None, manage_transaction=True):
    """Provision a new organization database with full verification.
    
    Creates a new MySQL database for the organization, initializes the schema,
    and registers it in the Primary DB. Includes comprehensive verification to
    ensure the database file is actually created and accessible.
    
    Args:
        org_name (str): Organization name (must be unique)
        domain (str, optional): Custom domain for the organization
        conn (mysql.connector.MySQLConnection, optional): Primary DB connection for transaction participation
        manage_transaction (bool): If False, assumes parent manages transaction; skips standalone rollbacks
    
    Returns:
        tuple: (success: bool, result: dict, status_code: int)
            - On success: (True, {"org_id": int, "db_file_path": str}, 201)
            - On failure: (False, {"status": "error", "message": str}, status_code)
    
    Raises:
        No exceptions raised - all errors are caught and returned in the tuple
    
    Verification Steps:
        1. Check organization name uniqueness
        2. Create organization record with 'pending' db_file_path placeholder
        3. Generate tenant database filename
        4. Create MySQL database
        5. Initialize schema with create_tenant_schema()
        6. Commit transaction
        7. VERIFY file exists on disk (CRITICAL)
        8. VERIFY file size > 0 (not empty)
        9. Update organization record with encrypted db_file_path
        10. VERIFY UPDATE succeeded
        11. Log success to audit_logs
    
    Rollback on Failure:
        - Deletes organization record from Primary DB
        - Removes partially created database file
        - Returns error response with appropriate status code
    
    Notes:
        - Function is idempotent (safe to retry on failure)
        - All database operations use transactions for atomicity
        - Comprehensive logging for debugging
        - File path is encrypted before storage (if ENCRYPTION_KEY set)
    """
    if DB_TYPE.lower() == "mysql":
        try:
            if conn is None:
                existing = execute_primary_query(
                    "SELECT COUNT(*) FROM organizations WHERE name = ?",
                    params=(org_name,),
                    fetch_one=True
                )
            else:
                _cur = conn.cursor()
                _cur.execute(convert_query_placeholders("SELECT COUNT(*) FROM organizations WHERE name = ?", DB_TYPE), (org_name,))
                existing = _cur.fetchone()
            if existing and (existing[0] if isinstance(existing, (list, tuple)) else existing.get('COUNT(*)', 0)) > 0:
                return (False, {"status": "error", "message": "Organization with this name already exists"}, 409)

            if conn is None:
                org_id = execute_primary_query(
                    "INSERT INTO organizations (name, domain, db_file_path, status) VALUES (?, ?, ?, ?)",
                    params=(org_name, domain, 'pending', 'active'),
                    return_lastrowid=True
                )
            else:
                _cur = conn.cursor()
                _cur.execute(
                    convert_query_placeholders("INSERT INTO organizations (name, domain, db_file_path, status) VALUES (?, ?, ?, ?)", DB_TYPE),
                    (org_name, domain, 'pending', 'active')
                )
                org_id = _cur.lastrowid

            db_name = get_tenant_db_name(org_id)

            admin_conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset=MYSQL_CHARSET,
                autocommit=True,
            )
            admin_cursor = admin_conn.cursor()
            admin_cursor.execute(
                f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET {MYSQL_CHARSET} COLLATE utf8mb4_unicode_ci"
            )
            admin_cursor.close()
            admin_conn.close()

            tenant_conn = base_get_db_connection(db_name)
            create_tenant_schema(tenant_conn)
            tenant_conn.commit()
            tenant_conn.close()

            if conn is None:
                execute_primary_query(
                    "UPDATE organizations SET db_file_path = ? WHERE id = ?",
                    params=(db_name, org_id)
                )
            else:
                _cur = conn.cursor()
                _cur.execute(
                    convert_query_placeholders("UPDATE organizations SET db_file_path = ? WHERE id = ?", DB_TYPE),
                    (db_name, org_id)
                )

            try:
                user_id = getattr(g, 'user_id', None)
                details = json.dumps({"org_name": org_name, "db_name": db_name})
                if conn is None:
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        params=(org_id, user_id, 'org_database_created', details)
                    )
                else:
                    _cur = conn.cursor()
                    _cur.execute(
                        convert_query_placeholders("INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)", DB_TYPE),
                        (org_id, user_id, 'org_database_created', details)
                    )
            except Exception:
                pass

            return (True, {"org_id": org_id, "db_file_path": db_name}, 201)
        except (MySQLError, MySQLError, Exception) as e:
            print(f"[DB-API] MySQL provision error: {e}")
            return (False, {"status": "error", "message": "Failed to create organization database"}, 500)

    try:
        # Duplicate name (case-sensitive here; org signup will do case-insensitive check earlier)
        if conn is None:
            existing = execute_primary_query(
                "SELECT COUNT(*) FROM organizations WHERE name = ?",
                params=(org_name,),
                fetch_one=True
            )
        else:
            _cur = conn.cursor()
            _cur.execute("SELECT COUNT(*) FROM organizations WHERE name = ?", (org_name,))
            existing = _cur.fetchone()
        if existing and existing[0] > 0:
            return (False, {"status": "error", "message": "Organization with this name already exists"}, 409)

        if conn is None:
            org_id = execute_primary_query(
                "INSERT INTO organizations (name, domain, db_file_path, status) VALUES (?, ?, ?, ?)",
                params=(org_name, domain, 'pending', 'active'),
                return_lastrowid=True
            )
        else:
            _cur = conn.cursor()
            _cur.execute(
                "INSERT INTO organizations (name, domain, db_file_path, status) VALUES (?, ?, ?, ?)",
                (org_name, domain, 'pending', 'active')
            )
            org_id = _cur.lastrowid
        
        print(f"[DB-PROVISION] Organization record created: org_id={org_id}, name={org_name}, initial_db_file_path='pending'")

        db_name = get_tenant_db_name(org_id)
        print(f"[DB-API] Creating MySQL database for org_id={org_id}, database={db_name}")
        tenant_conn = None
        try:
            # Create MySQL database
            admin_conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                charset=MYSQL_CHARSET,
                autocommit=True,
            )
            admin_cursor = admin_conn.cursor()
            admin_cursor.execute(f"CREATE DATABASE IF NOT EXISTS `{db_name}` CHARACTER SET {MYSQL_CHARSET} COLLATE utf8mb4_unicode_ci")
            admin_cursor.close()
            admin_conn.close()
            print(f"[DB-API] MySQL database created: {db_name}")
            
            # Connect to the new database and create schema
            tenant_conn = mysql.connector.connect(
                host=MYSQL_HOST,
                port=MYSQL_PORT,
                user=MYSQL_USER,
                password=MYSQL_PASSWORD,
                database=db_name,
                charset=MYSQL_CHARSET,
            )
            
            create_tenant_schema(tenant_conn)
            print(f"[DB-API] Schema created successfully for org_id={org_id}")
            tenant_conn.commit()
            print(f"[DB-PROVISION] Tenant MySQL database committed: org_id={org_id}, database={db_name}")
        except MySQLError as e:
            print(f"[DB-API] MySQL error: {e}, database={db_name}")
            if manage_transaction:
                if conn is None:
                    affected = execute_primary_query("DELETE FROM organizations WHERE id = ?", params=(org_id,))
                else:
                    try:
                        _cur = conn.cursor()
                        _cur.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
                        affected = _cur.rowcount
                    except Exception:
                        affected = -1
                try:
                    # Verify deletion
                    if conn is None:
                        verify = execute_primary_query("SELECT COUNT(*) FROM organizations WHERE id = ?", params=(org_id,), fetch_one=True)
                    else:
                        _cur = conn.cursor()
                        _cur.execute("SELECT COUNT(*) FROM organizations WHERE id = ?", (org_id,))
                        verify = _cur.fetchone()
                    remaining = verify[0] if verify else None
                    print(f"[DB-API] Cleanup DELETE organizations affected={affected}, remaining_rows={remaining}")
                except Exception:
                    pass
            # Failure audit log
            try:
                details = json.dumps({"org_name": org_name, "error": str(e), "error_type": "OSError"})
                if conn is None:
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        params=(org_id, None, 'org_database_creation_failed', details)
                    )
                else:
                    _cur = conn.cursor()
                    _cur.execute(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (org_id, None, 'org_database_creation_failed', details)
                    )
            except Exception:
                pass
            # Note: db_filename only exists for SQLite, not MySQL
            return (False, {"status": "error", "message": "File system error during database creation"}, 500)
        except MySQLError as e:
            print(f"[DB-API] MySQL error: {e}, database={db_name}")
            if manage_transaction:
                if conn is None:
                    affected = execute_primary_query("DELETE FROM organizations WHERE id = ?", params=(org_id,))
                else:
                    try:
                        _cur = conn.cursor()
                        _cur.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
                        affected = _cur.rowcount
                    except Exception:
                        affected = -1
                try:
                    if conn is None:
                        verify = execute_primary_query("SELECT COUNT(*) FROM organizations WHERE id = ?", params=(org_id,), fetch_one=True)
                    else:
                        _cur = conn.cursor()
                        _cur.execute("SELECT COUNT(*) FROM organizations WHERE id = ?", (org_id,))
                        verify = _cur.fetchone()
                    remaining = verify[0] if verify else None
                    print(f"[DB-API] Cleanup DELETE organizations affected={affected}, remaining_rows={remaining}")
                except Exception:
                    pass
            # Failure audit log
            try:
                details = json.dumps({"org_name": org_name, "error": str(e), "error_type": "MySQLError"})
                if conn is None:
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        params=(org_id, None, 'org_database_creation_failed', details)
                    )
                else:
                    _cur = conn.cursor()
                    _cur.execute(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (org_id, None, 'org_database_creation_failed', details)
                    )
            except Exception:
                pass
            # Note: db_filename only exists for SQLite, not MySQL
            return (False, {"status": "error", "message": "Failed to create organization database"}, 500)
        finally:
            if tenant_conn is not None:
                tenant_conn.close()

        print(f"[DB-API] Updating organizations table with db_file_path for org_id={org_id}")
        try:
            if conn is None:
                execute_primary_query(
                    "UPDATE organizations SET db_file_path = ? WHERE id = ?",
                    params=(encrypt_db_path(db_name), org_id)
                )
            else:
                _cur = conn.cursor()
                _cur.execute(
                    "UPDATE organizations SET db_file_path = ? WHERE id = ?",
                    (encrypt_db_path(db_name), org_id)
                )
            print(f"[DB-PROVISION] UPDATE organizations executed: org_id={org_id}, encrypted_path_length={len(encrypt_db_path(db_name))}")
            
            # Verify the UPDATE succeeded (check that it's not None, empty, or still 'pending')
            if conn is None:
                verify_row = execute_primary_query(
                    "SELECT db_file_path FROM organizations WHERE id = ?",
                    params=(org_id,),
                    fetch_one=True
                )
            else:
                _cur = conn.cursor()
                _cur.execute("SELECT db_file_path FROM organizations WHERE id = ?", (org_id,))
                verify_row = _cur.fetchone()
            # Decrypt to check actual value (in case encryption is enabled)
            db_path_to_check = verify_row[0] if verify_row and verify_row[0] else None
            try:
                db_path_to_check = decrypt_db_path(db_path_to_check) if db_path_to_check else None
            except Exception:
                pass  # Use original value if decryption fails
            
            if not verify_row or not db_path_to_check or db_path_to_check == 'pending':
                error_msg = f"Failed to update db_file_path for org_id={org_id} (still 'pending' or empty)"
                print(f"[DB-API] CRITICAL: {error_msg}")
                raise MySQLError(error_msg)
            print(f"[DB-PROVISION] Verification passed: org_id={org_id}, db_file_path is not 'pending'")
        except (MySQLError, Exception) as e:
            print(f"[DB-API] Error updating organizations table or verification failed: {e}")
            # Rollback: delete organization and database file
            if manage_transaction:
                if conn is None:
                    affected = execute_primary_query("DELETE FROM organizations WHERE id = ?", params=(org_id,))
                else:
                    try:
                        _cur = conn.cursor()
                        _cur.execute("DELETE FROM organizations WHERE id = ?", (org_id,))
                        affected = _cur.rowcount
                    except Exception:
                        affected = -1
                try:
                    if conn is None:
                        verify = execute_primary_query("SELECT COUNT(*) FROM organizations WHERE id = ?", params=(org_id,), fetch_one=True)
                    else:
                        _cur = conn.cursor()
                        _cur.execute("SELECT COUNT(*) FROM organizations WHERE id = ?", (org_id,))
                        verify = _cur.fetchone()
                    remaining = verify[0] if verify else None
                    print(f"[DB-API] Cleanup DELETE organizations affected={affected}, remaining_rows={remaining}")
                except Exception:
                    pass
            # Note: db_filename only exists for SQLite, not MySQL
            # Failure audit log
            try:
                details = json.dumps({"org_name": org_name, "error": str(e), "error_type": "UpdateVerificationFailed"})
                if conn is None:
                    execute_primary_query(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        params=(org_id, None, 'org_database_creation_failed', details)
                    )
                else:
                    _cur = conn.cursor()
                    _cur.execute(
                        "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                        (org_id, None, 'org_database_creation_failed', details)
                    )
            except Exception:
                pass
            raise

        try:
            user_id = getattr(g, 'user_id', None)
            details = json.dumps({"org_name": org_name, "db_file_path": db_name})
            if conn is None:
                execute_primary_query(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    params=(org_id, user_id, 'org_database_created', details)
                )
            else:
                _cur = conn.cursor()
                _cur.execute(
                    "INSERT INTO audit_logs (org_id, user_id, action, details) VALUES (?, ?, ?, ?)",
                    (org_id, user_id, 'org_database_created', details)
                )
        except Exception as e:
            print(f"[DB-API] Audit log failure for org_id={org_id}: {e}")

        # Get final db_file_path for logging
        final_path_result = execute_primary_query(
            "SELECT db_file_path FROM organizations WHERE id = ?",
            params=(org_id,),
            fetch_one=True
        )
        final_db_file_path = final_path_result[0] if final_path_result else None
        print(f"[DB-PROVISION] SUCCESS: Organization database provisioned successfully for org_id={org_id}, db_file_path={final_db_file_path}")
        return (True, {"org_id": org_id, "db_file_path": db_name}, 201)
    except mysql.connector.IntegrityError:
        return (False, {"status": "error", "message": "Organization with this name already exists"}, 409)
    except Exception as e:
        print(f"[DB-API] Unexpected error in provision_organization_database: {e}")
        return (False, {"status": "error", "message": "Failed to create organization database"}, 500)

@app.route(f"{DB_API_PREFIX}/orgs", methods=['POST'])
@superadmin_required
def create_organization_database():
    """Create a new organization database by cloning the tenant schema.
    
    This endpoint provisions a new MySQL database for the organization,
    registers it in the Primary DB, and returns the new org details.
    """
    try:
        payload = request.get_json(silent=True) or {}
        org_name = (payload.get('org_name') or '').strip()
        domain = (payload.get('domain') or '').strip() or None
        if not org_name:
            return jsonify({"status": "error", "message": "Organization name is required"}), 400

        success, result, status_code = provision_organization_database(org_name, domain)
        if success:
            return jsonify({
                "status": "success",
                "message": "Organization database created successfully",
                **result
            }), status_code
        else:
            return jsonify(result), status_code
    except Exception as e:
        print(f"[DB-API] Unexpected error in create_organization_database: {e}")
        return jsonify({"status": "error", "message": "Failed to create organization database"}), 500


@app.route(f"{DB_API_PREFIX}/orgs/<int:org_id>", methods=['GET'])
@superadmin_required
def get_organization_details(org_id):
    """Retrieve organization details and useful statistics from Primary DB."""
    try:
        org = execute_primary_query(
            "SELECT id, name, domain, db_file_path, created_at, status FROM organizations WHERE id = ?",
            params=(org_id,),
            fetch_one=True
        )
        if not org:
            return jsonify({"status": "error", "message": "Organization not found"}), 404

        org_dict = dict(zip(['id', 'name', 'domain', 'db_file_path', 'created_at', 'status'], org))

        # Optional stats
        user_count_row = execute_primary_query(
            "SELECT COUNT(*) FROM users WHERE org_id = ?",
            params=(org_id,),
            fetch_one=True
        )
        user_count = user_count_row[0] if user_count_row else 0

        subscription = execute_primary_query(
            "SELECT plan_type, status, start_date, end_date FROM subscriptions WHERE org_id = ? ORDER BY id DESC LIMIT 1",
            params=(org_id,),
            fetch_one=True
        )
        subscription_dict = dict(zip(['plan_type', 'status', 'start_date', 'end_date'], subscription)) if subscription else None

        db_file_exists = False
        if DB_TYPE.lower() == "mysql":
            db_file_path_dec = org_dict.get('db_file_path')
            db_file_exists = True if db_file_path_dec else False
        else:
            db_file_path = org_dict.get('db_file_path')
            try:
                db_file_path_dec = decrypt_db_path(db_file_path) if db_file_path else db_file_path
            except Exception:
                db_file_path_dec = db_file_path

            try:
                db_file_exists = bool(db_file_path_dec and os.path.exists(db_file_path_dec))
            except OSError:
                db_file_exists = False

        return jsonify({
            "status": "success",
            "organization": org_dict,
            "user_count": user_count,
            "subscription": subscription_dict,
            "db_file_exists": db_file_exists
        })
    except MySQLError as e:
        print(f"[DB-API] Primary DB error in get_organization_details: {e}")
        return jsonify({"status": "error", "message": "Failed to retrieve organization details"}), 500


@app.route(f"{DB_API_PREFIX}/orgs/<int:org_id>/migrate", methods=['POST'])
@superadmin_required
def migrate_organization_database(org_id):
    """Run schema migrations on an organization's database - MySQL only."""
    try:
        # MySQL-only application - migrations handled differently
        return jsonify({"status": "error", "message": "Migration endpoint is not available for MySQL backend"}), 400
    except MySQLError as e:
        print(f"[DB-API] Migration primary DB error: {e}")
        return jsonify({"status": "error", "message": f"Migration failed: {e}"}), 500


@app.route(f"{DB_API_PREFIX}/orgs/<int:org_id>/health", methods=['GET'])
@superadmin_required
def check_organization_database_health(org_id):
    """Perform health checks on an organization's database and return a detailed report."""
    health = {}
    try:
        row = execute_primary_query(
            "SELECT db_file_path, status FROM organizations WHERE id = ?",
            params=(org_id,),
            fetch_one=True
        )
        if not row:
            return jsonify({"status": "error", "message": "Organization not found"}), 404
        db_file_path, status = row
        health['org_status'] = status

        if DB_TYPE.lower() == "mysql":
            health['db_name'] = db_file_path
            try:
                conn = base_get_db_connection(db_file_path)
                cursor = conn.cursor()
                cursor.execute("SELECT 1")
                health['connectivity'] = 'ok'
                cursor.close()
                conn.close()
            except Exception as e:
                health['connectivity'] = 'failed'
                health['error'] = str(e)
                return jsonify({"status": "success", "org_id": org_id, "health": health})
            health['status'] = 'healthy' if health.get('connectivity') == 'ok' else 'warning'
            return jsonify({"status": "success", "org_id": org_id, "health": health})

        # SQLite path - decrypt db_file_path
        try:
            db_file_path_dec = decrypt_db_path(db_file_path) if db_file_path else db_file_path
        except Exception:
            db_file_path_dec = db_file_path

        # Last modified
        try:
            health['last_modified'] = datetime.fromtimestamp(os.path.getmtime(db_file_path_dec)).isoformat()
        except OSError as e:
            print(f"[DB-API] OS error reading mtime: {e}")

        # Determine overall status
        status_overall = 'healthy'
        if health.get('integrity_check') != 'ok' or health.get('connectivity') != 'ok' or health.get('missing_tables'):
            status_overall = 'critical'
        elif health.get('missing_indexes'):
            status_overall = 'warning'
        health['status'] = status_overall
        print(f"[DB-API] Health check: org_id={org_id}, status={status_overall}")
        return jsonify({"status": "success", "org_id": org_id, "health": health})
    except Exception as e:
        print(f"[DB-API] Health check unexpected error: {e}")
        health['status'] = 'critical'
        health['error'] = str(e)
        return jsonify({"status": "success", "org_id": org_id, "health": health})


@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/load', methods=['GET'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def load_data():
    project_name = request.args.get('project')
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400
    
    # Get pagination parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    load_all = request.args.get('load_all', 'false').lower() == 'true'
    
    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404
        
        # Load tasks from database
        data = load_tasks_from_db(project_id)
        if data is None:
            return jsonify({"status": "error", "message": "Could not read project data"}), 500
        # #region agent log
        try:
            import json as _json
            first = (data[0] if isinstance(data, list) and data else None)
            with open(r'd:\Digital Transformation\PROTON\Productization\PROTON-V5_Optimization\.cursor\debug.log', 'a', encoding='utf-8') as _f:
                _f.write(_json.dumps({
                    "sessionId": "debug-session",
                    "runId": "dates-run1",
                    "hypothesisId": "H2",
                    "location": "app.py:load_data:pre_sanitize",
                    "message": "API /api/load first task date fields before sanitize/jsonify",
                    "data": {
                        "project_id": project_id,
                        "first_task_wbs": (first or {}).get("wbs") if isinstance(first, dict) else None,
                        "plannedStartDate": str((first or {}).get("plannedStartDate")) if isinstance(first, dict) else None,
                        "plannedStartDate_type": str(type((first or {}).get("plannedStartDate"))) if isinstance(first, dict) else None,
                        "plannedEndDate": str((first or {}).get("plannedEndDate")) if isinstance(first, dict) else None,
                        "plannedEndDate_type": str(type((first or {}).get("plannedEndDate"))) if isinstance(first, dict) else None
                    },
                    "timestamp": int(datetime.now().timestamp() * 1000)
                }) + "\n")
        except Exception:
            pass
        # #endregion
            
        data = sanitize(data)
        
        # If load_all is requested, return all data
        if load_all:
            return jsonify(data)
        
        # Apply pagination to top-level tasks only
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_data = data[start_idx:end_idx]
        
        return jsonify({
            'data': paginated_data,
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': len(data),
                'has_more': end_idx < len(data)
            }
        })
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in load_data: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error in load_data: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500

@limiter.limit(RATE_LIMIT_API, key_func=get_user_id_for_rate_limit)
@app.route('/api/save', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
@subscription_required
def save_data():
    project_name = sanitize_text_input(request.args.get('project') or '', max_length=100)
    if not project_name: return jsonify({"status": "error", "message": "Project name is required."}), 400
    
    payload = sanitize_json_input(request.get_json(silent=True) or {}, allowed_keys=['tasks','user_email'])
    if not payload: return jsonify({"status": "error", "message": "No data received"}), 400

    new_tasks_data = payload.get('tasks')
    user_email = sanitize_text_input(payload.get('user_email') or '')

    if new_tasks_data is None:
        return jsonify({"status": "error", "message": "Payload must include tasks"}), 400

    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # --- Load old data for comparison ---
        old_data = load_tasks_from_db(project_id) or []

        # --- Conditional Logging ---
        if user_email:
            old_tasks = {}
            def task_to_dict(tasks_list, task_dict):
                for t in tasks_list:
                    task_dict[t['id']] = t
                    if t.get('subtasks'): task_to_dict(t['subtasks'], task_dict)
            
            task_to_dict(old_data, old_tasks)

            new_tasks = {}
            task_to_dict(new_tasks_data, new_tasks)
            
            added_tasks = set(new_tasks.keys()) - set(old_tasks.keys())
            deleted_tasks = set(old_tasks.keys()) - set(new_tasks.keys())
            common_tasks = set(new_tasks.keys()) & set(old_tasks.keys())

            for task_id in added_tasks: log_activity(user_email, project_name, "Task Added", f"Task '{new_tasks[task_id]['taskName']}' (WBS: {new_tasks[task_id]['wbs']}) was created.")
            for task_id in deleted_tasks: log_activity(user_email, project_name, "Task Deleted", f"Task '{old_tasks[task_id]['taskName']}' (WBS: {old_tasks[task_id]['wbs']}) was deleted.")
            for task_id in common_tasks:
                if tasks_differ(old_tasks[task_id], new_tasks[task_id]):
                     log_activity(user_email, project_name, "Task Edited", f"Task '{new_tasks[task_id]['taskName']}' (WBS: {new_tasks[task_id]['wbs']}) was modified.")

        # --- Optimized Progress Recalculation ---
        if needs_progress_recalculation(old_data, new_tasks_data):
            final_data = sanitize(recalculate_progress_recursively(new_tasks_data))
        else:
            final_data = sanitize(new_tasks_data)
            
        # Save to database
        if not save_tasks_to_db(project_id, final_data):
            return jsonify({"status": "error", "message": "Failed to save data"}), 500
            
        return jsonify({"status": "success"})

    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        print(f"Database error in save_data: {e}")
        return jsonify({"status": "error", "message": "Database error occurred"}), 500
    except Exception as e:
        print(f"Unexpected error in save_data: {e}")
        return jsonify({"status": "error", "message": "An unexpected error occurred"}), 500
@limiter.limit(RATE_LIMIT_FILE_UPLOAD, key_func=get_user_id_for_rate_limit)
@app.route('/api/upload', methods=['POST'])
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN])
@subscription_required
@check_plan_limit(RESOURCE_TYPE_FILE)
def upload_csv():
    """
    Upload and import tasks from a CSV file into an existing project.

    This endpoint accepts a CSV file containing project tasks in WBS (Work Breakdown Structure)
    format and imports them into the specified project. All existing tasks in the project
    are replaced with the imported tasks.

    Authentication:
        - Requires valid JWT token (tenant context)
        - Requires SuperAdmin or OrgAdmin role
        - Requires active subscription

    Request:
        - Method: POST
        - Content-Type: multipart/form-data
        - Query Parameters:
            - project (required): Name of the existing project to import tasks into
        - Form Data:
            - file (required): CSV file containing tasks
            - user_email (optional): Email of the user performing the import (for logging)

    CSV Format:
        The CSV file should contain the following columns (column names are flexible):
        
        Required Columns:
            - WBS / Activity ID / ID: Work Breakdown Structure number (e.g., 1, 1.1, 1.1.1)
            - Name / Task Name / Activity Name: Task name/description
            - Start / Start_Date: Planned start date (various formats supported, e.g., DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD)
            - Finish / Finish_Date: Planned end date (various formats supported, e.g., DD/MM/YYYY, MM/DD/YYYY, YYYY-MM-DD)
        
        Note: Date parsing automatically detects format (day-first vs month-first) based on parsing success rate.
        
        Optional Columns:
            - Duration: Task duration in days (defaults if missing)
            - Weightage / Weightage (%): Task weight for progress calculation (0-100, defaults to 0 if missing)
            - Predecessors: Comma-separated list of predecessor task IDs
            - Notes: Task notes/description
            - Actual Start Date / Actual Start: Actual start date
            - Actual End Date / Actual End: Actual end date
            - Progress / Progress(%): Task completion percentage (0-100)
            - Status: Task status (e.g., 'Not Started', 'In Progress', 'Completed')
            - Is Critical / Critical: Whether task is on critical path (Yes/No, True/False)
        
        Example CSV:
            WBS,Name,Start,Finish,Duration,Weightage,Predecessors,Progress,Status
            1,Project Root,2025-01-01,2025-12-31,365,100,,0,Not Started
            1.1,Phase 1,2025-01-01,2025-03-31,90,30,,0,Not Started
            1.1.1,Task 1,2025-01-01,2025-01-15,15,10,,50,In Progress

    Behavior:
        - All existing tasks in the project are deleted before import (cascading delete)
        - Tasks are organized hierarchically based on WBS numbering
        - Parent task progress is calculated from child tasks
        - Activity log entry is created for the import
        - Transaction-based: all-or-nothing import (rollback on error)

    File Limits:
        - Maximum file size: 10 MB
        - Maximum rows: Limited by file size and server memory

    Response:
        Success (200):
            {"status": "uploaded", "rows": <number_of_rows>}
        
        Error (400/404/413/500):
            {"status": "error", "message": <error_description>}

    Error Codes:
        - 400: Missing/invalid parameters, invalid file format
        - 404: Project not found
        - 413: File size exceeds limit
        - 500: Database error, parsing error, unexpected error

    See Also:
        - build_task_hierarchy(): Parses CSV and builds task hierarchy
        - save_tasks_to_db(): Saves tasks to database
        - log_activity(): Logs import action
    """
    # CSV IMPORT WORKFLOW:
    # 1. Validate request (file size, file presence, project name)
    # 2. Validate file extension (.csv only)
    # 3. Lookup project ID from project name
    # 4. Parse CSV with pandas (flexible column mapping)
    # 5. Build task hierarchy based on WBS numbering
    # 6. Sanitize task data (prevent XSS)
    # 7. Save to database (transaction-based, cascading delete)
    # 8. Log activity for audit trail
    # 9. Return success response with row count
    #
    # ERROR HANDLING:
    # - Validation errors: 400 Bad Request
    # - Project not found: 404 Not Found
    # - File too large: 413 Payload Too Large
    # - Database errors: 500 Internal Server Error
    # - All errors are logged for debugging
    #
    # SECURITY:
    # - Tenant-aware: Only accesses organization's database
    # - Role-based: Only SuperAdmin and OrgAdmin can upload
    # - Subscription-required: Active subscription needed
    # - Data sanitization: Prevents XSS attacks
    # - Transaction-based: Rollback on error (data integrity)
    
    # Limit CSV upload size to 10 MB
    try:
        if request.content_length and request.content_length > 10 * 1024 * 1024:
            print(f"[CSV-UPLOAD] Validation failed: File size exceeds 10 MB limit ({request.content_length} bytes)")
            return jsonify({"status": "error", "message": "CSV exceeds 10 MB limit"}), 413
    except Exception:
        pass
    project_name = sanitize_text_input(request.args.get('project') or '', max_length=100)
    if not project_name:
        print(f"[CSV-UPLOAD] Validation failed: Missing project name")
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    if 'file' not in request.files:
        print(f"[CSV-UPLOAD] Validation failed: No file part in request")
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        print(f"[CSV-UPLOAD] Validation failed: Empty filename")
        return jsonify({"status": "error", "message": "No selected file"}), 400
    
    # Validate file extension
    if not file.filename.lower().endswith('.csv'):
        print(f"[CSV-UPLOAD] Validation failed: Invalid file extension '{file.filename}'")
        return jsonify({"status": "error", "message": "Only CSV files are allowed. Please upload a .csv file."}), 400
    
    # Log upload attempt start
    user_email = request.form.get('user_email', 'Unknown')
    print(f"[CSV-UPLOAD] Upload attempt started: project={project_name}, filename={file.filename}, user={user_email}")
        
    try:
        # Get the project ID
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            print(f"[CSV-UPLOAD] Project not found: {project_name}")
            return jsonify({"status": "error", "message": "Project not found"}), 404

        # Read CSV file
        print(f"[CSV-UPLOAD] Parsing CSV: project={project_name}, filename={file.filename}, size={request.content_length or 'unknown'} bytes")
        try:
            df = pd.read_csv(file, encoding='utf-8', encoding_errors='ignore')
        except pd.errors.EmptyDataError:
            print(f"[CSV-UPLOAD] Empty CSV file uploaded for project: {project_name}")
            return jsonify({"status": "error", "message": "The CSV file is empty. Please upload a file with task data."}), 400
        except pd.errors.ParserError as e:
            print(f"[CSV-UPLOAD] CSV parsing error for project {project_name}: {e}")
            return jsonify({"status": "error", "message": "Invalid CSV format. Please check that the file is properly formatted with comma-separated values."}), 400
        except Exception as e:
            import traceback
            print(f"[CSV-UPLOAD] Failed to read CSV file: {e}")
            print(traceback.format_exc())
            return jsonify({"status": "error", "message": f"Failed to read CSV file. Please ensure it's a valid CSV format. Error: {str(e)}"}), 400
        
        if df.empty:
            print(f"[CSV-UPLOAD] Empty CSV: no data rows found")
            return jsonify({"status": "error", "message": "CSV file is empty or contains no valid data"}), 400
        
        # Validate row count to prevent memory issues
        MAX_CSV_ROWS = 10000  # Adjust based on server capacity
        if len(df) > MAX_CSV_ROWS:
            print(f"[CSV-UPLOAD] CSV too large: {len(df)} rows (max: {MAX_CSV_ROWS})")
            return jsonify({
                "status": "error", 
                "message": f"CSV file contains {len(df)} rows, which exceeds the maximum limit of {MAX_CSV_ROWS} rows. Please split your project into smaller files or contact support for assistance."
            }), 413
        
        print(f"[CSV-UPLOAD] CSV row count validation passed: {len(df)} rows")
        
        # Validate that CSV has required columns
        required_columns_map = {
            'WBS': ['WBS', 'Activity ID', 'ID'],
            'Name': ['Name', 'Task Name', 'Activity Name'],
            'Start': ['Start', 'start', 'Start_Date'],
            'Finish': ['Finish', 'finish', 'Finish_Date']
        }
        
        missing_columns = []
        for required_col, possible_names in required_columns_map.items():
            if not any(name in df.columns for name in possible_names):
                missing_columns.append(f"{required_col} (expected one of: {', '.join(possible_names)})")
        
        if missing_columns:
            error_msg = f"CSV is missing required columns: {'; '.join(missing_columns)}"
            print(f"[CSV-UPLOAD] Validation failed: {error_msg}")
            return jsonify({"status": "error", "message": error_msg}), 400
        
        print(f"[CSV-UPLOAD] CSV validation passed: all required columns present")
        
        df = df.where(pd.notnull(df), None)

        # Build task hierarchy
        try:
            hierarchical_data = build_task_hierarchy(df)
        except KeyError as e:
            print(f"[CSV-UPLOAD] Missing required column in CSV for project {project_name}: {e}")
            return jsonify({"status": "error", "message": f"Missing required column in CSV: {str(e)}. Please ensure your CSV includes WBS, Name, Start, and Finish columns."}), 400
        except ValueError as e:
            print(f"[CSV-UPLOAD] Invalid data in CSV for project {project_name}: {e}")
            return jsonify({"status": "error", "message": f"Invalid data in CSV: {str(e)}. Please check date formats and numeric values."}), 400
        except Exception as e:
            import traceback
            print(f"[CSV-UPLOAD] Failed to build task hierarchy: {e}")
            print(traceback.format_exc())
            return jsonify({"status": "error", "message": f"Failed to process CSV data. Please check the CSV format. Error: {str(e)}"}), 400
        
        if not hierarchical_data or len(hierarchical_data) == 0:
            print(f"[CSV-UPLOAD] No valid tasks found in CSV for project {project_name}")
            return jsonify({"status": "error", "message": "No valid tasks found in CSV. Please ensure the CSV contains a 'WBS' column."}), 400
        
        print(f"[CSV-UPLOAD] Built task hierarchy: project={project_name}, total_tasks={len(df)}, top_level_tasks={len(hierarchical_data)}")
        
        # Sanitize data
        try:
            data = sanitize(hierarchical_data)
        except Exception as e:
            import traceback
            print(f"[CSV-UPLOAD] Failed to sanitize data: {e}")
            print(traceback.format_exc())
            return jsonify({"status": "error", "message": f"Failed to process data. Error: {str(e)}"}), 500
        
        # Save to database
        print(f"[CSV-UPLOAD] Saving tasks to database: project={project_name}, project_id={project_id}")
        try:
            if not save_tasks_to_db(project_id, data):
                print(f"[CSV-UPLOAD] Failed to save tasks to database: project={project_name}")
                return jsonify({"status": "error", "message": "Failed to save uploaded data to database"}), 500
        except Exception as e:
            import traceback
            print(f"[CSV-UPLOAD] Failed to save tasks to database: {e}")
            print(traceback.format_exc())
            return jsonify({"status": "error", "message": f"Failed to save data to database. Error: {str(e)}"}), 500
        
        # Log this action. Assumes user info is not available here, so generic log.
        log_activity(
            user_email, 
            project_name, 
            "CSV Upload", 
            f"{len(df)} rows imported from '{file.filename}' ({len(data)} top-level tasks, {request.content_length or 0} bytes)"
        )
        print(f"[CSV-UPLOAD] SUCCESS: project={project_name}, rows={len(df)}, filename={file.filename}, user={user_email}")

        return jsonify({"status": "uploaded", "rows": len(df)})
    except TenantDatabaseError as e:
        import traceback
        print(f"[TENANT-ERROR] {e}")
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": "Unable to access organization database. Please contact support."}), 500
    except TenantResolutionError as e:
        import traceback
        print(f"[TENANT-ERROR] {e}")
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": "Organization not found or inactive."}), 404
    except MySQLError as e:
        import traceback
        print(f"[UPLOAD-ERROR] Database error in upload_csv: {e}")
        print(traceback.format_exc())
        return jsonify({"status": "error", "message": f"Database error occurred: {str(e)}"}), 500
    except KeyError as e:
        print(f"[CSV-UPLOAD] Missing required column in CSV for project {project_name}: {e}")
        return jsonify({"status": "error", "message": f"Missing required column in CSV: {str(e)}. Please ensure your CSV includes WBS, Name, Start, and Finish columns."}), 400
    except ValueError as e:
        print(f"[CSV-UPLOAD] Invalid data in CSV for project {project_name}: {e}")
        return jsonify({"status": "error", "message": f"Invalid data in CSV: {str(e)}. Please check date formats and numeric values."}), 400
    except Exception as e:
        import traceback
        print(f"[CSV-UPLOAD] Unexpected error uploading CSV for project {project_name}: {e}")
        traceback.print_exc()  # Print full stack trace for debugging
        return jsonify({"status": "error", "message": f"An unexpected error occurred while processing the CSV. Please contact support if the issue persists."}), 500

# NEW: Route for the charts page
@app.route('/charts')
def charts_page():
    # We can pass the project name to the template if needed
    project_name = request.args.get('project', 'Default Project')
    return render_template('charts.html', project_name=project_name)



def get_s_curve_data(tasks):
    """
    MODIFIED: Calculates data for a planned vs actual progress S-Curve.
    - Planned progress is calculated recursively based on task hierarchy and planned end dates.
    - Actual progress uses actual end dates for historical points.
    - A smoothing algorithm is applied to the last few days to create a natural ramp-up to today's live overall progress.
    """
    overall_project_progress = tasks[0].get('progress', 0) if tasks else 0

    all_tasks_for_dates = []
    def get_all_tasks(task_list):
        for t in task_list:
            all_tasks_for_dates.append(t)
            if t.get('subtasks'):
                get_all_tasks(t['subtasks'])
    get_all_tasks(tasks)

    if not all_tasks_for_dates:
        return {}

    try:
        all_dates = [datetime.now()]
        for t in all_tasks_for_dates:
            if t.get('plannedStartDate'): all_dates.append(datetime.fromisoformat(t['plannedStartDate']))
            if t.get('plannedEndDate'): all_dates.append(datetime.fromisoformat(t['plannedEndDate']))
            if t.get('actualEndDate'): all_dates.append(datetime.fromisoformat(t['actualEndDate']))

        project_start_date = min(all_dates)
        project_end_date = max(all_dates) + timedelta(days=5)
    except (ValueError, TypeError):
        return {}

    def get_planned_progress_for_date(task, calc_date):
        """
        Day-based planned progress calculation (inclusive of start and end dates).
        - Leaf tasks: linear ramp from 0% to 100% over total days
        - Parent tasks: weighted average of children
        Notes:
        - No weekends/holidays exclusion
        - If dates invalid/missing -> 0%
        - If end < start (or same day) -> treat as 1-day task
        """
        # Parent aggregation
        if task.get('subtasks') and len(task['subtasks']) > 0:
            total_weight = 0.0
            weighted_progress_sum = 0.0
            for subtask in task['subtasks']:
                weight = float(subtask.get('weightage', 0.0))
                subtask_planned_progress = get_planned_progress_for_date(subtask, calc_date)
                total_weight += weight
                weighted_progress_sum += subtask_planned_progress * weight
            return (weighted_progress_sum / total_weight) if total_weight > 0 else 0.0

        # Leaf calculation
        try:
            start_str = task.get('plannedStartDate')
            end_str = task.get('plannedEndDate')
            if not start_str or not end_str:
                return 0.0
            start_date = datetime.fromisoformat(start_str).date()
            end_date = datetime.fromisoformat(end_str).date()
        except (ValueError, TypeError):
            return 0.0

        # Treat invalid order or same day as 1-day task
        if end_date < start_date:
            end_date = start_date

        total_days = max(1, (end_date - start_date).days + 1)

        if calc_date < start_date:
            return 0.0
        if calc_date >= end_date:
            return 100.0

        days_elapsed = (calc_date - start_date).days + 1
        fraction = days_elapsed / total_days
        # Piecewise planned distribution:
        # - First 30% of days delivers 10% of work (linear within segment)
        # - Middle 40% delivers 60% of work
        # - Last 30% delivers 30% of work
        if fraction <= 0.3:
            planned_percent = (fraction / 0.3) * 10.0
        elif fraction <= 0.7:
            planned_percent = 10.0 + ((fraction - 0.3) / 0.4) * 60.0
        else:
            planned_percent = 70.0 + ((fraction - 0.7) / 0.3) * 30.0
        return max(0.0, min(100.0, planned_percent))

    all_leaf_tasks = []
    def flatten_tasks_for_actual(task_list):
        for task in task_list:
            if not task.get('subtasks') and float(task.get('weightage', 0)) > 0:
                 all_leaf_tasks.append(task)
            elif task.get('subtasks'):
                flatten_tasks_for_actual(task['subtasks'])
    
    flatten_tasks_for_actual(tasks)
        
    total_weightage = sum(float(t.get('weightage', 0)) for t in all_leaf_tasks)

    s_curve_data = {'dates': [], 'planned_progress': [], 'actual_progress': []}
    current_date = project_start_date
    today_obj = datetime.now().date()
    
    # --- STEP 1: Calculate historical data up to today ---
    historical_actual_points = []
    while current_date.date() <= today_obj:
        date_str = current_date.strftime('%d-%b-%y')
        current_date_obj = current_date.date()

        # Planned Progress
        planned_progress_percent = get_planned_progress_for_date(tasks[0], current_date_obj) if tasks else 0
        s_curve_data['dates'].append(date_str)
        s_curve_data['planned_progress'].append(round(planned_progress_percent, 2))

        # Actual Progress based on completed tasks (tasks with an actual end date)
        actual_earned_value = sum(
            float(t.get('weightage', 0))
            for t in all_leaf_tasks
            if t.get('actualEndDate') and datetime.fromisoformat(t['actualEndDate']).date() <= current_date_obj
        )
        actual_progress_percent = round((actual_earned_value / total_weightage) * 100, 2) if total_weightage > 0 else 0
        historical_actual_points.append(actual_progress_percent)
        
        current_date += timedelta(days=1)

    # --- STEP 2: Apply smoothing to the last few days ---
    smoothing_days = 5 # The number of days to distribute the progress increase over
    
    if len(historical_actual_points) > smoothing_days:
        # The progress value based on completed tasks right before the smoothing period starts
        base_progress_before_smoothing = historical_actual_points[-smoothing_days -1]
        
        # The total progress we need to "catch up" to by today
        progress_to_add = float(overall_project_progress) - base_progress_before_smoothing

        if progress_to_add > 0:
            for i in range(smoothing_days):
                # Calculate the incremental progress to add for each day of the smoothing period
                # This creates a linear ramp from the base point to the final overall progress
                increment = (progress_to_add / smoothing_days) * (i + 1)
                
                # The index in our list to update
                target_index = len(historical_actual_points) - smoothing_days + i
                
                # The new progress is the historical base plus the smoothed increment
                smoothed_progress = base_progress_before_smoothing + increment
                
                # Update the point in our list, ensuring it doesn't exceed the final target
                historical_actual_points[target_index] = min(smoothed_progress, overall_project_progress)

    # Ensure the very last point is exactly the overall progress
    if historical_actual_points:
        historical_actual_points[-1] = overall_project_progress

    s_curve_data['actual_progress'].extend(historical_actual_points)

    # --- STEP 3: Add future dates for the planned curve ---
    while current_date <= project_end_date:
        date_str = current_date.strftime('%d-%b-%y')
        planned_progress_percent = get_planned_progress_for_date(tasks[0], current_date.date()) if tasks else 0
        s_curve_data['dates'].append(date_str)
        s_curve_data['planned_progress'].append(round(planned_progress_percent, 2))
        s_curve_data['actual_progress'].append(None) # No actual progress for future dates
        current_date += timedelta(days=1)

    return s_curve_data


def get_planned_progress_for_date_single_task(task, calc_date):
    """
    Calculate planned progress for a single task based on the calculation date.
    Similar to the S-curve logic but for individual tasks.
    """
    if task.get('subtasks') and len(task['subtasks']) > 0:
        total_weight = 0.0
        weighted_progress_sum = 0.0
        for subtask in task['subtasks']:
            weight = float(subtask.get('weightage', 0.0))
            subtask_planned_progress = get_planned_progress_for_date_single_task(subtask, calc_date)
            total_weight += weight
            weighted_progress_sum += subtask_planned_progress * weight
        return (weighted_progress_sum / total_weight) if total_weight > 0 else 0.0

    try:
        start_str = task.get('plannedStartDate')
        end_str = task.get('plannedEndDate')
        if not start_str or not end_str:
            return 0.0
        start_date = datetime.fromisoformat(start_str).date()
        end_date = datetime.fromisoformat(end_str).date()
    except (ValueError, TypeError):
        return 0.0

    if end_date < start_date:
        end_date = start_date

    if calc_date < start_date:
        return 0.0
    elif calc_date >= end_date:
        return 100.0
    else:
        total_days = max(1, (end_date - start_date).days + 1)
        elapsed_days = (calc_date - start_date).days + 1
        fraction = elapsed_days / total_days
        if fraction <= 0.3:
            planned_percent = (fraction / 0.3) * 10.0
        elif fraction <= 0.7:
            planned_percent = 10.0 + ((fraction - 0.3) / 0.4) * 60.0
        else:
            planned_percent = 70.0 + ((fraction - 0.7) / 0.3) * 30.0
        return max(0.0, min(100.0, planned_percent))

@app.route('/api/chart_data')
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_chart_data():
    project_name = request.args.get('project')
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    try:
        # Get project ID and load tasks from database
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({
                'epc_split_completion_data': {},
                'total_delays': {},
                's_curve_data': {},
                'overall_actual_progress': 0,
                'next_critical_activity': None,
                'engineering_disciplines_data': {} # Ensure this is always returned
            })

        tasks = load_tasks_from_db(project_id)
        if not tasks:
            return jsonify({
                'epc_split_completion_data': {},
                'total_delays': {},
                's_curve_data': {},
                'overall_actual_progress': 0,
                'next_critical_activity': None,
                'engineering_disciplines_data': {} # Ensure this is always returned
            })
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({
            'epc_split_completion_data': {},
            'total_delays': {},
            's_curve_data': {},
            'overall_actual_progress': 0,
            'next_critical_activity': None,
            'engineering_disciplines_data': {}
        })
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({
            'epc_split_completion_data': {},
            'total_delays': {},
            's_curve_data': {},
            'overall_actual_progress': 0,
            'next_critical_activity': None,
            'engineering_disciplines_data': {}
        })
    except MySQLError as e:
        print(f"Database error in get_chart_data: {e}")
        return jsonify({
            'epc_split_completion_data': {},
            'total_delays': {},
            's_curve_data': {},
            'overall_actual_progress': 0,
            'next_critical_activity': None,
            'engineering_disciplines_data': {}
        })

    # 1. EPC Split Completion Data
    epc_split_completion_data = {
        "Engineering": {"weightage": 0, "completed_count": 0, "total_tasks": 0, "progress": 0},
        "Procurement": {"weightage": 0, "completed_count": 0, "total_tasks": 0, "progress": 0},
        "Construction": {"weightage": 0, "completed_count": 0, "total_tasks": 0, "progress": 0}
    }

    def get_task_counts_recursive(task_list):
        """Recursively traverses tasks and counts total and completed tasks."""
        total = 0
        completed = 0
        for task in task_list:
            total += 1
            if task.get('status') == 'Completed':
                completed += 1
            if task.get('subtasks'):
                sub_total, sub_completed = get_task_counts_recursive(task.get('subtasks'))
                total += sub_total
                completed += sub_completed
        return total, completed

    if tasks and tasks[0].get('subtasks'):
        for category_task in tasks[0]['subtasks']:
            wbs = category_task.get('wbs')
            category_name = None
            if wbs == '1.2':
                category_name = "Engineering"
            elif wbs == '1.3':
                category_name = "Procurement"
            elif wbs == '1.4':
                category_name = "Construction"

            if category_name:
                epc_split_completion_data[category_name]['weightage'] = float(category_task.get('weightage', 0.0) or 0.0)
                # Add the overall progress of the category task (actual progress)
                epc_split_completion_data[category_name]['progress'] = int(category_task.get('progress', 0) or 0)
                
                # Calculate planned progress based on current date
                from datetime import datetime
                today = datetime.now().date()
                planned_progress = get_planned_progress_for_date_single_task(category_task, today)
                epc_split_completion_data[category_name]['planned_progress'] = round(planned_progress, 1)

                total_count, completed_count = get_task_counts_recursive([category_task])
                epc_split_completion_data[category_name]['total_tasks'] = total_count
                epc_split_completion_data[category_name]['completed_count'] = completed_count

    final_epc_data = {k: v for k, v in epc_split_completion_data.items() if v['weightage'] > 0 or v['total_tasks'] > 0}


    all_tasks = []
    def flatten_tasks(task_list):
        for task in task_list:
            all_tasks.append(task)
            if task.get('subtasks'):
                flatten_tasks(task['subtasks'])
    flatten_tasks(tasks)

    # 2. Total Delays by Type
    total_delays = { 'weather': 0, 'contractor': 0, 'client': 0 }
    for task in all_tasks:
        total_delays['weather'] += task.get('delayWeatherDays', 0) or 0
        total_delays['contractor'] += task.get('delayContractorDays', 0) or 0
        total_delays['client'] += task.get('delayClientDays', 0) or 0

    # 3. Overall Actual Progress
    overall_actual_progress = tasks[0].get('progress', 0) if tasks else 0

    # 4. S-Curve Data
    s_curve_data = get_s_curve_data(tasks)

    # 5. Find the next single critical activity
    future_critical_tasks = []
    today = datetime.now().date()

    for task in all_tasks:
        if task.get('isCritical'):
            try:
                start_date_str = task.get('plannedStartDate')
                if start_date_str and datetime.fromisoformat(start_date_str).date() >= today:
                    future_critical_tasks.append(task)
            except (ValueError, TypeError):
                continue

    next_critical_activity_obj = None
    if future_critical_tasks:
        next_critical_activity_obj = min(future_critical_tasks, key=lambda x: datetime.fromisoformat(x['plannedStartDate']))

    next_critical_activity_data = None
    if next_critical_activity_obj:
        next_critical_activity_data = {
            'wbs': next_critical_activity_obj.get('wbs', ''),
            'taskName': next_critical_activity_obj.get('taskName', '')
        }

    # 6. Engineering Progress by Discipline
    engineering_disciplines_data = {}
    engineering_parent_wbs = "1.2" # Assuming '1.2' is the WBS for Engineering

    for task in all_tasks:
        # Check if the task is a direct child of the main Engineering WBS
        # and has a format like '1.2.X' where X is a number
        wbs_parts = task.get('wbs', '').split('.')
        if len(wbs_parts) == 3 and wbs_parts[0] == '1' and wbs_parts[1] == '2':

            discipline_wbs_part = wbs_parts[2]

            # Use the taskName of the direct child (e.g., "Civil Engineering")
            # If the taskName is generic, you might want to map WBS parts to specific discipline names
            discipline_name = task.get('taskName', f"Discipline {discipline_wbs_part}").strip()
            if not discipline_name: # Fallback if taskName is empty
                discipline_name = f"Discipline {discipline_wbs_part}"

            if discipline_name not in engineering_disciplines_data:
                engineering_disciplines_data[discipline_name] = {
                    "total_weightage": 0.0,
                    "progress": 0 # Overall progress for the discipline
                }

            # Aggregate total weightage for the discipline
            weight = float(task.get('weightage', 0.0) or 0.0)
            engineering_disciplines_data[discipline_name]["total_weightage"] += weight

            # For discipline progress, we directly use the reported progress of the WBS 1.2.X task itself.
            # This assumes the progress of 1.2.X accurately reflects its overall discipline progress.
            # If 1.2.X has sub-tasks, its 'progress' would be a weighted average of its children.
            engineering_disciplines_data[discipline_name]["progress"] = int(task.get('progress', 0) or 0)

    # Filter out disciplines with no weightage if desired, or keep them to show 0 progress
    final_engineering_disciplines_data = {
        name: data for name, data in engineering_disciplines_data.items()
        if data["total_weightage"] > 0
    }

    # 7. Overall Planned Progress
    def get_planned_progress_for_date_internal(task, calc_date):
        if task.get('subtasks') and len(task['subtasks']) > 0:
            total_weight = 0.0
            weighted_progress_sum = 0.0
            for subtask in task['subtasks']:
                weight = float(subtask.get('weightage', 0.0) or 0.0)
                subtask_planned_progress = get_planned_progress_for_date_internal(subtask, calc_date)
                total_weight += weight
                weighted_progress_sum += subtask_planned_progress * weight
            return (weighted_progress_sum / total_weight) if total_weight > 0 else 0.0

        try:
            start_str = task.get('plannedStartDate')
            end_str = task.get('plannedEndDate')
            if not start_str or not end_str:
                return 0.0
            start_date = datetime.fromisoformat(start_str).date()
            end_date = datetime.fromisoformat(end_str).date()
        except (ValueError, TypeError):
            return 0.0

        if end_date < start_date:
            end_date = start_date

        total_days = max(1, (end_date - start_date).days + 1)

        if calc_date < start_date:
            return 0.0
        if calc_date >= end_date:
            return 100.0

        days_elapsed = (calc_date - start_date).days + 1
        fraction = days_elapsed / total_days
        if fraction <= 0.3:
            planned_percent = (fraction / 0.3) * 10.0
        elif fraction <= 0.7:
            planned_percent = 10.0 + ((fraction - 0.3) / 0.4) * 60.0
        else:
            planned_percent = 70.0 + ((fraction - 0.7) / 0.3) * 30.0
        return max(0.0, min(100.0, planned_percent))

    overall_planned_progress = get_planned_progress_for_date_internal(tasks[0], today) if tasks else 0

    return jsonify({
        'epc_split_completion_data': final_epc_data,
        'total_delays': total_delays,
        's_curve_data': s_curve_data,
        'overall_actual_progress': overall_actual_progress,
        'overall_planned_progress': round(overall_planned_progress, 1),
        'next_critical_activity': next_critical_activity_data,
        'engineering_disciplines_data': final_engineering_disciplines_data
    })

@app.route('/api/overall_planned_progress')
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER])
def get_overall_planned_progress():
    project_name = request.args.get('project')
    if not project_name:
        return jsonify({"status": "error", "message": "Project name is required."}), 400

    try:
        # Get project ID and load tasks from database
        project_id = get_project_id_by_name(project_name)
        if project_id is None:
            return jsonify({"planned_progress": 0})

        tasks = load_tasks_from_db(project_id)
        if not tasks:
            return jsonify({"planned_progress": 0})
    except TenantDatabaseError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"planned_progress": 0})
    except TenantResolutionError as e:
        print(f"[TENANT-ERROR] {e}")
        return jsonify({"planned_progress": 0})
    except MySQLError as e:
        print(f"Database error in get_overall_planned_progress: {e}")
        return jsonify({"planned_progress": 0})

    # This is the same logic used by the S-Curve function.
    def get_planned_progress_for_date(task, calc_date):
        """
        Day-based planned progress calculation (inclusive of start and end dates).
        Matches S-curve logic.
        """
        if task.get('subtasks') and len(task['subtasks']) > 0:
            total_weight = 0.0
            weighted_progress_sum = 0.0
            for subtask in task['subtasks']:
                weight = float(subtask.get('weightage', 0.0))
                subtask_planned_progress = get_planned_progress_for_date(subtask, calc_date)
                total_weight += weight
                weighted_progress_sum += subtask_planned_progress * weight
            return (weighted_progress_sum / total_weight) if total_weight > 0 else 0.0

        try:
            start_str = task.get('plannedStartDate')
            end_str = task.get('plannedEndDate')
            if not start_str or not end_str:
                return 0.0
            start_date = datetime.fromisoformat(start_str).date()
            end_date = datetime.fromisoformat(end_str).date()
        except (ValueError, TypeError):
            return 0.0

        if end_date < start_date:
            end_date = start_date

        total_days = max(1, (end_date - start_date).days + 1)

        if calc_date < start_date:
            return 0.0
        if calc_date >= end_date:
            return 100.0

        days_elapsed = (calc_date - start_date).days + 1
        fraction = days_elapsed / total_days
        if fraction <= 0.3:
            planned_percent = (fraction / 0.3) * 10.0
        elif fraction <= 0.7:
            planned_percent = 10.0 + ((fraction - 0.3) / 0.4) * 60.0
        else:
            planned_percent = 70.0 + ((fraction - 0.7) / 0.3) * 30.0
        return max(0.0, min(100.0, planned_percent))

    today = datetime.now().date()
    # We calculate the progress for the root task (the first task in the list)
    planned_progress = get_planned_progress_for_date(tasks[0], today)

    return jsonify(planned_progress=planned_progress)

 
 
 # --- HTML Routes (Publicly Accessible with Client-Side Authentication) ---
 #
# AUTHENTICATION PATTERN FOR HTML ROUTES:
#
# HTML routes (/, /index, /home, /dashboard, /dashboard/projects,
# /dashboard/workspace/<project_id>, /dashboard/reports, /dashboard/admin,
# /dashboard/client-view, /charts, /superadmin, /org/users) are
# publicly accessible and do NOT use server-side authentication decorators.
# Authentication is handled client-side using JavaScript in the templates:
#
#   - landing.html: Client-side auth / redirect logic for unauthenticated users
#   - index.html: Client-side redirect to /dashboard for authenticated users
#   - home.html: Client-side auth check using static/js/auth.js (deprecated, redirects to /dashboard)
#   - dashboard_main.html: Client-side auth check via auth_config.html (included in base.html)
#   - projects.html: Client-side auth check via auth_config.html (included in base.html)
#   - project_workspace.html: Client-side auth check via auth_config.html and workspace access validation API
#   - reports.html: Client-side auth check via auth_config.html (included in base.html)
#   - admin_panel.html: Client-side auth + role checks via auth_config.html (included in base.html)
#   - client_view.html: Client-side auth + role checks via auth_config.html (included in base.html)
#   - charts.html: Client-side auth check and redirects
#   - superadmin.html: Client-side auth + role checks (super_admin only)
#   - org_admin_users.html: Client-side auth + role checks using static/js/auth.js
#
# IMPORTANT: HTML routes should NEVER use authentication decorators
# (@role_required, @tenant_required, @superadmin_required, etc.).
# Decorators are for API routes only (/api/*).
#
# If a decorator is accidentally applied to an HTML route, the decorator will
# detect HTML requests (via Accept header) and redirect to / instead of
# returning JSON errors (defense-in-depth).
#
# This pattern ensures:
#   - Fast page loads (no server-side auth delay)
#   - Secure API access (server-side validation)
#   - Good UX (redirects vs JSON errors for browsers)
#
# WARNING: Future developers should NOT add decorators to HTML routes.
# Use client-side authentication checks in templates instead.

@app.route('/')
def landing():
    """Landing page that redirects logged-in users to their appropriate dashboard."""
    # Check if user has valid JWT token in request headers
    try:
        verify_jwt_in_request(optional=True)
        claims = get_jwt()
        
        if claims:
            # User is logged in, redirect based on role
            user_role = claims.get('role')
            
            if user_role == 'super_admin':
                # SuperAdmin should go to superadmin dashboard
                return redirect('/superadmin')
            else:
                # All other users should go to main dashboard
                return redirect('/dashboard')
    except (JWTExtendedException, NoAuthorizationError, InvalidHeaderError, RuntimeError):
        # No valid token or token error - show landing page
        pass
    except Exception as e:
        # Any other error - log and show landing page
        print(f"[LANDING] Error checking authentication: {e}")
    
    # No valid authentication - show landing page
    return render_template('landing.html', razorpay_key_id=RAZORPAY_KEY_ID)

@app.route('/dashboard')
def dashboard():
    """Serve the main dashboard page with client-side authentication.

    Authentication is handled client-side via auth_config.html which checks
    for JWT tokens in localStorage and redirects to / if not authenticated.
    All data is fetched via authenticated API calls from the React components.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template('dashboard/dashboard_main.html')

# Legacy dashboard route removed after complete migration verification
# If rollback is needed, uncomment the route below and restore dashboard_main.html
# @app.route('/dashboard/legacy')
# def dashboard_legacy():
#     """Legacy dashboard for backward compatibility during transition"""
#     return render_template('dashboard/dashboard_main.html')

@app.route('/dashboard/projects')
def dashboard_projects():
    """Serve the Projects list page with client-side authentication.

    Authentication and role checks are handled client-side via auth_config.html
    (included in base.html) which validates JWT tokens in localStorage and
    redirects to / if not authenticated. All data is fetched via authenticated
    API calls from the React components.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template('dashboard/projects.html')

@app.route('/dashboard/workspace/<project_id>')
def dashboard_workspace(project_id):
    """
    Serve the Project Workspace page with tabbed interface using client-side authentication.

    Authentication and project access validation are handled client-side via
    auth_config.html (included in base.html) and a dedicated API endpoint
    (/api/workspace/<project_id>/validate) that verifies the user's access to
    the requested project.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template(
        'dashboard/project_workspace.html',
        project_id=project_id
    )


@app.route('/api/workspace/<project_id>/validate', methods=['GET'])
@jwt_required()
@tenant_required
@role_required([ROLE_SUPER_ADMIN, ROLE_ORG_ADMIN, ROLE_ORG_USER, ROLE_CLIENT])
def validate_workspace_access(project_id):
    """
    API endpoint to validate access to a project workspace.

    This endpoint replaces the previous server-side validation logic in the
    /dashboard/workspace/<project_id> HTML route. It is intended to be called
    from client-side code after the workspace page loads.

    Validation steps:
      1. Validate project_id format (must be a valid integer ID)
      2. Get current user from JWT
      3. Load the project row by ID from the tenant projects table
      4. For client users, verify the project name matches their assigned project in JWT claims
      5. For non-client users, ensure the project exists in the tenant DB
      6. Log activity (best-effort; failures do not affect the response)
    """
    try:
        # Validate and normalize project_id format (URL parameter is a string)
        if not project_id or not isinstance(project_id, str):
            return jsonify(status="error", message="Invalid project ID"), 400

        try:
            project_id_int = int(project_id)
        except (TypeError, ValueError):
            return jsonify(status="error", message="Invalid project ID"), 400

        # Get current user from JWT
        current_user = get_jwt_identity()
        user_email = current_user if isinstance(current_user, str) else current_user.get('email', current_user)

        # Load project by canonical identifier (ID) from tenant DB
        project_row = execute_tenant_query(
            "SELECT id, name FROM projects WHERE id = ?",
            (project_id_int,),
            fetch_one=True
        )
        if not project_row:
            return jsonify(status="error", message="Project not found"), 404

        # Unpack project fields for clarity
        project_db_id = project_row[0]
        project_name = project_row[1]

        # Verify user has access based on role
        user_role = g.get('user_role', 'org_user')

        # For clients, verify they have access to this specific project
        if user_role == ROLE_CLIENT:
            # Get client's allowed project from JWT claims
            jwt_data = get_jwt()
            client_project = jwt_data.get('project')

            # Validate that the requested project matches the client's assigned project (by name)
            if not client_project or client_project != project_name:
                return jsonify(
                    status="error",
                    message="Access denied. You do not have permission to access this project."
                ), 403

        # Log activity (best-effort)
        try:
            log_activity(
                user_email=user_email,
                project_name=project_name,
                action='VIEW_PROJECT_WORKSPACE',
                details=f'Validated access for workspace project {project_name} (id={project_db_id})'
            )
        except Exception as log_err:
            # Log activity is optional, don't fail if it errors
            app.logger.warning(f'Failed to log activity in validate_workspace_access: {str(log_err)}')

        return jsonify(status="success", project_id=project_db_id), 200

    except Exception as e:
        app.logger.error(f'Error validating project workspace access: {str(e)}')
        return jsonify(status="error", message="Error validating project workspace access"), 500

@app.route('/dashboard/reports')
def dashboard_reports():
    """Serve the Reports page with client-side authentication.

    Authentication is handled client-side via auth_config.html (included in
    base.html) which checks for JWT tokens in localStorage and redirects to /
    if not authenticated. Role-based access control is also enforced
    client-side based on the decoded JWT.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template('dashboard/reports.html')

@app.route('/dashboard/admin')
def dashboard_admin():
    """Serve the Admin panel page with client-side authentication and role checks.

    Authentication and role enforcement (org_admin or super_admin) are handled
    client-side via auth_config.html (included in base.html), which validates
    JWT tokens in localStorage and redirects or hides content as appropriate.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template('dashboard/admin_panel.html')

@app.route('/dashboard/client-view')
def dashboard_client_view():
    """Serve the Client view page with client-side authentication and role checks.

    Authentication is handled client-side via auth_config.html (included in
    base.html), which validates JWT tokens in localStorage and enforces that
    only users with the client role can access this view.

    This route follows the documented pattern for HTML routes (see lines 11449-11476)
    where authentication decorators should NOT be used on HTML-serving routes.
    """
    return render_template('dashboard/client_view.html')

@app.route('/charts')
def charts():
    # Serve the charts page that checks auth and redirects appropriately
    return render_template('charts.html')

# Keep the old index route for backward compatibility
@app.route('/index')
def index():
    return render_template('index.html')

 # Note: The /home route now redirects all users to /dashboard.
 # This route is maintained for backward compatibility with bookmarks and external links.
 # All authenticated users should use /dashboard as the primary landing page.
@app.route('/home')
def home():
    """Redirect to dashboard for backward compatibility.
    
    The /home page has been deprecated in favor of /dashboard.
    This route is maintained to handle bookmarks and external links.
    """
    return redirect(url_for('dashboard'))


@app.route('/superadmin')
def superadmin_dashboard():
    """Serve the SuperAdmin dashboard page (client-side role check)."""
    return render_template('superadmin.html')

@app.route('/org/users')
def org_admin_users_page():
    """Serve the Organization Admin User Management page with client-side authentication and role check."""
    return render_template('org_admin_users.html')


# Health check endpoint
@limiter.exempt
@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        # Timestamp and uptime
        ts = datetime.now(timezone.utc).isoformat() + 'Z'
        try:
            uptime_seconds = int((datetime.now(timezone.utc) - APP_START_TIME).total_seconds())
        except Exception:
            uptime_seconds = None
        primary_db_ok = True
        primary_db_size_mb = 0.0
        try:
            execute_primary_query("SELECT 1")
            # MySQL database size is handled by the database server
        except Exception:
            primary_db_ok = False

        pool_active = 0
        try:
            pool_active = len(getattr(tenant_pool, '_connections', {}))
        except Exception:
            pass

        status = 'healthy' if primary_db_ok else 'unhealthy'
        http_code = 200 if primary_db_ok else 503
        return jsonify({
            "status": status,
            "timestamp": ts,
            "uptime_seconds": uptime_seconds,
            "version": APP_VERSION,
            "checks": {
                "primary_db": {"status": "healthy" if primary_db_ok else "unhealthy", "size_mb": primary_db_size_mb},
                "connection_pool": {"active": pool_active, "max": MAX_CONNECTIONS_PER_DB}
            }
        }), http_code
    except Exception:
        return jsonify({"status": "unhealthy"}), 503

# --- Application Cleanup ---

def cleanup_stale_connections():
    """Clean up stale/invalid connections from the pool (called after each request)."""
    # For MySQL, let the connector handle connection pooling - no manual cleanup needed
    pass

@app.teardown_appcontext
def cleanup_after_request(error):
    """Clean up after request context ends - only remove stale connections, not all."""
    # Don't close all connections - they should be reused!
    # Only clean up stale/invalid connections
    cleanup_stale_connections()

def cleanup_on_shutdown():
    """Clean up connection pool when application shuts down."""
    try:
        tenant_pool.close_all()
        print("Application shutdown: Connection pool cleaned up successfully")
    except Exception as e:
        print(f"Error cleaning up connection pool on shutdown: {e}")

# Register cleanup handlers for application shutdown
atexit.register(cleanup_on_shutdown)

# Handle SIGTERM and SIGINT signals for graceful shutdown
def signal_handler(signum, frame):
    cleanup_on_shutdown()
    exit(0)

signal.signal(signal.SIGTERM, signal_handler)
signal.signal(signal.SIGINT, signal_handler)

# Background scheduler for automatic payment retries
scheduler = None

def setup_payment_retry_scheduler():
    """Set up APScheduler for automatic payment retry execution."""
    global scheduler
    
    if not APSCHEDULER_AVAILABLE:
        print("Warning: APScheduler not available. Automatic payment retries will not run.")
        print("Install with: pip install apscheduler")
        return
    
    try:
        from utils.payment_retry import PaymentRetryManager, retry_failed_payments
        
        scheduler = BackgroundScheduler()
        
        def execute_automatic_retry():
            """Scheduled job to automatically retry failed payments."""
            try:
                if razorpay_client is None:
                    return
                
                ready_payments = PaymentRetryManager.get_failed_payments_ready_for_retry()
                if ready_payments:
                    print(f"[SCHEDULER] Found {len(ready_payments)} payments ready for retry")
                    results = retry_failed_payments(ready_payments, razorpay_client)
                    print(f"[SCHEDULER] Retry completed: {results.get('success_count', 0)} succeeded, {results.get('failed_count', 0)} failed")
            except Exception as e:
                print(f"[SCHEDULER] Error in automatic payment retry: {e}")
        
        # Schedule to run daily at 2 AM
        scheduler.add_job(
            execute_automatic_retry,
            trigger=CronTrigger(hour=2, minute=0),
            id='payment_retry_job',
            name='Automatic Payment Retry',
            replace_existing=True
        )
        
        scheduler.start()
        print("✓ Payment retry scheduler started (runs daily at 2 AM)")
        
    except Exception as e:
        print(f"Error setting up payment retry scheduler: {e}")

def cleanup_scheduler():
    """Stop the scheduler on shutdown."""
    global scheduler
    if scheduler and scheduler.running:
        scheduler.shutdown()
        print("Payment retry scheduler stopped")

# Register cleanup
atexit.register(cleanup_scheduler)


if __name__ == '__main__':
    # When debug=True, Flask uses a reloader which spawns a child process.
    # The parent process runs this block once (WERKZEUG_RUN_MAIN is None).
    # The child process runs this block again (WERKZEUG_RUN_MAIN is 'true').
    # We only want to run initialization logic in the child process (the actual server).
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        # initialize_database()  # REMOVED: Legacy single-tenant DB no longer needed in multi-tenant architecture
        initialize_primary_database()
        migrate_schema_versioning()  # Create schema_migrations table first (must run before other migrations)
        migrate_users_table_for_auth_features()
        auto_create_superadmin_from_env()  # Auto-create SuperAdmin from environment credentials when configured
        # seed_super_admin()  # DISABLED: Use /api/superadmin/signup endpoint instead
        migrate_plan_limits_to_new_pricing()  # Migrate existing databases to new pricing structure
        migrate_organizations_table_for_tour()  # Add tour_seen column to organizations table
        migrate_billing_transactions_unique_constraint()  # Add UNIQUE constraint on razorpay_payment_id
        migrate_billing_transactions_retry_tracking()  # Add retry_attempts and last_retry_at columns
        seed_plan_limits()
        setup_payment_retry_scheduler()  # Set up automatic payment retry scheduler
    
    app.run(debug=True, host='0.0.0.0', port=5125)