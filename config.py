"""
Centralized configuration values shared across modules.

This module reads environment variables once and exposes commonly used
constants so that other modules (app, utils, etc.) can import them
without creating circular dependencies.

MySQL-only configuration - SQLite support has been removed.
"""
import os

from dotenv import load_dotenv

# Ensure .env values are loaded regardless of import order
load_dotenv()

# Database configuration - MySQL only
DB_TYPE = os.environ.get("DB_TYPE", "mysql")  # MySQL-only application

# MySQL configuration
MYSQL_HOST = os.environ.get("MYSQL_HOST", "localhost")
MYSQL_PORT = int(os.environ.get("MYSQL_PORT", "3306"))
MYSQL_USER = os.environ.get("MYSQL_USER", "")
MYSQL_PASSWORD = os.environ.get("MYSQL_PASSWORD", "")
MYSQL_PRIMARY_DATABASE = os.environ.get("MYSQL_PRIMARY_DATABASE", "proton_primary")
MYSQL_CHARSET = os.environ.get("MYSQL_CHARSET", "utf8mb4")
MYSQL_POOL_SIZE = int(os.environ.get("MYSQL_POOL_SIZE", "10"))
MYSQL_POOL_RECYCLE = int(os.environ.get("MYSQL_POOL_RECYCLE", "3600"))

# SMTP / Email configuration
SMTP_HOST = os.environ.get("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USERNAME = os.environ.get("SMTP_USERNAME", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
SMTP_FROM_EMAIL = os.environ.get("SMTP_FROM_EMAIL", "noreply@proton.com")
SMTP_FROM_NAME = os.environ.get("SMTP_FROM_NAME", "PROTON")

# Email feature timing configuration
OTP_EXPIRY_MINUTES = int(os.environ.get("OTP_EXPIRY_MINUTES", "10"))
OTP_MAX_ATTEMPTS = int(os.environ.get("OTP_MAX_ATTEMPTS", "5"))
RESET_TOKEN_EXPIRY_HOURS = int(os.environ.get("RESET_TOKEN_EXPIRY_HOURS", "24"))

# SuperAdmin direct credentials (optional automatic provisioning)
SUPERADMIN_EMAIL = os.environ.get("SUPERADMIN_EMAIL", "")
SUPERADMIN_PASSWORD = os.environ.get("SUPERADMIN_PASSWORD", "")

# Google Gemini API keys (server-side only)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")
CHATBOT_GEMINI_API_KEY = os.environ.get("CHATBOT_GEMINI_API_KEY", "")

__all__ = [
    "DB_TYPE",
    "MYSQL_HOST",
    "MYSQL_PORT",
    "MYSQL_USER",
    "MYSQL_PASSWORD",
    "MYSQL_PRIMARY_DATABASE",
    "MYSQL_CHARSET",
    "MYSQL_POOL_SIZE",
    "MYSQL_POOL_RECYCLE",
    "SMTP_HOST",
    "SMTP_PORT",
    "SMTP_USERNAME",
    "SMTP_PASSWORD",
    "SMTP_FROM_EMAIL",
    "SMTP_FROM_NAME",
    "OTP_EXPIRY_MINUTES",
    "OTP_MAX_ATTEMPTS",
    "RESET_TOKEN_EXPIRY_HOURS",
    "SUPERADMIN_EMAIL",
    "SUPERADMIN_PASSWORD",
    "GEMINI_API_KEY",
    "CHATBOT_GEMINI_API_KEY",
]

