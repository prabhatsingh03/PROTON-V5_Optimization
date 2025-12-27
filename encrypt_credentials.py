#!/usr/bin/env python3
"""
Credential Encryption Utility for PROTON Payment System

This script helps encrypt sensitive Razorpay credentials for secure storage.
Encrypted credentials can be stored in environment variables with the ENCRYPTED_ prefix.

Usage:
    python encrypt_credentials.py

Security Recommendations:
1. Use this only as a temporary solution for development/staging
2. For production, use dedicated secret management:
   - AWS Secrets Manager (recommended for AWS deployments)
   - Azure Key Vault (recommended for Azure deployments)
   - HashiCorp Vault (recommended for on-premise/multi-cloud)
   - Google Cloud Secret Manager (recommended for GCP deployments)

3. Rotate credentials regularly (quarterly at minimum)
4. Never commit encrypted credentials to version control
5. Use different credentials for development, staging, and production
6. Monitor access to credentials with audit logging

Setup:
    1. Generate a 32-character encryption key:
       python -c "import secrets; print(secrets.token_urlsafe(32))"
    
    2. Set ENCRYPTION_KEY environment variable with the generated key
    
    3. Run this script to encrypt your Razorpay credentials
    
    4. Add encrypted values to your environment:
       export ENCRYPTED_RAZORPAY_KEY_ID="<encrypted_value>"
       export ENCRYPTED_RAZORPAY_KEY_SECRET="<encrypted_value>"
       export ENCRYPTED_RAZORPAY_WEBHOOK_SECRET="<encrypted_value>"
"""

import os
import sys
import base64
import getpass
from cryptography.fernet import Fernet


def generate_encryption_key():
    """Generate a new encryption key for Fernet."""
    return Fernet.generate_key().decode()


def encrypt_credential(credential, encryption_key):
    """
    Encrypt a credential string using Fernet symmetric encryption.
    
    Args:
        credential: The credential string to encrypt
        encryption_key: The encryption key (must be Fernet-compatible)
        
    Returns:
        Base64-encoded encrypted credential
    """
    try:
        # Ensure key is properly formatted for Fernet
        if len(encryption_key) == 32:
            # If key is 32 bytes, encode it as base64 for Fernet
            key = base64.urlsafe_b64encode(encryption_key.encode()[:32])
        else:
            key = encryption_key.encode()
        
        cipher = Fernet(key)
        encrypted = cipher.encrypt(credential.encode())
        return encrypted.decode()
    except Exception as e:
        print(f"Error encrypting credential: {e}")
        return None


def main():
    """Main function to encrypt Razorpay credentials."""
    print("=" * 70)
    print("PROTON Payment Credential Encryption Utility")
    print("=" * 70)
    print()
    
    # Check for encryption key
    encryption_key = os.environ.get('ENCRYPTION_KEY', '')
    
    if not encryption_key:
        print("WARNING: ENCRYPTION_KEY not found in environment variables")
        print()
        print("Would you like to:")
        print("1. Generate a new encryption key")
        print("2. Enter an existing encryption key")
        print("3. Exit")
        print()
        choice = input("Enter choice (1-3): ").strip()
        
        if choice == '1':
            encryption_key = generate_encryption_key()
            print()
            print("=" * 70)
            print("Generated Encryption Key (SAVE THIS SECURELY):")
            print("=" * 70)
            print(encryption_key)
            print("=" * 70)
            print()
            print("Add this to your environment variables:")
            print(f"export ENCRYPTION_KEY='{encryption_key}'")
            print()
        elif choice == '2':
            encryption_key = getpass.getpass("Enter your encryption key: ")
            if not encryption_key:
                print("ERROR: Encryption key cannot be empty")
                sys.exit(1)
        else:
            print("Exiting...")
            sys.exit(0)
    
    print("Encryption key loaded successfully")
    print()
    
    # Encrypt Razorpay credentials
    credentials = {}
    
    print("Enter your Razorpay credentials (leave blank to skip):")
    print()
    
    # RAZORPAY_KEY_ID
    key_id = getpass.getpass("Razorpay Key ID: ").strip()
    if key_id:
        encrypted_key_id = encrypt_credential(key_id, encryption_key)
        if encrypted_key_id:
            credentials['ENCRYPTED_RAZORPAY_KEY_ID'] = encrypted_key_id
    
    # RAZORPAY_KEY_SECRET
    key_secret = getpass.getpass("Razorpay Key Secret: ").strip()
    if key_secret:
        encrypted_key_secret = encrypt_credential(key_secret, encryption_key)
        if encrypted_key_secret:
            credentials['ENCRYPTED_RAZORPAY_KEY_SECRET'] = encrypted_key_secret
    
    # RAZORPAY_WEBHOOK_SECRET
    webhook_secret = getpass.getpass("Razorpay Webhook Secret: ").strip()
    if webhook_secret:
        encrypted_webhook = encrypt_credential(webhook_secret, encryption_key)
        if encrypted_webhook:
            credentials['ENCRYPTED_RAZORPAY_WEBHOOK_SECRET'] = encrypted_webhook
    
    # Display results
    print()
    print("=" * 70)
    print("Encrypted Credentials")
    print("=" * 70)
    print()
    
    if not credentials:
        print("No credentials were encrypted")
        return
    
    print("Add these to your environment variables or .env file:")
    print()
    
    for key, value in credentials.items():
        print(f"{key}='{value}'")
    
    print()
    print("=" * 70)
    print("IMPORTANT: Security Reminders")
    print("=" * 70)
    print()
    print("1. Never commit these values to version control")
    print("2. Store them securely in your deployment environment")
    print("3. Use different credentials for dev/staging/production")
    print("4. Rotate credentials regularly (quarterly minimum)")
    print("5. For production, migrate to AWS Secrets Manager or similar")
    print("6. Keep the ENCRYPTION_KEY separate and highly secure")
    print()


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(0)
    except Exception as e:
        print(f"\nERROR: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

