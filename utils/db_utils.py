"""
Database helper utilities for MySQL backend.
"""
from typing import Any, Iterable, List, Optional, Sequence, Tuple

try:
    import mysql.connector
    from mysql.connector import Error as MySQLError
except ImportError:  # pragma: no cover - optional dependency
    mysql = None
    MySQLError = Exception

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
)


def convert_query_placeholders(query: str, db_type: str) -> str:
    """Convert parameter placeholders based on database type."""
    if db_type.lower() == "mysql":
        return query.replace("?", "%s")
    return query


def get_tenant_db_name(org_id: int) -> str:
    """Return the tenant database name for the given org_id."""
    return f"org_{org_id}"




def _get_mysql_connection(database_name: Optional[str] = None):
    """Create a MySQL connection using connector."""
    if mysql is None:
        raise ImportError("mysql-connector-python is required for MySQL support")
    return mysql.connector.connect(
        host=MYSQL_HOST,
        port=MYSQL_PORT,
        user=MYSQL_USER,
        password=MYSQL_PASSWORD,
        database=database_name or MYSQL_PRIMARY_DATABASE,
        charset=MYSQL_CHARSET,
        use_pure=True,
        autocommit=False,
        connection_timeout=10,
        pool_name=f"{(database_name or MYSQL_PRIMARY_DATABASE)}_pool",
        pool_size=MYSQL_POOL_SIZE,
        pool_reset_session=True,
        consume_results=True,  # Auto-consume unread results to prevent connection errors
    )


def get_db_connection(database_name: Optional[str] = None):
    """Return a MySQL database connection."""
    return _get_mysql_connection(database_name or MYSQL_PRIMARY_DATABASE)


def get_primary_db_connection():
    """Return a connection to the primary MySQL database."""
    return get_db_connection(MYSQL_PRIMARY_DATABASE)


def execute_primary_query(
    query: str,
    params: Optional[Sequence[Any]] = None,
    *,
    fetch_one: bool = False,
    fetch_all: bool = False,
    commit: bool = True,
    return_lastrowid: bool = False,
) -> Any:
    """Execute a query against the primary database with error handling."""
    conn = None
    cursor = None
    try:
        conn = get_primary_db_connection()
        normalized_query = convert_query_placeholders(query, DB_TYPE)
        # Use buffered tuple-based cursors for MySQL to avoid "Unread result found" errors.
        # This keeps row access consistent for callers that rely on positional indexing.
        if DB_TYPE.lower() == "mysql":
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
            if return_lastrowid or (normalized_query.strip().upper().startswith("INSERT") and cursor.lastrowid is not None):
                result = cursor.lastrowid
            else:
                result = cursor.rowcount

        if commit:
            conn.commit()

        return result
    except MySQLError as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"Primary database error: {exc}")
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


def execute_primary_transaction(operations: Iterable[dict]) -> Tuple[bool, List[Any], Optional[str]]:
    """
    Execute multiple primary database operations in a single atomic transaction.

    Args:
        operations (Iterable[dict]): Dicts describing query, params, and fetch flags.

    Returns:
        tuple: (success, results, error_message)
    """
    conn = None
    cursor = None
    results: List[Any] = []
    try:
        conn = get_primary_db_connection()
        # Use buffered cursors for MySQL to avoid "Unread result found" errors.
        if DB_TYPE.lower() == "mysql":
            conn.start_transaction()
            cursor = conn.cursor(buffered=True)
        else:
            conn.execute("BEGIN TRANSACTION")
            cursor = conn.cursor()

        for op in operations:
            query = convert_query_placeholders(op.get("query"), DB_TYPE)
            params = op.get("params")
            fetch_one = op.get("fetch_one", False)
            fetch_all = op.get("fetch_all", False)
            return_lastrowid = op.get("return_lastrowid", False)

            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)

            if fetch_one:
                results.append(cursor.fetchone())
            elif fetch_all:
                results.append(cursor.fetchall())
            else:
                if return_lastrowid or (query.strip().upper().startswith("INSERT") and cursor.lastrowid is not None):
                    results.append(cursor.lastrowid)
                else:
                    results.append(cursor.rowcount)

        conn.commit()
        return True, results, None
    except MySQLError as exc:
        if conn:
            try:
                conn.rollback()
            except Exception:
                pass
        print(f"Primary transaction error: {exc}")
        return False, [], str(exc)
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


__all__ = [
    "convert_query_placeholders",
    "get_db_connection",
    "get_primary_db_connection",
    "execute_primary_query",
    "execute_primary_transaction",
    "get_tenant_db_name",
]

