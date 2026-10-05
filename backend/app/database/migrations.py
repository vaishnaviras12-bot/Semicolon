"""
Database Schema Migrations
==========================
Provides idempotent schema synchronization and migration for SQLite and relational databases.
Ensures existing tables receive missing model columns without data loss or dropping tables.
"""

import logging
from sqlalchemy import inspect, text

logger = logging.getLogger("ecdat.database.migrations")

def run_schema_migrations(engine, base):
    """
    Inspects the target database schema against SQLAlchemy Base metadata models.
    Executes ALTER TABLE ADD COLUMN for any model columns missing from existing tables.
    Preserves all existing tables, rows, and persisted data.
    Idempotent: Safe to execute on every application startup.
    """
    try:
        inspector = inspect(engine)
        existing_tables = inspector.get_table_names()
        
        with engine.connect() as conn:
            for table_name, table in base.metadata.tables.items():
                if table_name in existing_tables:
                    existing_cols = {col['name'] for col in inspector.get_columns(table_name)}
                    for col in table.columns:
                        if col.name not in existing_cols:
                            # Map SQLAlchemy column type to SQL dialect string
                            col_type_str = str(col.type)
                            if "VARCHAR" in col_type_str.upper() or "STRING" in col_type_str.upper():
                                type_sql = "VARCHAR(255)"
                                if hasattr(col.type, 'length') and col.type.length:
                                    type_sql = f"VARCHAR({col.type.length})"
                            elif "FLOAT" in col_type_str.upper() or "REAL" in col_type_str.upper():
                                type_sql = "FLOAT"
                            elif "TEXT" in col_type_str.upper() or "JSON" in col_type_str.upper():
                                type_sql = "TEXT"
                            elif "INT" in col_type_str.upper():
                                type_sql = "INTEGER"
                            elif "BOOL" in col_type_str.upper():
                                type_sql = "BOOLEAN"
                            elif "DATETIME" in col_type_str.upper() or "TIMESTAMP" in col_type_str.upper():
                                type_sql = "DATETIME"
                            else:
                                type_sql = "TEXT"
                            
                            alter_cmd = f"ALTER TABLE {table_name} ADD COLUMN {col.name} {type_sql}"
                            logger.info(f"Applying schema migration: {alter_cmd}")
                            try:
                                conn.execute(text(alter_cmd))
                                conn.commit()
                                logger.info(f"Successfully added column {col.name} to table {table_name}")
                            except Exception as ex:
                                logger.warning(f"Could not execute '{alter_cmd}': {ex}")
    except Exception as e:
        logger.error(f"Error during schema migration check: {e}")
