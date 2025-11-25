import psycopg2
import os
import logging
import sys

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_db_connection():
    """Establish a database connection."""
    # Import the db module from the app to reuse the same connection logic
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    from app.db import get_db_connection
    return get_db_connection()

def update_invoices_table():
    """Update the invoices table to add discount_id and discount_amount columns."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # First check if the columns already exist
        cursor.execute("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'invoices' 
            AND column_name IN ('discount_id', 'discount_amount');
        """)
        existing_columns = [row[0] for row in cursor.fetchall()]
        
        # Add discount_id column if it doesn't exist
        if 'discount_id' not in existing_columns:
            logger.info("Adding discount_id column to invoices table")
            cursor.execute("""
                ALTER TABLE invoices
                ADD COLUMN discount_id INTEGER DEFAULT NULL;
            """)
        else:
            logger.info("discount_id column already exists")
        
        # Add discount_amount column if it doesn't exist
        if 'discount_amount' not in existing_columns:
            logger.info("Adding discount_amount column to invoices table")
            cursor.execute("""
                ALTER TABLE invoices
                ADD COLUMN discount_amount DECIMAL(10, 2) DEFAULT 0.00;
            """)
        else:
            logger.info("discount_amount column already exists")
        
        conn.commit()
        logger.info("Invoices table updated successfully")
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Error updating invoices table: {e}")
    finally:
        if conn:
            conn.close()

if __name__ == "__main__":
    try:
        logger.info("Starting update of invoices table")
        update_invoices_table()
        logger.info("Update completed successfully")
    except Exception as e:
        logger.error(f"Update failed: {e}") 