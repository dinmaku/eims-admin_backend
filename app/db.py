#db.py
import pg8000
import logging
from .config import DATABASE_CONFIG

# Configure logging
logger = logging.getLogger(__name__)

def get_db_connection():
    try:
        logger.info("Attempting database connection using pg8000...")

        conn = pg8000.connect(
            host=DATABASE_CONFIG['host'],
            database=DATABASE_CONFIG['database'],
            user=DATABASE_CONFIG['user'],
            password=DATABASE_CONFIG['password'],
            port=DATABASE_CONFIG.get('port', 5432)  # default to 5432 if not specified
        )

        logger.info("Database connection successful")
        return conn

    except pg8000.exceptions.InterfaceError as e:
        logger.error(f"Database connection failed - InterfaceError: {str(e)}")
        raise

    except pg8000.exceptions.DatabaseError as e:
        logger.error(f"Database connection failed - DatabaseError: {str(e)}")
        raise

    except Exception as e:
        logger.error(f"Database connection failed - Unexpected error: {str(e)}")
        raise

def get_all_discounts():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT discount_id, name, description, type, value, 
                   start_date, end_date, status, created_at, updated_at
            FROM discounts
            ORDER BY name
        """)
        discounts = []
        for row in cur.fetchall():
            discount = {
                'discount_id': row[0],
                'name': row[1],
                'description': row[2],
                'type': row[3],
                'value': float(row[4]) if row[4] is not None else None,
                'start_date': row[5].isoformat() if row[5] else None,
                'end_date': row[6].isoformat() if row[6] else None,
                'status': row[7],
                'created_at': row[8].isoformat() if row[8] else None,
                'updated_at': row[9].isoformat() if row[9] else None
            }
            discounts.append(discount)
        cur.close()
        conn.close()
        return discounts
    except Exception as e:
        logger.error(f"Error in get_all_discounts: {str(e)}")
        raise

def get_active_discounts():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT discount_id, name, description, type, value, 
                   start_date, end_date, status, created_at, updated_at
            FROM discounts
            WHERE status = 'active'
            AND (start_date IS NULL OR start_date <= CURRENT_DATE)
            AND (end_date IS NULL OR end_date >= CURRENT_DATE)
            ORDER BY name
        """)
        discounts = []
        for row in cur.fetchall():
            discount = {
                'discount_id': row[0],
                'name': row[1],
                'description': row[2],
                'type': row[3],
                'value': float(row[4]) if row[4] is not None else None,
                'start_date': row[5].isoformat() if row[5] else None,
                'end_date': row[6].isoformat() if row[6] else None,
                'status': row[7],
                'created_at': row[8].isoformat() if row[8] else None,
                'updated_at': row[9].isoformat() if row[9] else None
            }
            discounts.append(discount)
        cur.close()
        conn.close()
        return discounts
    except Exception as e:
        logger.error(f"Error in get_active_discounts: {str(e)}")
        raise

def get_discount_by_id(discount_id):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT discount_id, name, description, type, value, 
                   start_date, end_date, status, created_at, updated_at
            FROM discounts
            WHERE discount_id = %s
        """, (discount_id,))
        row = cur.fetchone()
        if row:
            discount = {
                'discount_id': row[0],
                'name': row[1],
                'description': row[2],
                'type': row[3],
                'value': float(row[4]) if row[4] is not None else None,
                'start_date': row[5].isoformat() if row[5] else None,
                'end_date': row[6].isoformat() if row[6] else None,
                'status': row[7],
                'created_at': row[8].isoformat() if row[8] else None,
                'updated_at': row[9].isoformat() if row[9] else None
            }
            cur.close()
            conn.close()
            return discount
        cur.close()
        conn.close()
        return None
    except Exception as e:
        logger.error(f"Error in get_discount_by_id: {str(e)}")
        raise

def get_inactive_discounts():
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("""
            SELECT discount_id, name, description, type, value, 
                   start_date, end_date, status, created_at, updated_at
            FROM discounts
            WHERE status = 'inactive'
            ORDER BY name
        """)
        discounts = []
        for row in cur.fetchall():
            discount = {
                'discount_id': row[0],
                'name': row[1],
                'description': row[2],
                'type': row[3],
                'value': float(row[4]) if row[4] is not None else None,
                'start_date': row[5].isoformat() if row[5] else None,
                'end_date': row[6].isoformat() if row[6] else None,
                'status': row[7],
                'created_at': row[8].isoformat() if row[8] else None,
                'updated_at': row[9].isoformat() if row[9] else None
            }
            discounts.append(discount)
        cur.close()
        conn.close()
        return discounts
    except Exception as e:
        logger.error(f"Error in get_inactive_discounts: {str(e)}")
        raise