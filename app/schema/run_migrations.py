import psycopg2
import os

def run_migrations():
    conn = None
    cursor = None
    try:
        conn = psycopg2.connect(
            dbname="eims_db",
            user="postgres",
            password="meadmin0921",
            host="localhost",
            port="5432"
        )
        cursor = conn.cursor()
        
        # Drop existing tables if they exist
        cursor.execute("""
            DROP TABLE IF EXISTS wishlist_package_services CASCADE;
            DROP TABLE IF EXISTS wishlist_suppliers CASCADE;
            DROP TABLE IF EXISTS wishlist_outfits CASCADE;
            DROP TABLE IF EXISTS wishlist_packages CASCADE;
        """)
        
        # Read and execute the SQL file
        with open('wishlist_tables.sql', 'r') as file:
            sql = file.read()
            cursor.execute(sql)
        
        # Verify table structure
        cursor.execute("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_name = 'wishlist_package_services'
            ORDER BY ordinal_position;
        """)
        columns = cursor.fetchall()
        print("Table structure:")
        for col in columns:
            print(f"Column: {col[0]}, Type: {col[1]}")
        
        conn.commit()
        print("Migrations completed successfully!")
        
    except Exception as e:
        print(f"Error running migrations: {str(e)}")
        if conn:
            conn.rollback()
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

if __name__ == "__main__":
    # Change to the directory containing this script
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    run_migrations()
