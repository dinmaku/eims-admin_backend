from app.db import get_db_connection
import logging

def fix_gown_package_constraints():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Drop the existing foreign key constraint
        cursor.execute("""
            ALTER TABLE wishlist_packages 
            DROP CONSTRAINT IF EXISTS wishlist_packages_gown_package_id_fkey;
        """)
        
        # Add the correct foreign key constraint
        cursor.execute("""
            ALTER TABLE wishlist_packages
            ADD CONSTRAINT wishlist_packages_gown_package_id_fkey 
            FOREIGN KEY (gown_package_id) 
            REFERENCES gown_package(gown_package_id);
        """)
        
        # Also fix the constraint in wishlist_outfits table
        cursor.execute("""
            ALTER TABLE wishlist_outfits
            DROP CONSTRAINT IF EXISTS wishlist_outfits_gown_package_id_fkey;
        """)
        
        cursor.execute("""
            ALTER TABLE wishlist_outfits
            ADD CONSTRAINT wishlist_outfits_gown_package_id_fkey
            FOREIGN KEY (gown_package_id)
            REFERENCES gown_package(gown_package_id);
        """)
        
        conn.commit()
        print("Successfully fixed gown package constraints")
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error fixing gown package constraints: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

if __name__ == "__main__":
    fix_gown_package_constraints()
