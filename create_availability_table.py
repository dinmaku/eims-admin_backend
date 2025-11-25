#!/usr/bin/env python3

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from app.db import get_db_connection

def create_availability_table():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Create the supplier_availability table
        sql = """
        -- Table for storing supplier availability/unavailability
        CREATE TABLE IF NOT EXISTS supplier_availability (
            availability_id SERIAL PRIMARY KEY,
            supplier_id INTEGER NOT NULL,
            date DATE NOT NULL,
            is_available BOOLEAN DEFAULT true,
            reason TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            CONSTRAINT fk_supplier_availability_supplier FOREIGN KEY (supplier_id) 
                REFERENCES suppliers(supplier_id) ON DELETE CASCADE,
            CONSTRAINT unique_supplier_date UNIQUE (supplier_id, date)
        );

        -- Index for better query performance
        CREATE INDEX IF NOT EXISTS idx_supplier_availability_supplier_date 
        ON supplier_availability(supplier_id, date);

        -- Index for date range queries
        CREATE INDEX IF NOT EXISTS idx_supplier_availability_date 
        ON supplier_availability(date);
        """
        
        cursor.execute(sql)
        conn.commit()
        
        print("✅ Supplier availability table created successfully!")
        
        cursor.close()
        conn.close()
        
    except Exception as e:
        print(f"❌ Error creating supplier availability table: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()

if __name__ == "__main__":
    create_availability_table() 