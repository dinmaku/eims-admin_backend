# models.py
import hashlib
from . import db
import logging
from datetime import date, time
import json
import pg8000


# Configure logging
logging.basicConfig(level=logging.ERROR)
logger = logging.getLogger(__name__)


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#admin login
def check_user(email, password):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    hashed_password = hash_password(password)
    
    try:
        # Fetch the user entry
        cursor.execute("SELECT password, user_type FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        
        # Ensure user exists, password matches, and user_type is allowed
        allowed_user_types = {'Admin', 'Assistant', 'Staff'}
        if user and user[0] == hashed_password and user[1] in allowed_user_types:
            return True, user[1]  # Return True and user_type
        return False, None
    finally:
        cursor.close()
        conn.close()

#manage-users.py / models     

def create_user(first_name, last_name, username, email, contact_number, password, user_type, address):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if email already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE email = %s", (email,))
        if cursor.fetchone()[0] > 0:
            logger.info(f"Duplicate email found: {email}")
            return False, None, "Email already exists"

        # Check if username already exists
        cursor.execute("SELECT COUNT(*) FROM users WHERE username = %s", (username,))
        if cursor.fetchone()[0] > 0:
            logger.info(f"Duplicate username found: {username}")
            return False, None, "Username already exists"

        # Hash the password before inserting it
        hashed_password = hash_password(password)

        # Use the hashed password in the query with correct column names
        cursor.execute(
            "INSERT INTO users (firstname, lastname, username, email, contactnumber, password, user_type, address) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, %s) RETURNING userid", 
            (first_name, last_name, username, email, contact_number, hashed_password, user_type, address)
        )
        
        # Retrieve the 'userid' of the newly inserted user
        user_id = cursor.fetchone()[0]
        
        # Commit the transaction
        conn.commit()
        
        # Return success flag, user_id, and no error message
        return True, user_id, None

    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        conn.rollback()
        return False, None, str(e)
    
    finally:
        cursor.close()
        conn.close()


def create_supplier(userid, service, price):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "INSERT INTO suppliers (userid, service, price, status) VALUES (%s, %s, %s, %s)",
            (userid, service, price, 'Active')
        )
        conn.commit()
        return True
    finally:
        cursor.close()
        conn.close()


def get_users_by_type():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT userid, firstname, lastname, email, contactnumber, user_type
            FROM users
            WHERE user_type IN ('Assistant', 'Staff')
            """
        )
        users = cursor.fetchall()
        # Transform the result into a list of dictionaries
        return [
            {
                'userid': item[0],
                'firstname': item[1],
                'lastname': item[2],
                'email': item[3],
                'contactnumber': item[4],
                'user_type': item[5],
            }
            for item in users
        ]
    finally:
        cursor.close()
        conn.close()

def get_admin_users():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT userid, firstname, lastname, email, contactnumber, user_type
            FROM users
            WHERE user_type IN ('Admin')
            """
        )
        users = cursor.fetchall()
        # Transform the result into a list of dictionaries
        return [
            {
                'userid': item[0],
                'firstname': item[1],
                'lastname': item[2],
                'email': item[3],
                'contactnumber': item[4],
                'user_type': item[5],
            }
            for item in users
        ]
    finally:
        cursor.close()
        conn.close()


def get_suppliers_with_users():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT s.supplier_id, u.firstname, u.lastname, u.email, u.contactnumber, 
                   u.username, u.password, s.service, s.price, s.status, u.userid
            FROM suppliers s
            JOIN users u ON s.userid = u.userid
            WHERE s.status = 'Active'
            ORDER BY s.supplier_id
        """)
        suppliers = cursor.fetchall()
        
        # Convert to list of dictionaries
        suppliers_list = []
        for supplier in suppliers:
            suppliers_list.append({
                'supplier_id': supplier[0],
                'firstname': supplier[1],
                'lastname': supplier[2],
                'email': supplier[3],
                'contactnumber': supplier[4],
                'username': supplier[5],
                'password': supplier[6],
                'service': supplier[7],
                'price': float(supplier[8]) if supplier[8] else 0,
                'status': supplier[9],
                'userid': supplier[10]
            })
        return suppliers_list
    finally:
        cursor.close()
        conn.close()


def get_package_services_with_suppliers():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # Query to fetch package service details and associated supplier info
        cursor.execute(
            """
            SELECT ps.package_service_id, ps.supplier_id, ps.external_supplier_name, 
                   ps.external_supplier_contact, ps.external_supplier_price, ps.remarks
            FROM package_service ps
            """
        )
        package_services = cursor.fetchall()

        # Map the query result into a structured dictionary
        return [
            {
                'package_service_id': item[0],
                'supplier_id': item[1],
                'external_supplier_name': item[2],
                'external_supplier_contact': item[3],
                'external_supplier_price': float(item[4]) if item[4] is not None else 0.0,
                'remarks': item[5],
            }
            for item in package_services
        ]
    except Exception as e:
        # Log the exception if needed
        print(f"Error fetching package services: {e}")
        return []
    finally:
        cursor.close()
        conn.close()





def update_suppliers_and_user(
    supplier_id, service, price, 
    userid, firstname, lastname, email, contactnumber, username, password
):
    if not supplier_id or not userid:
        logger.error("Invalid supplier_id or userid provided")
        return False

    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Hash the password before updating it
        hashed_password = hash_password(password)

        # Update the `suppliers` table
        cursor.execute(
            """
            UPDATE suppliers
            SET service = %s, price = %s
            WHERE supplier_id = %s
            """,
            (service, price, supplier_id),
        )
        if cursor.rowcount == 0:
            logger.warning(f"No supplier found with supplier_id {supplier_id}")
            return False

        # Update the `users` table
        cursor.execute(
            """
            UPDATE users
            SET firstname = %s, lastname = %s, email = %s, 
                contactnumber = %s, username = %s, password = %s
            WHERE userid = %s
            """,
            (firstname, lastname, email, contactnumber, username, hashed_password, userid),
        )
        if cursor.rowcount == 0:
            logger.warning(f"No user found with userid {userid}")
            return False

        # Commit the transaction if both updates are successful
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating supplier and user: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()




def update_staff(userid, firstname, lastname, email, contactnumber, user_type):
    if not userid:
        logger.error("Invalid userid provided")
        return False
    
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE users 
            SET firstname = %s, lastname = %s, email = %s, contactnumber = %s, user_type = %s 
            WHERE userid = %s
            """,
            (firstname, lastname, email, contactnumber, user_type, userid),
        )
        if cursor.rowcount == 0:
            logger.warning(f"No user found with userid {userid}")
            return False
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error updating staff {userid}: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def delete_user(userid):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # First, delete related events (to avoid foreign key violation)
        cursor.execute("DELETE FROM events WHERE userid = %s", (userid,))
        conn.commit()

        # Then delete the user from the users table
        cursor.execute("DELETE FROM users WHERE userid = %s", (userid,))
        conn.commit()

        # Return True if the package was deleted
        if cursor.rowcount == 0:
            logger.warning(f"No user found with userid {userid}")
            return False
        
        logger.info(f"User with userid {userid} deleted successfully.")
        return True
    except Exception as e:
        logger.error(f"Error deleting user {userid}: {e}")
        conn.rollback()  # Rollback in case of error
        return False
    finally:
        cursor.close()
        conn.close()



#models for add-services

def get_packages():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get basic package information with event type
        cursor.execute("""
            SELECT 
                p.package_id,
                p.package_name,
                et.event_type_name,
                p.event_type_id,
                p.capacity,
                p.description,
                p.venue_id,
                v.venue_name,
                p.gown_package_id,
                gp.gown_package_name,
                p.additional_capacity_charges,
                p.charge_unit,
                p.total_price,
                p.created_at,
                p.status
            FROM event_packages p
            LEFT JOIN venues v ON p.venue_id = v.venue_id
            LEFT JOIN gown_package gp ON p.gown_package_id = gp.gown_package_id
            LEFT JOIN event_type et ON p.event_type_id = et.event_type_id
            ORDER BY p.created_at DESC
        """)
        rows = cursor.fetchall()
        
        # Convert rows to dictionaries
        packages = []
        for row in rows:
            package = {
                'package_id': row[0],
                'package_name': row[1],
                'event_type_name': row[2],
                'event_type_id': row[3],
                'capacity': row[4],
                'description': row[5],
                'venue_id': row[6],
                'venue_name': row[7],
                'gown_package_id': row[8],
                'gown_package_name': row[9],
                'additional_capacity_charges': float(row[10]) if row[10] else 0,
                'charge_unit': row[11],
                'total_price': float(row[12]) if row[12] else 0,
                'created_at': row[13].strftime('%Y-%m-%d') if row[13] else None,
                'status': row[14]
            }
            
            # Get suppliers for this package
            cursor.execute("""
                SELECT 
                    s.supplier_id,
                    u.firstname,
                    u.lastname,
                    s.service,
                    s.price,
                    ps.remarks
                FROM event_package_services eps
                JOIN package_service ps ON eps.package_service_id = ps.package_service_id
                JOIN suppliers s ON ps.supplier_id = s.supplier_id
                JOIN users u ON s.userid = u.userid
                WHERE eps.package_id = %s
            """, (row[0],))  # Use row[0] for package_id
            
            package['suppliers'] = []
            supplier_rows = cursor.fetchall()
            for supplier_row in supplier_rows:
                package['suppliers'].append({
                    'supplier_id': supplier_row[0],
                    'name': f"{supplier_row[1]} {supplier_row[2]}",
                    'service': supplier_row[3],
                    'price': float(supplier_row[4]) if supplier_row[4] else 0,
                    'remarks': supplier_row[5]
                })
                
            # Get additional services for this package
            cursor.execute("""
                SELECT 
                    a.add_service_id,
                    a.add_service_name,
                    a.add_service_price
                FROM event_package_additional_services epas
                JOIN additional_services a ON epas.add_service_id = a.add_service_id
                WHERE epas.package_id = %s
            """, (row[0],))  # Use row[0] for package_id
            
            package['additional_services'] = []
            service_rows = cursor.fetchall()
            for service_row in service_rows:
                package['additional_services'].append({
                    'service_id': service_row[0],
                    'name': service_row[1],
                    'price': float(service_row[2]) if service_row[2] else 0
                })
            
            packages.append(package)
        
        return packages
    except Exception as e:
        print(f"Error fetching packages: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()

def create_package(package_data):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        print("Received data:", package_data)
        
        # Insert into event_packages first
        cursor.execute("""
            INSERT INTO event_packages (
                package_name, event_type_id, venue_id, capacity,
                additional_capacity_charges, charge_unit, description,
                gown_package_id, total_price
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING package_id
        """, (
            package_data['package_name'],
            package_data['event_type_id'],
            package_data['venue_id'],
            package_data['capacity'],
            package_data['additional_capacity_charges'],
            package_data['charge_unit'],
            package_data['description'],
            package_data['gown_package_id'],
            package_data['total_price']
        ))
        
        package_id = cursor.fetchone()[0]
        print(f"Package ID: {package_id}")
        
        # Handle suppliers through package_service table
        for supplier in package_data['suppliers']:
            # First create entry in package_service
            cursor.execute("""
                INSERT INTO package_service (
                    supplier_id, remarks
                ) VALUES (
                    %s, %s
                ) RETURNING package_service_id
            """, (
                supplier['supplier_id'],
                supplier['remarks']
            ))
            package_service_id = cursor.fetchone()[0]
            
            # Then link it in event_package_services
            cursor.execute("""
                INSERT INTO event_package_services (package_id, package_service_id)
                VALUES (%s, %s)
            """, (
                package_id,
                package_service_id
            ))
        
        # Handle additional services
        if 'additional_services' in package_data:
            for service in package_data['additional_services']:
                cursor.execute("""
                    INSERT INTO event_package_additional_services (package_id, add_service_id)
                    VALUES (%s, %s)
                """, (
                    package_id,
                    service['add_service_id']
                ))
        
        conn.commit()
        return package_id
        
    except Exception as e:
        conn.rollback()
        print(f"Error creating package: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()

def calculate_total_price(package_id, cursor):
    """Calculate the total price of a package including all services."""
    total_price = 0

    # Get supplier prices
    cursor.execute(
        """
        SELECT COALESCE(SUM(s.price), 0)
        FROM event_package_services eps
        JOIN package_service ps ON eps.package_service_id = ps.package_service_id
        JOIN suppliers s ON ps.supplier_id = s.supplier_id
        WHERE eps.package_id = %s
        """,
        (package_id,)
    )
    supplier_price = cursor.fetchone()[0]
    total_price += supplier_price

    # Get external supplier prices
    cursor.execute(
        """
        SELECT COALESCE(SUM(ps.external_supplier_price), 0)
        FROM event_package_services eps
        JOIN package_service ps ON eps.package_service_id = ps.package_service_id
        WHERE eps.package_id = %s AND ps.external_supplier_price IS NOT NULL
        """,
        (package_id,)
    )
    external_price = cursor.fetchone()[0]
    total_price += external_price

    # Get additional services prices
    cursor.execute(
        """
        SELECT COALESCE(SUM(ads.add_service_price), 0)
        FROM event_package_additional_services pas
        JOIN additional_services ads ON pas.add_service_id = ads.add_service_id
        WHERE pas.package_id = %s
        """,
        (package_id,)
    )
    additional_services_price = cursor.fetchone()[0]
    total_price += additional_services_price

    return total_price

def calculate_gown_package_price(gown_package_id, cursor):
    cursor.execute(
        """
        SELECT COALESCE(SUM(o.rent_price), 0)
        FROM gown_package_outfits gpo
        JOIN outfits o ON gpo.outfit_id = o.outfit_id
        WHERE gpo.gown_package_id = %s
        """, (gown_package_id,)
    )
    result = cursor.fetchone()
    logging.info(f"Calculated price for gown_package_id {gown_package_id}: {result[0]}")
    return result[0] if result[0] is not None else 0.00

def update_gown_package_price(gown_package_id, cursor):
    gown_package_price = calculate_gown_package_price(gown_package_id, cursor)
    cursor.execute(
        """
        UPDATE gown_package
        SET gown_package_price = %s
        WHERE gown_package_id = %s
        """, (gown_package_price, gown_package_id)
    )
    logging.info(f"Updated price for gown_package_id {gown_package_id} to {gown_package_price}")





def update_package(package_id, package_data):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # First check if package exists
        cursor.execute("SELECT * FROM event_packages WHERE package_id = %s", (package_id,))
        if not cursor.fetchone():
            return False, "Package not found"

        # Update the package details
        cursor.execute("""
            UPDATE event_packages 
            SET package_name = %s,
                event_type_id = %s,
                capacity = %s,
                charge_unit = %s,
                additional_capacity_charges = %s,
                description = %s
            WHERE package_id = %s
            """, (
                package_data['package_name'],
                package_data['event_type_id'],
                package_data['capacity'],
                package_data['charge_unit'],
                package_data['additional_capacity_charges'],
                package_data['description'],
                package_id
            ))

        conn.commit()
        return True, "Package updated successfully"

    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def delete_package(package_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Delete the package from the event_packages table
        cursor.execute("DELETE FROM event_packages WHERE package_id = %s", (package_id,))
        conn.commit()

        # Return True if the package was deleted
        if cursor.rowcount == 0:
            logger.warning(f"No package found with package_id {package_id}")
            return False
        
        logger.info(f"Package with package_id {package_id} deleted successfully.")
        return True
    except Exception as e:
        logger.error(f"Error deleting package {package_id}: {e}")
        conn.rollback()  # Rollback in case of error
        return False
    finally:
        cursor.close()
        conn.close()





#models for create event
def get_user_id_by_email(email):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT userid FROM users WHERE email = %s", (email,))
        user = cursor.fetchone()
        if user:
            return user[0]
        else:
            logger.warning(f"No user found with email: {email}")
            return None
    except Exception as e:
        logger.error(f"Error retrieving user ID for email {email}: {str(e)}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_all_booked_wishlist():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT 
                e.events_id, e.event_name, e.event_type, e.event_theme, e.event_color,
                e.schedule, e.start_time, e.end_time, e.status, e.booking_type,
                e.onsite_firstname, e.onsite_lastname, e.onsite_contact, e.onsite_address,
                e.total_price, e.userid,
                wp.wishlist_id, wp.package_name, wp.capacity, wp.description as package_description,
                wp.additional_capacity_charges, wp.charge_unit, wp.venue_status,
                v.venue_id, v.venue_name, v.location, v.description as venue_description,
                v.venue_price, v.venue_capacity,
                gp.gown_package_id, gp.gown_package_name, gp.gown_package_price,
                et.event_type_id, et.event_type_name,
                u.firstname, u.lastname, u.email, u.contactnumber
            FROM events e
            LEFT JOIN wishlist_packages wp ON e.events_id = wp.events_id
            LEFT JOIN venues v ON wp.venue_id = v.venue_id
            LEFT JOIN gown_package gp ON wp.gown_package_id = gp.gown_package_id
            LEFT JOIN event_types et ON wp.event_type_id = et.event_type_id
            LEFT JOIN users u ON e.userid = u.userid
            WHERE LOWER(e.status) = 'wishlist'
            ORDER BY e.schedule DESC
        """)
        events = []
        for row in cursor.fetchall():
            event = {
                'events_id': row[0],
                'event_name': row[1],
                'event_type': row[2],
                'event_theme': row[3],
                'event_color': row[4],
                'schedule': row[5].strftime('%Y-%m-%d') if row[5] else None,
                'start_time': row[6].strftime('%H:%M') if row[6] else None,
                'end_time': row[7].strftime('%H:%M') if row[7] else None,
                'status': row[8],
                'booking_type': row[9],
                'onsite_firstname': row[10],
                'onsite_lastname': row[11],
                'onsite_contact': row[12],
                'onsite_address': row[13],
                'total_price': float(row[14]) if row[14] else 0,
                'userid': row[15],
                'wishlist_id': row[16],
                'package_name': row[17],
                'capacity': row[18],
                'package_description': row[19],
                'additional_capacity_charges': float(row[20]) if row[20] else 0,
                'charge_unit': row[21],
                'venue_status': row[22] if row[22] else 'Pending',
                'venue_id': row[23],
                'venue_name': row[24],
                'venue_location': row[25],
                'venue_description': row[26],
                'venue_price': float(row[27]) if row[27] else 0,
                'venue_capacity': row[28],
                'gown_package_id': row[29],
                'gown_package_name': row[30],
                'gown_package_price': float(row[31]) if row[31] else 0,
                'event_type_id': row[32],
                'event_type_name': row[33],
                'firstname': row[34],
                'lastname': row[35],
                'email': row[36],
                'contactnumber': row[37],
                'bookedBy': f"{row[34] or ''} {row[35] or ''}".strip(),
                'suppliers': [],
                'services': [],
                'venues': [],
                'outfits': []
            }
            
            # Get wishlist venues for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        wv.wishlist_venue_id, wv.venue_id, wv.price, wv.status,
                        v.venue_name, v.location, v.description, v.venue_capacity
                    FROM wishlist_venues wv
                    JOIN venues v ON wv.venue_id = v.venue_id
                    WHERE wv.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                wishlist_venues = cursor.fetchall()
                event['wishlist_venues'] = [{
                    'wishlist_venue_id': wv[0],
                    'venue_id': wv[1],
                    'price': float(wv[2]) if wv[2] else 0,
                    'status': wv[3],
                    'venue_name': wv[4],
                    'location': wv[5],
                    'description': wv[6],
                    'venue_capacity': wv[7]
                } for wv in wishlist_venues]
            
            # Get suppliers for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        ws.wishlist_supplier_id, ws.supplier_id, ws.status,
                        s.service, u.firstname, u.lastname, ws.price,
                        ws.external_supplier_name, ws.external_supplier_contact,
                        ws.remarks
                    FROM wishlist_suppliers ws
                    LEFT JOIN suppliers s ON ws.supplier_id = s.supplier_id
                    LEFT JOIN users u ON s.userid = u.userid
                    WHERE ws.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                suppliers = cursor.fetchall()
                event['suppliers'] = [{
                    'wishlist_supplier_id': s[0],
                    'supplier_id': s[1],
                    'status': s[2],
                    'service': s[9] if s[1] is None else s[3],  # Use remarks as service for external suppliers
                    'firstname': s[7] if s[1] is None else s[4],  # Use external_supplier_name for external suppliers
                    'lastname': '' if s[1] is None else s[5],  # No lastname for external suppliers
                    'price': float(s[6]) if s[6] else 0,
                    'external_supplier_name': s[7],
                    'external_supplier_contact': s[8],
                    'remarks': s[9],
                    'type': 'external' if s[1] is None else 'internal'
                } for s in suppliers]
            
            # Get services for this event
            cursor.execute("""
                SELECT 
                    was.id, was.wishlist_id, was.add_service_id, was.price, was.remarks, was.status,
                    a.add_service_name, a.add_service_description, a.add_service_price
                FROM wishlist_additional_services was
                JOIN additional_services a ON was.add_service_id = a.add_service_id
                WHERE was.wishlist_id = %s
            """, (event['wishlist_id'],))
            
            services = cursor.fetchall()
            event['services'] = [{
                'id': s[0],
                'wishlist_id': s[1],
                'add_service_id': s[2],
                'price': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0,
                'remarks': s[4] if s[4] else '',
                'status': s[5] if s[5] else 'Pending',
                'add_service_name': s[6],
                'add_service_description': s[7],
                'add_service_price': float(s[8]) if s[8] is not None else 0,
                'total': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0
            } for s in services]
            
            # Get outfits for this event
            if event['wishlist_id']:
                # Query to get individual outfits
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        o.outfit_name, o.outfit_type, o.rent_price, o.size
                    FROM wishlist_outfits wo
                    LEFT JOIN outfits o ON wo.outfit_id = o.outfit_id
                    WHERE wo.wishlist_id = %s AND wo.outfit_id IS NOT NULL
                """, (event['wishlist_id'],))
                
                individual_outfits = cursor.fetchall()
                
                # Query to get gown packages
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        gp.gown_package_name, gp.gown_package_price
                    FROM wishlist_outfits wo
                    LEFT JOIN gown_package gp ON wo.gown_package_id = gp.gown_package_id
                    WHERE wo.wishlist_id = %s AND wo.gown_package_id IS NOT NULL
                """, (event['wishlist_id'],))
                
                package_outfits = cursor.fetchall()
                
                # Process individual outfits
                for outfit in individual_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'outfit_id': outfit[1],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'outfit_name': outfit[6],
                        'outfit_type': outfit[7],
                        'rent_price': float(outfit[8]) if outfit[8] is not None else 0,
                        'size': outfit[9],
                        'type': 'individual'
                    }
                    event['outfits'].append(outfit_data)
                
                # Process package outfits
                for outfit in package_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'gown_package_id': outfit[2],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'gown_package_name': outfit[6],
                        'gown_package_price': float(outfit[7]) if outfit[7] is not None else 0,
                        'type': 'outfit_package'
                    }
                    event['outfits'].append(outfit_data)
            
            events.append(event)
            
        return events
    except Exception as e:
        print(f"Error in get_all_booked_wishlist: {str(e)}")
        return []
    finally:
        cursor.close()
        conn.close()

def update_event(events_id, event_name, event_type, event_theme, event_color, venue):
    if not events_id:
        logger.error("Invalid events_id provided")
        return False

    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            UPDATE events
            SET event_name = %s, event_type = %s, event_theme = %s, event_color = %s, venue = %s
            WHERE events_id = %s
        """
        cursor.execute(query, (event_name, event_type, event_theme, event_color, venue, events_id))
        if cursor.rowcount == 0:
            logger.warning(f"No event found with events_id {events_id}")
            return False
        conn.commit()
        logger.info(f"Event {events_id} updated successfully.")
        return True
    except Exception as e:
        logger.error(f"Error updating event {events_id}: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()



def get_packages_wedding():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            """
            SELECT package_id, package_name, package_type, venue, price, capacity, description
            FROM event_packages
            WHERE package_type = 'Wedding'
            """
        )
        packages = cursor.fetchall()
        # Transform the result into a list of dictionaries
        return [
            {
                'package_id': item[0],
                'package_name': item[1],
                'package_type': item[2],
                'venue': item[3],
                'price': item[4],
                'capacity': item[5],
                'description': item[6],
            }
            for item in packages
        ]
    finally:
        cursor.close()
        conn.close()


#models for venues

def create_venue(venue_name, location, description, venue_capacity, image=None):
    """
    Create a new venue in the database
    Returns the venue_id if successful, otherwise None
    """
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Set default price (can be updated later)
        default_price = 0.00
        status = 'Active'
        
        cursor.execute("""
            INSERT INTO venues (venue_name, location, venue_price, description, venue_capacity, status, image)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            RETURNING venue_id
        """, (venue_name, location, default_price, description, venue_capacity, status, image))
        
        venue_id = cursor.fetchone()[0]
        conn.commit()
        return venue_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating venue: {str(e)}")
        return None
    finally:
        cursor.close()
        conn.close()

# Function to fetch all venues from the venues table
def get_all_venues():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT venue_id, venue_name, location, venue_price, 
                   venue_capacity, description, status 
            FROM venues 
            WHERE status = 'Active'
        """)
        venues = cursor.fetchall()

        # Transform the result into a list of dictionaries
        return [
            {
                'venue_id': item[0],
                'venue_name': item[1],
                'location': item[2],
                'venue_price': item[3],
                'venue_capacity': item[4],
                'description': item[5],
                'status': item[6]
            }
            for item in venues
        ]
    finally:
        cursor.close()
        conn.close()

def delete_venue(venue_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Start a transaction and delete from event_packages first to avoid foreign key issues
        cursor.execute("DELETE FROM event_packages WHERE venue_id = %s", (venue_id,))
        conn.commit()

        cursor.execute("DELETE FROM venues WHERE venue_id = %s", (venue_id,))
        conn.commit()

        # Check if any rows were affected
        if cursor.rowcount == 0:
            logger.warning(f"No venue found with venue_id {venue_id}")
            return False
        
        logger.info(f"Venue with venue_id {venue_id} deleted successfully.")
        return True
    except Exception as e:
        logger.error(f"Error deleting venue {venue_id}: {e}")
        conn.rollback()  # Rollback in case of error
        return False
    finally:
        cursor.close()
        conn.close()


def update_venue(venue_id, venue_name, location, venue_price, venue_capacity, description, image=None):
    """
    Update venue information
    Returns True if successful, otherwise False
    """
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Build dynamic query based on which values are provided
        query_parts = []
        params = []
        
        if venue_name:
            query_parts.append("venue_name = %s")
            params.append(venue_name)
            
        if location:
            query_parts.append("location = %s")
            params.append(location)
            
        if venue_price is not None:
            query_parts.append("venue_price = %s")
            params.append(venue_price)
            
        if venue_capacity:
            query_parts.append("venue_capacity = %s")
            params.append(venue_capacity)
            
        if description:
            query_parts.append("description = %s")
            params.append(description)
            
        if image:
            query_parts.append("image = %s")
            params.append(image)
        
        # Return if nothing to update
        if not query_parts:
            return False
            
        # Build the complete query
        query = f"UPDATE venues SET {', '.join(query_parts)} WHERE venue_id = %s"
        params.append(venue_id)
        
        # Execute the query
        cursor.execute(query, params)
        
        rows_affected = cursor.rowcount
        conn.commit()
        
        return rows_affected > 0
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating venue: {str(e)}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_active_venues():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT venue_id, venue_name, location, venue_price, description, venue_capacity, status
            FROM venues
            WHERE status = 'Active'
            ORDER BY venue_id
        """)
        venues = cursor.fetchall()
        
        venues_list = []
        for venue in venues:
            venues_list.append({
                'venue_id': venue[0],
                'venue_name': venue[1],
                'location': venue[2],
                'venue_price': float(venue[3]) if venue[3] else 0,
                'description': venue[4],
                'venue_capacity': venue[5],
                'status': venue[6]
            })
        return venues_list
    finally:
        cursor.close()
        conn.close()

def get_inactive_venues():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT venue_id, venue_name, location, venue_price, description, venue_capacity, status
            FROM venues
            WHERE status = 'Inactive'
            ORDER BY venue_id
        """)
        venues = cursor.fetchall()
        
        venues_list = []
        for venue in venues:
            venues_list.append({
                'venue_id': venue[0],
                'venue_name': venue[1],
                'location': venue[2],
                'venue_price': float(venue[3]) if venue[3] else 0,
                'description': venue[4],
                'venue_capacity': venue[5],
                'status': venue[6]
            })
        return venues_list
    finally:
        cursor.close()
        conn.close()

def toggle_venue_status(venue_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # First get current status
        cursor.execute("SELECT status FROM venues WHERE venue_id = %s", (venue_id,))
        current_status = cursor.fetchone()
        
        if not current_status:
            return False, "Venue not found"
            
        # Toggle the status
        new_status = 'Inactive' if current_status[0] == 'Active' else 'Active'
        
        cursor.execute(
            "UPDATE venues SET status = %s WHERE venue_id = %s",
            (new_status, venue_id)
        )
        conn.commit()
        return True, new_status
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def update_venue_price(venue_id, price):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE venues SET venue_price = %s WHERE venue_id = %s",
            (price, venue_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating venue price: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

#gown package models
def get_gown_packages():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT gown_package_id, gown_package_name, description, gown_package_price, status
            FROM gown_package
            WHERE status = 'Active'
            ORDER BY gown_package_id
        """)
        packages = cursor.fetchall()
        return [
            {
                'gown_package_id': package[0],
                'gown_package_name': package[1],
                'description': package[2],
                'gown_package_price': float(package[3]) if package[3] else 0,
                'status': package[4]
            }
            for package in packages
        ]
    finally:
        cursor.close()
        conn.close()

def get_inactive_packages():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        logger.info("Executing query to fetch inactive gown packages")
        cursor.execute("""
            SELECT gown_package_id, gown_package_name, description, gown_package_price, status
            FROM gown_package
            WHERE status = 'Inactive' OR status IS NULL
            ORDER BY gown_package_id
        """)
        packages = cursor.fetchall()
        logger.info(f"Found {len(packages)} inactive packages")
        
        result = [
            {
                'gown_package_id': package[0],
                'gown_package_name': package[1],
                'description': package[2],
                'gown_package_price': float(package[3]) if package[3] else 0,
                'status': package[4] or 'Active'  # Default to Active if NULL
            }
            for package in packages
        ]
        logger.info("Successfully processed package data")
        return result
    except Exception as e:
        logger.error(f"Error fetching inactive packages: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def toggle_package_status(package_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # First get the current status
        cursor.execute("SELECT status FROM gown_package WHERE gown_package_id = %s", (package_id,))
        result = cursor.fetchone()
        if not result:
            logger.error(f"No package found with id {package_id}")
            return False
            
        current_status = result[0] or 'Active'  # Default to Active if None
        logger.info(f"Current status for package {package_id}: {current_status}")
        
        # Toggle the status
        new_status = 'Inactive' if current_status == 'Active' else 'Active'
        logger.info(f"New status will be: {new_status}")
        
        cursor.execute("""
            UPDATE gown_package 
            SET status = %s 
            WHERE gown_package_id = %s
        """, (new_status, package_id))
        
        conn.commit()
        logger.info(f"Successfully updated package {package_id} status to {new_status}")
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Error toggling package status: {str(e)}")
        return False
    finally:
        cursor.close()
        conn.close()

def get_all_gown_packages():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT gown_package_id, gown_package_name, gown_package_price, description FROM gown_package")
        gown_packages = cursor.fetchall()

        # Transform the result into a list of dictionaries
        return [
            {
                'gown_package_id': item[0],
                'gown_package_name': item[1],
                'gown_package_price': item[2],
                'description': item[3]

            }
            for item in gown_packages
        ]
    finally:
        cursor.close()
        conn.close()



def add_gown_package(gown_package_name, description, outfits):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # Insert gown package
        cursor.execute("""
            INSERT INTO gown_package (gown_package_name, description)
            VALUES (%s, %s) RETURNING gown_package_id
        """, (gown_package_name, description))
        
        gown_package_id = cursor.fetchone()[0]

        # Insert outfits associated with the gown package
        for outfit_id in outfits:
            cursor.execute("""
                INSERT INTO gown_package_outfits (gown_package_id, outfit_id)
                VALUES (%s, %s)
            """, (gown_package_id, outfit_id))

        # Update gown package price based on outfits
        update_gown_package_price(gown_package_id, cursor)
        
        # Commit transaction
        conn.commit()

        return gown_package_id
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding gown package: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()

#additional services models
def create_additional_service(add_service_name, add_service_description):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO additional_services (add_service_name, add_service_description, add_service_price, status) VALUES (%s, %s, %s, %s)",
            (add_service_name, add_service_description, 0, 'Active')
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error creating additional service: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def update_additional_service_price(service_id, price):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE additional_services SET add_service_price = %s WHERE add_service_id = %s",
            (price, service_id)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error updating additional service price: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_active_additional_services():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT add_service_id, add_service_name, add_service_description, 
                   add_service_price, status 
            FROM additional_services 
            WHERE status = 'Active' 
            ORDER BY add_service_id
        """)
        services = cursor.fetchall()
        return [
            {
                'add_service_id': service[0],
                'add_service_name': service[1],
                'add_service_description': service[2],
                'add_service_price': float(service[3]),
                'status': service[4]
            }
            for service in services
        ]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()

def get_inactive_additional_services():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT * FROM additional_services WHERE status = 'Inactive' ORDER BY add_service_id"
        )
        services = cursor.fetchall()
        return [
            {
                'add_service_id': service[0],
                'add_service_name': service[1],
                'add_service_description': service[2],
                'add_service_price': float(service[3]),
                'status': service[4]
            }
            for service in services
        ]
    except Exception as e:
        print(f"Error getting inactive additional services: {str(e)}")
        return []
    finally:
        cursor.close()
        conn.close()

def toggle_additional_service_status(service_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE additional_services SET status = CASE WHEN status = 'Active' THEN 'Inactive' ELSE 'Active' END WHERE add_service_id = %s",
            (service_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"Error toggling additional service status: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

# Function to fetch all additional services from the additional_services table
def get_all_additional_services():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT add_service_id, add_service_name, add_service_description, 
                   add_service_price, status 
            FROM additional_services 
            WHERE status = 'Active'
        """)
        services = cursor.fetchall()

        # Transform the result into a list of dictionaries
        return [
            {
                'add_service_id': item[0],
                'add_service_name': item[1],
                'add_service_description': item[2],
                'add_service_price': item[3],
                'status': item[4]
            }
            for item in services
        ]
    finally:
        cursor.close()
        conn.close()

def update_additional_service(add_service_id, add_service_name, add_service_description, add_service_price):
    if not add_service_id:
        logger.error("Invalid add_service_id provided")
        return False

    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        query = """
            UPDATE additional_services
            SET add_service_name = %s, add_service_description = %s, add_service_price = %s
            WHERE add_service_id = %s
        """
        cursor.execute(query, (add_service_name, add_service_description, add_service_price, add_service_id))
        if cursor.rowcount == 0:
            logger.warning(f"No additional service found with add_service_id {add_service_id}")
            return False
        conn.commit()
        logger.info(f"Additional service {add_service_id} updated successfully.")
        return True
    except Exception as e:
        logger.error(f"Error updating additional service {add_service_id}: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_event_types():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT event_type_id, event_type_name 
            FROM event_type 
            ORDER BY event_type_name
        """)
        rows = cursor.fetchall()
        event_types = [
            {
                'event_type_id': row[0],
                'event_type_name': row[1]
            }
            for row in rows
        ]
        return event_types
    except Exception as e:
        print(f"Error fetching event types: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()

def initialize_event_types():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # First check if we already have event types
        cursor.execute("SELECT COUNT(*) FROM event_type")
        count = cursor.fetchone()[0]
        logging.info(f"Current event type count: {count}")
        
        if count == 0:
            # Insert default event types
            event_types = [
                'Wedding',
                'Birthday',
                'Corporate Event',
                'Anniversary',
                'Graduation',
                'Family Gathering',
                'Reunion',
                'Conference',
                'Seminar',
                'Other'
            ]
            
            for event_type in event_types:
                logging.info(f"Inserting event type: {event_type}")
                cursor.execute(
                    "INSERT INTO event_type (event_type_name) VALUES (%s)",
                    (event_type,)
                )
            
            conn.commit()
            logging.info("Default event types initialized successfully")
        else:
            logging.info("Event types already exist, skipping initialization")
        
    except Exception as e:
        conn.rollback()
        logging.error(f"Error initializing event types: {e}")
        raise e
    finally:
        cursor.close()
        conn.close()

def create_event_type(event_type_name):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Check if event type already exists
        cursor.execute("SELECT event_type_id FROM event_type WHERE event_type_name = %s", (event_type_name,))
        if cursor.fetchone():
            raise ValueError("Event type already exists")

        # Insert new event type
        cursor.execute(
            "INSERT INTO event_type (event_type_name) VALUES (%s) RETURNING event_type_id",
            (event_type_name,)
        )
        new_event_type_id = cursor.fetchone()[0]
        conn.commit()
        
        return {
            'event_type_id': new_event_type_id,
            'event_type_name': event_type_name
        }
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        cursor.close()
        conn.close()


        
def add_event_item(userid, event_name, event_type, event_theme, event_color, 
                  package_id, suppliers, schedule=None, start_time=None, 
                  end_time=None, status='Wishlist', onsite_firstname=None, 
                  onsite_lastname=None, onsite_contact=None, onsite_address=None, 
                  total_price=0, outfits=None, services=None, additional_items=None,
                  booking_type='Onsite'):
    """Add a new event with its package configuration"""
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("BEGIN")

        # Ensure numeric values are properly formatted
        total_price = float(total_price) if total_price is not None else 0

        # Insert into events table
        cursor.execute("""
            INSERT INTO events (
                userid, event_name, event_type, event_theme, event_color, 
                package_id, schedule, start_time, end_time, status,
                onsite_firstname, onsite_lastname, onsite_contact, onsite_address,
                total_price, booking_type
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) 
            RETURNING events_id
        """, (
            userid, event_name, event_type, event_theme, event_color, 
            package_id, schedule, start_time, end_time, status,
            onsite_firstname, onsite_lastname, onsite_contact, onsite_address,
            total_price, booking_type
        ))
        events_id = cursor.fetchone()[0]

        # Create package configuration if package_id is provided
        if package_id:
            cursor.execute("""
                INSERT INTO event_package_configurations (events_id, package_id)
                VALUES (%s, %s)
                RETURNING config_id
            """, (events_id, package_id))
            config_id = cursor.fetchone()[0]

            # Store package suppliers
            if suppliers:
                for supplier in suppliers:
                    if not supplier:  # Skip if supplier is None
                        continue
                    cursor.execute("""
                        INSERT INTO event_package_suppliers (
                            config_id, supplier_id, original_price, modified_price,
                            is_modified, is_removed, remarks
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        config_id,
                        supplier.get('supplier_id'),
                        float(supplier.get('original_price', 0) or 0),
                        float(supplier.get('modified_price', 0) or 0),
                        supplier.get('is_modified', False),
                        supplier.get('is_removed', False),
                        supplier.get('remarks', '')
                    ))

            # Store package outfits
            if outfits:
                for outfit in outfits:
                    if not outfit:  # Skip if outfit is None
                        continue
                    cursor.execute("""
                        INSERT INTO event_package_outfits (
                            config_id, outfit_id, gown_package_id,
                            original_price, modified_price,
                            is_modified, is_removed, remarks
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        config_id,
                        outfit.get('outfit_id'),
                        outfit.get('gown_package_id'),
                        float(outfit.get('original_price', 0) or 0),
                        float(outfit.get('modified_price', 0) or 0),
                        outfit.get('is_modified', False),
                        outfit.get('is_removed', False),
                        outfit.get('remarks', '')
                    ))

            # Store package services
            if services:
                for service in services:
                    if not service:  # Skip if service is None
                        continue
                    if 'package_service_id' in service:
                        cursor.execute("""
                            INSERT INTO event_package_services (package_id, package_service_id)
                            VALUES (%s, %s)
                        """, (
                            package_id,
                            service.get('package_service_id')
                        ))
                    else:
                        cursor.execute("""
                            INSERT INTO package_service (supplier_id, remarks)
                            VALUES (%s, %s)
                            RETURNING package_service_id
                        """, (
                            service.get('supplier_id'),
                            service.get('remarks', '')
                        ))
                        package_service_id = cursor.fetchone()[0]
                        cursor.execute("""
                            INSERT INTO event_package_services (package_id, package_service_id)
                            VALUES (%s, %s)
                        """, (
                            package_id,
                            package_service_id
                        ))

        # Store additional (non-package) items
        if additional_items:
            for item in additional_items:
                if not item:  # Skip if item is None
                    continue
                cursor.execute("""
                    INSERT INTO event_additional_items (
                        events_id, item_type, item_id, price, remarks
                    )
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    events_id,
                    item.get('item_type'),
                    item.get('item_id'),
                    float(item.get('price', 0) or 0),
                    item.get('remarks', '')
                ))

        cursor.execute("COMMIT")
        return events_id

    except Exception as e:
        cursor.execute("ROLLBACK")
        print(f"Error in add_event_item: {str(e)}")  # Add debug print
        raise e
    finally:
        cursor.close()
        conn.close()

def get_event_package_configuration(events_id):
    """Get all package configuration details for an event"""
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # Get the base configuration
        cursor.execute("""
            SELECT config_id, package_id, created_at
            FROM event_package_configurations
            WHERE events_id = %s
        """, (events_id,))
        config = cursor.fetchone()
        
        if not config:
            return None

        config_id = config[0]
        
        # Get configured suppliers
        cursor.execute("""
            SELECT s.supplier_id, s.service, u.firstname, u.lastname, u.email,
                   eps.original_price, eps.modified_price, eps.is_modified, 
                   eps.is_removed, eps.remarks
            FROM event_package_suppliers eps
            JOIN suppliers s ON eps.supplier_id = s.supplier_id
            JOIN users u ON s.userid = u.userid
            WHERE eps.config_id = %s
        """, (config_id,))
        suppliers = cursor.fetchall()

        # Get configured services
        cursor.execute("""
            SELECT s.service_id, s.add_service_name, s.add_service_description,
                   eps.original_price, eps.modified_price, eps.is_modified,
                   eps.is_removed, eps.remarks
            FROM event_package_services eps
            JOIN additional_services s ON eps.service_id = s.add_service_id
            WHERE eps.config_id = %s
        """, (config_id,))
        services = cursor.fetchall()

        # Get configured outfits
        cursor.execute("""
            SELECT o.outfit_id, o.outfit_name, o.outfit_type,
                   gp.gown_package_id, gp.gown_package_name,
                   epo.original_price, epo.modified_price, epo.is_modified,
                   epo.is_removed, epo.remarks
            FROM event_package_outfits epo
            LEFT JOIN outfits o ON epo.outfit_id = o.outfit_id
            LEFT JOIN gown_packages gp ON epo.gown_package_id = gp.gown_package_id
            WHERE epo.config_id = %s
        """, (config_id,))
        outfits = cursor.fetchall()

        # Get additional items
        cursor.execute("""
            SELECT item_type, item_id, price, remarks
            FROM event_additional_items
            WHERE events_id = %s
        """, (events_id,))
        additional_items = cursor.fetchall()

        return {
            'config_id': config[0],
            'package_id': config[1],
            'created_at': config[2],
            'suppliers': [{
                'supplier_id': s[0],
                'service': s[1],
                'firstname': s[2],
                'lastname': s[3],
                'email': s[4],
                'original_price': float(s[5]) if s[5] else 0,
                'modified_price': float(s[6]) if s[6] else 0,
                'is_modified': s[7],
                'is_removed': s[8],
                'remarks': s[9]
            } for s in suppliers],
            'services': [{
                'service_id': s[0],
                'service_name': s[1],
                'service_description': s[2],
                'original_price': float(s[3]) if s[3] else 0,
                'modified_price': float(s[4]) if s[4] else 0,
                'is_modified': s[5],
                'is_removed': s[6],
                'remarks': s[7]
            } for s in services],
            'outfits': [{
                'outfit_id': o[0],
                'outfit_name': o[1],
                'outfit_type': o[2],
                'gown_package_id': o[3],
                'gown_package_name': o[4],
                'original_price': float(o[5]) if o[5] else 0,
                'modified_price': float(o[6]) if o[6] else 0,
                'is_modified': o[7],
                'is_removed': o[8],
                'remarks': o[9]
            } for o in outfits],
            'additional_items': [{
                'item_type': i[0],
                'item_id': i[1],
                'price': float(i[2]) if i[2] else 0,
                'remarks': i[3]
            } for i in additional_items]
        }
    finally:
        cursor.close()
        conn.close()

def get_event_details(event_id):
    "Get detailed information about an event, including all inclusions."
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()

        # Get basic event information
        event_query = """
        SELECT e.*, et.event_type_name as event_type_name
            FROM events e
        LEFT JOIN event_type et ON e.event_type = et.event_type_name
            WHERE e.events_id = %s
        """
        cursor.execute(event_query, (event_id,))
        event = cursor.fetchone()
        
        if not event:
            return None

        # Convert to dictionary
        cols = [desc[0] for desc in cursor.description]
        event_dict = dict(zip(cols, event))
        
        # Debug: Print out the keys to see if onsite fields are included
        logger.info(f"Event dictionary keys: {event_dict.keys()}")
        
        # Ensure onsite fields are properly included
        for field in ['onsite_firstname', 'onsite_lastname', 'onsite_contact', 'onsite_address', 'booking_type']:
            if field not in event_dict:
                logger.warning(f"Field {field} missing from event_dict, fetching directly from database")
                # If somehow the field is missing from the query results, fetch it directly
                try:
                    cursor.execute(f"SELECT {field} FROM events WHERE events_id = %s", (event_id,))
                    result = cursor.fetchone()
                    if result and result[0] is not None:
                        event_dict[field] = result[0]
                        logger.info(f"Added missing field {field} = {result[0]}")
                    else:
                        event_dict[field] = None
                        logger.info(f"Field {field} is NULL in the database")
                except Exception as e:
                    logger.error(f"Error fetching field {field}: {e}")
                    event_dict[field] = None
        
        # Get wishlist details to fetch inclusions
        wishlist_query = """
        SELECT wp.wishlist_id, 
               wp.venue_id, wp.venue_status,
               v.venue_name, v.venue_price
        FROM wishlist_packages wp
        LEFT JOIN venues v ON wp.venue_id = v.venue_id
        WHERE wp.events_id = %s
        """
        cursor.execute(wishlist_query, (event_id,))
        wishlist = cursor.fetchone()
        
        if wishlist:
            wishlist_cols = [desc[0] for desc in cursor.description]
            wishlist_dict = dict(zip(wishlist_cols, wishlist))
            event_dict['wishlist_id'] = wishlist_dict['wishlist_id']
            
            # Add venue information
            if wishlist_dict['venue_id']:
                event_dict['venue'] = {
                    'venue_id': wishlist_dict['venue_id'],
                    'venue_status': wishlist_dict['venue_status'],
                    'venue_name': wishlist_dict['venue_name'],
                    'venue_price': wishlist_dict['venue_price']
                }
            
            # Check if package_id exists in the event data
            if 'package_id' in event_dict and event_dict['package_id']:
                package_query = """
                SELECT p.package_id, p.package_name, p.total_price
                FROM event_packages p
                WHERE p.package_id = %s
                """
                cursor.execute(package_query, (event_dict['package_id'],))
                package = cursor.fetchone()
                
                if package:
                    package_cols = [desc[0] for desc in cursor.description]
                    package_dict = dict(zip(package_cols, package))
                    event_dict['package_id'] = package_dict['package_id']
                    event_dict['package_name'] = package_dict['package_name']
                    event_dict['package_price'] = package_dict['total_price']
            
            # Get suppliers
            suppliers_query = """
            SELECT ws.wishlist_supplier_id, ws.supplier_id, ws.status,
                   s.service, u.firstname, u.lastname, ws.price
            FROM wishlist_suppliers ws
            JOIN suppliers s ON ws.supplier_id = s.supplier_id
            JOIN users u ON s.userid = u.userid
            WHERE ws.wishlist_id = %s
            """
            cursor.execute(suppliers_query, (wishlist_dict['wishlist_id'],))
            suppliers = cursor.fetchall()
            
            if suppliers:
                supplier_cols = ['wishlist_supplier_id', 'supplier_id', 'status', 
                                 'service', 'firstname', 'lastname', 'price']
                suppliers_list = []
                for supplier in suppliers:
                    supplier_dict = dict(zip(supplier_cols, supplier))
                    # Add a computed supplier_name field
                    supplier_dict['supplier_name'] = f"{supplier_dict['firstname']} {supplier_dict['lastname']}"
                    # For backwards compatibility
                    supplier_dict['service_type'] = supplier_dict['service']
                    suppliers_list.append(supplier_dict)
                event_dict['suppliers'] = suppliers_list
            
            # Get outfits
            outfits_query = """
            SELECT wo.wishlist_outfit_id, wo.outfit_id, wo.status,
                   o.outfit_type, o.outfit_name, wo.price,
                   o.outfit_color, o.outfit_desc, o.outfit_img
            FROM wishlist_outfits wo
            LEFT JOIN outfits o ON wo.outfit_id = o.outfit_id
            WHERE wo.wishlist_id = %s AND wo.gown_package_id IS NULL
            """
            cursor.execute(outfits_query, (wishlist_dict['wishlist_id'],))
            outfits = cursor.fetchall()
            
            outfit_cols = [desc[0] for desc in cursor.description]
            outfits_list = [dict(zip(outfit_cols, outfit)) for outfit in outfits]
            
            # Get gown packages
            gown_packages_query = """
            SELECT wo.wishlist_outfit_id, wo.gown_package_id, wo.status,
                   gp.gown_package_name, wo.price
            FROM wishlist_outfits wo
            JOIN gown_package gp ON wo.gown_package_id = gp.gown_package_id
            WHERE wo.wishlist_id = %s AND wo.gown_package_id IS NOT NULL
            """
            cursor.execute(gown_packages_query, (wishlist_dict['wishlist_id'],))
            packages = cursor.fetchall()
            
            if packages:
                package_cols = ['wishlist_outfit_id', 'gown_package_id', 'status', 'gown_package_name', 'price']
                for package in packages:
                    package_dict = dict(zip(package_cols, package))
                    
                    # Map to the same format as individual outfits for frontend compatibility
                    outfits_list.append({
                        'wishlist_outfit_id': package_dict['wishlist_outfit_id'],
                        'gown_package_id': package_dict['gown_package_id'],
                        'outfit_id': None,
                        'outfit_name': package_dict['gown_package_name'] + ' (Package)',
                        'outfit_type': 'Package',
                        'status': package_dict['status'],
                        'price': package_dict['price'],
                        'is_package': True
                    })
            
            event_dict['outfits'] = outfits_list
            
            # Get additional services
            services_query = """
            SELECT was.id, was.add_service_id, was.status,
                   a.add_service_name as service_name, was.price
            FROM wishlist_additional_services was
            JOIN additional_services a ON was.add_service_id = a.add_service_id
            WHERE was.wishlist_id = %s
            """
            cursor.execute(services_query, (wishlist_dict['wishlist_id'],))
            services = cursor.fetchall()
            
            if services:
                service_cols = ['id', 'add_service_id', 'status', 'service_name', 'price']
                services_list = []
                for service in services:
                    service_dict = dict(zip(service_cols, service))
                    # For backwards compatibility
                    service_dict['additional_service_id'] = service_dict['add_service_id']
                    services_list.append(service_dict)
                event_dict['additional_services'] = services_list
          
          # Log the final event dictionary for debugging
        logger.info(f"Final event_dict keys: {event_dict.keys()}")
        logger.info(f"onsite_firstname: {event_dict.get('onsite_firstname')}")
        logger.info(f"onsite_lastname: {event_dict.get('onsite_lastname')}")
        logger.info(f"booking_type: {event_dict.get('booking_type')}")
        
        return event_dict
    except Exception as e:
        logger.error(f"Error in get_event_details: {e}")
        raise
    finally:
        if 'cursor' in locals() and cursor:
            cursor.close()
        if 'conn' in locals() and conn:
            conn.close()


def track_service_modification(events_id, package_service_id, modification_type, original_price=None, modified_price=None, remarks=None):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO modified_event_services 
            (event_id, package_service_id, modification_type, original_price, modified_price, remarks)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING modification_id
        """, (events_id, package_service_id, modification_type, original_price, modified_price, remarks))
        
        modification_id = cursor.fetchone()[0]
        conn.commit()
        return modification_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Error tracking service modification: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def add_service_customization(events_id, package_service_id, custom_price=None, custom_details=None):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            INSERT INTO event_service_customizations 
            (event_id, package_service_id, custom_price, custom_details)
            VALUES (%s, %s, %s, %s)
            RETURNING customization_id
        """, (events_id, package_service_id, custom_price, custom_details))
        
        customization_id = cursor.fetchone()[0]
        conn.commit()
        return customization_id
    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding service customization: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_event_modifications(events_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get all modifications for the event
        cursor.execute("""
            SELECT m.modification_id, m.package_service_id, m.modification_type,
                   m.original_price, m.modified_price, m.remarks,
                   COALESCE(ps.supplier_id::text, ps.external_supplier_name) as supplier_identifier,
                   ps.external_supplier_contact, ps.external_supplier_price
            FROM modified_event_services m
            JOIN package_service ps ON m.package_service_id = ps.package_service_id
            WHERE m.event_id = %s
            ORDER BY m.created_at
        """, (events_id,))
        
        modifications = cursor.fetchall()
        
        # Get all customizations for the event
        cursor.execute("""
            SELECT c.customization_id, c.package_service_id, c.custom_price,
                   c.custom_details,
                   COALESCE(ps.supplier_id::text, ps.external_supplier_name) as supplier_identifier
            FROM event_service_customizations c
            JOIN package_service ps ON c.package_service_id = ps.package_service_id
            WHERE c.event_id = %s
            ORDER BY c.created_at
        """, (events_id,))
        
        customizations = cursor.fetchall()
        
        return {
            'modifications': [{
                'modification_id': m[0],
                'package_service_id': m[1],
                'modification_type': m[2],
                'original_price': float(m[3]) if m[3] else None,
                'modified_price': float(m[4]) if m[4] else None,
                'remarks': m[5],
                'supplier_identifier': m[6],
                'external_supplier_contact': m[7],
                'external_supplier_price': float(m[8]) if m[8] else None
            } for m in modifications],
            'customizations': [{
                'customization_id': c[0],
                'package_service_id': c[1],
                'custom_price': float(c[2]) if c[2] else None,
                'custom_details': c[3],
                'supplier_identifier': c[4]
            } for c in customizations]
        }
    finally:
        cursor.close()
        conn.close()

def get_all_events():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                e.events_id, e.event_name, e.event_type, e.event_theme, e.event_color,
                e.schedule, e.start_time, e.end_time, e.status, e.booking_type,
                e.onsite_firstname, e.onsite_lastname, e.onsite_contact, e.onsite_address,
                e.total_price, e.userid,
                wp.wishlist_id, wp.package_name, wp.capacity, wp.description as package_description,
                wp.additional_capacity_charges, wp.charge_unit, wp.venue_status,
                v.venue_id, v.venue_name, v.location, v.description as venue_description,
                v.venue_price, v.venue_capacity,
                gp.gown_package_id, gp.gown_package_name, gp.gown_package_price,
                et.event_type_id, et.event_type_name,
                u.firstname, u.lastname, u.email, u.contactnumber
            FROM events e
            LEFT JOIN wishlist_packages wp ON e.events_id = wp.events_id
            LEFT JOIN venues v ON wp.venue_id = v.venue_id
            LEFT JOIN gown_package gp ON wp.gown_package_id = gp.gown_package_id
            LEFT JOIN event_types et ON wp.event_type_id = et.event_type_id
            LEFT JOIN users u ON e.userid = u.userid
            WHERE LOWER(e.status) IN ('finished', 'cancelled')
            ORDER BY e.schedule DESC
        """)
        
        events = []
        
        for row in cursor.fetchall():
            event = {
                'events_id': row[0],
                'event_name': row[1],
                'event_type': row[2],
                'event_theme': row[3],
                'event_color': row[4],
                'schedule': row[5].strftime('%Y-%m-%d') if row[5] else None,
                'start_time': row[6].strftime('%H:%M') if row[6] else None,
                'end_time': row[7].strftime('%H:%M') if row[7] else None,
                'status': row[8],
                'booking_type': row[9],
                'onsite_firstname': row[10],
                'onsite_lastname': row[11],
                'onsite_contact': row[12],
                'onsite_address': row[13],
                'total_price': float(row[14]) if row[14] else 0,
                'userid': row[15],
                'wishlist_id': row[16],
                'package_name': row[17],
                'capacity': row[18],
                'package_description': row[19],
                'additional_capacity_charges': float(row[20]) if row[20] else 0,
                'charge_unit': row[21],
                'venue_status': row[22] if row[22] else 'Pending',
                'venue_id': row[23],
                'venue_name': row[24],
                'venue_location': row[25],
                'venue_description': row[26],
                'venue_price': float(row[27]) if row[27] else 0,
                'venue_capacity': row[28],
                'gown_package_id': row[29],
                'gown_package_name': row[30],
                'gown_package_price': float(row[31]) if row[31] else 0,
                'event_type_id': row[32],
                'event_type_name': row[33],
                'firstname': row[34],
                'lastname': row[35],
                'email': row[36],
                'contactnumber': row[37],
                'bookedBy': f"{row[34] or ''} {row[35] or ''}".strip(),
                'suppliers': [],
                'services': [],
                'venues': [],
                'outfits': [],
                'wishlist_venues': []
            }

            # Get wishlist venues for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        wv.wishlist_venue_id, wv.venue_id, wv.price, wv.status,
                        v.venue_name, v.location, v.description, v.venue_capacity
                    FROM wishlist_venues wv
                    JOIN venues v ON wv.venue_id = v.venue_id
                    WHERE wv.wishlist_id = %s
                """, (event['wishlist_id'],))

                wishlist_venues = cursor.fetchall()
                event['wishlist_venues'] = []
                for wv in wishlist_venues:
                    venue_data = {
                        'wishlist_venue_id': wv[0],
                        'venue_id': wv[1],
                        'price': float(wv[2]) if wv[2] else 0,
                        'status': wv[3],
                        'venue_name': wv[4],
                        'location': wv[5],
                        'description': wv[6],
                        'venue_capacity': wv[7]
                    }
                    event['wishlist_venues'].append(venue_data)

                    # Also add to the main venues array with wishlist_venue_id
                    event['venues'].append({
                        'wishlist_venue_id': wv[0],
                        'venue_id': wv[1],
                        'venue_name': wv[4],
                        'location': wv[5],
                        'description': wv[6],
                        'venue_price': float(wv[2]) if wv[2] else 0,
                        'venue_capacity': wv[7],
                        'status': wv[3] if wv[3] else 'Pending'
                    })
            
            # If no wishlist venues but we have a direct venue from the main query
            elif event['venue_id']:
                event['venues'].append({
                    'venue_id': event['venue_id'],
                    'venue_name': event['venue_name'],
                    'location': event['venue_location'],
                    'description': event['venue_description'],
                    'venue_price': event['venue_price'],
                    'venue_capacity': event['venue_capacity'],
                    'status': event['venue_status']
                })

            # Get suppliers for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        ws.wishlist_supplier_id, ws.supplier_id, ws.status,
                        s.service, u.firstname, u.lastname, ws.price,
                        ws.external_supplier_name, ws.external_supplier_contact,
                        ws.remarks
                    FROM wishlist_suppliers ws
                    LEFT JOIN suppliers s ON ws.supplier_id = s.supplier_id
                    LEFT JOIN users u ON s.userid = u.userid
                    WHERE ws.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                suppliers = cursor.fetchall()
                event['suppliers'] = [{
                    'wishlist_supplier_id': s[0],
                    'supplier_id': s[1],
                    'status': s[2],
                    'service': s[9] if s[1] is None else s[3],  # Use remarks as service for external suppliers
                    'firstname': s[7] if s[1] is None else s[4],  # Use external_supplier_name for external suppliers
                    'lastname': '' if s[1] is None else s[5],  # No lastname for external suppliers
                    'price': float(s[6]) if s[6] else 0,
                    'external_supplier_name': s[7],
                    'external_supplier_contact': s[8],
                    'remarks': s[9],
                    'type': 'external' if s[1] is None else 'internal'
                } for s in suppliers]

            # Get services for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        was.id, was.wishlist_id, was.add_service_id, was.price, was.remarks, was.status,
                        a.add_service_name, a.add_service_description, a.add_service_price
                    FROM wishlist_additional_services was
                    JOIN additional_services a ON was.add_service_id = a.add_service_id
                    WHERE was.wishlist_id = %s
                """, (event['wishlist_id'],))

                services = cursor.fetchall()
                event['services'] = [{
                    'id': s[0],
                    'wishlist_id': s[1],
                    'add_service_id': s[2],
                    'price': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0,
                    'remarks': s[4] if s[4] else '',
                    'status': s[5] if s[5] else 'Pending',
                    'add_service_name': s[6],
                    'add_service_description': s[7],
                    'add_service_price': float(s[8]) if s[8] is not None else 0,
                    'total': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0
                } for s in services]

            # Get outfits for this event
            if event['wishlist_id']:
                # Query to get individual outfits
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        o.outfit_name, o.outfit_type, o.rent_price, o.size
                    FROM wishlist_outfits wo
                    LEFT JOIN outfits o ON wo.outfit_id = o.outfit_id
                    WHERE wo.wishlist_id = %s AND wo.outfit_id IS NOT NULL
                """, (event['wishlist_id'],))

                individual_outfits = cursor.fetchall()

                # Query to get gown packages
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        gp.gown_package_name, gp.gown_package_price
                    FROM wishlist_outfits wo
                    LEFT JOIN gown_package gp ON wo.gown_package_id = gp.gown_package_id
                    WHERE wo.wishlist_id = %s AND wo.gown_package_id IS NOT NULL
                """, (event['wishlist_id'],))

                package_outfits = cursor.fetchall()

                # Process individual outfits
                for outfit in individual_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'outfit_id': outfit[1],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'outfit_name': outfit[6],
                        'outfit_type': outfit[7],
                        'rent_price': float(outfit[8]) if outfit[8] is not None else 0,
                        'size': outfit[9],
                        'type': 'individual'
                    }
                    event['outfits'].append(outfit_data)

                # Process package outfits
                for outfit in package_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'gown_package_id': outfit[2],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'gown_package_name': outfit[6],
                        'gown_package_price': float(outfit[7]) if outfit[7] is not None else 0,
                        'type': 'outfit_package'
                    }
                    event['outfits'].append(outfit_data)
            
            events.append(event)
        
        logger.info(f"Found {len(events)} upcoming events")
        return events
    except Exception as e:
        logger.error(f"Error in get_all_events: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_events_by_date(date):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT events_id
            FROM events
            WHERE DATE(schedule) = DATE(%s)
        """, (date,))
        events = cursor.fetchall()
        return events
    except Exception as e:
        logger.error(f"Error in get_events_by_date: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_event_types_count():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT event_type, COUNT(*) as count
            FROM events
            WHERE event_type IS NOT NULL
            GROUP BY event_type
            ORDER BY count DESC
        """)
        
        events_count = cursor.fetchall()
        result = []
        for event in events_count:
            result.append({
                'type': event[0],  # event_type
                'count': int(event[1])  # count
            })
        return result
        
    except Exception as e:
        logger.error(f"Error in get_event_types_count: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_events_by_month_and_type():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                event_type,
                EXTRACT(MONTH FROM schedule)::integer as month,
                COUNT(*) as count
            FROM events
            WHERE event_type IS NOT NULL
                AND EXTRACT(YEAR FROM schedule) = EXTRACT(YEAR FROM CURRENT_DATE)
            GROUP BY event_type, EXTRACT(MONTH FROM schedule)
            ORDER BY EXTRACT(MONTH FROM schedule), event_type
        """)
        
        events_data = cursor.fetchall()
        
        # Get unique event types
        cursor.execute("""
            SELECT DISTINCT event_type
            FROM events
            WHERE event_type IS NOT NULL
            ORDER BY event_type
        """)
        event_types = [row[0] for row in cursor.fetchall()]
        
        # Process the data
        months = list(range(1, 13))  # 1 to 12
        result = {
            'months': months,
            'eventTypes': event_types,
            'data': {}
        }
        
        # Initialize data structure
        for event_type in event_types:
            result['data'][event_type] = [0] * 12  # Initialize with zeros for all months
        
        # Fill in the actual counts
        for row in events_data:
            event_type, month, count = row
            # Adjust month index to 0-based for array
            month_index = int(month) - 1
            result['data'][event_type][month_index] = int(count)
        
        return result
        
    except Exception as e:
        logger.error(f"Error in get_events_by_month_and_type: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_inactive_suppliers():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT s.supplier_id, u.firstname, u.lastname, u.email, u.contactnumber, 
                   u.username, u.password, s.service, s.price, s.status, u.userid
            FROM suppliers s
            JOIN users u ON s.userid = u.userid
            WHERE s.status = 'Inactive'
            ORDER BY s.supplier_id
        """)
        suppliers = cursor.fetchall()
        
        suppliers_list = []
        for supplier in suppliers:
            suppliers_list.append({
                'supplier_id': supplier[0],
                'firstname': supplier[1],
                'lastname': supplier[2],
                'email': supplier[3],
                'contactnumber': supplier[4],
                'username': supplier[5],
                'password': supplier[6],
                'service': supplier[7],
                'price': float(supplier[8]) if supplier[8] else 0,
                'status': supplier[9],
                'userid': supplier[10]
            })
        return suppliers_list
    finally:
        cursor.close()
        conn.close()

def add_supplier_social_media(supplier_id, platform, handle, url=None):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            INSERT INTO supplier_social_media (supplier_id, platform, handle, url)
            VALUES (%s, %s, %s, %s)
            RETURNING social_media_id
        """, (supplier_id, platform, handle, url))
        
        social_media_id = cursor.fetchone()[0]
        conn.commit()
        return True, social_media_id

    except Exception as e:
        conn.rollback()
        logger.error(f"Error adding supplier social media: {str(e)}")
        return False, None

    finally:
        cursor.close()
        conn.close()

def get_supplier_social_media(supplier_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT social_media_id, platform, handle, url 
            FROM supplier_social_media 
            WHERE supplier_id = %s
        """, (supplier_id,))
        
        social_media = cursor.fetchall()
        return [{
            'social_media_id': sm[0],
            'platform': sm[1],
            'handle': sm[2],
            'url': sm[3]
        } for sm in social_media]

    finally:
        cursor.close()
        conn.close()

class Supplier:
    def __init__(self, supplier_id, userid=None, service=None, price=None, status=None):
        self.supplier_id = supplier_id
        self.userid = userid
        self.service = service
        self.price = price
        self.status = status

    def get_social_media(self):
        cursor = None
        conn = None
        try:
            print(f"Getting social media for supplier_id: {self.supplier_id}")
            query = """
                SELECT social_media_id, platform, handle, url 
                FROM supplier_social_media 
                WHERE supplier_id = %s
            """
            conn = db.get_db_connection()
            cursor = conn.cursor()
            cursor.execute(query, (self.supplier_id,))
            social_media = cursor.fetchall()
            print(f"Raw social media data: {social_media}")
            
            # Convert tuple results to dictionaries
            result = [{
                'social_media_id': row[0],
                'platform': row[1],
                'handle': row[2],
                'url': row[3]
            } for row in social_media]
            
            print(f"Formatted social media: {result}")
            return result
        except Exception as e:
            print(f"Error fetching social media: {str(e)}")
            return []
        finally:
            if cursor:
                cursor.close()
            if conn:
                conn.close()

def initialize_supplier_social_media():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Create the table if it doesn't exist
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS supplier_social_media (
                social_media_id SERIAL PRIMARY KEY,
                supplier_id INTEGER NOT NULL,
                platform VARCHAR(100) NOT NULL,
                handle VARCHAR(255) NOT NULL,
                url VARCHAR(255),
                FOREIGN KEY (supplier_id) REFERENCES suppliers(supplier_id) ON DELETE CASCADE
            )
        """)
        conn.commit()
        print("supplier_social_media table initialized successfully")
    except Exception as e:
        print(f"Error initializing supplier_social_media table: {str(e)}")
    finally:
        cursor.close()
        conn.close()

def get_active_outfits():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT outfit_id, outfit_name, outfit_type, outfit_color, 
                   outfit_desc, rent_price, status, outfit_img, size, weight
            FROM outfits 
            WHERE status = 'Active'
            ORDER BY outfit_id
        """)
        outfits = cursor.fetchall()
        return [{
            'outfit_id': outfit[0],
            'outfit_name': outfit[1],
            'outfit_type': outfit[2],
            'outfit_color': outfit[3],
            'outfit_desc': outfit[4],
            'rent_price': float(outfit[5]) if outfit[5] else 0,
            'status': outfit[6],
            'outfit_img': outfit[7],
            'size': outfit[8],
            'weight': float(outfit[9]) if outfit[9] else 0
        } for outfit in outfits]
    except Exception:
        return []
    finally:
        cursor.close()
        conn.close()

def add_event_outfit(events_id, outfit_type, outfit_id=None, gown_package_id=None):
    try:
        with db.get_db_cursor() as cursor:
            cursor.execute("""
                INSERT INTO event_outfits (events_id, outfit_type, outfit_id, gown_package_id)
                VALUES (%s, %s, %s, %s)
                RETURNING event_outfit_id
            """, (events_id, outfit_type, outfit_id, gown_package_id))
            result = cursor.fetchone()
            return result[0] if result else None
    except Exception as e:
        print(f"Error adding event outfit: {str(e)}")
        return None

def get_event_outfits(events_id):
    try:
        with db.get_db_cursor() as cursor:
            # Get both individual outfits and gown packages
            cursor.execute("""
                SELECT eo.event_outfit_id, eo.outfit_type, 
                       o.outfit_id, o.outfit_name, o.outfit_type as outfit_category, o.size, o.rent_price,
                       gp.gown_package_id, gp.gown_package_name, gp.gown_package_price
                FROM event_outfits eo
                LEFT JOIN outfits o ON eo.outfit_id = o.outfit_id
                LEFT JOIN gown_package gp ON eo.gown_package_id = gp.gown_package_id
                WHERE eo.events_id = %s
            """, (events_id,))
            outfits = cursor.fetchall()
            
            result = []
            for outfit in outfits:
                outfit_id = outfit[2]
                gown_package_id = outfit[7]
                
                # Handle individual outfit
                if outfit_id:
                    result.append({
                        'event_outfit_id': outfit[0],
                        'outfit_type': outfit[1],
                        'outfit_id': outfit_id,
                        'outfit_name': outfit[3] or f"Outfit #{outfit_id}",  # Fallback name
                        'outfit_category': outfit[4],
                        'size': outfit[5],
                        'rent_price': float(outfit[6]) if outfit[6] else 0,
                        'gown_package_id': None,
                        'gown_package_name': None,
                        'gown_package_price': None,
                        'type': 'individual'
                    })
                
                # Handle gown package
                if gown_package_id:
                    # Get outfit contents of package if it's a gown package
                    package_outfits = []
                    if gown_package_id:
                        cursor.execute("""
                            SELECT o.outfit_id, o.outfit_name, o.outfit_type, o.size, o.rent_price
                            FROM gown_package_outfits gpo
                            JOIN outfits o ON gpo.outfit_id = o.outfit_id
                            WHERE gpo.gown_package_id = %s
                        """, (gown_package_id,))
                        package_outfits = cursor.fetchall()
                    
                    result.append({
                        'event_outfit_id': outfit[0],
                        'outfit_type': outfit[1],
                        'outfit_id': None,
                        'outfit_name': None,
                        'outfit_category': None,
                        'size': None,
                        'rent_price': None,
                        'gown_package_id': gown_package_id,
                        'gown_package_name': outfit[8] or f"Package #{gown_package_id}",  # Fallback name if empty
                        'gown_package_price': float(outfit[9]) if outfit[9] else 0,
                        'type': 'package',
                        'package_outfits': [
                            {
                                'outfit_id': po[0],
                                'outfit_name': po[1] or f"Package Outfit #{po[0]}",
                                'outfit_type': po[2],
                                'size': po[3],
                                'rent_price': float(po[4]) if po[4] else 0
                            } for po in package_outfits
                        ],
                        'outfits_count': len(package_outfits)
                    })
            
            return result
    except Exception as e:
        logger.error(f"Error getting event outfits: {str(e)}")
        return []

def toggle_supplier_status(supplier_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # First get current status
        cursor.execute("SELECT status FROM suppliers WHERE supplier_id = %s", (supplier_id,))
        current_status = cursor.fetchone()

        if not current_status:
            return ("not_found", None)

        # Toggle the status
        new_status = 'Inactive' if current_status[0] == 'Active' else 'Active'
        
        cursor.execute(
            "UPDATE suppliers SET status = %s WHERE supplier_id = %s",
            (new_status, supplier_id)
        )
        
        conn.commit()
        return new_status
    finally:
        cursor.close()
        conn.close()

def get_available_suppliers():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("""
            SELECT s.supplier_id, u.firstname, u.lastname, s.service, s.price
            FROM suppliers s
            JOIN users u ON s.userid = u.userid
            WHERE s.status = 'Active'
        """)
        suppliers = cursor.fetchall()

        # Transform the result into a list of dictionaries
        return [
            {
                'supplier_id': item[0],
                'firstname': item[1],
                'lastname': item[2],
                'service': item[3],
                'price': item[4]
            }
            for item in suppliers
        ]
    finally:
        cursor.close()
        conn.close()

def get_available_venues():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT venue_id, venue_name, location, venue_price FROM venues WHERE status = 'Active'")
        venues = cursor.fetchall()

        return [
            {
                'venue_id': item[0],
                'venue_name': item[1],
                'location': item[2],
                'venue_price': item[3]
            }
            for item in venues
        ]
    finally:
        cursor.close()
        conn.close()

def get_available_gown_packages():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT gown_package_id, gown_package_name, gown_package_price FROM gown_package WHERE status = 'Active'")
        packages = cursor.fetchall()

        return [
            {
                'gown_package_id': item[0],
                'gown_package_name': item[1],
                'gown_package_price': item[2]
            }
            for item in packages
        ]
    finally:
        cursor.close()
        conn.close()

def get_package_details_by_id(package_id):
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        # First get the main package details
        cursor.execute("""
            SELECT ep.package_id, ep.package_name, et.event_type_name, ep.capacity, ep.description, ep.total_price,
                   ep.additional_capacity_charges, ep.charge_unit,
                   v.venue_name, v.location, v.venue_price,
                   gp.gown_package_name, gp.gown_package_price,
                   array_agg(ps.package_service_id) AS package_service_ids,
                   array_agg(ps.supplier_id) AS supplier_ids,
                   array_agg(s.service) AS services,
                   array_agg(s.price) AS service_prices,
                   array_agg(u.firstname) AS supplier_firstnames,
                   array_agg(u.lastname) AS supplier_lastnames,
                   array_agg(u.email) AS supplier_emails,
                   array_agg(ps.external_supplier_name) AS external_supplier_names,
                   array_agg(ps.external_supplier_contact) AS external_supplier_contacts,
                   array_agg(ps.external_supplier_price) AS external_supplier_prices,
                   array_agg(ps.remarks) AS remarks
            FROM event_packages ep
            LEFT JOIN event_type et ON ep.event_type_id = et.event_type_id
            LEFT JOIN venues v ON ep.venue_id = v.venue_id
            LEFT JOIN gown_package gp ON ep.gown_package_id = gp.gown_package_id
            LEFT JOIN event_package_services eps ON ep.package_id = eps.package_id
            LEFT JOIN package_service ps ON eps.package_service_id = ps.package_service_id
            LEFT JOIN suppliers s ON ps.supplier_id = s.supplier_id
            LEFT JOIN users u ON s.userid = u.userid
            WHERE ep.package_id = %s
            GROUP BY ep.package_id, et.event_type_name, v.venue_name, v.location, v.venue_price, 
                     gp.gown_package_name, gp.gown_package_price
        """, (package_id,))
        
        row = cursor.fetchone()
        if row:
            package_details = {
                'package_id': row[0],
                'package_name': row[1],
                'event_type_name': row[2],
                'capacity': row[3],
                'description': row[4],
                'total_price': float(row[5]) if row[5] else 0,
                'additional_capacity_charges': float(row[6]) if row[6] else 0,
                'charge_unit': row[7],
                'venue_name': row[8],
                'venue_location': row[9],
                'venue_price': float(row[10]) if row[10] else 0,
                'gown_package_name': row[11],
                'gown_package_price': float(row[12]) if row[12] else 0,
                'package_service_ids': row[13] if row[13] and row[13][0] is not None else [],
                'supplier_ids': row[14] if row[14] and row[14][0] is not None else [],
                'services': row[15] if row[15] and row[15][0] is not None else [],
                'service_prices': [float(p) if p else 0 for p in row[16]] if row[16] and row[16][0] is not None else [],
                'supplier_firstnames': row[17] if row[17] and row[17][0] is not None else [],
                'supplier_lastnames': row[18] if row[18] and row[18][0] is not None else [],
                'supplier_emails': row[19] if row[19] and row[19][0] is not None else [],
                'external_supplier_names': row[20] if row[20] and row[20][0] is not None else [],
                'external_supplier_contacts': row[21] if row[21] and row[21][0] is not None else [],
                'external_supplier_prices': [float(p) if p else 0 for p in row[22]] if row[22] and row[22][0] is not None else [],
                'remarks': row[23] if row[23] and row[23][0] is not None else []
            }

            # Now get the additional services
            cursor.execute("""
                SELECT 
                    a.add_service_id,
                    a.add_service_name,
                    a.add_service_price
                FROM event_package_additional_services epas
                JOIN additional_services a ON epas.add_service_id = a.add_service_id
                WHERE epas.package_id = %s
            """, (package_id,))
            
            additional_services = []
            for service_row in cursor.fetchall():
                additional_services.append({
                    'service_id': service_row[0],
                    'name': service_row[1],
                    'price': float(service_row[2]) if service_row[2] else 0
                })
            
            package_details['additional_services'] = additional_services
            return package_details
        return None
    finally:
        cursor.close()
        conn.close()

def track_outfit_modification(events_id, outfit_id=None, gown_package_id=None, modification_type=None, original_price=None, modified_price=None, remarks=None):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE events 
            SET modified_outfits = COALESCE(modified_outfits, '[]'::jsonb) || jsonb_build_object(
                'outfit_id', outfit_id,
                'gown_package_id', gown_package_id,
                'modification_type', modification_type,
                'original_price', original_price,
                'modified_price', modified_price,
                'remarks', remarks,
                'modified_at', CURRENT_TIMESTAMP
            )::jsonb
            WHERE events_id = %s
            RETURNING modified_outfits
        """, (events_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error tracking outfit modification: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def track_individual_outfit_modification(events_id, outfit_data):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE events 
            SET modified_individual_outfit = %s::jsonb
            WHERE events_id = %s
            RETURNING modified_individual_outfit
        """, (json.dumps(outfit_data), events_id))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error tracking individual outfit modification: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def track_additional_service_modification(events_id, service_id, modification_type, original_price=None, modified_price=None, remarks=None):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE events 
            SET modified_additional_services = COALESCE(modified_additional_services, '[]'::jsonb) || jsonb_build_object(
                'service_id', service_id,
                'modification_type', modification_type,
                'original_price', original_price,
                'modified_price', modified_price,
                'remarks', remarks,
                'modified_at', CURRENT_TIMESTAMP
            )::jsonb
            WHERE events_id = %s
            RETURNING modified_additional_services
        """, (events_id,))
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error tracking additional service modification: {str(e)}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def get_all_outfits():
    conn = db.get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT outfit_id, outfit_name, outfit_type, outfit_color, outfit_desc, rent_price, status, outfit_img, size, weight FROM outfits")
        outfits = cursor.fetchall()

        # Transform the result into a list of dictionaries
        return [
            {
                'outfit_id': item[0],
                'outfit_name': item[1],
                'outfit_type': item[2],
                'outfit_color': item[3],
                'outfit_desc': item[4],
                'rent_price': item[5],
                'status': item[6],
                'outfit_img': item[7],
                'size': item[8],
                'weight': item[9]
            }
            for item in outfits
        ]
    finally:
        cursor.close()
        conn.close()

def create_outfit(outfit_data):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert outfit data
        cursor.execute("""
            INSERT INTO outfits (outfit_name, outfit_type, outfit_color, outfit_desc, 
                               rent_price, status, outfit_img, size, weight)
            VALUES (%(outfit_name)s, %(outfit_type)s, %(outfit_color)s, %(outfit_desc)s,
                    %(rent_price)s, %(status)s, %(outfit_img)s, %(size)s, %(weight)s)
            RETURNING outfit_id
        """, {
            'outfit_name': outfit_data.get('outfit_name'),
            'outfit_type': outfit_data.get('outfit_type'),
            'outfit_color': outfit_data.get('outfit_color'),
            'outfit_desc': outfit_data.get('outfit_desc'),
            'rent_price': float(outfit_data.get('rent_price', 0)),
            'status': 'Available',  # Default status
            'outfit_img': outfit_data.get('outfit_img'),
            'size': outfit_data.get('size'),
            'weight': float(outfit_data.get('weight', 0))
        })
        
        outfit_id = cursor.fetchone()[0]
        
        # Create archive entry
        archive_data = outfit_data.get('archive', {})
        cursor.execute("""
            INSERT INTO outfit_archive (outfit_id, creation_address, creation_date,
                                      owner, retail_price, usage)
            VALUES (%s, %s, CURRENT_DATE, %s, %s, 0)
        """, (
            outfit_id,
            archive_data.get('creation_address'),
            archive_data.get('owner'),
            float(archive_data.get('retail_price', 0)) if archive_data.get('retail_price') else 0
        ))
        
        conn.commit()
        return True, outfit_id, "Outfit created successfully"
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating outfit: {str(e)}")
        return False, None, str(e)
    finally:
        cursor.close()
        conn.close()

def create_wishlist_package(events_id, package_data):
    """Create a new wishlist package for an event"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Insert the main wishlist package
        cursor.execute("""
            INSERT INTO wishlist_packages (
                events_id, package_name, capacity, description, venue_id,
                gown_package_id, additional_capacity_charges, charge_unit,
                total_price, event_type_id, status, venue_status
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
            ) RETURNING wishlist_id
        """, (
            events_id,
            package_data.get('package_name'),
            package_data.get('capacity'),
            package_data.get('description'),
            package_data.get('venue_id'),
            package_data.get('gown_package_id'),
            package_data.get('additional_capacity_charges', 0),
            package_data.get('charge_unit', 1),
            package_data.get('total_price', 0),
            package_data.get('event_type_id'),
            package_data.get('status', 'Active'),
            package_data.get('venue_status', 'Pending')
        ))
        
        wishlist_id = cursor.fetchone()[0]
        
        # Add venue to wishlist_venues if provided
        if package_data.get('venue'):
            venue_data = package_data['venue']
            cursor.execute("""
                INSERT INTO wishlist_venues (
                    wishlist_id, venue_id, price, remarks, status
                ) VALUES (
                    %s, %s, %s, %s, %s
                )
            """, (
                wishlist_id,
                venue_data.get('venue_id'),
                venue_data.get('venue_price', 0),
                venue_data.get('remarks', ''),
                'Pending'  # Set initial status to Pending
            ))
        
        # Add services if provided
        if package_data.get('services'):
            for service in package_data['services']:
                cursor.execute("""
                    INSERT INTO wishlist_additional_services (wishlist_id, add_service_id, price, remarks, status)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    wishlist_id, 
                    service['add_service_id'],
                    service.get('price', 0),
                    service.get('remarks', ''),
                    'Pending'  # Set initial status to Pending
                ))
        
        # Add suppliers if provided
        if package_data.get('suppliers'):
            for supplier in package_data['suppliers']:
                status = supplier.get('status', 'Pending')
                if supplier.get('type') == 'external':
                    cursor.execute("""
                        INSERT INTO wishlist_suppliers (
                            wishlist_id, supplier_id, price, remarks, status,
                            external_supplier_name, external_supplier_contact
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        wishlist_id,
                        None,  # supplier_id is NULL for external suppliers
                        supplier.get('price', 0),
                        supplier.get('service', ''),  # Store service type in remarks
                        status,
                        supplier.get('external_supplier_name', ''),
                        supplier.get('external_supplier_contact', '')
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO wishlist_suppliers (wishlist_id, supplier_id, price, remarks, status)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        wishlist_id,
                        supplier['supplier_id'],
                        supplier.get('price', 0),
                        supplier.get('remarks', ''),
                        status
                    ))
        
        # Add outfits if provided
        if package_data.get('outfits'):
            for outfit in package_data['outfits']:
                cursor.execute("""
                    INSERT INTO wishlist_outfits (wishlist_id, outfit_id, gown_package_id, price, remarks)
                    VALUES (%s, %s, %s, %s, %s)
                """, (
                    wishlist_id,
                    outfit.get('outfit_id'),
                    outfit.get('gown_package_id'),
                    outfit.get('price'),
                    outfit.get('remarks')
                ))
        
        conn.commit()
        return wishlist_id
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error creating wishlist package: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def get_wishlist_package(wishlist_id):
    "Get detailed information about a wishlist package."
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT wp.*
        FROM wishlist_packages wp
        WHERE wp.wishlist_id = %s
        """
        cursor.execute(query, (wishlist_id,))
        package = cursor.fetchone()
        
        if not package:
            return None
            
        cols = [desc[0] for desc in cursor.description]
        wishlist_dict = dict(zip(cols, package))
        
        # Get package details from events if available
        if 'events_id' in wishlist_dict:
            try:
                cursor.execute("""
                    SELECT p.package_id, p.package_name, p.total_price
                    FROM event_packages p
                    JOIN events e ON e.package_id = p.package_id
                    WHERE e.events_id = %s
                """, (wishlist_dict['events_id'],))
                
                package_data = cursor.fetchone()
                if package_data:
                    wishlist_dict['package_id'] = package_data[0]
                    wishlist_dict['package_name'] = package_data[1] 
                    wishlist_dict['package_price'] = package_data[2]
            except Exception as e:
                logger.warning(f"Could not fetch package data for event: {e}")
        
        return wishlist_dict
    except Exception as e:
        logger.error(f"Error in get_wishlist_package: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()


def get_event_wishlists(events_id):
    """Get all wishlist packages for an event"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT wishlist_id FROM wishlist_packages 
            WHERE events_id = %s
        """, (events_id,))
        
        wishlist_ids = cursor.fetchall()
        wishlists = [get_wishlist_package(wid[0]) for wid in wishlist_ids]
        # Filter out None values
        return [wishlist for wishlist in wishlists if wishlist is not None]
        
    finally:
        cursor.close()
        conn.close()

def update_wishlist_package(wishlist_id, package_data):
    """Update an existing wishlist package"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Log the venue_status for debugging
        venue_status = package_data.get('venue_status', 'Pending')
        logger.info(f"Updating wishlist_package {wishlist_id} with venue_status: {venue_status}")

        # Get the events_id associated with this wishlist
        cursor.execute("SELECT events_id FROM wishlist_packages WHERE wishlist_id = %s", (wishlist_id,))
        result = cursor.fetchone()
        if not result:
            logger.error(f"No events_id found for wishlist_id {wishlist_id}")
            conn.rollback()
            return False

        events_id = result[0]
        
        # We'll use separate transactions for different operations to avoid aborting everything
        
        # First, update the events table
        try:
            cursor.execute("""
                UPDATE events SET
                    event_name = COALESCE(%s, event_name),
                    event_theme = COALESCE(%s, event_theme),
                    event_color = COALESCE(%s, event_color),
                    schedule = COALESCE(%s, schedule),
                    start_time = COALESCE(%s, start_time),
                    end_time = COALESCE(%s, end_time)
                WHERE events_id = %s
            """, (
                package_data.get('event_name'),
                package_data.get('event_theme'),
                package_data.get('event_color'),
                package_data.get('schedule'),
                package_data.get('start_time'),
                package_data.get('end_time'),
                events_id
            ))
            conn.commit()
            logger.info(f"Successfully updated events table for events_id {events_id}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating events table: {str(e)}")
            # We'll continue with other updates anyway
            
        # Update capacity separately
        if package_data.get('capacity') is not None:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE events SET capacity = %s WHERE events_id = %s
                """, (
                    package_data.get('capacity'),
                    events_id
                ))
                conn.commit()
                logger.info(f"Updated capacity for events_id {events_id} to {package_data.get('capacity')}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating capacity: {str(e)}")
            finally:
                cursor.close()
                conn.close()
                
        # Update description field which stores our alternative capacity info
        if package_data.get('description') is not None:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE events SET description = %s WHERE events_id = %s
                """, (
                    package_data.get('description'),
                    events_id
                ))
                conn.commit()
                logger.info(f"Updated description for events_id {events_id}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating description: {str(e)}")
            finally:
                cursor.close()
                conn.close()
        
        # Now update the main wishlist package
        try:
            conn = db.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE wishlist_packages SET
                    package_name = %s,
                    capacity = %s,
                    description = %s,
                    venue_id = %s,
                    gown_package_id = %s,
                    additional_capacity_charges = %s,
                    charge_unit = %s,
                    total_price = %s,
                    event_type_id = %s,
                    status = %s,
                    venue_status = %s
                WHERE wishlist_id = %s
            """, (
                package_data.get('package_name'),
                package_data.get('capacity'),
                package_data.get('description'),
                package_data.get('venue_id'),
                package_data.get('gown_package_id'),
                package_data.get('additional_capacity_charges', 0),
                package_data.get('charge_unit', 1),
                package_data.get('total_price', 0),
                package_data.get('event_type_id'),
                package_data.get('status', 'Active'),
                venue_status,
                wishlist_id
            ))
            conn.commit()
            logger.info(f"Successfully updated wishlist_packages for wishlist_id {wishlist_id}")
        except Exception as e:
            conn.rollback()
            logger.error(f"Error updating wishlist_packages: {str(e)}")
            # Continue with other updates
        finally:
            cursor.close()
            conn.close()

        # Update venue in wishlist_venues if provided
        if package_data.get('venue'):
            venue_data = package_data['venue']
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                # First check if venue exists
                cursor.execute("""
                    SELECT wishlist_venue_id FROM wishlist_venues 
                    WHERE wishlist_id = %s
                """, (wishlist_id,))
                existing_venue = cursor.fetchone()

                if existing_venue:
                    # Update existing venue
                    cursor.execute("""
                        UPDATE wishlist_venues SET
                            venue_id = %s,
                            price = %s,
                            remarks = %s,
                            status = %s
                        WHERE wishlist_id = %s
                    """, (
                        venue_data.get('venue_id'),
                        venue_data.get('venue_price', 0),
                        venue_data.get('remarks', ''),
                        venue_status,
                        wishlist_id
                    ))
                else:
                    # Insert new venue
                    cursor.execute("""
                        INSERT INTO wishlist_venues (
                            wishlist_id, venue_id, price, remarks, status
                        ) VALUES (
                            %s, %s, %s, %s, %s
                        )
                    """, (
                        wishlist_id,
                        venue_data.get('venue_id'),
                        venue_data.get('venue_price', 0),
                        venue_data.get('remarks', ''),
                        venue_status
                    ))
                conn.commit()
                logger.info(f"Successfully updated venue for wishlist_id {wishlist_id}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating venue: {str(e)}")
            finally:
                cursor.close()
                conn.close()
        
        # Update services
        if 'services' in package_data:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                # Log the services data for debugging
                logger.info(f"Services data for wishlist {wishlist_id}: {package_data['services']}")
                
                # Delete existing services
                cursor.execute("DELETE FROM wishlist_additional_services WHERE wishlist_id = %s", (wishlist_id,))
                
                # Insert updated services
                for service in package_data['services']:
                    status = service.get('status', 'Pending')  # Get status from data or default to 'Pending'
                    logger.info(f"Adding service with status: {status}")
                    
                    cursor.execute("""
                        INSERT INTO wishlist_additional_services (wishlist_id, add_service_id, price, remarks, status)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        wishlist_id, 
                        service['add_service_id'],
                        service.get('price', 0) or service.get('add_service_price', 0), 
                        service.get('remarks', ''),
                        status
                    ))
                conn.commit()
                logger.info(f"Successfully updated services for wishlist_id {wishlist_id}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating services: {str(e)}")
            finally:
                cursor.close()
                conn.close()
        
        # Update suppliers
        if 'suppliers' in package_data:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                # Delete existing suppliers
                cursor.execute("DELETE FROM wishlist_suppliers WHERE wishlist_id = %s", (wishlist_id,))
                
                # Insert updated suppliers
                for supplier in package_data['suppliers']:
                    status = supplier.get('status', 'Pending')
                    if supplier.get('type') == 'external':
                        cursor.execute("""
                            INSERT INTO wishlist_suppliers (
                                wishlist_id, supplier_id, price, remarks, status,
                                external_supplier_name, external_supplier_contact
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s)
                        """, (
                            wishlist_id,
                            None,  # supplier_id is NULL for external suppliers
                            supplier.get('price', 0),
                            supplier.get('remarks', ''),
                            status,
                            supplier.get('external_supplier_name', ''),
                            supplier.get('external_supplier_contact', '')
                        ))
                    else:
                        cursor.execute("""
                            INSERT INTO wishlist_suppliers (wishlist_id, supplier_id, price, remarks, status)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            wishlist_id,
                            supplier['supplier_id'],
                            supplier.get('price', 0),
                            supplier.get('remarks', ''),
                            status
                        ))
                conn.commit()
                logger.info(f"Successfully updated suppliers for wishlist_id {wishlist_id}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating suppliers: {str(e)}")
            finally:
                cursor.close()
                conn.close()
        
        # Update outfits
        if 'outfits' in package_data:
            try:
                conn = db.get_db_connection()
                cursor = conn.cursor()
                # Delete existing outfits
                cursor.execute("DELETE FROM wishlist_outfits WHERE wishlist_id = %s", (wishlist_id,))
                
                # Insert updated outfits
                for outfit in package_data['outfits']:
                    cursor.execute("""
                        INSERT INTO wishlist_outfits (wishlist_id, outfit_id, gown_package_id, price, remarks, status)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        wishlist_id,
                        outfit.get('outfit_id'),
                        outfit.get('gown_package_id'),
                        outfit.get('price', 0),
                        outfit.get('remarks', ''),
                        outfit.get('status', 'Pending')
                    ))
                conn.commit()
                logger.info(f"Successfully updated outfits for wishlist_id {wishlist_id}")
            except Exception as e:
                conn.rollback()
                logger.error(f"Error updating outfits: {str(e)}")
            finally:
                cursor.close()
                conn.close()
        
        return True
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating wishlist package: {str(e)}")
        return False
    finally:
        try:
            cursor.close()
            conn.close()
        except:
            pass

def delete_wishlist_package(wishlist_id):
    """Delete a wishlist package and all related data"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("DELETE FROM wishlist_packages WHERE wishlist_id = %s", (wishlist_id,))
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        logger.error(f"Error deleting wishlist package: {str(e)}")
        return False
    finally:
        cursor.close()
        conn.close()

def update_wishlist_supplier_status(wishlist_supplier_id, status):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if the supplier has been updated before
        cursor.execute("""
            SELECT status, has_been_updated 
            FROM wishlist_suppliers 
            WHERE wishlist_supplier_id = %s
        """, (wishlist_supplier_id,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Supplier not found"
            
        current_status, has_been_updated = result
        
        # If already updated once, prevent further updates
        if has_been_updated:
            return False, "This supplier has already been updated once. You cannot update it again."
            
        # Update the status and mark as updated
        cursor.execute(
            "UPDATE wishlist_suppliers SET status = %s, has_been_updated = TRUE WHERE wishlist_supplier_id = %s",
            (status, wishlist_supplier_id)
        )
            
        conn.commit()
        return True, "Status updated successfully"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def update_wishlist_outfit_status(wishlist_outfit_id, status):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if the outfit has been updated before
        cursor.execute("""
            SELECT status, has_been_updated 
            FROM wishlist_outfits 
            WHERE wishlist_outfit_id = %s
        """, (wishlist_outfit_id,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Outfit not found"
            
        current_status, has_been_updated = result
        
        # If already updated once, prevent further updates
        if has_been_updated:
            return False, "This outfit has already been updated once. You cannot update it again."
            
        # Update the status and mark as updated
        cursor.execute(
            "UPDATE wishlist_outfits SET status = %s, has_been_updated = TRUE WHERE wishlist_outfit_id = %s",
            (status, wishlist_outfit_id)
        )
            
        conn.commit()
        return True, "Status updated successfully"
    except Exception as e:
        conn.rollback()
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def update_wishlist_additional_service_status(wishlist_id, service_id, status):
    try:
        conn = psycopg2.connect(**DATABASE_CONFIG)
        cur = conn.cursor()
        
        # First check if this service has been updated before
        cur.execute("""
            SELECT has_been_updated 
            FROM wishlist_additional_services 
            WHERE wishlist_id = %s AND service_id = %s
        """, (wishlist_id, service_id))
        
        result = cur.fetchone()
        if result and result[0]:
            return False, "This service has already been updated once"
        
        # Update the status
        cur.execute("""
            UPDATE wishlist_additional_services 
            SET status = %s, has_been_updated = TRUE 
            WHERE wishlist_id = %s AND service_id = %s
            RETURNING *
        """, (status, wishlist_id, service_id))
        
        updated_service = cur.fetchone()
        conn.commit()
        
        if updated_service:
            return True, "Service status updated successfully"
        return False, "Service not found"
        
    except Exception as e:
        logger.error(f"Error updating additional service status: {str(e)}")
        return False, str(e)
    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def delete_wishlist_outfit_direct(wishlist_outfit_id):
    """Directly delete a wishlist outfit from the database"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM wishlist_outfits WHERE wishlist_outfit_id = %s",
            (wishlist_outfit_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting wishlist outfit: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def delete_wishlist_service_direct(service_id):
    """Directly delete a wishlist service from the database"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM wishlist_additional_services WHERE id = %s",
            (service_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting wishlist service: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def delete_wishlist_supplier_direct(wishlist_supplier_id):
    """Directly delete a wishlist supplier from the database"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM wishlist_suppliers WHERE wishlist_supplier_id = %s",
            (wishlist_supplier_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting wishlist supplier: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def delete_wishlist_venue_direct(wishlist_venue_id):
    """Directly delete a wishlist venue from the database"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "DELETE FROM wishlist_venues WHERE wishlist_venue_id = %s",
            (wishlist_venue_id,)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"Error deleting wishlist venue: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def fetch_upcoming_events():
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT 
                e.events_id, e.event_name, e.event_type, e.event_theme, e.event_color,
                e.schedule, e.start_time, e.end_time, e.status, e.booking_type,
                e.onsite_firstname, e.onsite_lastname, e.onsite_contact, e.onsite_address,
                e.total_price, e.userid,
                wp.wishlist_id, wp.package_name, wp.capacity, wp.description as package_description,
                wp.additional_capacity_charges, wp.charge_unit, wp.venue_status,
                v.venue_id, v.venue_name, v.location, v.description as venue_description,
                v.venue_price, v.venue_capacity,
                gp.gown_package_id, gp.gown_package_name, gp.gown_package_price,
                et.event_type_id, et.event_type_name,
                u.firstname, u.lastname, u.email, u.contactnumber
            FROM events e
            LEFT JOIN wishlist_packages wp ON e.events_id = wp.events_id
            LEFT JOIN venues v ON wp.venue_id = v.venue_id
            LEFT JOIN gown_package gp ON wp.gown_package_id = gp.gown_package_id
            LEFT JOIN event_types et ON wp.event_type_id = et.event_type_id
            LEFT JOIN users u ON e.userid = u.userid
            WHERE LOWER(e.status) = 'upcoming'
            ORDER BY e.schedule DESC
        """)
        events = []
        for row in cursor.fetchall():
            event = {
                'events_id': row[0],
                'event_name': row[1],
                'event_type': row[2],
                'event_theme': row[3],
                'event_color': row[4],
                'schedule': row[5].strftime('%Y-%m-%d') if row[5] else None,
                'start_time': row[6].strftime('%H:%M') if row[6] else None,
                'end_time': row[7].strftime('%H:%M') if row[7] else None,
                'status': row[8],
                'booking_type': row[9],
                'onsite_firstname': row[10],
                'onsite_lastname': row[11],
                'onsite_contact': row[12],
                'onsite_address': row[13],
                'total_price': float(row[14]) if row[14] else 0,
                'userid': row[15],
                'wishlist_id': row[16],
                'package_name': row[17],
                'capacity': row[18],
                'package_description': row[19],
                'additional_capacity_charges': float(row[20]) if row[20] else 0,
                'charge_unit': row[21],
                'venue_status': row[22] if row[22] else 'Pending',
                'venue_id': row[23],
                'venue_name': row[24],
                'venue_location': row[25],
                'venue_description': row[26],
                'venue_price': float(row[27]) if row[27] else 0,
                'venue_capacity': row[28],
                'gown_package_id': row[29],
                'gown_package_name': row[30],
                'gown_package_price': float(row[31]) if row[31] else 0,
                'event_type_id': row[32],
                'event_type_name': row[33],
                'firstname': row[34],
                'lastname': row[35],
                'email': row[36],
                'contactnumber': row[37],
                'bookedBy': f"{row[34] or ''} {row[35] or ''}".strip(),
                'suppliers': [],
                'services': [],
                'venues': [],
                'outfits': [],
                'wishlist_venues': []
            }
            
            # Get wishlist venues for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        wv.wishlist_venue_id, wv.venue_id, wv.price, wv.status,
                        v.venue_name, v.location, v.description, v.venue_capacity
                    FROM wishlist_venues wv
                    JOIN venues v ON wv.venue_id = v.venue_id
                    WHERE wv.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                wishlist_venues = cursor.fetchall()
                event['wishlist_venues'] = []
                for wv in wishlist_venues:
                    venue_data = {
                        'wishlist_venue_id': wv[0],
                        'venue_id': wv[1],
                        'price': float(wv[2]) if wv[2] else 0,
                        'status': wv[3],
                        'venue_name': wv[4],
                        'location': wv[5],
                        'description': wv[6],
                        'venue_capacity': wv[7]
                    }
                    event['wishlist_venues'].append(venue_data)
                    
                    # Also add to the main venues array with wishlist_venue_id
                    event['venues'].append({
                        'wishlist_venue_id': wv[0],
                        'venue_id': wv[1],
                        'venue_name': wv[4],
                        'location': wv[5],
                        'description': wv[6],
                        'venue_price': float(wv[2]) if wv[2] else 0,
                        'venue_capacity': wv[7],
                        'status': wv[3] if wv[3] else 'Pending'
                    })
            
            # If no wishlist venues but we have a direct venue from the main query
            elif event['venue_id']:
                event['venues'].append({
                    'venue_id': event['venue_id'],
                    'venue_name': event['venue_name'],
                    'location': event['venue_location'],
                    'description': event['venue_description'],
                    'venue_price': event['venue_price'],
                    'venue_capacity': event['venue_capacity'],
                    'status': event['venue_status']
                })
            
            # Get suppliers for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        ws.wishlist_supplier_id, ws.supplier_id, ws.status,
                        s.service, u.firstname, u.lastname, ws.price,
                        ws.external_supplier_name, ws.external_supplier_contact,
                        ws.remarks
                    FROM wishlist_suppliers ws
                    LEFT JOIN suppliers s ON ws.supplier_id = s.supplier_id
                    LEFT JOIN users u ON s.userid = u.userid
                    WHERE ws.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                suppliers = cursor.fetchall()
                event['suppliers'] = [{
                    'wishlist_supplier_id': s[0],
                    'supplier_id': s[1],
                    'status': s[2],
                    'service': s[9] if s[1] is None else s[3],  # Use remarks as service for external suppliers
                    'firstname': s[7] if s[1] is None else s[4],  # Use external_supplier_name for external suppliers
                    'lastname': '' if s[1] is None else s[5],  # No lastname for external suppliers
                    'price': float(s[6]) if s[6] else 0,
                    'external_supplier_name': s[7],
                    'external_supplier_contact': s[8],
                    'remarks': s[9],
                    'type': 'external' if s[1] is None else 'internal'
                } for s in suppliers]
            
            # Get services for this event
            if event['wishlist_id']:
                cursor.execute("""
                    SELECT 
                        was.id, was.wishlist_id, was.add_service_id, was.price, was.remarks, was.status,
                        a.add_service_name, a.add_service_description, a.add_service_price
                    FROM wishlist_additional_services was
                    JOIN additional_services a ON was.add_service_id = a.add_service_id
                    WHERE was.wishlist_id = %s
                """, (event['wishlist_id'],))
                
                services = cursor.fetchall()
                event['services'] = [{
                    'id': s[0],
                    'wishlist_id': s[1],
                    'add_service_id': s[2],
                    'price': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0,
                    'remarks': s[4] if s[4] else '',
                    'status': s[5] if s[5] else 'Pending',
                    'add_service_name': s[6],
                    'add_service_description': s[7],
                    'add_service_price': float(s[8]) if s[8] is not None else 0,
                    'total': float(s[3]) if s[3] is not None else float(s[8]) if s[8] is not None else 0
                } for s in services]
            
            # Get outfits for this event
            if event['wishlist_id']:
                # Query to get individual outfits
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        o.outfit_name, o.outfit_type, o.rent_price, o.size
                    FROM wishlist_outfits wo
                    LEFT JOIN outfits o ON wo.outfit_id = o.outfit_id
                    WHERE wo.wishlist_id = %s AND wo.outfit_id IS NOT NULL
                """, (event['wishlist_id'],))
                
                individual_outfits = cursor.fetchall()
                
                # Query to get gown packages
                cursor.execute("""
                    SELECT 
                        wo.wishlist_outfit_id, wo.outfit_id, wo.gown_package_id, wo.price, wo.remarks, wo.status,
                        gp.gown_package_name, gp.gown_package_price
                    FROM wishlist_outfits wo
                    LEFT JOIN gown_package gp ON wo.gown_package_id = gp.gown_package_id
                    WHERE wo.wishlist_id = %s AND wo.gown_package_id IS NOT NULL
                """, (event['wishlist_id'],))
                
                package_outfits = cursor.fetchall()
                
                # Process individual outfits
                for outfit in individual_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'outfit_id': outfit[1],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'outfit_name': outfit[6],
                        'outfit_type': outfit[7],
                        'rent_price': float(outfit[8]) if outfit[8] is not None else 0,
                        'size': outfit[9],
                        'type': 'individual'
                    }
                    event['outfits'].append(outfit_data)
                
                # Process package outfits
                for outfit in package_outfits:
                    outfit_data = {
                        'wishlist_outfit_id': outfit[0],
                        'gown_package_id': outfit[2],
                        'price': float(outfit[3]) if outfit[3] is not None else 0,
                        'remarks': outfit[4] if outfit[4] else '',
                        'status': outfit[5] if outfit[5] else 'Pending',
                        'gown_package_name': outfit[6],
                        'gown_package_price': float(outfit[7]) if outfit[7] is not None else 0,
                        'type': 'outfit_package'
                    }
                    event['outfits'].append(outfit_data)
            
            events.append(event)
        
        logger.info(f"Found {len(events)} upcoming events")
        return events
    except Exception as e:
        logger.error(f"Error in fetch_upcoming_events: {str(e)}")
        return []
    finally:
        cursor.close()
        conn.close()

# Functions for invoice management
def create_invoice(data):
    """Create a new invoice record."""
    conn = None
    try:
        logger.info(f"Starting invoice creation for event ID: {data.get('events_id', 'unknown')}")
        logger.info(f"Invoice data: {data}")
        
        conn = db.get_db_connection()  # Fixed function name to match db.py
        cursor = conn.cursor()
        
        # First verify the events_id exists
        try:
            cursor.execute("SELECT COUNT(*) FROM events WHERE events_id = %s", (data['events_id'],))
            event_count = cursor.fetchone()[0]
            if event_count == 0:
                logger.warning(f"Event with ID {data['events_id']} does not exist in the database")
            else:
                logger.info(f"Event verification successful for ID: {data['events_id']}")
        except Exception as event_verify_error:
            logger.error(f"Error verifying event existence: {event_verify_error}")
            # Continue despite error, not critical for table creation
        
        query = """
        INSERT INTO invoices (
            events_id, invoice_number, invoice_date, 
            total_amount, discount_amount, final_amount, 
            status, notes
        ) VALUES (
            %s, %s, %s, 
            %s, %s, %s, 
            %s, %s
        ) RETURNING invoice_id;
        """
        
        # Log the actual values being inserted
        param_values = (
            data['events_id'],
            data['invoice_number'],
            data['invoice_date'],
            data['total_amount'],
            data['discount_amount'],
            data['final_amount'],
            data['status'],
            data.get('notes', '')
        )
        logger.info(f"Executing invoice creation query with values: {param_values}")
        
        cursor.execute(query, param_values)
        
        result = cursor.fetchone()
        logger.info(f"Query execution result: {result}")
        
        if not result:
            logger.error("No invoice_id returned from insert operation")
            raise Exception("Failed to create invoice - no ID returned")
            
        invoice_id = result[0]
        logger.info(f"Created invoice with ID: {invoice_id}")
        
        conn.commit()
        logger.info("Transaction committed successfully")
        
        # Return the full invoice data
        return get_invoice_by_id(invoice_id)
    except Exception as e:
        error_msg = f"Error in create_invoice: {e}"
        logger.error(error_msg)
        if conn:
            try:
                conn.rollback()
                logger.info("Transaction rolled back due to error")
            except Exception as rollback_error:
                logger.error(f"Error during rollback: {rollback_error}")
        
        # Return detailed error info for debugging
        error_details = {
            "error": str(e),
            "event_id": data.get('events_id', None),
            "invoice_number": data.get('invoice_number', None)
        }
        logger.error(f"Invoice creation failed with details: {error_details}")
        raise Exception(f"Failed to create invoice: {str(e)}")
    finally:
        if conn:
            try:
                conn.close()
                logger.info("Database connection closed")
            except Exception as close_error:
                logger.error(f"Error closing connection: {close_error}")

def get_invoice_by_id(invoice_id):
    """Retrieve invoice by ID."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT invoice_id, events_id, invoice_number, invoice_date,
               total_amount, subtotal, discount_id, discount_amount, final_amount, 
               status, notes, created_at, updated_at
        FROM invoices
        WHERE invoice_id = %s;
        """
        
        cursor.execute(query, (invoice_id,))
        invoice = cursor.fetchone()
        
        if not invoice:
            return None
        
        cols = [desc[0] for desc in cursor.description]
        invoice_dict = dict(zip(cols, invoice))
        
        # Convert decimal values to float for JSON serialization
        for key in ['total_amount', 'subtotal', 'discount_amount', 'final_amount']:
            if key in invoice_dict and invoice_dict[key] is not None:
                invoice_dict[key] = float(invoice_dict[key])
        
        # Convert dates to string
        for key in ['invoice_date', 'created_at', 'updated_at']:
            if key in invoice_dict and invoice_dict[key] is not None:
                invoice_dict[key] = invoice_dict[key].isoformat()
        
        return invoice_dict
    except Exception as e:
        logger.error(f"Error in get_invoice_by_id: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def get_invoice_by_event(event_id):
    """Retrieve invoice by event ID."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT invoice_id, events_id, invoice_number, invoice_date,
               total_amount, subtotal, discount_id, discount_amount, final_amount, 
               status, notes, created_at, updated_at
        FROM invoices
        WHERE events_id = %s
        ORDER BY invoice_date DESC
        LIMIT 1;
        """
        
        cursor.execute(query, (event_id,))
        invoice = cursor.fetchone()
        
        if not invoice:
            return None
        
        cols = [desc[0] for desc in cursor.description]
        invoice_dict = dict(zip(cols, invoice))
        
        # Convert decimal values to float for JSON serialization
        for key in ['total_amount', 'subtotal', 'discount_amount', 'final_amount']:
            if key in invoice_dict and invoice_dict[key] is not None:
                invoice_dict[key] = float(invoice_dict[key])
        
        # Convert dates to string
        for key in ['invoice_date', 'created_at', 'updated_at']:
            if key in invoice_dict and invoice_dict[key] is not None:
                invoice_dict[key] = invoice_dict[key].isoformat()
        
        return invoice_dict
    except Exception as e:
        logger.error(f"Error in get_invoice_by_event: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def update_invoice(invoice_id, data):
    """Update an existing invoice."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        # Build the SET part of the query dynamically based on provided fields
        set_clauses = []
        values = []
        
        allowed_fields = [
            'invoice_number', 'invoice_date', 'total_amount', 'subtotal',
            'discount_id', 'discount_amount', 'final_amount', 'status', 'notes'
        ]
        
        for field in allowed_fields:
            if field in data:
                set_clauses.append(f"{field} = %s")
                values.append(data[field])
        
        if not set_clauses:
            return None  # No fields to update
        
        query = f"""
        UPDATE invoices
        SET {', '.join(set_clauses)}, updated_at = NOW()
        WHERE invoice_id = %s
        RETURNING invoice_id;
        """
        
        values.append(invoice_id)
        cursor.execute(query, values)
        
        updated_id = cursor.fetchone()
        conn.commit()
        
        if not updated_id:
            return None
        
        # Return the updated invoice
        return get_invoice_by_id(invoice_id)
    except Exception as e:
        logger.error(f"Error in update_invoice: {e}")
        if conn:
            conn.rollback()
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def record_payment(data):
    """Record a payment for an invoice."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        # Insert the payment record
        query = """
        INSERT INTO payments (
            invoice_id, amount, payment_method,
            reference_number, payment_date, recorded_by
        ) VALUES (
            %s, %s, %s,
            %s, %s, %s
        ) RETURNING payment_id;
        """
        
        cursor.execute(query, (
            data['invoice_id'],
            data['amount'],
            data['payment_method'],
            data.get('reference_number'),
            data['payment_date'],
            data['recorded_by']
        ))
        
        payment_id = cursor.fetchone()[0]
        
        # Get the invoice
        invoice_query = "SELECT status, final_amount FROM invoices WHERE invoice_id = %s"
        cursor.execute(invoice_query, (data['invoice_id'],))
        invoice = cursor.fetchone()
        
        if not invoice:
            conn.rollback()
            raise Exception(f"Invoice with ID {data['invoice_id']} not found")
        
        # Get total payments for this invoice
        payments_query = "SELECT SUM(amount) FROM payments WHERE invoice_id = %s"
        cursor.execute(payments_query, (data['invoice_id'],))
        total_paid = cursor.fetchone()[0] or 0
        
        # Update invoice status based on payment amount
        final_amount = invoice[1]
        new_status = 'Unpaid'
        
        if total_paid >= final_amount:
            new_status = 'Paid'
        elif total_paid > 0:
            new_status = 'Partially Paid'
        
        update_query = "UPDATE invoices SET status = %s, updated_at = NOW() WHERE invoice_id = %s"
        cursor.execute(update_query, (new_status, data['invoice_id']))
        
        conn.commit()
        
        # Get the created payment
        return get_payment_by_id(payment_id)
    except Exception as e:
        logger.error(f"Error in record_payment: {e}")
        if conn:
            conn.rollback()
        raise

def get_payment_by_id(payment_id):
    """Retrieve a payment by its ID."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT payment_id, invoice_id, amount, payment_method,
               reference_number, payment_date, recorded_by,
               created_at
        FROM payments
        WHERE payment_id = %s;
        """
        
        cursor.execute(query, (payment_id,))
        payment = cursor.fetchone()
        
        if not payment:
            return None
        
        cols = [desc[0] for desc in cursor.description]
        payment_dict = dict(zip(cols, payment))
        
        # Convert decimal values to float for JSON serialization
        if 'amount' in payment_dict and payment_dict['amount'] is not None:
            payment_dict['amount'] = float(payment_dict['amount'])
        
        # Convert dates to string
        for key in ['payment_date', 'created_at']:
            if key in payment_dict and payment_dict[key] is not None:
                payment_dict[key] = payment_dict[key].isoformat()
        
        return payment_dict
    except Exception as e:
        logger.error(f"Error in get_payment_by_id: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def get_payments_by_invoice(invoice_id):
    """Get all payments for a specific invoice."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT payment_id, invoice_id, amount, payment_method,
               reference_number, payment_date, recorded_by,
               created_at
        FROM payments
        WHERE invoice_id = %s
        ORDER BY payment_date DESC;
        """
        
        cursor.execute(query, (invoice_id,))
        payments = cursor.fetchall()
        
        result = []
        if payments:
            cols = [desc[0] for desc in cursor.description]
            
            for payment in payments:
                payment_dict = dict(zip(cols, payment))
                
                # Convert decimal values to float for JSON serialization
                if 'amount' in payment_dict and payment_dict['amount'] is not None:
                    payment_dict['amount'] = float(payment_dict['amount'])
                
                # Convert dates to string
                for key in ['payment_date', 'created_at']:
                    if key in payment_dict and payment_dict[key] is not None:
                        payment_dict[key] = payment_dict[key].isoformat()
                
                result.append(payment_dict)
        
        return result
    except Exception as e:
        logger.error(f"Error in get_payments_by_invoice: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def get_all_discounts():
    """Get all discounts from the database."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        query = """
        SELECT discount_id, name, description, type, value,
               start_date, end_date, status,
               created_at, updated_at
        FROM discounts
        ORDER BY name;
        """
        
        cursor.execute(query)
        discounts = cursor.fetchall()
        
        result = []
        if discounts:
            cols = [desc[0] for desc in cursor.description]
            
            for discount in discounts:
                discount_dict = dict(zip(cols, discount))
                
                # Convert decimal values to float for JSON serialization
                for key in ['value']:
                    if key in discount_dict and discount_dict[key] is not None:
                        discount_dict[key] = float(discount_dict[key])
                
                # Convert dates to string
                for key in ['start_date', 'end_date', 'created_at', 'updated_at']:
                    if key in discount_dict and discount_dict[key] is not None:
                        discount_dict[key] = discount_dict[key].isoformat()
                
                result.append(discount_dict)
        
        return result
    except Exception as e:
        logger.error(f"Error in get_all_discounts: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def get_active_discounts():
    """Get all active discounts that are currently valid."""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor()
        
        # Get only active discounts that are either:
        # 1. Not time-limited (start_date and end_date are null)
        # 2. Currently within the valid date range
        query = """
        SELECT discount_id, name, description, type, value, code,
               start_date, end_date, status,
               created_at, updated_at
        FROM discounts
        WHERE status = 'active'
        AND (
            (start_date IS NULL AND end_date IS NULL) OR
            (start_date IS NULL AND end_date >= CURRENT_DATE) OR
            (end_date IS NULL AND start_date <= CURRENT_DATE) OR
            (start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE)
        )
        ORDER BY name;
        """
        
        cursor.execute(query)
        discounts = cursor.fetchall()
        
        result = []
        if discounts:
            cols = [desc[0] for desc in cursor.description]
            
            for discount in discounts:
                discount_dict = dict(zip(cols, discount))
                
                # Convert decimal values to float for JSON serialization
                for key in ['value']:
                    if key in discount_dict and discount_dict[key] is not None:
                        discount_dict[key] = float(discount_dict[key])
                
                # Convert dates to string
                for key in ['start_date', 'end_date', 'created_at', 'updated_at']:
                    if key in discount_dict and discount_dict[key] is not None:
                        discount_dict[key] = discount_dict[key].isoformat()
                
                result.append(discount_dict)
        
        return result
    except Exception as e:
        logger.error(f"Error in get_active_discounts: {e}")
        raise
    finally:
        if 'conn' in locals() and conn:
            conn.close()

def get_inactive_discounts():
    conn = None
    cursor = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT discount_id, name, description, type, value,
                   start_date, end_date, status,
                   created_at, updated_at
            FROM discounts
            WHERE status = 'inactive'
            ORDER BY name
        """)
        
        discounts = []
        for row in cursor.fetchall():
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
        
        return discounts
        
    except Exception as e:
        logger.error(f"Database error in get_inactive_discounts: {str(e)}")
        raise
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

def update_wishlist_venue_status(wishlist_venue_id, status):
    """Update the status of a venue in the wishlist_venues table"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # Check if the venue exists and get its current status
        cursor.execute("""
            SELECT status, has_been_updated 
            FROM wishlist_venues 
            WHERE wishlist_venue_id = %s
        """, (wishlist_venue_id,))
        result = cursor.fetchone()
        
        if not result:
            return False, "Venue not found"
            
        current_status, has_been_updated = result
        
        # If already updated once and trying to change from an approved/rejected state, prevent update
        if has_been_updated and (current_status.lower() in ['approved', 'rejected']):
            return False, "This venue's status cannot be changed once approved or rejected"
            
        # Update the status and mark as updated
        cursor.execute("""
            UPDATE wishlist_venues 
            SET status = %s, 
                has_been_updated = CASE 
                    WHEN LOWER(%s) IN ('approved', 'rejected') THEN TRUE 
                    ELSE has_been_updated 
                END 
            WHERE wishlist_venue_id = %s
        """, (status, status, wishlist_venue_id))
            
        conn.commit()
        return True, "Status updated successfully"
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating venue status: {str(e)}")
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def get_wishlist_venues(wishlist_id):
    """Get all venues for a specific wishlist"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                wv.wishlist_venue_id, wv.venue_id, wv.price, wv.status,
                v.venue_name, v.location, v.description, v.venue_capacity
            FROM wishlist_venues wv
            JOIN venues v ON wv.venue_id = v.venue_id
            WHERE wv.wishlist_id = %s
        """, (wishlist_id,))
        
        venues = cursor.fetchall()
        return [{
            'wishlist_venue_id': wv[0],
            'venue_id': wv[1],
            'price': float(wv[2]) if wv[2] else 0,
            'status': wv[3],
            'venue_name': wv[4],
            'location': wv[5],
            'description': wv[6],
            'venue_capacity': wv[7]
        } for wv in venues]
    except Exception as e:
        logger.error(f"Error getting wishlist venues: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_venues():
    """Get all active venues from the database"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT venue_id, venue_name, location, venue_price, description, venue_capacity, image FROM venues WHERE status = 'Active' ORDER BY venue_id DESC"
        )
        venues = cursor.fetchall()
        
        # Convert to list of dictionaries
        venues_list = []
        for venue in venues:
            venues_list.append({
                'venue_id': venue[0],
                'venue_name': venue[1],
                'location': venue[2],
                'venue_price': float(venue[3]) if venue[3] else 0,
                'description': venue[4],
                'venue_capacity': venue[5],
                'image': venue[6]
            })
        return venues_list
    finally:
        cursor.close()
        conn.close()

def get_inactive_event_packages():
    """Get all inactive event packages with their details"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT 
                p.package_id,
                p.package_name,
                p.capacity,
                p.description,
                p.venue_id,
                p.gown_package_id,
                p.additional_capacity_charges,
                p.charge_unit,
                p.total_price,
                p.status,
                p.event_type_id,
                v.venue_name,
                v.location,
                v.venue_price,
                et.event_type_name,
                gp.gown_package_name,
                gp.gown_package_price
            FROM event_packages p
            LEFT JOIN venues v ON p.venue_id = v.venue_id
            LEFT JOIN event_type et ON p.event_type_id = et.event_type_id
            LEFT JOIN gown_package gp ON p.gown_package_id = gp.gown_package_id
            WHERE p.status = 'Inactive'
            ORDER BY p.package_id DESC
        """)
        
        packages = cursor.fetchall()
        
        # Transform into list of dictionaries
        result = []
        for pkg in packages:
            package_dict = {
                'package_id': pkg[0],
                'package_name': pkg[1],
                'capacity': pkg[2],
                'description': pkg[3],
                'venue_id': pkg[4],
                'gown_package_id': pkg[5],
                'additional_capacity_charges': float(pkg[6]) if pkg[6] else 0,
                'charge_unit': pkg[7],
                'total_price': float(pkg[8]) if pkg[8] else 0,
                'status': pkg[9],
                'event_type_id': pkg[10],
                'venue_name': pkg[11],
                'location': pkg[12],
                'venue_price': float(pkg[13]) if pkg[13] else 0,
                'event_type_name': pkg[14],
                'gown_package_name': pkg[15],
                'gown_package_price': float(pkg[16]) if pkg[16] else 0
            }
            
            # Get suppliers for this package through configurations
            cursor.execute("""
                SELECT DISTINCT s.supplier_id, u.firstname, u.lastname, s.service, 
                       COALESCE(eps.modified_price, eps.original_price, s.price) as effective_price
                FROM event_package_configurations epc
                JOIN event_package_suppliers eps ON eps.config_id = epc.config_id
                JOIN suppliers s ON s.supplier_id = eps.supplier_id
                JOIN users u ON s.userid = u.userid
                WHERE epc.package_id = %s
                  AND eps.is_removed = false
            """, (pkg[0],))
            
            suppliers = cursor.fetchall()
            package_dict['suppliers'] = [
                {
                    'supplier_id': s[0],
                    'name': f"{s[1]} {s[2]}",
                    'service': s[3],
                    'price': float(s[4]) if s[4] else 0
                } for s in suppliers
            ]
            
            # Get additional services for this package
            cursor.execute("""
                SELECT a.add_service_id, a.add_service_name, a.add_service_price
                FROM event_package_additional_services epas
                JOIN additional_services a ON a.add_service_id = epas.add_service_id
                WHERE epas.package_id = %s
            """, (pkg[0],))
            
            services = cursor.fetchall()
            package_dict['additional_services'] = [
                {
                    'service_id': s[0],
                    'name': s[1],
                    'price': float(s[2]) if s[2] else 0
                } for s in services
            ]
            
            result.append(package_dict)
            
        return result
    except Exception as e:
        logger.error(f"Error fetching inactive packages: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def toggle_event_package_status(package_id):
    """Toggle the status of an event package between Active and Inactive"""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        # First check if the package exists
        cursor.execute("SELECT status FROM event_packages WHERE package_id = %s", (package_id,))
        result = cursor.fetchone()
        if not result:
            logger.error(f"No package found with id {package_id}")
            raise Exception(f"No package found with id {package_id}")
            
        current_status = result[0] or 'Active'  # Default to Active if None
        logger.info(f"Current status for package {package_id}: {current_status}")
        
        # Toggle the status
        new_status = 'Inactive' if current_status == 'Active' else 'Active'
        logger.info(f"New status will be: {new_status}")
        
        cursor.execute("""
            UPDATE event_packages 
            SET status = %s 
            WHERE package_id = %s
            RETURNING package_id
        """, (new_status, package_id))
        
        updated = cursor.fetchone()
        conn.commit()
        
        if updated:
            logger.info(f"Successfully updated package {package_id} status to {new_status}")
            return True, new_status
        else:
            logger.error(f"Failed to update package {package_id}")
            return False, current_status
            
    except Exception as e:
        conn.rollback()
        logger.error(f"Error toggling event package status: {str(e)}")
        raise
    finally:
        cursor.close()
        conn.close()

def update_outfit(outfit_data):
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Update outfit data
        cursor.execute("""
            UPDATE outfits
            SET outfit_name = %(outfit_name)s,
                outfit_type = %(outfit_type)s,
                outfit_color = %(outfit_color)s,
                outfit_desc = %(outfit_desc)s,
                rent_price = %(rent_price)s,
                status = %(status)s,
                size = %(size)s,
                weight = %(weight)s
            WHERE outfit_id = %(outfit_id)s
        """, {
            'outfit_id': outfit_data.get('outfit_id'),
            'outfit_name': outfit_data.get('outfit_name'),
            'outfit_type': outfit_data.get('outfit_type'),
            'outfit_color': outfit_data.get('outfit_color'),
            'outfit_desc': outfit_data.get('outfit_desc'),
            'rent_price': float(outfit_data.get('rent_price', 0)),
            'status': outfit_data.get('status', 'Available'),
            'size': outfit_data.get('size'),
            'weight': float(outfit_data.get('weight', 0))
        })
        
        # Update outfit image if provided
        if 'outfit_img' in outfit_data and outfit_data['outfit_img']:
            cursor.execute("""
                UPDATE outfits
                SET outfit_img = %(outfit_img)s
                WHERE outfit_id = %(outfit_id)s
            """, {
                'outfit_id': outfit_data.get('outfit_id'),
                'outfit_img': outfit_data.get('outfit_img')
            })
        
        # Update archive entry if provided
        if 'archive' in outfit_data and outfit_data['archive']:
            archive_data = outfit_data['archive']
            cursor.execute("""
                UPDATE outfit_archive
                SET creation_address = %(creation_address)s,
                    owner = %(owner)s
                WHERE outfit_id = %(outfit_id)s
            """, {
                'outfit_id': outfit_data.get('outfit_id'),
                'creation_address': archive_data.get('creation_address'),
                'owner': archive_data.get('owner')
            })
        
        conn.commit()
        return True, "Outfit updated successfully"
        
    except Exception as e:
        conn.rollback()
        logger.error(f"Error updating outfit: {str(e)}")
        return False, str(e)
    finally:
        cursor.close()
        conn.close()

def get_event_outfits_enhanced(events_id):
    """
    Enhanced function to fetch both individual outfits and gown packages for an event.
    Returns both types of outfits separately for easier handling.
    """
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Get individual outfits
        cursor.execute("""
            SELECT eo.event_outfit_id, eo.outfit_type, 
                   o.outfit_id, o.outfit_name, o.outfit_type as outfit_category, 
                   o.size, o.rent_price, o.outfit_img, o.outfit_color
            FROM event_outfits eo
            JOIN outfits o ON eo.outfit_id = o.outfit_id
            WHERE eo.events_id = %s AND eo.outfit_id IS NOT NULL
        """, (events_id,))
        
        individual_outfits = [{
            'event_outfit_id': outfit[0],
            'outfit_type': outfit[1],
            'outfit_id': outfit[2],
            'outfit_name': outfit[3] or f"Outfit #{outfit[2]}", # Fallback name if empty
            'outfit_category': outfit[4],
            'size': outfit[5],
            'rent_price': float(outfit[6]) if outfit[6] else 0,
            'outfit_img': outfit[7],
            'outfit_color': outfit[8],
            'type': 'individual',
            'display_name': outfit[3] or f"Outfit #{outfit[2]}" # Extra field for display
        } for outfit in cursor.fetchall()]
        
        # Get gown packages
        cursor.execute("""
            SELECT eo.event_outfit_id, eo.outfit_type, 
                   gp.gown_package_id, gp.gown_package_name, gp.gown_package_price, gp.description
            FROM event_outfits eo
            JOIN gown_package gp ON eo.gown_package_id = gp.gown_package_id
            WHERE eo.events_id = %s AND eo.gown_package_id IS NOT NULL
        """, (events_id,))
        
        gown_packages = []
        for package in cursor.fetchall():
            package_outfits = get_gown_package_outfits(package[2])
            
            gown_packages.append({
                'event_outfit_id': package[0],
                'outfit_type': package[1],
                'gown_package_id': package[2],
                'outfit_name': package[3] or f"Package #{package[2]}", # Fallback name if empty
                'gown_package_name': package[3] or f"Package #{package[2]}", # Fallback name if empty
                'rent_price': float(package[4]) if package[4] else 0, # Added for consistency
                'gown_package_price': float(package[4]) if package[4] else 0,
                'description': package[5],
                'type': 'package',
                'display_name': package[3] or f"Package #{package[2]}", # Extra field for display
                'package_outfits': package_outfits,
                'outfit_count': len(package_outfits)
            })
        
        # Combined list with proper formatting for display
        all_outfits = []
        for outfit in individual_outfits:
            all_outfits.append({
                'id': outfit['event_outfit_id'],
                'outfit_id': outfit['outfit_id'],
                'type': 'individual',
                'name': outfit['outfit_name'],
                'display_name': outfit['outfit_name'],
                'rent_price': outfit['rent_price'],
                'size': outfit['size'],
                'category': outfit['outfit_category'],
                'details': outfit
            })
            
        for package in gown_packages:
            all_outfits.append({
                'id': package['event_outfit_id'],
                'gown_package_id': package['gown_package_id'],
                'type': 'package',
                'name': package['gown_package_name'],
                'display_name': package['gown_package_name'] + f" (Package of {len(package['package_outfits'])} outfits)",
                'rent_price': package['gown_package_price'],
                'outfits_count': len(package['package_outfits']),
                'details': package
            })
        
        return {
            'individual_outfits': individual_outfits,
            'gown_packages': gown_packages,
            'all_outfits': all_outfits
        }
    except Exception as e:
        logger.error(f"Error getting event outfits: {str(e)}")
        return {
            'individual_outfits': [],
            'gown_packages': [],
            'all_outfits': []
        }
    finally:
        cursor.close()
        conn.close()

def get_gown_package_outfits(gown_package_id):
    """
    Get all outfits that belong to a specific gown package.
    """
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT o.outfit_id, o.outfit_name, o.outfit_type, o.size, 
                   o.rent_price, o.outfit_img, o.outfit_color, o.outfit_desc
            FROM gown_package_outfits gpo
            JOIN outfits o ON gpo.outfit_id = o.outfit_id
            WHERE gpo.gown_package_id = %s
        """, (gown_package_id,))
        
        return [{
            'outfit_id': outfit[0],
            'outfit_name': outfit[1],
            'outfit_type': outfit[2],
            'size': outfit[3],
            'rent_price': float(outfit[4]) if outfit[4] else 0,
            'outfit_img': outfit[5],
            'outfit_color': outfit[6],
            'outfit_desc': outfit[7]
        } for outfit in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Error getting gown package outfits: {str(e)}")
        return []
    finally:
        cursor.close()
        conn.close()

def get_user_id_by_email(email):
    """Get user ID from email."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT userid FROM users WHERE email = %s", (email,))
        result = cursor.fetchone()
        return result[0] if result else None
    except Exception as e:
        logger.error(f"Error getting user ID by email: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_profile_by_id(userid):
    """Get user profile information by user ID."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("""
            SELECT 
                userid,
                firstname,
                lastname,
                username,
                email,
                contactnumber,
                address,
                user_type,
                user_img
            FROM users 
            WHERE userid = %s
        """, (userid,))
        
        row = cursor.fetchone()
        
        if row:
            user_data = {
                'userid': row[0],
                'firstname': row[1],
                'lastname': row[2],
                'username': row[3],
                'email': row[4],
                'contactnumber': row[5],
                'address': row[6],
                'user_type': row[7].lower() if row[7] else None,
                'user_img': row[8]
            }
            
            logger.info(f"Raw user data from database: {user_data}")
            
            # If there's no profile picture, use the new default
            if not user_data['user_img']:
                user_data['user_img'] = "saved/users_profile/dummy_profile.png"
                logger.info("Using default profile picture")
            
            logger.info(f"Final user data: {user_data}")
            return user_data
            
        logger.warning(f"No user found with ID: {userid}")
        return None

    except Exception as e:
        logger.error(f"Error in get_user_profile_by_id: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def update_user_profile(userid, firstname, lastname, username, contactnumber, address):
    """Update user profile information."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute(
            """UPDATE users 
               SET firstname = %s, lastname = %s, username = %s, contactnumber = %s, address = %s
               WHERE userid = %s""",
            (firstname, lastname, username, contactnumber, address, userid)
        )
        conn.commit()
        return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Error updating user profile: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def update_user_profile_picture(userid, image_path):
    """Update user profile picture."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    
    try:
        # Log the update attempt
        logger.info(f"Updating profile picture for user {userid} with path {image_path}")
        
        cursor.execute(
            """UPDATE users 
               SET user_img = %s
               WHERE userid = %s
               RETURNING user_img""",
            (image_path, userid)
        )
        
        # Get the updated value to confirm it worked
        updated_path = cursor.fetchone()
        
        conn.commit()
        
        if updated_path:
            logger.info(f"Successfully updated profile picture for user {userid}")
            return True
        
        logger.warning(f"Failed to update profile picture: no rows updated for user {userid}")
        return False
        
    except Exception as e:
        logger.error(f"Error updating user profile picture: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()

def change_password(user_id, current_password, new_password):
    """Change user password after verifying current password."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    current_password_hash = hash_password(current_password)
    new_password_hash = hash_password(new_password)

    try:
        # First verify the current password
        cursor.execute(
            "SELECT password FROM users WHERE userid = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        
        if not user:
            return False, "User not found"
            
        if user[0] != current_password_hash:
            return False, "Current password is incorrect"
            
        # Update the password
        cursor.execute(
            "UPDATE users SET password = %s WHERE userid = %s",
            (new_password_hash, user_id)
        )
        conn.commit()
        return True, "Password changed successfully"
        
    except Exception as e:
        logger.error(f"Error in change_password: {str(e)}")
        return False, "An error occurred while changing password"
    finally:
        cursor.close()
        conn.close()

def get_user_by_email(email):
    """Get user by email."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT userid, firstname, lastname, email, password, user_type, username
            FROM users 
            WHERE email = %s
        """, (email,))
        user = cursor.fetchone()
        if user:
            return {
                'userid': user[0],
                'firstname': user[1],
                'lastname': user[2],
                'email': user[3],
                'password': user[4],
                'user_type': user[5],
                'username': user[6]
            }
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_by_username(username):
    """Get user by username."""
    conn = db.get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            SELECT userid, firstname, lastname, email, password, user_type, username
            FROM users 
            WHERE username = %s
        """, (username,))
        user = cursor.fetchone()
        if user:
            return {
                'userid': user[0],
                'firstname': user[1],
                'lastname': user[2],
                'email': user[3],
                'password': user[4],
                'user_type': user[5],
                'username': user[6]
            }
        return None
    finally:
        cursor.close()
        conn.close()

def get_event_feedback(events_id):
    """Get feedback for a specific event."""
    try:
        conn = db.get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT f.*, u.firstname, u.lastname
            FROM event_feedbacks f
            JOIN users u ON f.userid = u.userid
            WHERE f.events_id = %s
        """, (events_id,))
        
        feedback = cur.fetchone()
        
        cur.close()
        conn.close()
        
        return feedback
    except Exception as e:
        print(f"Error getting event feedback: {e}")
        return None

def get_calendar_events():
    """Get all events with their details for calendar display"""
    try:
        conn = db.get_db_connection()
        cursor = conn.cursor(cursor_factory=RealDictCursor)
        
        cursor.execute("""
            SELECT 
                event_id,
                event_type,
                schedule,
                event_name,
                event_theme,
                status
            FROM events 
            WHERE schedule >= CURRENT_DATE
            ORDER BY schedule ASC
        """)
        
        events = cursor.fetchall()
        cursor.close()
        conn.close()
        
        return events
    except Exception as e:
        print(f"Error getting calendar events: {e}")
        return None

def get_feedback_statistics():
    """Get statistics for all event feedbacks."""
    try:
        conn = db.get_db_connection()
        cur = conn.cursor()
        
        # Get count of ratings grouped by rating value
        cur.execute("""
            SELECT rating, COUNT(*) as count
            FROM event_feedbacks
            GROUP BY rating
            ORDER BY rating
        """)
        
        # Initialize counts for all ratings (1-5)
        rating_counts = {i: 0 for i in range(1, 6)}
        
        # Fill in actual counts
        for row in cur.fetchall():
            rating = row[0]
            count = row[1]
            rating_counts[rating] = count
        
        # Convert to list format for frontend
        statistics = [rating_counts[i] for i in range(1, 6)]
        
        cur.close()
        conn.close()
        
        return statistics
    except Exception as e:
        print(f"Error getting feedback statistics: {e}")
        return [0, 0, 0, 0, 0]  # Return zeros if there's an error