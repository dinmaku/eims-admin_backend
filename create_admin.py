from app.db import get_db_connection
from app.models import create_user

def create_admin_account():
    # Admin account details - you can modify these as needed
    admin_details = {
        'first_name': 'Admin',
        'last_name': 'User',
        'username': 'admin',
        'email': 'admin@example.com',
        'contact_number': '1234567890',
        'password': 'admin',  # Make sure to change this to a secure password
        'user_type': 'Admin',
        'address': 'Admin Address'
    }
    
    success, user_id, error = create_user(
        first_name=admin_details['first_name'],
        last_name=admin_details['last_name'],
        username=admin_details['username'],
        email=admin_details['email'],
        contact_number=admin_details['contact_number'],
        password=admin_details['password'],
        user_type=admin_details['user_type'],
        address=admin_details['address']
    )
    
    if success:
        print(f"Admin account created successfully! User ID: {user_id}")
        print("You can now login with:")
        print(f"Email: {admin_details['email']}")
        print(f"Password: {admin_details['password']}")
    else:
        print(f"Failed to create admin account. Error: {error}")

if __name__ == "__main__":
    create_admin_account()