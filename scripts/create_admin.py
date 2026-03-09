import argparse
import os
import sys
from datetime import datetime

# Add the project root to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db, User, get_eat_now

def create_admin(username, email, password):
    """Creates a new admin user."""
    with app.app_context():
        try:
            # Check if an admin user already exists
            admin_exists = db.session.execute(
                db.select(User).filter_by(role='admin')
            ).scalar()

            if admin_exists:
                print("An admin user already exists.")
                return

            admin = User(
                username=username,
                email=email,
                role='admin',
                is_active=True,
                created_at=get_eat_now()
            )
            admin.set_password(password)
            db.session.add(admin)
            db.session.commit()
            print(f"Admin user '{username}' created successfully.")

        except Exception as e:
            db.session.rollback()
            print(f"Error creating admin user: {str(e)}")

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Create a new admin user.')
    parser.add_argument('username', type=str, help='The username for the admin user.')
    parser.add_argument('email', type=str, help='The email for the admin user.')
    parser.add_argument('password', type=str, help='The password for the admin user.')

    args = parser.parse_args()

    create_admin(args.username, args.email, args.password)
