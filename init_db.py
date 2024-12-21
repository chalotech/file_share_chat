from app import app, db, User
from werkzeug.security import generate_password_hash

def init_db():
    with app.app_context():
        # Drop all tables
        db.drop_all()
        
        # Create all tables
        db.create_all()
        
        # Create admin user
        admin = User(
            username='charles',
            email='admin@example.com',
            password_hash=generate_password_hash('chalo'),
            is_admin=True,
            email_verified=True
        )
        
        db.session.add(admin)
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
