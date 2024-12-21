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
            email='chalomtech4@gmail.com',
            is_admin=True,
            email_verified=True
        )
        admin.set_password('chalo')
        
        db.session.add(admin)
        db.session.commit()
        print("Database initialized successfully!")

if __name__ == '__main__':
    init_db()
