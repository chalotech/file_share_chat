from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime
import os
import secrets
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

# Set up base directory
if 'PYTHONANYWHERE_DOMAIN' in os.environ:
    BASE_DIR = '/home/charlestechmaster/file_share_chat'
else:
    BASE_DIR = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__)

# Debug configuration values
logger.debug(f"MAIL_USERNAME: {os.getenv('MAIL_USERNAME')}")
logger.debug(f"MAIL_DEFAULT_SENDER: {os.getenv('MAIL_DEFAULT_SENDER')}")
logger.debug(f"MAIL_PASSWORD is set: {bool(os.getenv('MAIL_PASSWORD'))}")

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(BASE_DIR, "file_share.db")}'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Email configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME', 'chalomtech4@gmail.com')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER', 'chalomtech4@gmail.com')
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_DEBUG'] = True

# Debug mail configuration
logger.debug("Mail Configuration:")
for key in ['MAIL_SERVER', 'MAIL_PORT', 'MAIL_USE_TLS', 'MAIL_USERNAME', 'MAIL_DEFAULT_SENDER', 'MAIL_DEBUG']:
    logger.debug(f"{key}: {app.config.get(key)}")

db = SQLAlchemy(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Ensure upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True)
    files = db.relationship('File', backref='owner', lazy=True)
    comments = db.relationship('Comment', backref='author', lazy=True)
    ratings = db.relationship('Rating', backref='user', lazy=True)

    def generate_verification_token(self):
        if not self.verification_token:
            self.verification_token = secrets.token_urlsafe(32)
            db.session.commit()
        return self.verification_token

    def send_verification_email(self):
        try:
            token = self.generate_verification_token()
            verification_url = url_for('verify_email', token=token, _external=True)
            
            msg = Message('Welcome to FileShare - Please Verify Your Email',
                         sender=app.config['MAIL_DEFAULT_SENDER'],
                         recipients=[self.email])
            
            msg.body = f'''Hello {self.username},
            Welcome to FileShare! We're excited to have you join our community.
            To complete your registration and access all features of FileShare, please verify your email address by clicking the link below:
            {verification_url}
            This link will expire in 24 hours for security purposes.
            If you did not create an account with FileShare, please ignore this email.
            Best regards,
            The FileShare Team
            Contact: chalomtech4@gmail.com'''
            
            msg.html = f'''
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #ddd; border-radius: 5px;">
                <h1 style="color: #2c3e50; text-align: center;">Welcome to FileShare!</h1>
                <p style="color: #34495e;">Hello {self.username},</p>
                <p style="color: #34495e;">We're excited to have you join our community.</p>
                <p style="color: #34495e;">To complete your registration and access all features of FileShare, please verify your email address by clicking the button below:</p>
                <div style="text-align: center; margin: 30px 0;">
                    <a href="{verification_url}" style="background-color: #3498db; color: white; padding: 12px 24px; text-decoration: none; border-radius: 5px; display: inline-block;">Verify Email Address</a>
                </div>
                <p style="color: #7f8c8d; font-size: 0.9em;">This link will expire in 24 hours for security purposes.</p>
                <p style="color: #7f8c8d; font-size: 0.9em;">If you did not create an account with FileShare, please ignore this email.</p>
                <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
                <div style="text-align: center; color: #7f8c8d; font-size: 0.8em;">
                    <p>Best regards,<br>The FileShare Team</p>
                    <p>Contact: chalomtech4@gmail.com</p>
                </div>
            </div>
            '''
            
            logger.debug(f"Attempting to send email to {self.email}")
            mail.send(msg)
            logger.debug("Email sent successfully")
            return True
        except Exception as e:
            logger.error(f"Error sending email: {str(e)}")
            raise

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer)  # Size in bytes
    mime_type = db.Column(db.String(100))
    is_deleted = db.Column(db.Boolean, default=False)
    
    comments = db.relationship('Comment', backref='file', lazy=True, cascade='all, delete-orphan')
    ratings = db.relationship('Rating', backref='file', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<File {self.filename}>'
    
    def get_average_rating(self):
        if not self.ratings:
            return 0
        return sum(r.value for r in self.ratings) / len(self.ratings)

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)  # 1-5 stars
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('error.html', error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return render_template('error.html', error_code=500, message="Internal server error"), 500

@app.errorhandler(403)
def forbidden_error(error):
    return render_template('error.html', error_code=403, message="Access forbidden"), 403

@app.errorhandler(401)
def unauthorized_error(error):
    return render_template('error.html', error_code=401, message="Unauthorized access"), 401

# Add logging configuration
if not app.debug:
    import logging
    from logging.handlers import RotatingFileHandler
    import os
    
    # Create logs directory if it doesn't exist
    if not os.path.exists('logs'):
        os.mkdir('logs')
    
    # Configure file handler
    file_handler = RotatingFileHandler('logs/file_share.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    
    app.logger.setLevel(logging.INFO)
    app.logger.info('FileShare startup')

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'zip', 'rar'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Routes
@app.route('/')
def index():
    if not current_user.is_authenticated:
        return render_template('welcome.html')
    files = File.query.order_by(File.upload_date.desc()).all()
    return render_template('index.html', files=files)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form.get('username')).first()
        if user and check_password_hash(user.password_hash, request.form.get('password')):
            if not user.email_verified and not user.is_admin:
                flash('Please verify your email before logging in.')
                return redirect(url_for('login'))
            
            login_user(user)
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        try:
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            
            if User.query.filter_by(username=username).first():
                flash('Username already exists')
                return redirect(url_for('register'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already registered')
                return redirect(url_for('register'))
                
            user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                email_verified=False
            )
            
            logger.debug(f"Creating new user: {username}, {email}")
            db.session.add(user)
            db.session.commit()
            logger.debug("User created successfully")
            
            try:
                user.send_verification_email()
                flash('Registration successful! Please check your email to verify your account.')
                logger.debug("Verification email sent successfully")
            except Exception as e:
                logger.error(f"Failed to send verification email: {str(e)}")
                flash('Registration successful! However, we could not send the verification email. Please try again later.')
                
            return redirect(url_for('login'))
        except Exception as e:
            logger.error(f"Registration error: {str(e)}")
            flash('An error occurred during registration. Please try again.')
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/verify-email/<token>')
def verify_email(token):
    user = User.query.filter_by(verification_token=token).first()
    if user:
        user.email_verified = True
        user.verification_token = None
        db.session.commit()
        flash('Your email has been verified! You can now log in.')
    else:
        flash('Invalid or expired verification link.')
    return redirect(url_for('login'))

@app.route('/resend-verification')
@login_required
def resend_verification():
    if current_user.email_verified:
        flash('Your email is already verified.')
        return redirect(url_for('index'))
    
    try:
        current_user.send_verification_email()
        flash('Verification email has been resent. Please check your inbox.')
    except Exception as e:
        logger.error(f"Failed to resend verification email: {str(e)}")
        flash('Could not send verification email. Please try again later.')
    
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    if not current_user.is_admin:
        flash('Only admins can upload files')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            # Check if the post request has the file part
            if 'file' not in request.files:
                flash('No file part', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            
            # If user does not select file, browser also submits an empty part without filename
            if file.filename == '':
                flash('No selected file', 'error')
                return redirect(request.url)
            
            if not allowed_file(file.filename):
                flash('File type not allowed', 'error')
                return redirect(request.url)
            
            if file and allowed_file(file.filename):
                # Secure the filename
                filename = secure_filename(file.filename)
                
                # Create uploads directory if it doesn't exist
                if not os.path.exists(app.config['UPLOAD_FOLDER']):
                    os.makedirs(app.config['UPLOAD_FOLDER'])
                
                # Save the file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                
                # Create file record in database
                new_file = File(
                    filename=filename,
                    original_filename=file.filename,
                    description=request.form.get('description'),
                    user_id=current_user.id,
                    file_path=file_path,
                    file_size=os.path.getsize(file_path),
                    mime_type=file.mimetype
                )
                db.session.add(new_file)
                db.session.commit()
                
                flash('File successfully uploaded', 'success')
                return redirect(url_for('index'))
                
        except Exception as e:
            app.logger.error(f'Error uploading file: {str(e)}')
            db.session.rollback()
            flash('Error uploading file', 'error')
            return redirect(request.url)
            
    return render_template('upload.html')

@app.route('/file/<int:file_id>', methods=['GET', 'POST'])
@login_required
def file_detail(file_id):
    file = File.query.get_or_404(file_id)
    if request.method == 'POST':
        if 'comment' in request.form:
            comment = Comment(
                content=request.form['comment'],
                user_id=current_user.id,
                file_id=file_id
            )
            db.session.add(comment)
        elif 'rating' in request.form:
            existing_rating = Rating.query.filter_by(
                user_id=current_user.id,
                file_id=file_id
            ).first()
            
            if existing_rating:
                existing_rating.value = int(request.form['rating'])
            else:
                rating = Rating(
                    value=int(request.form['rating']),
                    user_id=current_user.id,
                    file_id=file_id
                )
                db.session.add(rating)
        
        db.session.commit()
        return redirect(url_for('file_detail', file_id=file_id))
        
    return render_template('file_detail.html', file=file)

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    return send_from_directory(app.config['UPLOAD_FOLDER'], file.filename, 
                             download_name=file.original_filename)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Create admin user if it doesn't exist
        admin = User.query.filter_by(username='charles').first()
        if not admin:
            admin = User(
                username='charles',
                email='chalomtech4@gmail.com',
                password_hash=generate_password_hash('chalo'),
                is_admin=True,
                email_verified=True
            )
            db.session.add(admin)
            db.session.commit()
            print("Admin user 'charles' created successfully!")
    
    # Use environment variables for production settings
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(host='0.0.0.0', port=port, debug=debug)
