from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime, timedelta
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
    try:
        return User.query.get(int(user_id))
    except:
        return None

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    email_verified = db.Column(db.Boolean, default=False)
    verification_token = db.Column(db.String(100), unique=True, nullable=True)
    token_expiry = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    
    files = db.relationship('File', backref='owner', lazy=True, cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy=True, cascade='all, delete-orphan')
    ratings = db.relationship('Rating', backref='user', lazy=True, cascade='all, delete-orphan')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def get_id(self):
        return str(self.id)

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    original_filename = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_path = db.Column(db.String(500), nullable=False)
    file_size = db.Column(db.Integer, nullable=True)
    mime_type = db.Column(db.String(100), nullable=True)
    is_deleted = db.Column(db.Boolean, default=False)
    
    comments = db.relationship('Comment', backref='file', lazy=True, cascade='all, delete-orphan')
    ratings = db.relationship('Rating', backref='file', lazy=True, cascade='all, delete-orphan')

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    file_id = db.Column(db.Integer, db.ForeignKey('file.id'), nullable=False)

class Rating(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
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
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            if not email or not password:
                flash('Please fill in all fields', 'error')
                return redirect(url_for('login'))
            
            user = User.query.filter_by(email=email).first()
            
            if user is None:
                flash('Invalid email address', 'error')
                return redirect(url_for('login'))
                
            if not user.check_password(password):
                flash('Invalid password', 'error')
                return redirect(url_for('login'))
                
            if not user.email_verified:
                flash('Please verify your email before logging in', 'error')
                return redirect(url_for('login'))
            
            login_user(user, remember=True)
            flash('Logged in successfully', 'success')
            
            next_page = request.args.get('next')
            return redirect(next_page or url_for('index'))
            
        except Exception as e:
            app.logger.error(f'Login error: {str(e)}')
            flash('An error occurred during login', 'error')
            return redirect(url_for('login'))
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            username = request.form.get('username')
            password = request.form.get('password')
            confirm_password = request.form.get('confirm_password')
            
            if not all([email, username, password, confirm_password]):
                flash('Please fill in all fields', 'error')
                return redirect(url_for('register'))
            
            if password != confirm_password:
                flash('Passwords do not match', 'error')
                return redirect(url_for('register'))
                
            if User.query.filter_by(email=email).first():
                flash('Email already registered', 'error')
                return redirect(url_for('register'))
                
            if User.query.filter_by(username=username).first():
                flash('Username already taken', 'error')
                return redirect(url_for('register'))
            
            user = User(
                email=email,
                username=username,
                email_verified=False
            )
            user.set_password(password)
            
            # Generate verification token
            token = secrets.token_urlsafe(32)
            user.verification_token = token
            user.token_expiry = datetime.utcnow() + timedelta(hours=24)
            
            db.session.add(user)
            db.session.commit()
            
            # Send verification email
            verification_url = url_for('verify_email', token=token, _external=True)
            send_verification_email(user.email, verification_url)
            
            flash('Registration successful! Please check your email to verify your account.', 'success')
            return redirect(url_for('login'))
            
        except Exception as e:
            db.session.rollback()
            app.logger.error(f'Registration error: {str(e)}')
            flash('An error occurred during registration', 'error')
            return redirect(url_for('register'))
            
    return render_template('register.html')

def send_verification_email(email, verification_url):
    try:
        msg = Message('Verify your email',
                    sender=app.config['MAIL_DEFAULT_SENDER'],
                    recipients=[email])
        msg.body = f'''Please click the following link to verify your email:
{verification_url}

If you did not make this request, please ignore this email.

Best regards,
Chalo FileShare Team
'''
        mail.send(msg)
    except Exception as e:
        app.logger.error(f'Error sending verification email: {str(e)}')
        raise

@app.route('/verify-email/<token>')
def verify_email(token):
    try:
        user = User.query.filter_by(verification_token=token).first()
        
        if not user:
            flash('Invalid verification token', 'error')
            return redirect(url_for('login'))
            
        if user.token_expiry < datetime.utcnow():
            flash('Verification token has expired', 'error')
            return redirect(url_for('login'))
            
        user.email_verified = True
        user.verification_token = None
        user.token_expiry = None
        db.session.commit()
        
        flash('Email verified successfully! You can now log in.', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Email verification error: {str(e)}')
        flash('An error occurred during email verification', 'error')
        return redirect(url_for('login'))

@app.route('/resend-verification')
def resend_verification():
    try:
        email = request.args.get('email')
        if not email:
            flash('Email address is required', 'error')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email address not found', 'error')
            return redirect(url_for('login'))
            
        if user.email_verified:
            flash('Email is already verified', 'info')
            return redirect(url_for('login'))
            
        # Generate new verification token
        token = secrets.token_urlsafe(32)
        user.verification_token = token
        user.token_expiry = datetime.utcnow() + timedelta(hours=24)
        db.session.commit()
        
        # Send new verification email
        verification_url = url_for('verify_email', token=token, _external=True)
        send_verification_email(user.email, verification_url)
        
        flash('Verification email has been resent', 'success')
        return redirect(url_for('login'))
        
    except Exception as e:
        db.session.rollback()
        app.logger.error(f'Resend verification error: {str(e)}')
        flash('An error occurred while resending verification email', 'error')
        return redirect(url_for('login'))

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
                email_verified=True
            )
            admin.set_password('chalo')
            admin.is_admin = True
            db.session.add(admin)
            db.session.commit()
            print("Admin user 'charles' created successfully!")
    
    # Use environment variables for production settings
    port = int(os.environ.get('PORT', 8080))
    debug = os.environ.get('FLASK_DEBUG', 'False') == 'True'
    app.run(host='0.0.0.0', port=port, debug=debug)
