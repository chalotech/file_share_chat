# FileShare Chat Platform

A secure file sharing and chat platform built with Flask, featuring user authentication, file management, and real-time discussions.

## Features

- User Authentication with Email Verification
- File Upload and Management
- File Rating System
- Commenting System
- Admin Dashboard
- Responsive Design
- Secure File Handling

## Live Demo

Visit the live application at: https://charlestechmaster.pythonanywhere.com

## Tech Stack

- Python 3.8+
- Flask Framework
- SQLAlchemy
- Flask-Login for Authentication
- Flask-Mail for Email Verification
- Bootstrap 5 for UI
- SQLite Database

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/file_share_chat.git
cd file_share_chat
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Linux/Mac
# or
venv\Scripts\activate  # On Windows
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables in .env file:
```
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-specific-password
MAIL_DEFAULT_SENDER=your-email@gmail.com
```

5. Initialize the database:
```bash
python init_db.py
```

6. Run the application:
```bash
python app.py
```

7. Access the application at `http://localhost:8080`

## Default Admin Account

- Username: charles
- Password: chalo
- Email: chalomtech4@gmail.com

## Project Structure

```
file_share_chat/
├── app.py              # Main application file
├── init_db.py         # Database initialization
├── requirements.txt   # Python dependencies
├── static/           # Static files (CSS, JS)
├── templates/        # HTML templates
└── uploads/         # File upload directory
```

## Contributing

1. Fork the repository
2. Create a new branch
3. Make your changes
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

- Developer: Charles
- Email: chalomtech4@gmail.com
- Website: https://charlestechmaster.pythonanywhere.com
