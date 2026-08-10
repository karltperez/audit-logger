# Deployment Guide - Internal Audit Tracker

## 🚀 Production Deployment

### Prerequisites
- Python 3.8 or higher
- Git
- Web server (Apache/Nginx) or cloud platform
- Domain name (optional but recommended)

### Quick Deployment

#### Option 1: Local/Server Deployment

1. **Clone the repository:**
```bash
git clone https://github.com/macximum12/audit-logger.git
cd audit-logger
```

2. **Create virtual environment:**
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Set environment variables:**
```bash
# Windows:
set SECRET_KEY=your-secret-key-here
set FLASK_ENV=production

# Linux/Mac:
export SECRET_KEY=your-secret-key-here
export FLASK_ENV=production
```

5. **Run the application:**
```bash
python main.py
```

#### Option 2: Cloud Deployment (Heroku)

1. **Install Heroku CLI and login**
2. **Create Heroku app:**
```bash
heroku create your-app-name
```

3. **Add Procfile:**
```bash
echo "web: python main.py" > Procfile
```

4. **Deploy:**
```bash
git add Procfile
git commit -m "Add Procfile for Heroku"
git push heroku main
```

#### Option 3: Cloud Deployment (Railway/Render)

1. **Connect GitHub repository to Railway/Render**
2. **Set environment variables in dashboard:**
   - `SECRET_KEY`: Generate a secure secret key
   - `PORT`: 5000 (Railway auto-detects)
3. **Deploy automatically on push**

### 🔐 Security Configuration

#### 1. Change Default Credentials
```python
# First login after deployment:
Username: admin
Password: admin123
# IMMEDIATELY change this password!
```

#### 2. Environment Variables
```bash
SECRET_KEY=your-super-secret-key-here-minimum-32-characters
DATABASE_URL=sqlite:///audit_findings.db
FLASK_ENV=production
```

#### 3. Database Security
- The SQLite database will be created automatically
- Ensure proper file permissions in production
- Consider PostgreSQL for multi-user production environments

### 📁 File Structure After Deployment
```
audit-logger/
├── main.py                 # Flask application
├── requirements.txt        # Dependencies
├── README.md              # Documentation
├── DEPLOYMENT.md          # This file
├── .gitignore            # Git ignore rules
├── Procfile              # For Heroku (if needed)
├── static/               # Static assets
│   ├── css/
│   │   └── style.css     # Custom styles
│   └── js/
│       └── theme.js      # Persistent theme controls
├── templates/            # HTML templates
│   ├── base.html
│   ├── index.html
│   ├── login.html
│   ├── add_finding.html
│   ├── edit_finding.html
│   ├── findings.html
│   ├── import.html
│   ├── activity_logs.html
│   ├── settings.html
│   ├── force_password_change.html
│   └── admin/           # User management templates
└── audit_findings.db    # Database (auto-created)
```

### 🔧 Configuration Options

#### Application Settings (in main.py)
```python
# Session timeout (default: 30 minutes)
app.permanent_session_lifetime = timedelta(minutes=30)

# Password requirements
PASSWORD_MIN_LENGTH = 12
PASSWORD_EXPIRY_DAYS = 90
MAX_LOGIN_ATTEMPTS = 5
```

#### Security Features
- ✅ Session management with timeout
- ✅ Password complexity requirements
- ✅ Account lockout protection
- ✅ CSRF protection
- ✅ Admin exception handling
- ✅ Audit logging
- ✅ Role-based access control

### 🎯 Access Levels After Deployment

| Role | Permissions |
|------|-------------|
| **Administrator** | Full access: user management, system settings, all features |
| **Content Manager** | Add/edit/delete findings, activity logs, content management |
| **Contributor** | Add/edit findings, limited content creation |
| **Viewer** | View-only access, basic reporting |

### 🔍 Post-Deployment Checklist

#### Immediate Tasks (First 24 hours)
- [ ] Change default admin password
- [ ] Create additional admin user
- [ ] Test all user roles and permissions
- [ ] Verify database creation and functionality
- [ ] Test finding creation, editing, and deletion
- [ ] Test Excel import functionality
- [ ] Verify session timeout works
- [ ] Check activity logging

#### Security Verification
- [ ] Confirm admin exception works for 'admin' user
- [ ] Test password complexity enforcement
- [ ] Verify account lockout after failed attempts
- [ ] Test first-login password change requirement
- [ ] Confirm session security and timeout

#### Functionality Testing
- [ ] Add/edit/delete findings
- [ ] Import Excel files
- [ ] User management (admin only)
- [ ] Activity logs access
- [ ] Role-based access restrictions
- [ ] Responsive UI on mobile/tablet

### 🆘 Troubleshooting

#### Common Issues

**1. ModuleNotFoundError: No module named 'flask_limiter':**
```bash
# Ensure you have the latest requirements.txt and install all dependencies
pip install -r requirements.txt
# Or install flask-limiter specifically:
pip install Flask-Limiter==3.5.0
```

**2. Database doesn't exist:**
**2. Database doesn't exist:**
```bash
# The database will auto-create on first run
# If issues persist, delete audit_findings.db and restart
```

**3. Static files not loading:**
```bash
# Ensure static/ folder exists with css/ and js/ subdirectories
# The application includes custom CSS and JavaScript files
# Verify file permissions and web server configuration
```

**4. Admin lockout:**
**4. Admin lockout:**
```bash
# Admin user is exempt from first-login password change
# Use admin/admin123 to regain access
```

**5. Import errors:**
**5. Import errors:**
```bash
# Ensure Excel file has correct column headers
# Check file permissions and format
```

**6. Permission denied errors:**
```bash
# Check file permissions on database
chmod 666 audit_findings.db  # Linux/Mac
```

### 📞 Support

For deployment issues:
1. Check application logs
2. Verify all dependencies installed
3. Confirm environment variables set
4. Test database connectivity
5. Review security settings

### 🔄 Updates and Maintenance

#### Updating the Application
```bash
git pull origin main
pip install -r requirements.txt
# Restart the application
```

#### Database Backup (Production)
```bash
# SQLite backup
cp audit_findings.db audit_findings_backup_$(date +%Y%m%d).db
```

#### Log Management
- Application logs are printed to console
- Consider log rotation in production
- Monitor for security events and failed logins

---

**🎉 Deployment Complete!**

Your Internal Audit Tracker is now live at: https://github.com/macximum12/audit-logger

Default access: `admin` / `admin123` (change immediately!)
