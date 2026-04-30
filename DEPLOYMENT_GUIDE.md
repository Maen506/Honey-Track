# HoneyTrack Deployment Guide

## Option 1: Replit (Easiest - Free)

### Steps:
1. Go to https://replit.com
2. Click "Create" → "Import from GitHub"
3. Paste: `https://github.com/Maen506/Honey-Track.git`
4. Click "Import"
5. Replit will automatically detect Python and install dependencies
6. Click "Run" button
7. **Your app will be live at:** `https://[your-replit-name].replit.dev`

### Features:
- ✅ Free hosting
- ✅ Automatic deployment
- ✅ Public URL
- ✅ 15 minutes free per month
- ✅ Easy to share

---

## Option 2: Railway.app (Better - $5/month free tier)

### Steps:
1. Go to https://railway.app
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your HoneyTrack repository
5. Railway will auto-detect and deploy
6. **Your app will be live at:** `https://[project-name].up.railway.app`

### Environment Variables:
```
DB_HOST=your_db_host
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_NAME=honeypot_db
VIRUSTOTAL_API_KEY=your_api_key
FLASK_ENV=production
```

### Features:
- ✅ $5/month free tier
- ✅ Better performance
- ✅ Automatic HTTPS
- ✅ Database support
- ✅ Monitoring

---

## Option 3: Docker (Local or Any Server)

### Build:
```bash
docker build -t honeytrack .
```

### Run:
```bash
docker run -p 5000:5000 \
  -e DB_HOST=localhost \
  -e DB_USER=root \
  -e DB_PASSWORD=password \
  -e VIRUSTOTAL_API_KEY=your_key \
  honeytrack
```

### Access:
```
http://localhost:5000
```

---

## Option 4: Heroku (Paid - $7/month)

### Steps:
1. Install Heroku CLI
2. Login: `heroku login`
3. Create app: `heroku create your-app-name`
4. Set environment variables:
   ```bash
   heroku config:set DB_HOST=your_db
   heroku config:set VIRUSTOTAL_API_KEY=your_key
   ```
5. Deploy: `git push heroku main`

---

## Dashboard Access

After deployment, access the interactive dashboard:

```
https://[your-deployment-url]/app/dashboard.html
```

### Features:
- 📊 Real-time statistics
- 🔴 Attack monitoring
- ⚠️ Security alerts
- 🤖 ML analysis
- 🦠 VirusTotal reports
- ⚙️ System settings

---

## Troubleshooting

### "Connection refused"
- Check if database is running
- Verify DB credentials in `.env`
- Run: `python validate_env.py`

### "Module not found"
- Install dependencies: `pip install -r requirements.txt`
- Check Python version: `python --version` (should be 3.8+)

### "Port already in use"
- Change port in `main.py` line 289
- Or kill process: `lsof -i :5000` then `kill -9 [PID]`

### "Dashboard not loading"
- Check browser console (F12)
- Verify API endpoints are running
- Test: `curl http://localhost:5000/api/health`

---

## Recommended Setup

**For Development:**
- Use Replit (free, easy)
- Or Docker locally

**For Production:**
- Use Railway.app ($5/month)
- Or Docker on VPS

**For Demo/Presentation:**
- Use Replit (easiest to share)
- Public URL ready to go

---

## Quick Start Commands

```bash
# Clone
git clone https://github.com/Maen506/Honey-Track.git
cd Honey-Track

# Setup
cp .env.example .env
nano .env  # Edit your credentials

# Validate
python validate_env.py

# Initialize database
python setup_db.py

# Run
python main.py

# Access
# http://localhost:5000/app/dashboard.html
```

---

## Environment Variables

```env
# Database
DB_HOST=localhost
DB_PORT=3306
DB_USER=honeypot_user
DB_PASSWORD=secure_password
DB_NAME=honeypot_db

# VirusTotal
VIRUSTOTAL_API_KEY=your_api_key_here
VIRUSTOTAL_ENABLED=True

# Flask
FLASK_ENV=production
FLASK_DEBUG=False

# Honeypots
SSH_PORT=2222
HTTP_PORT=8080

# ML
ML_ENABLED=True
ML_MODEL_PATH=ml/models

# MITRE
MITRE_ENABLED=True
```

---

## Support

For issues:
1. Check logs: `tail -f logs/honeytrack.log`
2. Test connection: `python validate_env.py`
3. Check GitHub issues
4. Review error messages carefully

---

**Happy deploying! 🚀**
