# Smail - Secure Email Management

## Setup Instructions

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure API Key (IMPORTANT!)

**Option A: Using PowerShell Script (Recommended for Windows)**
```powershell
# Edit run.ps1 and add your API key, then:
.\run.ps1
```

**Option B: Set Environment Variable Manually**

**Windows (PowerShell):**
```powershell
$env:GEMINI_API_KEY="your_api_key_here"
python app.py
```

**Windows (Command Prompt):**
```cmd
set GEMINI_API_KEY=your_api_key_here
python app.py
```

**Linux/Mac:**
```bash
export GEMINI_API_KEY="your_api_key_here"
python app.py
```

**Option C: Create .env file (Advanced)**
```bash
# Copy the example file
cp .env.example .env

# Edit .env and add your API key
# Then install python-dotenv:
pip install python-dotenv
```

### 3. Get Your Gemini API Key
1. Visit: https://makersuite.google.com/app/apikey
2. Create a new API key
3. Copy and use it in one of the methods above

### 4. Run the Application
```bash
python app.py
```

## Security Notes

⚠️ **NEVER commit your API key to GitHub!**
- The `.gitignore` file is configured to exclude `.env` and sensitive files
- Always use environment variables for secrets
- Rotate your API key if accidentally exposed

## Features

- 🛡️ **AI-Powered Phishing Detection**: Gemini AI explains security threats in plain English
- ✨ **Smart Reply**: AI-generated professional email responses
- 📧 **Gmail Integration**: Secure OAuth authentication
- 🔍 **XAI Explanations**: Understand why emails are flagged

## Support

For issues or questions, check the walkthrough.md in the artifacts directory.
