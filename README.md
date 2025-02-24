# Malware Analysis Web Application

## Overview

This repository contains a **static malware analysis** web application that uses **React** for the frontend, **FastAPI** for the backend, and **MongoDB** as the database. The backend leverages **Python scripts (YARA, pefile)** to analyze uploaded executable files for malware signatures and characteristics.

## Features

- **Upload Files:** Users can upload executable files for analysis.
- **Static Analysis:** Uses YARA rules and pefile to extract metadata and detect malicious patterns.
- **Web Interface:** React-based frontend for easy interaction.
- **FastAPI Backend:** Handles requests and communicates with analysis scripts.
- **MongoDB Storage:** Stores results and file metadata.

---

## Repository Structure

```
malware-analysis/
│-- backend/              # FastAPI backend
│   │-- main.py           # Entry point for FastAPI server
│   │-- yara_handler.py   # Handles YARA scanning
│   │-- database.py       # MongoDB connection and models
│   │-- .env              # Environment variables (ignored in Git)
│   │-- rules/            # YARA rules folder
│   │   │-- malware_rules.yar  # YARA rule definitions
│-- frontend/             # React frontend
│   │-- src/              # Source files
│   │   │-- App.js        # Main React application
│   │   │-- style.css     # Stylesheet
│   │   │-- assist/       # Assist folder containing React components
│   │-- public/           # Public assets
│   │-- README.md         # Frontend-specific documentation
│-- database/             # MongoDB configuration
│-- .gitignore            # Files to exclude from Git tracking
│-- README.md             # Project documentation
│-- LICENSE               # Project license
```

---

## Code Summary

### **Backend (FastAPI & Python)**

- **`main.py`** - Entry point for FastAPI, defines API routes.
- **`yara_handler.py`** - Uses YARA rules to scan uploaded files for malware signatures.
- **`database.py`** - Connects to MongoDB and manages file metadata storage.
- **`rules/malware_rules.yar`** - Contains YARA rules for identifying malware patterns.

### **Frontend (React & JavaScript)**

- **`App.js`** - Main React component handling UI and API interactions.
- **`style.css`** - Styles for the frontend.
- **`assist/`** - Contains helper React components for UI structure.

---

## Installation & Setup

### **1. Clone the Repository**

```sh
git clone https://github.com/yourusername/malware-analysis.git
cd malware-analysis
```

### **2. Backend Setup (FastAPI & Python)**

#### **Create and activate a virtual environment**

```sh
python -m venv venv
source venv/bin/activate   # On macOS/Linux
source venv/scripts/activate      # On Windows
```

#### **Install dependencies**

```sh
pip install -r backend/requirements.txt
```

#### **Run the FastAPI server**

```sh
cd backend
uvicorn main:app --reload
```

### **3. Frontend Setup (React)**

```sh
cd frontend
npm install
npm run dev
```

### **4. MongoDB Setup**

Ensure MongoDB is running locally or via a cloud service like MongoDB Atlas. Update the database connection string in `backend/.env`.

---

## Usage

1. **Start the backend and frontend** as mentioned above.
2. **Access the application** in your browser at `http://localhost:5137`.
3. **Upload a file** and view analysis results.

---

## API Endpoints

| Method | Endpoint   | Description                    |
| ------ | ---------- | ------------------------------ |
| POST   | `/upload`  | Uploads a file for analysis    |
| GET    | `/results` | Fetches previous analysis data |
| GET    | `/status`  | Checks API health              |

---

## Contributions

Feel free to open issues and submit pull requests to improve the project.

---

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.
