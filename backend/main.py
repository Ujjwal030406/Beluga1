# main.py
from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import hashlib
import shutil
import asyncio
from datetime import datetime
from typing import List, Dict
from pydantic import BaseModel
from database import init_db, db
from yara_handler import YaraHandler
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    filename='malware_analysis.log'
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()

class AnalysisResponse(BaseModel):
    file_name: str
    hash: str
    file_size: int
    timestamp: datetime
    status: str
    risk_level: str
    indicators: List[str]
    yara_matches: List[Dict]
    recommendations: str

app = FastAPI(title="Malware Analysis API")

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Temporarily allow all origins for debugging
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables
UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys','.bat'}

# Initialize handlers
yara_handler = None

def validate_file(file: UploadFile) -> None:
    """Validate file size and type."""
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
        )

async def cleanup_old_files():
    """Clean up files older than 1 hour."""
    while True:
        try:
            for file in os.listdir(UPLOAD_DIR):
                file_path = os.path.join(UPLOAD_DIR, file)
                if os.path.getctime(file_path) > 3600:
                    os.remove(file_path)
            await asyncio.sleep(3600)
        except Exception as e:
            logger.error(f"Error in cleanup task: {str(e)}")
            await asyncio.sleep(3600)

@app.on_event("startup")
async def startup():
    global yara_handler
    try:
        await init_db()
        yara_handler = YaraHandler()
        os.makedirs(UPLOAD_DIR, exist_ok=True)
        asyncio.create_task(cleanup_old_files())
        logger.info("Application started successfully")
    except Exception as e:
        logger.error(f"Startup failed: {str(e)}")
        raise

def get_file_indicators(yara_results: Dict) -> List[str]:
    indicators = []
    for match in yara_results.get("matches", []):
        if match.get("meta", {}).get("description"):
            indicators.append(match["meta"]["description"])
    return indicators

def get_recommendations(risk_level: str, indicators: List[str]) -> str:
    if risk_level == "high":
        return "This file shows strong indicators of malicious behavior. Do not execute it and consider reporting it to your security team."
    elif risk_level == "medium":
        return "This file shows some suspicious characteristics. Exercise caution and verify its source before execution."
    elif risk_level == "low":
        return "While no major threats were detected, always verify files from unknown sources before execution."
    return "No significant threats detected. Follow standard security practices when executing files."

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    file_path = None
    try:
        validate_file(file)
        file_path = os.path.join(UPLOAD_DIR, file.filename)
        with open(file_path, "wb") as f:
            shutil.copyfileobj(file.file, f)
        if not os.path.exists(file_path):
            raise HTTPException(status_code=500, detail="File was not saved correctly")
        file_size = os.path.getsize(file_path)
        logger.info(f"File {file.filename} saved successfully, Size: {file_size} bytes")
        with open(file_path, "rb") as f:
            file_data = f.read()
            file_hash = hashlib.sha256(file_data).hexdigest()
        cached_analysis = await db.analyses.find_one({"hash": file_hash})
        if cached_analysis:
            os.remove(file_path)
            cached_analysis["_id"] = str(cached_analysis["_id"])
            return AnalysisResponse(**cached_analysis)
        yara_results = yara_handler.scan_file(file_path)
        logger.info(f"YARA scan completed for {file.filename}: {yara_results}")
        risk_level = yara_results["summary"]["risk_level"]
        indicators = get_file_indicators(yara_results)
        analysis_result = {
            "file_name": file.filename,
            "hash": file_hash,
            "file_size": file_size,
            "timestamp": datetime.now(),
            "status": "completed",
            "risk_level": risk_level,
            "indicators": indicators,
            "yara_matches": yara_results["matches"],
            "recommendations": get_recommendations(risk_level, indicators)
        
        }
        await db.analyses.insert_one(analysis_result)
        background_tasks.add_task(os.remove, file_path)
        logger.info(f"Successfully analyzed file: {file.filename}")
        return AnalysisResponse(**analysis_result)
    except Exception as e:
        logger.error(f"Error analyzing file: {str(e)}")
        if file_path and os.path.exists(file_path):
            os.remove(file_path)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analysis-history")
async def get_analysis_history():
    try:
        cursor = db.analyses.find().sort("timestamp", -1).limit(100)
        analyses = await cursor.to_list(length=100)
        return [{**analysis, "_id": str(analysis["_id"])} for analysis in analyses]
    except Exception as e:
        logger.error(f"Error retrieving analysis history: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/health")
async def health_check():
    try:
        await db.command("ping")
        return {"status": "healthy"}
    except Exception as e:
        raise HTTPException(status_code=503, detail="Service unhealthy")


# # main.py
# from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
# from fastapi.middleware.cors import CORSMiddleware
# from motor.motor_asyncio import AsyncIOMotorClient
# from dotenv import load_dotenv
# import os
# import hashlib
# import shutil
# import asyncio
# from datetime import datetime
# from typing import List, Dict
# from pydantic import BaseModel
# from database import init_db, db
# from yara_handler import YaraHandler
# import logging

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     filename='malware_analysis.log'
# )
# logger = logging.getLogger(__name__)

# # Load environment variables
# load_dotenv()

# class AnalysisResponse(BaseModel):
#     file_name: str
#     hash: str
#     timestamp: datetime
#     status: str
#     risk_level: str
#     indicators: List[str]
#     yara_matches: List[Dict]
#     recommendations: str

# app = FastAPI(title="Malware Analysis API")

# # CORS configuration
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Global variables
# UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")
# MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
# ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys','.bat'}

# # Initialize handlers
# yara_handler = None

# def validate_file(file: UploadFile) -> None:
#     """Validate file size and type."""
#     # Check file extension
#     file_ext = os.path.splitext(file.filename)[1].lower()
#     if file_ext not in ALLOWED_EXTENSIONS:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
#         )

# async def cleanup_old_files():
#     """Clean up files older than 1 hour."""
#     while True:
#         try:
#             for file in os.listdir(UPLOAD_DIR):
#                 file_path = os.path.join(UPLOAD_DIR, file)
#                 if os.path.getctime(file_path) > 3600:  # 1 hour
#                     os.remove(file_path)
#             await asyncio.sleep(3600)  # Check every hour
#         except Exception as e:
#             logger.error(f"Error in cleanup task: {str(e)}")
#             await asyncio.sleep(3600)

# @app.on_event("startup")
# async def startup():
#     global yara_handler
#     try:
#         # Initialize database
#         await init_db()
        
#         # Initialize YARA handler
#         yara_handler = YaraHandler()
        
#         # Create upload directory
#         os.makedirs(UPLOAD_DIR, exist_ok=True)
        
#         # Start cleanup task
#         asyncio.create_task(cleanup_old_files())
        
#         logger.info("Application started successfully")
#     except Exception as e:
#         logger.error(f"Startup failed: {str(e)}")
#         raise

# def get_file_indicators(yara_results: Dict) -> List[str]:
#     """Extract indicators from YARA results."""
#     indicators = []
#     for match in yara_results.get("matches", []):
#         if match.get("meta", {}).get("description"):
#             indicators.append(match["meta"]["description"])
#     return indicators

# def get_recommendations(risk_level: str, indicators: List[str]) -> str:
#     """Generate recommendations based on analysis."""
#     if risk_level == "high":
#         return "This file shows strong indicators of malicious behavior. Do not execute it and consider reporting it to your security team."
#     elif risk_level == "medium":
#         return "This file shows some suspicious characteristics. Exercise caution and verify its source before execution."
#     elif risk_level == "low":
#         return "While no major threats were detected, always verify files from unknown sources before execution."
#     return "No significant threats detected. Follow standard security practices when executing files."

# @app.post("/analyze", response_model=AnalysisResponse)
# async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
#     file_path = None
#     try:
#         # Validate file
#         validate_file(file)
        
#         # Create temporary file
#         file_path = os.path.join(UPLOAD_DIR, file.filename)
#         with open(file_path, "wb") as f:
#             shutil.copyfileobj(file.file, f)

#         # Check if file exists and log its size
#         if not os.path.exists(file_path):
#             raise HTTPException(status_code=500, detail="File was not saved correctly")
        
#         file_size = os.path.getsize(file_path)
#         logger.info(f"File {file.filename} saved successfully, Size: {file_size} bytes")

#         # Read file to calculate hash
#         with open(file_path, "rb") as f:
#             file_data = f.read()
#             file_hash = hashlib.sha256(file_data).hexdigest()
        
        # # Check cache
        # cached_analysis = await db.analyses.find_one({"hash": file_hash})
        # if cached_analysis:
        #     os.remove(file_path)  # Clean up
        #     cached_analysis["_id"] = str(cached_analysis["_id"])
        #     return AnalysisResponse(**cached_analysis)

        # # Perform YARA analysis
        # yara_results = yara_handler.scan_file(file_path)
        # logger.info(f"YARA scan completed for {file.filename}: {yara_results}")

        # # Extract risk level and indicators
        # risk_level = yara_results["summary"]["risk_level"]
        # indicators = get_file_indicators(yara_results)

        # # Create analysis result
        # analysis_result = {
        #     "file_name": file.filename,
        #     "hash": file_hash,
        #     "timestamp": datetime.now(),
        #     "status": "completed",
        #     "risk_level": risk_level,
        #     "indicators": indicators,
        #     "yara_matches": yara_results["matches"],
        #     "recommendations": get_recommendations(risk_level, indicators)
        # }

        # Save to database
        # await db.analyses.insert_one(analysis_result)
        
        # Schedule cleanup
#         background_tasks.add_task(os.remove, file_path)

#         logger.info(f"Successfully analyzed file: {file.filename}")
#         return AnalysisResponse(**analysis_result)

#     except Exception as e:
#         logger.error(f"Error analyzing file: {str(e)}")
#         if file_path and os.path.exists(file_path):
#             os.remove(file_path)
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/analysis-history")
# async def get_analysis_history():
#     try:
#         cursor = db.analyses.find().sort("timestamp", -1).limit(100)
#         analyses = await cursor.to_list(length=100)
#         return [
#             {**analysis, "_id": str(analysis["_id"])}
#             for analysis in analyses
#         ]
#     except Exception as e:
#         logger.error(f"Error retrieving analysis history: {str(e)}")
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/health")
# async def health_check():
#     try:
#         # Check database connection
#         await db.command("ping")
#         return {"status": "healthy"}
#     except Exception as e:
#         raise HTTPException(status_code=503, detail="Service unhealthy")



# # main.py
# from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
# from fastapi.middleware.cors import CORSMiddleware
# from motor.motor_asyncio import AsyncIOMotorClient
# from dotenv import load_dotenv
# import os
# import hashlib
# import shutil
# import asyncio
# from datetime import datetime
# from typing import List, Dict
# from pydantic import BaseModel
# from database import init_db, db
# from yara_handler import YaraHandler
# import logging

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
#     filename='malware_analysis.log'
# )
# logger = logging.getLogger(__name__)

# # Load environment variables
# load_dotenv()

# class AnalysisResponse(BaseModel):
#     file_name: str
#     hash: str
#     timestamp: datetime
#     status: str
#     risk_level: str
#     indicators: List[str]
#     yara_matches: List[Dict]
#     recommendations: str

# app = FastAPI(title="Malware Analysis API")

# # CORS configuration
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Global variables
# UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")
# MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
# ALLOWED_EXTENSIONS = {'.exe', '.dll', '.sys','.bat'}

# # Initialize handlers
# yara_handler = None

# def validate_file(file: UploadFile) -> None:
#     """Validate file size and type."""
#     # Check file extension
#     file_ext = os.path.splitext(file.filename)[1].lower()
#     if file_ext not in ALLOWED_EXTENSIONS:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}"
#         )

# async def cleanup_old_files():
#     """Clean up files older than 1 hour."""
#     while True:
#         try:
#             for file in os.listdir(UPLOAD_DIR):
#                 file_path = os.path.join(UPLOAD_DIR, file)
#                 if os.path.getctime(file_path) > 3600:  # 1 hour
#                     os.remove(file_path)
#             await asyncio.sleep(3600)  # Check every hour
#         except Exception as e:
#             logger.error(f"Error in cleanup task: {str(e)}")
#             await asyncio.sleep(3600)

# @app.on_event("startup")
# async def startup():
#     global yara_handler
#     try:
#         # Initialize database
#         await init_db()
        
#         # Initialize YARA handler
#         yara_handler = YaraHandler()
        
#         # Create upload directory
#         os.makedirs(UPLOAD_DIR, exist_ok=True)
        
#         # Start cleanup task
#         asyncio.create_task(cleanup_old_files())
        
#         logger.info("Application started successfully")
#     except Exception as e:
#         logger.error(f"Startup failed: {str(e)}")
#         raise

# def get_file_indicators(yara_results: Dict) -> List[str]:
#     """Extract indicators from YARA results."""
#     indicators = []
#     for match in yara_results.get("matches", []):
#         if match.get("meta", {}).get("description"):
#             indicators.append(match["meta"]["description"])
#     return indicators

# def get_recommendations(risk_level: str, indicators: List[str]) -> str:
#     """Generate recommendations based on analysis."""
#     if risk_level == "high":
#         return "This file shows strong indicators of malicious behavior. Do not execute it and consider reporting it to your security team."
#     elif risk_level == "medium":
#         return "This file shows some suspicious characteristics. Exercise caution and verify its source before execution."
#     elif risk_level == "low":
#         return "While no major threats were detected, always verify files from unknown sources before execution."
#     return "No significant threats detected. Follow standard security practices when executing files."

# @app.post("/analyze", response_model=AnalysisResponse)
# async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
#     file_path = None
#     try:
#         # Validate file
#         validate_file(file)
        
#         # Create temporary file
#         file_path = os.path.join(UPLOAD_DIR, file.filename)
#         with open(file_path, "wb") as f:
#             shutil.copyfileobj(file.file, f)

#         # Check if file exists and log its size
#         if not os.path.exists(file_path):
#             raise HTTPException(status_code=500, detail="File was not saved correctly")
        
#         file_size = os.path.getsize(file_path)
#         logger.info(f"File {file.filename} saved successfully, Size: {file_size} bytes")

#         # Read file to calculate hash
#         with open(file_path, "rb") as f:
#             file_data = f.read()
#             file_hash = hashlib.sha256(file_data).hexdigest()
        
#         # # Check cache
#         # cached_analysis = await db.analyses.find_one({"hash": file_hash})
#         # if cached_analysis:
#         #     os.remove(file_path)  # Clean up
#         #     cached_analysis["_id"] = str(cached_analysis["_id"])
#         #     return AnalysisResponse(**cached_analysis)

#         # Perform YARA analysis
#         yara_results = yara_handler.scan_file(file_path)
#         logger.info(f"YARA scan completed for {file.filename}: {yara_results}")

#         # Extract risk level and indicators
#         risk_level = yara_results["summary"]["risk_level"]
#         indicators = get_file_indicators(yara_results)

#         # Create analysis result
#         analysis_result = {
#             "file_name": file.filename,
#             "hash": file_hash,
#             "timestamp": datetime.now(),
#             "status": "completed",
#             "risk_level": risk_level,
#             "indicators": indicators,
#             "yara_matches": yara_results["matches"],
#             "recommendations": get_recommendations(risk_level, indicators)
#         }

#         # Save to database
#         # await db.analyses.insert_one(analysis_result)
        
#         # Schedule cleanup
#         background_tasks.add_task(os.remove, file_path)

#         logger.info(f"Successfully analyzed file: {file.filename}")
#         return AnalysisResponse(**analysis_result)

#     except Exception as e:
#         logger.error(f"Error analyzing file: {str(e)}")
#         if file_path and os.path.exists(file_path):
#             os.remove(file_path)
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/analysis-history")
# async def get_analysis_history():
#     try:
#         cursor = db.analyses.find().sort("timestamp", -1).limit(100)
#         analyses = await cursor.to_list(length=100)
#         return [
#             {**analysis, "_id": str(analysis["_id"])}
#             for analysis in analyses
#         ]
#     except Exception as e:
#         logger.error(f"Error retrieving analysis history: {str(e)}")
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/health")
# async def health_check():
#     try:
#         # Check database connection
#         await db.command("ping")
#         return {"status": "healthy"}
#     except Exception as e:
#         raise HTTPException(status_code=503, detail="Service unhealthy")

# from fastapi import FastAPI, File, UploadFile, HTTPException, BackgroundTasks
# from fastapi.middleware.cors import CORSMiddleware
# from motor.motor_asyncio import AsyncIOMotorClient
# from dotenv import load_dotenv
# import os
# import hashlib
# import shutil
# import asyncio
# from datetime import datetime
# from typing import List, Dict
# from pydantic import BaseModel
# from database import init_db, db
# from yara_handler import YaraHandler
# import logging


# UPLOAD_DIR1 = "uploads"  # Directory to save uploaded files
# os.makedirs(UPLOAD_DIR1, exist_ok=True)  # Ensure the directory exists

# # Configure logging
# logging.basicConfig(
#     level=logging.INFO,
#     format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
#     filename="malware_analysis.log",
# )
# logger = logging.getLogger(__name__)

# # Load environment variables
# load_dotenv()

# class AnalysisResponse(BaseModel):
#     file_name: str
#     hash: str
#     timestamp: datetime
#     status: str
#     risk_level: str
#     indicators: List[str]
#     yara_matches: List[Dict]
#     recommendations: str

# app = FastAPI(title="Malware Analysis API")

# # CORS configuration
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins=[os.getenv("FRONTEND_URL", "http://localhost:3000")],
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

# # Global variables
# UPLOAD_DIR = os.path.join(os.path.dirname(__file__), "temp_uploads")
# MAX_FILE_SIZE = 50 * 1024 * 1024  # 50MB
# ALLOWED_EXTENSIONS = {".exe", ".dll", ".sys", ".bat"}

# # Initialize handlers
# yara_handler = None

# def validate_file(file: UploadFile) -> None:
#     """Validate file size and type."""
#     file_ext = os.path.splitext(file.filename)[1].lower()

#     # Check file extension
#     if file_ext not in ALLOWED_EXTENSIONS:
#         raise HTTPException(
#             status_code=400,
#             detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}",
#         )

#     # Check file size
#     file.file.seek(0, os.SEEK_END)  # Move cursor to end of file
#     file_size = file.file.tell()  # Get file size
#     file.file.seek(0)  # Reset cursor to beginning

#     if file_size > MAX_FILE_SIZE:
#         raise HTTPException(
#             status_code=400,
#             detail=f"File size exceeds the allowed limit of {MAX_FILE_SIZE / (1024 * 1024)} MB",
#         )

# async def cleanup_old_files():
#     """Clean up files older than 1 hour."""
#     while True:
#         try:
#             for file in os.listdir(UPLOAD_DIR):
#                 file_path = os.path.join(UPLOAD_DIR, file)
#                 if os.path.getctime(file_path) > 3600:  # 1 hour
#                     os.remove(file_path)
#             await asyncio.sleep(3600)  # Check every hour
#         except Exception as e:
#             logger.error(f"Error in cleanup task: {str(e)}")
#             await asyncio.sleep(3600)

# @app.on_event("startup")
# async def startup():
#     global yara_handler
#     try:
#         # Initialize database
#         await init_db()
        
#         # Initialize YARA handler
#         yara_handler = YaraHandler()
        
#         # Create upload directory
#         os.makedirs(UPLOAD_DIR, exist_ok=True)
        
#         # Start cleanup task
#         asyncio.create_task(cleanup_old_files())
        
#         logger.info("Application started successfully")
#     except Exception as e:
#         logger.error(f"Startup failed: {str(e)}")
#         raise

# def get_file_indicators(yara_results: Dict) -> List[str]:
#     """Extract indicators from YARA results."""
#     indicators = []
#     for match in yara_results.get("matches", []):
#         if match.get("meta", {}).get("description"):
#             indicators.append(match["meta"]["description"])
#     return indicators

# def get_recommendations(risk_level: str, indicators: List[str]) -> str:
#     """Generate recommendations based on analysis."""
#     if risk_level == "high":
#         return "This file shows strong indicators of malicious behavior. Do not execute it and consider reporting it to your security team."
#     elif risk_level == "medium":
#         return "This file shows some suspicious characteristics. Exercise caution and verify its source before execution."
#     elif risk_level == "low":
#         return "While no major threats were detected, always verify files from unknown sources before execution."
#     return "No significant threats detected. Follow standard security practices when executing files."

# @app.post("/analyze", response_model=AnalysisResponse)
# async def analyze_file(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
#     file_path = None
#     try:
#         file_path = f"{UPLOAD_DIR1}/{file.filename}"
    
#         validate_file(file)
        
#         with open(file_path, "wb") as f:
#             shutil.copyfileobj(file.file, f)

#         # Check if file exists and log its size
#         if not os.path.exists(file_path):
#             raise HTTPException(status_code=500, detail="File was not saved correctly")
        
#         file_size = os.path.getsize(file_path)
#         logger.info(f"File {file.filename} saved successfully, Size: {file_size} bytes")

#         # Read file to calculate hash
#         with open(file_path, "rb") as f:
#             file_data = f.read()
#             file_hash = hashlib.sha256(file_data).hexdigest()
        
#         # Check cache
#         cached_analysis = await db.analyses.find_one({"hash": file_hash})
#         # if cached_analysis:
#         #     os.remove(file_path)  # Clean up
#         #     cached_analysis["_id"] = str(cached_analysis["_id"])
#         #     return AnalysisResponse(**cached_analysis)

#         # Perform YARA analysis
#         yara_results = yara_handler.scan_file(file_path)
#         logger.info(f"YARA scan completed for {file.filename}: {yara_results}")

#         # Extract risk level and indicators
#         risk_level = yara_results["summary"]["risk_level"]
#         indicators = get_file_indicators(yara_results)

#         # Create analysis result
#         analysis_result = {
#             "file_name": file.filename,
#             "hash": file_hash,
#             "timestamp": datetime.now(),
#             "status": "completed",
#             "risk_level": risk_level,
#             "indicators": indicators,
#             "yara_matches": yara_results["matches"],
#             "recommendations": get_recommendations(risk_level, indicators),
#         }

#         # Save to database
#         # await db.analyses.insert_one(analysis_result)
        
#         # Schedule cleanup
#         # background_tasks.add_task(os.remove, file_path)

#         logger.info(f"Successfully analyzed file: {file.filename}")
#         return AnalysisResponse(**analysis_result)

#     except Exception as e:
#         logger.error(f"Error analyzing file: {str(e)}")
#         if file_path and os.path.exists(file_path):
#             os.remove(file_path)
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/analysis-history")
# async def get_analysis_history():
#     try:
#         cursor = db.analyses.find().sort("timestamp", -1).limit(100)
#         analyses = await cursor.to_list(length=100)
#         return [{**analysis, "_id": str(analysis["_id"])} for analysis in analyses]
#     except Exception as e:
#         logger.error(f"Error retrieving analysis history: {str(e)}")
#         raise HTTPException(status_code=500, detail=str(e))

# @app.get("/health")
# async def health_check():
#     try:
#         # Check database connection
#         await db.command("ping")
#         return {"status": "healthy"}
#     except Exception as e:
#         raise HTTPException(status_code=503, detail="Service unhealthy")
