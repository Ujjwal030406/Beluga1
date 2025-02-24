from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os
import certifi
import logging

logger = logging.getLogger(__name__)

load_dotenv()

# Get MongoDB configuration from environment variables
MONGODB_URL = os.getenv("MONGODB_URL")
DB_NAME = os.getenv("DB_NAME", "malware_analysis")

if not MONGODB_URL:
    raise ValueError("MongoDB URL not found in environment variables")

# Initialize MongoDB client with proper security settings
client = AsyncIOMotorClient(
    MONGODB_URL,
    tlsCAFile=certifi.where(),
    serverSelectionTimeoutMS=5000,
    connectTimeoutMS=10000
)

db = client[DB_NAME]

async def init_db():
    try:
        # Verify database connection
        await client.admin.command('ping')

        # Drop the index before potentially creating it
        try:
            # await db.analyses.drop_index("timestamp_1")
            logger.info("Dropped index timestamp_1")
        except Exception as e:
            logger.warning(f"Could not drop index timestamp_1: {e}")

        # Create indexes
        # await db.analyses.create_index("hash", unique=True)

        # Create TTL index for automatic cleanup of old records (30 days)
        # await db.analyses.create_index(
        #     "timestamp",
        #     expireAfterSeconds=30 * 24 * 60 * 60,
        #     name="timestamp_1"  # Explicitly name the index
        # )
        logger.info("Successfully created a TTL index on timestamp")

        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")
        raise
