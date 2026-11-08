
from backend.database import engine
from sqlalchemy import text

try:
    with engine.connect() as connection:
        connection.execute(text("SELECT 1"))
        print("SUCCESS: MySQL database connected!")

except Exception as error:
    print("DATABASE CONNECTION FAILED")
    print(error)
