
from backend.database import engine, Base
from backend import models

def create_tables():
    try:
        Base.metadata.create_all(bind=engine)
        print("SUCCESS: TrustVault tables created!")

        print("\nCreated tables:")
        for table_name in Base.metadata.tables:
            print("-", table_name)

    except Exception as error:
        print("TABLE CREATION FAILED")
        print(error)


if __name__ == "__main__":
    create_tables()
