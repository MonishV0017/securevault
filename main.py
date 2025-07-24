from database import setup_db
from gui import VaultApp

# 1. Run database setup immediately to create tables first
setup_db()

# 2. Start the application
if __name__ == "__main__":
    app = VaultApp()
    app.mainloop()