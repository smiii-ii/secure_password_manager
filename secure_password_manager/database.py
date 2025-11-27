import sqlite3

DB_NAME = 'password_manager.db'

def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    # Create users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        master_hash BLOB,
        recovery_phrase TEXT
    )''')

    # Create accounts table mapped to users, stores encrypted image path that holds multiple passwords
    c.execute('''
    CREATE TABLE IF NOT EXISTS accounts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        platform TEXT,
        username TEXT,
        image_path TEXT,
        FOREIGN KEY (user_id) REFERENCES users(id)
    )''')

    conn.commit()
    conn.close()

def add_user(username, master_hash, recovery_phrase):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    try:
        c.execute('INSERT INTO users (username, master_hash, recovery_phrase) VALUES (?, ?, ?)', 
                  (username, master_hash, recovery_phrase))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        # Username already exists
        return False
    finally:
        conn.close()

def verify_login(username, plain_password):
    import bcrypt
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT id, master_hash FROM users WHERE username=?', (username,))
    row = c.fetchone()
    conn.close()
    if row and bcrypt.checkpw(plain_password.encode('utf-8'), row[1]):
        return row[0]  # return user id on successful login
    return None

def add_account(user_id, platform, username, image_path):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('INSERT INTO accounts (user_id, platform, username, image_path) VALUES (?, ?, ?, ?)',
              (user_id, platform, username, image_path))
    conn.commit()
    conn.close()

def get_accounts(user_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT id, platform, username, image_path FROM accounts WHERE user_id=?', (user_id,))
    rows = c.fetchall()
    conn.close()
    return rows  # returns image_path for steganography

def delete_account(account_id):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('DELETE FROM accounts WHERE id=?', (account_id,))
    conn.commit()
    conn.close()

def get_accounts_by_image(user_id, image_path):
    """
    Fetch all accounts associated with the specific image_path for a user.
    Useful when embedding multiple passwords in one image.
    """
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute('SELECT id, platform, username FROM accounts WHERE user_id=? AND image_path=?', (user_id, image_path))
    rows = c.fetchall()
    conn.close()
    return rows
