import socket
import multiprocessing
import sqlite3
import bcrypt
import signal
import sys
import threading
import time

server = None
client_processes = []
shutdown_flag = threading.Event()
broadcast_t = None

def signal_handler(sig, frame):
    print('\nReceived SIGINT (Ctrl+C). Shutting down the server...')
    for process in client_processes:
        if process.is_alive():
            process.terminate()
            print("Client process closed.")
    if server:
        server.close()
        print("Server closed.")
    sys.exit(0)

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

# Initialize SQLite database
conn = sqlite3.connect('e2e_app.db', check_same_thread=False)
cursor = conn.cursor()
cursor.execute('PRAGMA foreign_keys = ON;')

cursor.execute('''
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(255) NOT NULL UNIQUE,
    password TEXT NOT NULL
)
''')

cursor.execute('''
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    sender INTEGER NOT NULL,
    receiver INTEGER NOT NULL,
    FOREIGN KEY (sender) REFERENCES users(id),
    FOREIGN KEY (receiver) REFERENCES users(id)
)
''')
conn.commit()


def send_message(sock, message):
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    header = f"{message_length:<10}".encode('utf-8')
    sock.sendall(header + message_bytes)

def send_message_with_error_code(sock, message, error_code):
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    header = f"{message_length:<10}".encode('utf-8')
    error_code_b = error_code.to_bytes(1, byteorder='big')
    sock.sendall(header + error_code_b + message_bytes)

def receive_message(sock):
    header = sock.recv(10)
    if not header:
        return None
    message_length = int(header.strip())
    message = sock.recv(message_length).decode('utf-8')
    return message

def broadcaster(client_socket, user_id, receiver_id, shutdown_flag, messages):
    try:
        conn = sqlite3.connect('e2e_app.db', check_same_thread=False)
        cursor = conn.cursor()
        print(f"Broadcasting messages from {user_id} to {receiver_id}")
        while not shutdown_flag.is_set():
            sql = "SELECT id,content FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY created_at ASC LIMIT 50"
            values = (user_id, receiver_id, receiver_id, user_id)
            cursor.execute(sql, values)
            messages_res = cursor.fetchall()
            for message in messages_res:
                if message not in messages:
                    send_message(client_socket, message[1])
                    messages.add(message)
            time.sleep(1 if not messages_res else 0)

    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()

def handle_client(client_socket):
    try:
        while True:
            login_or_register = receive_message(client_socket)
            if not login_or_register:
                send_message_with_error_code(client_socket, "Please enter 1, 2 or 3.", 3)
                continue
            try:
                choice = int(login_or_register)
            except ValueError as e:
                send_message_with_error_code(client_socket, "Please enter 1, 2 or 3.", 3)
                continue
            if choice == 1:
                send_message_with_error_code(client_socket, "Login", 0)
                username = receive_message(client_socket)
                if not username:
                    send_message_with_error_code(client_socket, "Username is required", 1)
                    continue
                if username == "exit":
                    continue
                send_message_with_error_code(client_socket, "Username entered", 0)
                password = receive_message(client_socket)
                if not password:
                    send_message_with_error_code(client_socket, "Password is required", 2)
                    continue
                if password == "exit":
                    continue
                send_message_with_error_code(client_socket, "Password entered", 0)
                sql = "SELECT id, password FROM users WHERE username = ?"
                values = (username,)
                cursor.execute(sql, values)
                res = cursor.fetchone()
                if not res:
                    send_message_with_error_code(client_socket, "Invalid credentials, please try again.", 3)
                    continue
                user_id, password_db = res
                if bcrypt.checkpw(password.encode('utf-8'), password_db):
                    user_id, password_db = res
                    send_message_with_error_code(client_socket, "Login successful", 0)
                    try:
                        while True:
                            receiver = receive_message(client_socket)
                            if not receiver:
                                send_message_with_error_code(client_socket, "Receiver is required", 1)
                                continue
                            if receiver == "exit":
                                break
                            sql = "SELECT id FROM users WHERE username = ?"
                            values = (receiver,)
                            cursor.execute(sql, values)
                            receiver_id = cursor.fetchone()
                            if not receiver_id:
                                send_message_with_error_code(client_socket, "Receiver not found", 2)
                                continue
                            send_message_with_error_code(client_socket, "Receiver entered", 0)
                            sql = "SELECT id,content FROM messages WHERE (sender = ? AND receiver = ?) OR (sender = ? AND receiver = ?) ORDER BY created_at ASC LIMIT 150"
                            values = (user_id, receiver_id[0], receiver_id[0], user_id)
                            cursor.execute(sql, values)
                            messages = cursor.fetchall()
                            send_message(client_socket, str(len(messages)))
                            for message in messages:
                                send_message(client_socket, message[1])
                            global broadcast_t
                            broadcast_t = threading.Thread(target=broadcaster, args=(client_socket, user_id, receiver_id[0], shutdown_flag, set(messages)))
                            broadcast_t.start()
                            while True:
                                data = receive_message(client_socket)
                                if not data:
                                    continue
                                if data == "exit":
                                    shutdown_flag.set()
                                    broadcast_t.join()
                                    shutdown_flag.clear()
                                    break
                                save_message(data, user_id, receiver_id[0])
                    except (BrokenPipeError, ConnectionResetError):
                        break
                else:
                    send_message_with_error_code(client_socket, "Invalid credentials, please try again.", 3)
                    continue
            elif choice == 2:
                send_message_with_error_code(client_socket, "Register", 0)
                username = receive_message(client_socket)
                if not username:
                    send_message_with_error_code(client_socket, "Username is required", 1)
                    continue
                send_message_with_error_code(client_socket, "Username entered", 0)
                password = receive_message(client_socket)
                if not password:
                    send_message_with_error_code(client_socket, "Password is required", 2)
                    continue
                send_message_with_error_code(client_socket, "Password entered", 0)
                password = hash_password(password)

                sql = "SELECT id FROM users WHERE username = ?"
                values = (username,)
                cursor.execute(sql, values)
                user_id = cursor.fetchone()
                if user_id:
                    send_message(client_socket, "Username already exists, please try again.")
                    continue
                sql = "INSERT INTO users (username, password) VALUES (?, ?)"
                values = (username, password)
                cursor.execute(sql, values)
                conn.commit()
                send_message(client_socket, "Registration successful, you can now login.")
                continue
            elif choice == 3:
                send_message_with_error_code(client_socket, "Exited.", 0)
                break
            else:
                send_message_with_error_code(client_socket, "Please enter 1, 2 or 3.", 3)
                continue
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if client_socket:
            client_socket.close()

def del_process(pid):
    for process in client_processes:
        if process.pid == pid:
            client_processes.remove(process)
            break

def save_message(message, sender_id, receiver_id):
    sql = "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)"
    values = (sender_id, receiver_id, message)
    cursor.execute(sql, values)
    conn.commit()


def start_server():
    global server
    global client_processes
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('172.20.10.9', 5555))
    server.listen(10)
    print("Server started and listening...")

    while True:
        try:
            client_socket, client_address = server.accept()
            print(f"Connection from {client_address}")
            client_process = multiprocessing.Process(target=handle_client, args=(client_socket,))
            client_processes.append(client_process)
            client_process.start()
        except Exception as e:
            print(f"Error: {e}")
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_server()
