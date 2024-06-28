import socket
import multiprocessing
import sqlite3
import bcrypt
import signal
import sys
import threading
import time
import select

shutdown_flag = threading.Event()
MAX_CONNECTIONS = 100

class ConnectionClosedError(Exception):
    pass

def signal_handler(sig, frame):
    print('\nReceived SIGINT (Ctrl+C). Shutting down the server...')
    sys.exit(0)

def hash_password(password):
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed

conn = sqlite3.connect('e2e.db', check_same_thread=False)
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

def save_message(message, sender_id, receiver_id):
    sql = "INSERT INTO messages (sender, receiver, content) VALUES (?, ?, ?)"
    values = (sender_id, receiver_id, message)
    cursor.execute(sql, values)
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

def receive_message_with_to(sock, timeout=5):
    ready = select.select([sock], [], [], timeout)
    if ready[0]:
        header = sock.recv(10)
        if not header:
            raise ConnectionClosedError
        try:
            message_length = int(header.strip())
        except ValueError:
            raise ConnectionClosedError
        
        if message_length == 0:
            return ""
        
        message = sock.recv(message_length).decode('utf-8')
        if not message:
            raise ConnectionClosedError
        
        return message
    else:
        raise TimeoutError

def broadcaster(client_socket, user_id, receiver_id, shutdown_flag, messages):
    try:
        conn = sqlite3.connect('e2e.db', check_same_thread=False)
        cursor = conn.cursor()
        while not shutdown_flag.is_set():
            sql = """
            SELECT id, content FROM messages 
            WHERE (sender = ? AND receiver = ?) 
                OR (sender = ? AND receiver = ?) 
            ORDER BY created_at ASC 
            LIMIT 50
            """
            values = (user_id, receiver_id, receiver_id, user_id)
            cursor.execute(sql, values)
            messages_res = cursor.fetchall()

            new_messages = [message for message in messages_res if message not in messages]
            if new_messages:
                for message in new_messages:
                    send_message(client_socket, message[1])
                    messages.add(message)
            time.sleep(0.1 if not new_messages else 0)

    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()

def handle_client(client_socket):
    try:
        i = 5
        while True:
            try:
                login_or_register = receive_message_with_to(client_socket, 60)
            except TimeoutError:
                if i == 0:
                    print("Number of tries exceeded.")
                    sys.exit(0)
                i -= 1
                continue
            except ConnectionClosedError:
                sys.exit(0)
            if not login_or_register:
                send_message_with_error_code(client_socket, "Please enter 1 or 2.", 3)
                continue
            try:
                choice = int(login_or_register)
            except ValueError as e:
                send_message_with_error_code(client_socket, "Please enter 1 or 2.", 3)
                continue
            if choice == 1:
                send_message_with_error_code(client_socket, "Login", 0)
                try:
                    username = receive_message_with_to(client_socket, 60)
                except TimeoutError:
                    print("Number of tries exceeded.")
                    sys.exit(0)
                except ConnectionClosedError:
                    sys.exit(0)
                if not username:
                    send_message_with_error_code(client_socket, "Username is required", 1)
                    continue
                if username == "exit":
                    sys.exit(0)
                if username == "..":
                    continue
                send_message_with_error_code(client_socket, "Username entered", 0)
                try:
                    password = receive_message_with_to(client_socket, 60)
                except TimeoutError:
                    print("Number of tries exceeded.")
                    sys.exit(0)
                except ConnectionClosedError:
                    sys.exit(0)
                if not password:
                    send_message_with_error_code(client_socket, "Password is required", 2)
                    continue
                if password == "exit":
                    sys.exit(0)
                if password == "..":
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
                    i = 5
                    while True:
                        try:
                            print("searching for a new receiver")
                            receiver = receive_message_with_to(client_socket, 60)
                        except TimeoutError:
                            if i == 0:
                                print("Number of tries exceeded.")
                                sys.exit(0)
                            i -= 1
                            continue
                        except ConnectionClosedError:
                            sys.exit(0)
                        if not receiver:
                            send_message_with_error_code(client_socket, "Receiver is required", 1)
                            continue
                        if receiver == "exit":
                            sys.exit(0)
                        if receiver == "..":
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
                        broadcast_t = threading.Thread(target=broadcaster, args=(client_socket, user_id, receiver_id[0], shutdown_flag, set(messages)))
                        broadcast_t.start()
                        i = 5
                        while True:
                            try:
                                print("waiting for a new message")
                                data = receive_message_with_to(client_socket, 60)
                                print(f"Received: {data}")
                            except TimeoutError:
                                if i == 0:
                                    print("Number of tries exceeded.")
                                    sys.exit(0)
                                i -= 1
                                continue
                            except ConnectionClosedError:
                                sys.exit(0)
                            if not data:
                                continue
                            if data == "exit":
                                sys.exit(0)
                            if data == "..":
                                shutdown_flag.set()
                                broadcast_t.join()
                                shutdown_flag.clear()
                                break
                            save_message(data, user_id, receiver_id[0])
                else:
                    send_message_with_error_code(client_socket, "Invalid credentials, please try again.", 3)
                    continue
            elif choice == 2:
                send_message_with_error_code(client_socket, "Register", 0)
                try:
                    username = receive_message_with_to(client_socket, 60)
                except TimeoutError:
                    print("Number of tries exceeded.")
                    sys.exit(0)
                except ConnectionClosedError:
                    sys.exit(0)
                if not username:
                    send_message_with_error_code(client_socket, "Username is required", 1)
                    continue
                send_message_with_error_code(client_socket, "Username entered", 0)
                try:
                    password = receive_message_with_to(client_socket, 60)
                except TimeoutError:
                    print("Number of tries exceeded.")
                    sys.exit(0)
                except ConnectionClosedError:
                    sys.exit(0)
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
            else:
                send_message_with_error_code(client_socket, "Please enter 1 or 2.", 3)
                continue
    except (BrokenPipeError, ConnectionResetError):
        pass
    except Exception as e:
        print(f"Error: {e}")
    finally:
        if broadcast_t:
            shutdown_flag.set()
            broadcast_t.join()
        if client_socket:
            client_socket.close()
        print("Connection closed.")
        

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('192.168.0.12', 5555))
    server.listen(10)
    print("Server started and listening...")
    client_processes = []

    try:
        while True:
            client_socket, client_address = server.accept()
            if len(client_processes) >= MAX_CONNECTIONS:
                print("Maximum number of connections reached.")
                client_socket.close()
                continue
            client_processes = [process for process in client_processes if process.is_alive()]
            print(f"Connection from {client_address}")
            client_process = multiprocessing.Process(target=handle_client, args=(client_socket,))
            client_processes.append(client_process)
            client_process.start()
    except Exception as e:
        print(f"Error: {e}")
    finally:
        for process in client_processes:
            if process.is_alive():
                process.terminate()
                print("Client process closed.")
        if server:
            server.close()
            print("Server closed.")
        
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    start_server()