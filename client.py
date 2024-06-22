import socket
import hashlib
import sys
import signal
import os
import threading
import select
import curses
import time

client_socket = None
shutdown_flag = threading.Event()
listener_t = None
stdscr = None

def signal_handler(sig, frame):
    stdscr.clear()
    stdscr.addstr(height - 2, 2, "Closing the client...")
    stdscr.refresh()
    if listener_t:
        shutdown_flag.set()
        listener_t.join()
    time.sleep(1)
    sys.exit(0)

def hash_data_sha3_512(data):
    sha3_512 = hashlib.sha3_512()
    sha3_512.update(data.encode('utf-8'))
    hashed_data = sha3_512.hexdigest()
    return hashed_data

def send_message(sock, message):
    message_bytes = message.encode('utf-8')
    message_length = len(message_bytes)
    header = f"{message_length:<10}".encode('utf-8')
    sock.sendall(header + message_bytes)

def receive_message(sock):
    header = sock.recv(10)
    if not header:
        return None
    message_length = int(header.strip())
    message = sock.recv(message_length).decode('utf-8')
    return message

def receive_message_with_error_code(sock):
    header = sock.recv(10)
    if not header:
        return None
    message_length = int(header.strip())
    error_code_b = sock.recv(1)
    error_code = int.from_bytes(error_code_b, byteorder='big')
    message = sock.recv(message_length).decode('utf-8')
    return message, error_code

def listener(sock, stdscr):
    while not shutdown_flag.is_set():
        ready_to_read, _, _ = select.select([sock], [], [], 2)
        if ready_to_read:
            stdscr.addstr(i_ctr, 0, receive_message(sock))
        else:
            continue

def input_curses(stdscr, input_desc):
    #stdscr.clear()
    stdscr.addstr(height - 2, 2, input_desc)
    input_window = curses.newwin(1, width - len(input_desc) - 1, height - 2, len(input_desc) + 2)
    input_window.border(0)
    
    choice = ""
    while True:
        input_window.clear()
        input_window.addstr(0, 0, choice)
        input_window.refresh()

        key = stdscr.getch()

        if key == curses.KEY_ENTER or key == 10:
            break
        elif key == curses.KEY_BACKSPACE or key == 127:  # Handle backspace
            if choice:
                choice = choice[:-1]
        elif key >= 32 and key < 127:  # Handle printable characters
            choice += chr(key)
    return choice


def enter(sock):
    try:
        while True:
            
            choice = input_curses(stdscr, "Login (1), Register (2) or Exit (3): ")
            stdscr.refresh()
            send_message(sock, choice)
            response = receive_message_with_error_code(sock)
            stdscr.clear()
            stdscr.addstr(1, 2, response[0])
            stdscr.refresh()
            if response[1] != 0:
                continue
            choice = int(choice)

            if choice == 1:
                try:
                    username = input_curses(stdscr, "Username: ")
                    send_message(sock, username)
                    if username == 'exit':
                        continue
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue

                    password = input_curses(stdscr, "Password: ")
                    if password == 'exit':
                        send_message(sock, password)
                        continue
                    send_message(sock, hash_data_sha3_512(password))
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue

                    response = receive_message_with_error_code(sock)

                    
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue
                    stdscr.clear()
                    stdscr.addstr(1, 2, f"Welcome, {username}!")
                    while True:
                        
                        receiver = input_curses(stdscr, "Enter the username of the user you want to communicate with: ")
                        send_message(sock, receiver)
                        if receiver == 'exit':
                            break
                        response = receive_message_with_error_code(sock)
                        if response[1] != 0:
                            stdscr.addstr(2, 2, response[0])
                            continue
                        number_of_messages = receive_message(sock)
                        global i_ctr
                        i_ctr = 3
                        for i in range(int(number_of_messages)):
                            prev_msgs = receive_message(sock)
                            stdscr.addstr(i_ctr, 2, prev_msgs)
                            i_ctr += 1
                        
                        global listener_t
                        listener_t = threading.Thread(target=listener, args=(sock, stdscr))
                        listener_t.start()
                        while True:
                            stdscr.move(height - 2, 0)
                            stdscr.clrtoeol()
                            msg_in = input_curses(stdscr, "Enter your message: ")
                            if msg_in == 'exit':
                                send_message(sock, msg_in)
                                break
                            
                    
                except BrokenPipeError as e:
                    print("The connection has been closed by the server.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    break
            elif choice == 2:
                try:
                    username = input("Username: ")
                    send_message(sock, username)
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        print(response[0])
                        continue

                    password = input("Password: ")
                    send_message(sock, hash_data_sha3_512(password))
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        print(response[0])
                        continue
                    response = receive_message(sock)
                    print(response)
                    continue
                except BrokenPipeError as e:
                    print("The connection has been closed by the server.")
                    break
                except Exception as e:
                    print(f"Error: {e}")
                    break
            elif choice == 3:
                break
            else:
                continue
    except Exception as e:
        print(f"Error: {e}")

def main(scr):
    global stdscr
    stdscr = scr
    #curses.curs_set(0)
    stdscr.clear()
    global height, width
    height, width = stdscr.getmaxyx()
    if curses.has_colors():
        curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLUE) # white on blue
    server_ip = '172.20.10.9'
    server_port = 5555       
    global client_socket 
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((server_ip, server_port))
        print(f"Connected to server at {server_ip}:{server_port}")

        enter(client_socket)

    finally:
        client_socket.close()
        stdscr.addstr(height - 2, 2, "Connection closed.")

if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    curses.wrapper(main)
