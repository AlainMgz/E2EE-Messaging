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

def listener(sock, i_ctr):
    try:
        while not shutdown_flag.is_set():
            ready_to_read, _, _ = select.select([sock], [], [], 2)
            if ready_to_read:
                i_ctr += 1
                stdscr.addstr(i_ctr, 2, receive_message(sock))
                stdscr.move(height - 2, len("Enter your message: ") + 2)
                stdscr.refresh()
                
            else:
                continue
    except (BrokenPipeError, ConnectionResetError):
        stdscr.clear()
        stdscr.addstr(2, 2, "The connection has been closed by the server.")
        stdscr.refresh()
        input_curses("Press Enter to exit...")
    except Exception as e:
        stdscr.clear()
        stdscr.addstr(2, 2, f"An error occurred. Verify your connection and try again. {e}")
        stdscr.refresh()
        input_curses("Press Enter to exit...")


def input_curses(input_desc):
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
            choice = input_curses("Login (1) or Register (2): ")
            if choice == 'exit':
                break
            if choice == '..':
                continue
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
                    username = input_curses("Username: ")
                    send_message(sock, username)
                    if username == 'exit':
                        exit()
                    if username == '..':
                        continue
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue

                    password = input_curses("Password: ")
                    if password == 'exit':
                        exit()
                    if password == '..':
                        send_message(sock, '..')
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
                        
                        receiver = input_curses("Enter the username of the user you want to communicate with: ")
                        send_message(sock, receiver)
                        if receiver == 'exit':
                            exit()
                        if receiver == '..':
                            break
                        response = receive_message_with_error_code(sock)
                        if response[1] != 0:
                            stdscr.addstr(2, 2, response[0])
                            continue
                        number_of_messages = receive_message(sock)
                        message_area_height = height - 6
                        message_area_width = width - 4
                        stdscr.clear()
                        stdscr.addstr(1, 2, f"Chatting with {receiver}...")
                        stdscr.addstr(2, 2, "Messages:")
                        stdscr.addstr(3, 2, "-"*message_area_width)
                        stdscr.addstr(height - 3, 2, "-"*message_area_width)
                        stdscr.refresh()

                        i_ctr = 3
                        for _ in range(int(number_of_messages)):
                            i_ctr += 1
                            prev_msgs = receive_message(sock)
                            stdscr.addstr(i_ctr, 2, prev_msgs)
                        
                        global listener_t
                        listener_t = threading.Thread(target=listener, args=(sock, i_ctr))
                        listener_t.start()
                        while True:
                            stdscr.move(height - 2, 0)
                            stdscr.clrtoeol()
                            msg_in = input_curses("Enter your message: ")
                            if msg_in == 'exit':
                                stdscr.clear()
                                stdscr.addstr(2, 2, "Exiting...")
                                stdscr.refresh()
                                shutdown_flag.set()
                                listener_t.join()
                                exit()
                            if msg_in == '..':
                                send_message(sock, msg_in)
                                break
                            send_message(sock, msg_in)
                    
                except (BrokenPipeError, ConnectionResetError):
                    stdscr.clear()
                    stdscr.addstr(2, 2, "The connection has been closed by the server.")
                    stdscr.refresh()
                    send_message(sock, 'exit')
                    if listener_t:
                        shutdown_flag.set()
                        listener_t.join()
                    break
                except Exception:
                    stdscr.clear()
                    stdscr.addstr(2, 2, "An error occurred. Verify your connection and try again.")
                    stdscr.refresh()
                    send_message(sock, 'exit')
                    if listener_t:
                        shutdown_flag.set()
                        listener_t.join()
                    break
            elif choice == 2:
                try:
                    username = input_curses("Username: ")
                    send_message(sock, username)
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue

                    password = input_curses("Password: ")
                    send_message(sock, hash_data_sha3_512(password))
                    response = receive_message_with_error_code(sock)
                    if response[1] != 0:
                        stdscr.addstr(2, 2, response[0])
                        continue
                    response = receive_message(sock)
                    stdscr.clear()
                    stdscr.addstr(1, 2, response)
                    stdscr.refresh()
                    input_curses("Press Enter to go back to the main menu... ")
                    stdscr.clear()
                    continue
                except (BrokenPipeError, ConnectionResetError) as e:
                    stdscr.clear()
                    stdscr.addstr(2, 2, "The connection has been closed by the server.")
                    stdscr.refresh()
                    break
                except Exception as e:
                    stdscr.clear()
                    stdscr.addstr(2, 2, "An error occurred. Verify your connection and try again.")
                    stdscr.refresh()
                    break
            else:
                continue
    except (BrokenPipeError, ConnectionResetError):
        stdscr.clear()
        stdscr.addstr(2, 2, "The connection has been closed by the server.")
        stdscr.refresh()
    except Exception as e:
        stdscr.clear()
        stdscr.addstr(2, 2, "An error occurred. Verify your connection and try again.")
        stdscr.refresh()
    finally:
        input_curses("Press Enter to exit...")
        sock.close()

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
    server_ip = '192.168.0.12'
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
