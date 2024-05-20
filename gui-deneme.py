import tkinter as tk
import os
import base64
import socket
import json
import time
import pyDes
from threading import Thread,Event
import threading
from json.decoder import JSONDecodeError
import random
import queue
import datetime

username_queue = queue.Queue()

stop_event = Event()
threads = []

class P2PChatApplicationClient:
    def __init__(self,username,app):
        self.LOCAL_IP_ADDRESS = socket.gethostbyname(socket.gethostname())
        #LOCAL_IP_ADDRESS = "127.0.0.1"
        self.SERVER_PORT = 6000
        #GUI_P2PChatApplicationClient = gui

        self.filename = "chat_log.json"

        self.input_timeout = False
        # Define the timeout duration (in seconds)
        self.input_timeout_duration = 5  # Adjust as needed

        self.users_dict = {}
        self.username = username
        self.app = app

        if not os.path.exists(self.filename):
            with open(self.filename, 'w') as file:
                pass

    def service_announcer(self):

        announced = False
        try:
            while not stop_event.is_set():
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
                client_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

                broadcast_address = self.get_broadcast_ip(self.LOCAL_IP_ADDRESS)

                announcement = json.dumps({"username": self.username, "IP_ADDRESS": self.LOCAL_IP_ADDRESS})
                client_socket.sendto(announcement.encode(), (broadcast_address, self.SERVER_PORT))

                if not announced:
                    self.app.display_event(f"{announcement} has been announced! \n")
                    #announced = True

                client_socket.close()
                time.sleep(8)  # Announce every 8 seconds

        except KeyboardInterrupt:
            self.app.display_event("Client shutdown requested. Exiting...")
        except Exception as e:
            self.app.display_event(f"An error occurred: {e}")

    def peer_discovery(self):

        self.app.display_event("Listening for broadcast messages...\n")
        try:
            serverPort = 6000
            client_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            client_socket.bind((self.LOCAL_IP_ADDRESS, serverPort))
            self.app.display_event("The server is ready to receive\n")

            while not stop_event.is_set():
                try:
                    data, addr = client_socket.recvfrom(2048)
                    if addr[0] == socket.gethostbyname(socket.gethostname()):
                        continue

                    try:
                        message = json.loads(data.decode())
                        #self.app.display_event(message)
                        if "username" in message:
                            username = message.get("username")
                            sender_ip = addr[0]
                            timestamp = time.time()

                            user_exists_in_file = False
                            updated_lines = []

                            with open(self.filename, 'r') as file:
                                for line in file:
                                    try:
                                        data = json.loads(line)
                                        try:
                                            if sender_ip == data.get(username, {}).get("sender_ip", ""):
                                                data[next(iter(data))]["timestamp"] = timestamp
                                                user_exists_in_file = True
                                                self.users_dict[sender_ip] = username
                                            updated_lines.append(json.dumps(data) + "\n")
                                        except:
                                            pass
                                    except json.JSONDecodeError:
                                        self.app.display_event(f"Error decoding JSON while discovering peers:{line}")

                            if not user_exists_in_file:
                                    self.app.display_event(f"\nNew user: {username}")
                                    new_user_data = {username: {"sender_ip": sender_ip, "timestamp": timestamp}}
                                    self.users_dict[sender_ip] = username
                                    updated_lines.append(json.dumps(new_user_data) + "\n")

                            with open(self.filename, 'w') as file:
                                file.writelines(updated_lines)

                    except JSONDecodeError as e:
                        self.app.display_event(f"Error decoding JSON: {e}")

                except Exception as a:
                    self.app.display_event(f"Error while discovering peers:{a}")

        finally:
            client_socket.close()

    def chat_initiator(self,mode,target_username,message):
        if not stop_event.is_set():
            if mode.lower() == "secured_chat":
                 self.initiate_chat("yes",target_username,message)
            elif mode.lower() == "unsecured_chat":
                self.initiate_chat("no",target_username,message)
            elif mode.lower() == "history":
                self.show_users()
            else:
                self.app.display_event("Invalid option.")


    def initiate_chat(self,secured,target_username,message_1):
        if not stop_event.is_set():
            #target_username = input("Enter the name of the user to chat with: ")
            try:
                with open('chat_log.json', 'r') as file:
                    chat_log = file.read()

                    chat_log_lines = chat_log.strip().split('\n')
                    chat_log_dict = {}
                    for line in chat_log_lines:
                        try:
                            data = json.loads(line)
                            chat_log_dict.update(data)
                            #self.app.display_event(str(chat_log_dict))
                        except json.JSONDecodeError:
                            self.app.display_event(f"Error decoding JSON: {line}")

                target_info = chat_log_dict.get(target_username)
                if not target_info:
                    self.app.display_event(f"Error: Target information not found for username '{target_username}' in chat log.")
                    return

                target_ip = target_info.get('sender_ip')
                if not target_ip:
                    self.app.display_event(f"Error: Target IP address not found for username '{target_username}' in chat log.")
                    return

                #secure_option = input("Do you want to chat securely? (yes/no): ").lower()
                #print(secured)
                if secured == "yes":
                    try:
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((target_ip, 6001))

                        p = 23  # Prime number shared by both parties
                        g = 5   # Generator shared by both parties

                        #a = int(input("Enter a private key."))
                        # Calculate public key 'A'
                        a = random.randrange(1,9999999)
                        A = pow(g, a, p)

                        message = {'key': A}
                        client_socket.sendall(json.dumps(message).encode())

                        received_data = client_socket.recv(2048)
                        data = json.loads(received_data.decode())
                        self.app.display_event(str(data))
                        if "key" in data:
                            self.app.display_event(f'Received {data["key"]}')
                            B = data['key']

                            S = pow(int(B), a, p)

                            encrypted_message = self.encrypt_message(message_1, str(S))  # Replace with your encryption function
                            message_2 = {'encrypted_message': encrypted_message}
                            client_socket.sendall(json.dumps(message_2).encode())
                            #self.app_display_tx(f"Sent message: {message_2}")
                            client_socket.close()

                    except Exception as e:
                        self.app.display_event(f"Error: Connection with {target_ip} could not be established: {e}")
                elif secured == "no":
                    try:
                        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        client_socket.connect((target_ip, 6001))

                        unencrypted_message = {'unencrypted_message': message_1}
                        client_socket.sendall(json.dumps(unencrypted_message).encode())

                        #self.app_display_tx(f"Sent message: {unencrypted_message}")

                        client_socket.close()
                    except Exception as e:
                        self.app.display_event(f"Error: Connection with {target_ip} could not be established: {e}")

                else:
                    self.app.display_event("Invalid option")


            except FileNotFoundError:
                self.app.display_event("Error: Chat log file 'chat_log.json' not found.")
            except json.JSONDecodeError:
                self.app.display_event("Error: Unable to parse chat log JSON.")

    def encrypt_message(self, message, key):
        des = pyDes.triple_des(key.ljust(24))
        encoded_message = message.encode()
        encrypted_message = des.encrypt(encoded_message, padmode=2)
        encrypted_message_base64 = base64.b64encode(encrypted_message).decode('utf-8')
        return encrypted_message_base64

    def decrypt_message(self, encrypted_message, key):
        try:
            decrypted_message_base64 = base64.b64decode(encrypted_message)
            des = pyDes.triple_des(key.ljust(24))
            decrypted_message = des.decrypt(decrypted_message_base64, padmode=2)
            return decrypted_message.decode()  # Assuming the decrypted message is UTF-8 encoded text
        except Exception as e:
            self.app.display_event(f"Error decrypting message:s{e}")
            return None  # Or handle the error in an appropriate way for your application

    def save_message(self, message, filename):
        fifteen_minutes = 15 * 60
        current_time = time.time()
        with open(filename, 'r') as file:
            lines = file.readlines()
            filtered_lines = []
            for line in lines:
                try:
                    data = json.loads(line)
                    first_value = next(iter(data.values()))
                    #print(first_value)
                    if "timestamp" in first_value:
                        timestamp = first_value["timestamp"]

                        if int(timestamp) >= current_time - fifteen_minutes:
                            filtered_lines.append(json.dumps(data) + "\n")
                except json.JSONDecodeError:
                    self.app.display_event(f"Error decoding JSON: {line}")

        filtered_lines.append(json.dumps(message, ensure_ascii=False) + "\n")

        with open(filename, 'w') as file:
            file.writelines(filtered_lines)


    def calculate_broadcast_address(self, LOCAL_IP_ADDRESS, subnet_mask):
        ip_parts = [int(part) for part in LOCAL_IP_ADDRESS.split('.')]
        mask_parts = [int(part) for part in subnet_mask.split('.')]

        broadcast_parts = [(ip_part | ~mask_part) & 0xFF for ip_part, mask_part in zip(ip_parts, mask_parts)]

        return '.'.join(map(str, broadcast_parts))

    def get_broadcast_ip(self, local_LOCAL_IP_ADDRESS):
        subnet_mask = '255.255.255.0'
        return self.calculate_broadcast_address(local_LOCAL_IP_ADDRESS, subnet_mask)

    def Responder(self):

        serverPort = 6001
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.bind(("", serverPort))
        client_socket.listen(1)
        self.app.display_event('The server is ready to respond \n')
        time.sleep(0.5)

        try:
            connectionSocket, addr = client_socket.accept()
            counter = 0
            while not stop_event.is_set():
                received_data = connectionSocket.recv(2048)
                if not received_data:
                    self.app.display_event("Socket has been closed \n")
                    time.sleep(0.5)
                    break
                #self.app.display_event(received_data)
                data = json.loads(received_data.decode())

                if "key" in data:
                    B = data['key']

                    p = 23  # Prime number shared by both parties
                    g = 5   # Generator shared by both parties

                    a = int(random.randrange(1,999999))
                    # Calculate public key 'A'
                    A = pow(g, a, p)
                    #self.app.display_event(A)
                    message = {'key': A}
                    try:
                        # Attempt to send the message back to the client
                        connectionSocket.sendall(json.dumps(message).encode())
                        self.app.display_event(f"Sent: {message}")
                    except Exception as e:
                        self.app.display_event(f"Error sending message: {e}")
                    S = pow(int(B), a, p)
                    self.app.display_event(f"The key is {S}")

                elif 'encrypted_message' in data:
                    # Decrypt and display encrypted message
                    encrypted_message = data['encrypted_message']
                    decrypted_message = self.decrypt_message(encrypted_message, str(S))
                    #self.app.display_event(decrypted_message)  # Replace with your decryption function
                    sender_username = self.users_dict[addr[0]]#data.get('sender_username', 'Unknown')
                    timestamp = time.time()
                    zaman = datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")
                    self.app.display_tx(f"Received encrypted message from {sender_username} at {zaman}: {decrypted_message} \n")
                    # Log the received message
                    log_entry = {
                        'timestamp': timestamp,
                        'sender_username': sender_username,
                        'message': decrypted_message,
                        'status': 'RECEIVED'
                    }
                    self.log_message(log_entry)
                else:
                    #self.app.display_event("zort")
                    # Display unencrypted message
                    unencrypted_message = data['unencrypted_message']
                    sender_username = self.users_dict[addr[0]]
                    timestamp = time.time()
                    zaman = datetime.datetime.fromtimestamp(int(timestamp)).strftime("%Y-%m-%d %H:%M:%S")

                    self.app.display_tx(f"Received unencrypted message from {sender_username} at {zaman}: {unencrypted_message} \n")
                    # Log the received message
                    log_entry = {
                        'timestamp': timestamp,
                        'sender_username': sender_username,
                        'message': unencrypted_message,
                        'status': 'RECEIVED'
                    }
                    self.log_message(log_entry)

        except KeyboardInterrupt:
            self.app.display_event("Responder thread terminated.")
        finally:
            client_socket.close()
            self.app.display_event("Socket has been closed on your side \n")


    def log_message(self, log_entry):
        with open(self.filename, 'a') as file:
            json.dump(log_entry, file)
            file.write('\n')






class GUI_P2PChatApplicationClient:
    def __init__(self, master):
        self.master = master

        master.title("P2P Chat Application")

        master.geometry("800x600")
        self.message = None

        self.button_frame = tk.Frame(master)
        self.button_frame.pack(side="top", pady=10)

        self.username_info_label = tk.Label(self.button_frame, text="Not logged in", bg="lightgray")
        self.username_info_label.pack(side="left", anchor="w", padx=(10, 8), fill="both")

        self.username_button = tk.Button(self.button_frame, text="Enter Username", command=self.enter_username)
        self.username_button.pack(side="left", padx=10)

        self.users_button = tk.Button(self.button_frame, text="Display Users", command=self.show_users)
        self.users_button.pack(side="left", padx=10)

        self.chat_button = tk.Button(self.button_frame, text="Chat", command=self.show_chat)
        self.chat_button.pack(side="left", padx=10)

        self.history_button = tk.Button(self.button_frame, text="History", command=self.show_history)
        self.history_button.pack(side="left", padx=10)

        self.exit = tk.Button(self.button_frame, text="Exit", command=self.quit_programme)
        self.exit.pack(side="left", padx=10)
        # Create a frame to hold events on the left
        self.events_frame = tk.Frame(master)
        self.events_frame.pack(side="left", padx=10, pady=10, fill="both")

        self.event_label = tk.Label(self.events_frame, text="Events", font=("Helvetica", 14, "bold"))
        self.event_label.pack(anchor="w", padx=10, pady=5)

        self.event_text = tk.Text(self.events_frame, wrap="word", width=100, height=20)
        self.event_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.message_frame = tk.Frame(master)
        self.message_frame.pack(side="left", padx=10, pady=10, fill="both")

        self.message_label = tk.Label(self.events_frame, text="Received/Sent Messages", font=("Helvetica", 14, "bold"))
        self.message_label.pack(anchor="w", padx=10, pady=5)

        self.message_text = tk.Text(self.events_frame, wrap="word", width=100, height=10)
        self.message_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.main_frame = tk.Frame(master)
        self.main_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        self.update_users = True


        self.display_text()

        self.current_frame = None
    def quit_programme(self):
        stop_event.set()
            # Clear the threads list and reset the stop event
        threads.clear()
        stop_event.clear()
        os._exit(1)
        quit()

    def display_text(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.main_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        #self.title_frame.pack(side="left", padx=10, pady=10,  expand=True)
        self.title_label = tk.Label(self.main_frame, text="To start, first enter your username.\n Then push one of the buttons: Display Users, Chat, History", font=("Helvetica", 14, "bold"))
        self.title_label.pack(side="top", anchor="center", padx=10, pady=5, fill="both", expand=True)

    def display_event(self,event):
        #self.events_frame = tk.Frame(self.master)
        #self.events_frame.pack(side="left", padx=10, pady=10, fill="both", expand=True)

        #self.event_label = tk.Label(self.events_frame, text="Events", font=("Helvetica", 14, "bold"))
        #self.event_label.pack(anchor="w", padx=10, pady=5)

        #self.event_text = tk.Text(self.events_frame, wrap="word", width=50, height=30)
        #self.event_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.event_text.insert(tk.END, f"{event} \n")
        self.event_text.see(tk.END)

    def display_tx(self,event):
        self.message_text.insert(tk.END, f"{event} \n")
        self.message_text.see(tk.END)

    def show_users(self):
        self.display_event("Displaying users.\n")

        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.user_label = tk.Label(self.main_frame, text="Users", font=("Helvetica", 14, "bold"))
        self.user_label.pack(anchor="w", padx=10, pady=5)

        self.user_text = tk.Text(self.main_frame, wrap="word", width=50, height=30)
        self.user_text.pack(fill="both", expand=True, padx=5, pady=5)

        self.close_button = tk.Button(self.main_frame, text="Close", command=self.close_chat)
        self.close_button.pack(side="left", anchor="center", expand=True,fill="x")
        # Function to update user status
        def update_user_status():
            if not self.update_users:  # Stop updating if the flag is False
                return
            users_status = self.check_user_status("chat_log.json")
            #print(users_status)
            self.user_text.delete('1.0', tk.END)  # Clear existing text
            self.user_text.insert(tk.END, "Users Status:\n")
            for user, status in users_status.items():
                if len(str(status)) < 10:
                    self.user_text.insert(tk.END, f"{user}: {status}\n")
            # Schedule the next update after 5 seconds
            self.main_frame.after(5000, update_user_status)

        # Start updating user status
        self.update_users = True
        update_user_status()


    def check_user_status(self, log_file, threshold=10):
        current_time = time.time()
        users_status = {}

        # Parse the log file
        with open(log_file, 'r') as file:
            for line in file:
                try:
                    data = json.loads(line)
                    #print(data.items())
                    for user, info in data.items():
                        if "sender_ip" in info:
                            sender_username = user
                            timestamp = info.get("timestamp")
                            #print(timestamp)
                            if sender_username not in users_status:
                                users_status[sender_username] = {
                                    "last_announcement": timestamp
                                }
                            else:
                                # Update the last announcement timestamp if it's newer
                                users_status[sender_username]["last_announcement"] = max(
                                    users_status[sender_username]["last_announcement"], timestamp
                                )
                except json.JSONDecodeError:
                    print("Error decoding JSON:", line)
                except TypeError:
                    pass

        # Determine user status
        for user, info in users_status.items():
            last_announcement = info["last_announcement"]
            if current_time - last_announcement <= threshold:
                users_status[user] = "Online"
            elif current_time - last_announcement <= threshold*6*15:
                users_status[user] = "Away"
            else:
                continue

        return users_status

    def show_chat(self):
        self.display_event("Displaying chat\n")
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.main_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)


        self.secure_button= tk.Button(self.main_frame,text="Secure Chat", command=self.secure_chat)
        self.secure_button.pack(side="top", anchor="center", padx=10, pady=10, fill="both", expand=True)

        self.unsecure_button= tk.Button(self.main_frame,text="Unsecure Chat", command=self.unsecure_chat)
        self.unsecure_button.pack(side="top", anchor="center", padx=10, pady=10, fill="both", expand=True)



    def secure_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        #self.main_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        #self.secure_chat_frame = tk.Frmae(self.main_frame)
        #self.secure_chat_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        self.target_username_label = tk.Label(self.main_frame, text="Enter Target Username:")
        self.target_username_label.pack(side="top",anchor="center", padx=10, pady=10)#, fill="both")#, expand=True)

        self.target_username_entry = tk.Entry(self.main_frame)
        self.target_username_entry.pack(side="top", fill="both", expand=True)#, fill="both")#, expand=True)

        self.submit_button = tk.Button(self.main_frame, text="Submit", command=lambda: self.initiate_chat("secured_chat"))
        self.submit_button.pack(side="top", anchor="center", padx=10, pady=10)

        self.display_event(f"Pressed secure chat button")


    def initiate_chat(self, mode):
        self.display_event(f"Mode is {mode}")
        target_username = self.target_username_entry.get()
        self.display_event(f"Target username is {target_username}")

        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.create_chat_input_frame(mode,target_username)
        #self.message = self.message_entry.get()


    def create_chat_input_frame(self,mode,target_username):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.chat_label = tk.Label(self.main_frame, text="Chat", font=("Helvetica", 14, "bold"))
        self.chat_label.pack(anchor="w", padx=10, pady=5)

        self.message_entry = tk.Entry(self.main_frame)
        self.message_entry.pack(side="top", fill="both", expand=True)

        self.send_button = tk.Button(self.main_frame, text="Send", command=lambda: self.send_message(mode, target_username))
        self.send_button.pack(side="left", anchor="center", expand=True,fill="x")

        self.close_button = tk.Button(self.main_frame, text="Close Chat", command=self.close_chat)
        self.close_button.pack(side="left", anchor="center", expand=True,fill="x")

    def close_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.display_text()

    def send_message(self,mode,target_username):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.message = self.message_entry.get()
        if self.message:
            #self.message_entry.delete(0, tk.END)
            # Call the send_message method of the client instance
            if client and target_username and self.message:
                #client.target_username = target_username
                client.chat_initiator(mode, target_username,self.message)
                  # Show the chat input frame
            self.display_tx(f"Sent: '{self.message}'. To: {target_username}")

    def unsecure_chat(self):
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()
        self.main_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        #self.secure_chat_frame = tk.Frmae(self.main_frame)
        #self.secure_chat_frame.pack(side="left", anchor = "center",padx=10, pady=10,  expand=True)

        self.target_username_label = tk.Label(self.main_frame, text="Enter Target Username:")
        self.target_username_label.pack(side="top",anchor="center", padx=10, pady=10)#, fill="both")#, expand=True)

        self.target_username_entry = tk.Entry(self.main_frame)
        self.target_username_entry.pack(side="top", fill="both", expand=True)#, fill="both")#, expand=True)

        self.submit_button = tk.Button(self.main_frame, text="Submit", command=lambda: self.initiate_chat("unsecured_chat"))
        self.submit_button.pack(side="top", anchor="center", padx=10, pady=10)

        self.display_event(f"Pressed unsecure chat button")

    def display_hist(self):
        try:
            with open(client.filename, "r") as f:
                chat_history = f.read()
                self.history_text.insert(tk.END, chat_history)
        except FileNotFoundError:
            self.history_text.insert(tk.END, "No chat history found.")

        self.history_text.config(state="disabled")

    def show_history(self):
        self.display_event("Displaying History\n")
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

        self.history_label = tk.Label(self.main_frame, text="History", font=("Helvetica", 14, "bold"))
        self.history_label.pack(side = "top",anchor="center", padx=10, pady=5)

        self.history_text = tk.Text(self.main_frame)
        self.history_text.pack(side="top",fill="both", expand=True)

        self.close_button = tk.Button(self.main_frame, text="Close History",command = self.display_text)
        self.close_button.pack(side="top", anchor="center", expand=True,fill="x")

        self.display_hist()

    def close_history():
        for widget in self.main_frame.winfo_children():
            widget.pack_forget()

    def enter_username(self):
        # Create a new window for entering username
        self.username_window = tk.Toplevel(self.master)
        self.username_window.title("Enter Username")

        # Set the size of the window and center it
        window_width = 300
        window_height = 100
        screen_width = self.username_window.winfo_screenwidth()
        screen_height = self.username_window.winfo_screenheight()
        x_coordinate = (screen_width - window_width) // 2
        y_coordinate = (screen_height - window_height) // 2
        self.username_window.geometry(f"{window_width}x{window_height}+{x_coordinate}+{y_coordinate}")

        # Create and pack the username entry widgets
        label_username = tk.Label(self.username_window, text="Enter your username:")
        label_username.pack()

        entry_username = tk.Entry(self.username_window)
        entry_username.pack()

        enter_button_username = tk.Button(self.username_window, text="Enter", command=lambda: self.process_username(entry_username.get()))
        enter_button_username.pack()

    def process_username(self, username):
        global username_queue  # Use the global username_queue
        # Do something with the entered username, such as storing it or processing it
        self.display_event(f"Entered username: {username} ")

        # Close the username entry window
        self.username_window.destroy()

        # Put the username into the queue
        username_queue.put(username)

        # Update the username label
        self.username_info_label.config(text="Logged in as " + username, bg="lightgreen")




def run_gui():
    root = tk.Tk()

    global app
    app = GUI_P2PChatApplicationClient(root)
    # print(app)
    root.mainloop()
    # Pass the app instance to the run_p2p_chat function
    run_p2p_chat()



def run_p2p_chat():
    global username_queue
    username = username_queue.get()
    global client
    client = P2PChatApplicationClient(username, app)


    # Start threads for each functionality
    announcer_thread = Thread(target=client.service_announcer)
    discovery_thread = Thread(target=client.peer_discovery)
    #chat_thread = Thread(target=client.chat_initiator)
    responder = Thread(target=client.Responder)

    threads.extend([announcer_thread, discovery_thread, responder])
    announcer_thread.start()
    discovery_thread.start()
    #chat_thread.start()
    responder.start()

    # Wait for threads to finish
    announcer_thread.join()
    discovery_thread.join()
    #chat_thread.join()
    responder.join()



if __name__ == "__main__":
    gui_thread = threading.Thread(target=run_gui)
    p2p_thread = threading.Thread(target=run_p2p_chat)

    gui_thread.start()
    p2p_thread.start()

    gui_thread.join()  # Wait for the GUI thread to finish before exiting
