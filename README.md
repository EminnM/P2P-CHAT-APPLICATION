# P2P Chat Application

## Overview

This is a peer-to-peer (P2P) chat application built in Python. It allows users to communicate with each other securely and efficiently over a local network.

## Features

- **Graphical User Interface (GUI):** The application features a user-friendly GUI built using the tkinter library.
- **Secure Communication:** Users can initiate secure chat sessions using encryption techniques.
- **Real-time Updates:** The application provides real-time updates on user statuses and events.
- **Chat History:** Users can view the chat history, including sent and received messages.

## Running the Application

To run the P2P Chat Application:

1. **Clone the repository:** 
   ```bash
   git clone https://github.com/your_username/your_repository.git
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```bash
   python main.py
   ```

## Usage

1. **Username Entry:** When prompted, enter your username to log in to the chat application.
   
2. **Display Users:** Click on the "Display Users" button to view a list of online users.
   
3. **Chat:** To start a chat session with another user, click on the "Chat" button and select whether you want a secure or unsecured chat. Enter the target username and your message, then click "Send".
   
4. **History:** Click on the "History" button to view the chat history.

5. **Exit:** To close the application, click on the "Exit" button.

## Code Overview

### `P2PChatApplicationClient` Class

This class represents the P2P chat client. It includes methods for service announcement, peer discovery, chat initiation, encryption/decryption, and message logging.

```python
# Insert code for P2PChatApplicationClient class here
```

### `GUI_P2PChatApplicationClient` Class

This class represents the GUI for the P2P chat application. It includes methods for displaying events, users, chat, and history.

```python
# Insert code for GUI_P2PChatApplicationClient class here
```

### Running the Application

The application is launched by executing the `run_gui()` and `run_p2p_chat()` functions in separate threads.

```python
# Insert code for running the application here
```

## Contribution Guidelines

Contributions are welcome! If you'd like to contribute to the project, please follow these guidelines:

- Fork the repository.
- Create a new branch for your feature or bug fix.
- Make your changes and ensure they are properly tested.
- Submit a pull request detailing your changes.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
