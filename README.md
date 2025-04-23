# 📦 File-Transfer-Protocol
A complete FTP system implemented in C++, consisting of a client program (`Ftp-Client3.cpp`) and a server program (`FTP-Server1.cpp`) that support both active (PORT) and passive (PASV) modes, featuring user authentication, file upload/download, and directory management capabilities.
# 🛠️ System Requirements
**1. Operating System:** Linux (e.g., Ubuntu, Debian, CentOS)  
**2. Compiler:** Requires g++ (GNU C++ Compiler)  
**3. Dependencies:** Uses standard Linux system libraries, no extra dependencies required  
**4. Network:** Ensure that the client and server machines are network accessible  
**5. Install the Compiler (if not installed):**
```bash
sudo apt update
sudo apt install g++
```
# 🚀 Getting Start
## 1. Compile the FTP Server and Client
```bash
g++ -o ftp_server FTP-Server1.cpp
g++ -o ftp_client Ftp-Client3.cpp
```
## 2. Run the Server  
In terminal 1:
```bash
./ftp_server 2121 2020
```
## 3. Run the Client  
In terminal 2 (replace 127.0.0.1 with your server IP):
```bash
./ftp_client 127.0.0.1 2121
```
# 🔐 Login Credentials
The following preset accounts are available for testing:  
Username: HjYuan, Password: 1234  
Username: Patton, Password: 4567  
# 📄 Supported Client Commands

| Command        | Description                                        |
|----------------|----------------------------------------------------|
| `put <file>`   | Upload a local file to the server                  |
| `get <file>`   | Download a file from the server                    |
| `pwd`          | Show the server’s current directory                |
| `cd <dir>`     | Change the server’s current directory              |
| `dir`          | List contents of the server’s current directory    |
| `client_pwd`   | Show the client’s current local directory          |
| `client_cd`    | Change the client’s local directory                |
| `client_dir`   | List contents of the client’s local directory      |
| `?`            | Show all supported commands                        |
| `quit`         | Exit the client program                            |
