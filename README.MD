# [P]ortswigger [A]cademy [A]utomatic [S]olver
#### With this tool, you can solve the labs in PortSwigger Academy with a few commands.
 - For now, PAAS only available for five categories: Authentication, Directory Traversal, OSCi, Access Control Vulnerabilities and SSRF
 - I'm developing the tool. More labs will be added in the future.
 
#### Usage
 - [x] Burp Suite must be open while the PAAS is running.
 - [x] Run the tool with the command `./python paas_linux.py`.
 - [x] Type `exit` to exit the tool, and `menu` to return to the main menu.
 
#### 07.07.2023 Update Notes
- [x] new labs added
- [x] some functions have been made asynchronous
- [x] with asynchronous attack feature, paas can resolve the "2FA bypass using a brute-force attack" lab 100x faster than PortSwigger Academy's solution
