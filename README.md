# UnhashedRealities




Unhashed Realities is a demonstration web application that highlights the risks of storing passwords without proper hashing and salting. It allows users to register with a password, then attempts to crack insecure password hashes using a dictionary attack powered by Hashcat and the rockyou.txt wordlist.

## Features

- User registration form
- Password hashing with bcrypt (secure) and MD5 (insecure)
- Dictionary attack simulation using Hashcat
- Reports how fast an insecure password can be cracked
- Simple and clean web interface using Flask

## Technologies Used

- Python
- Flask
- bcrypt
- hashlib (for MD5)
- Hashcat
- rockyou.txt wordlist

## Getting Started

### Prerequisites

- Python 3.8 or higher
- pip
- Hashcat installed and accessible from your terminal
- rockyou.txt wordlist (not included in this repository due to file size)

