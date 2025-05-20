# Config Endpoint

## Description

This project implements a secure server that delivers encrypted configuration data to authorized clients over a network. It uses SSL/TLS for secure communication, JWT for authentication, and a hybrid encryption approach (AES for symmetric encryption and RSA for key exchange) to ensure the confidentiality and integrity of the data. This is used as part of our AI agent application Mimir.

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Installation

### Prerequisites

- **CMake** 3.10 or higher
- **C++17 compliant compiler** (e.g., g++, clang++)
- **Boost** (system and thread components)
- **jsoncpp**
- **OpenSSL**
- **pkg-config** (for finding jsoncpp)

### Steps

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/secure-config-server.git
   ```

2. **Install dependencies**:
   - On Ubuntu:
     ```bash
     sudo apt-get install cmake g++ libboost-system-dev libboost-thread-dev libjsoncpp-dev libssl-dev pkg-config
     ```
   - On macOS (with Homebrew):
     ```bash
     brew install cmake boost jsoncpp openssl pkg-config
     ```

3. **Build the project**:
   ```bash
   cd secure-config-server
   mkdir build && cd build
   cmake ..
   cmake --build .
   ```

4. **Output**:
   The executable will be located in `bin/ConfigEndpoint`.

**Note**: Ensure that `cert.pem`, `key.pem`, and `data/secrets/config.json` are present in the project root directory. These files are required for the server to function.

### Generating SSL Certificates (for testing)

If you do not have SSL certificates, you can generate self-signed certificates for testing purposes using OpenSSL:
```bash
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```
- **Important**: For production use, obtain certificates from a trusted Certificate Authority (CA).

### Configuration File

- Create a `config.json` file in the `data/secrets/` directory.
- The file should contain valid JSON data that the server will encrypt and send to clients.
- **Security Note**: Do not commit sensitive files like `cert.pem`, `key.pem`, and `config.json` to version control. Ensure they are listed in `.gitignore`.

## Usage

### Running the Server

Run the server from the project root directory:
```bash
./bin/ConfigEndpoint
```
- The server will listen on port 4433 for SSL connections.
- Clients can send HTTP POST requests with a JSON body containing:
  - `token`: A valid JWT token issued by "https://securetoken.google.com/YOUR_PROJECT_ID".
  - `public_key`: The client's RSA public key for encrypting the AES key.

**Example Client Request**:
```json
{
  "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjIzNjk3MDY3Nzg2MzM4Nzk0NjY3NSJ9...",
  "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

**Server Response**:
- If the token is valid, the server responds with a JSON object containing:
  - `encrypted_config`: The encrypted configuration data (Base64-encoded).
  - `encrypted_key`: The encrypted AES key (Base64-encoded).
  - `iv`: The initialization vector (Base64-encoded).

**Note**: Replace `YOUR_PROJECT_ID` in the JWT issuer with your actual project ID (e.g., for Firebase or another JWT provider).

## Security Considerations

- **SSL Certificates**: Use production-grade SSL certificates obtained from a trusted Certificate Authority (CA) instead of self-signed certificates.
- **Private Key**: Keep `key.pem` secure and do not share it.
- **Configuration File**: Protect `config.json` as it may contain sensitive information. Avoid committing it to version control.
- **JWT Verification**: Ensure that the JWT issuer matches your actual project ID.

## Contributing

Contributions are welcome! Please fork the repository, make your changes, and submit a pull request. For bug reports or feature requests, open an issue on GitHub.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE.txt) file for details.

## Contact

For any questions or feedback, contact marius.hanssen@retinueai.com or josefjameshard@retinueai.com
