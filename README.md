# File Encryptor/Decryptor

## Overview

This project provides a simple script for encrypting and decrypting files using the AES encryption algorithm. The script is built using Python and the `cryptography` library to ensure secure file encryption and decryption.

## Features

- **Encrypt Files**: Securely encrypt any file using AES encryption.
- **Decrypt Files**: Decrypt previously encrypted files.
- **Password Protection**: Use a password to generate a secure encryption key.
- **Automatic Output File Naming**: Automatically generates output file names if not specified.
- **Error Handling**: Includes error handling for incorrect passwords and missing files.

## Requirements

- Python 3.6 or later
- `cryptography` library (install with `pip install cryptography`)

## Installation

1. **Clone the Repository**:
   ```sh
   git clone https://github.com/Hapi-iz/FileEncryptorDecryptor.git
   cd FileEncryptorDecryptor
   ```

2. **Install Required Packages**:
   ```sh
   pip install cryptography
   ```

## Usage

The script provides a command-line interface for encrypting and decrypting files.

### Encrypt a File

To encrypt a file, use the `-e` option followed by the input file name and the password. Optionally, you can specify an output file name using the `-o` option.

```sh
python enc.py -e input.txt my_password -o encrypted.enc
```

If you omit the `-o` option, the script will create an encrypted file named `input.txt.enc`.

### Decrypt a File

To decrypt a file, use the `-d` option followed by the input file name and the password. Optionally, you can specify an output file name using the `-o` option.

```sh
python enc.py -d encrypted.enc my_password -o decrypted.txt
```

If you omit the `-o` option, the script will create a decrypted file named `encrypted`.

### Example Commands

- **Encrypting a File**:
  ```sh
  python enc.py -e example.txt my_secure_password
  ```

- **Decrypting a File**:
  ```sh
  python enc.py -d example.txt.enc my_secure_password
  ```

## Creating an Alias for Easy Use

To make it easier to run the script, you can create an alias. This allows you to run the script with a simple command instead of typing the full path.

### Windows

1. Open Command Prompt as Administrator.
2. Create an alias by adding it to your `autoexec.bat` file or by using the `doskey` command:
   ```sh
   doskey enc=python C:\path\to\your\script\enc.py $*
   ```

   Replace `C:\path\to\your\script\enc.py` with the actual path to your script.

### macOS/Linux

1. Open your terminal.
2. Edit your shell configuration file (e.g., `.bashrc`, `.zshrc`):
   ```sh
   nano ~/.bashrc  # or ~/.zshrc
   ```

3. Add the alias to the file:
   ```sh
   alias enc="python /path/to/your/script/enc.py"
   ```

   Replace `/path/to/your/script/enc.py` with the actual path to your script.

4. Save the file and reload the shell configuration:
   ```sh
   source ~/.bashrc  # or ~/.zshrc
   ```

Now you can use the `enc` command to run the script:

- **Encrypting a File**:
  ```sh
  enc -e example.txt my_secure_password
  ```

- **Decrypting a File**:
  ```sh
  enc -d example.txt.enc my_secure_password
  ```

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.
