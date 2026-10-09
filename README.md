
# Performance Comparison of AES and RSA Encryption

## Live Demo

Open the deployed dashboard here: [AES vs RSA Performance Dashboard] https://performance-comparison-aes-and-rsa.onrender.com


## Project Overview
This Cryptography and Network Security (CNS) micro-project compares the encryption and decryption performance of AES and RSA for different input sizes.

## Features
- AES and RSA encryption/decryption benchmarks
- Average execution-time measurements
- Encryption and decryption performance graphs
- Downloadable benchmark results in CSV format
- Automatic performance analysis
- AES-EAX tamper-detection demonstration
- Hybrid encryption using AES for messages and RSA for the AES secret key

## Technologies Used
- Python
- Streamlit
- PyCryptodome
- Pandas
- Matplotlib

## Algorithms
- **AES-256 (EAX mode):** Encrypts messages and verifies their integrity.
- **RSA-2048 (OAEP padding):** Encrypts small messages and AES secret keys.
- **Hybrid encryption:** AES encrypts the message, while RSA encrypts the AES key.

## Run the Project Locally

1. Install Python 3.12 or a compatible Python version.
2. Open a terminal in the project folder.
3. Install dependencies:

   `pip install -r requirements.txt`

4. Start the dashboard:

   `streamlit run app.py`

5. Open the local URL displayed in the terminal, usually `http://localhost:8501`.

## Benchmark Methodology
The application measures average encryption and decryption execution times across selected input sizes. The results depend on the hardware, software environment, and number of repetitions.

RSA supports only small plaintexts when used directly. Therefore, this project tests RSA on smaller messages and AES on a wider range of message sizes.

## Academic Project
**Course:** Cryptography and Network Security (CNS)

**Project Title:** Performance Comparison of AES and RSA Encryption
