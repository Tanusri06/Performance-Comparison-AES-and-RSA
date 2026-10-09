
import time
import pandas as pd
import matplotlib.pyplot as plt

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ==========================================
# 1. AES IMPLEMENTATION
# ==========================================

aes_key = get_random_bytes(32)  # AES-256 key


def aes_encrypt(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext


# Test AES
message = b"Hello, this is our CNS micro project!"

nonce, ciphertext, tag = aes_encrypt(message, aes_key)
decrypted_message = aes_decrypt(nonce, ciphertext, tag, aes_key)

print("--- AES Encryption Test ---")
print("Original message:", message.decode())
print("Encrypted message:", ciphertext.hex())
print("Decrypted message:", decrypted_message.decode())
print("Decryption successful:", message == decrypted_message)


# ==========================================
# 2. RSA IMPLEMENTATION
# ==========================================

rsa_key = RSA.generate(2048)
rsa_public_key = rsa_key.publickey()


def rsa_encrypt(plaintext, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(plaintext)


def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


# Test RSA
rsa_message = b"Hello, this is our CNS micro project!"

encrypted_rsa = rsa_encrypt(rsa_message, rsa_public_key)
decrypted_rsa = rsa_decrypt(encrypted_rsa, rsa_key,)

print("\n--- RSA Encryption Test ---")
print("Original message:", rsa_message.decode())
print("Encrypted message:", encrypted_rsa.hex())
print("Decrypted message:", decrypted_rsa.decode())
print("Decryption successful:", rsa_message == decrypted_rsa)


# ==========================================
# 3. PERFORMANCE CONFIGURATION
# ==========================================

input_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
rsa_input_sizes = [16, 32, 64, 128, 190]

repetitions = 1000
results = []


# ==========================================
# 4. AES ENCRYPTION PERFORMANCE
# ==========================================

print("\n--- AES Encryption Performance ---")

for size in input_sizes:
    data = get_random_bytes(size)

    aes_encrypt(data, aes_key)  # Warm-up

    start_time = time.perf_counter()

    for _ in range(repetitions):
        aes_encrypt(data, aes_key)

    end_time = time.perf_counter()
    average_time = (end_time - start_time) / repetitions

    results.append({
        "Algorithm": "AES",
        "Operation": "Encryption",
        "Input Size (Bytes)": size,
        "Average Time (ms)": average_time * 1000
    })

    print(
        f"Input Size: {size:5} bytes | "
        f"Average Encryption Time: {average_time * 1000:.6f} ms"
    )


# ==========================================
# 5. RSA ENCRYPTION PERFORMANCE
# ==========================================

print("\n--- RSA Encryption Performance ---")

for size in rsa_input_sizes:
    data = get_random_bytes(size)

    rsa_encrypt(data, rsa_public_key)  # Warm-up

    start_time = time.perf_counter()

    for _ in range(repetitions):
        rsa_encrypt(data, rsa_public_key)

    end_time = time.perf_counter()
    average_time = (end_time - start_time) / repetitions

    results.append({
        "Algorithm": "RSA",
        "Operation": "Encryption",
        "Input Size (Bytes)": size,
        "Average Time (ms)": average_time * 1000
    })

    print(
        f"Input Size: {size:5} bytes | "
        f"Average Encryption Time: {average_time * 1000:.6f} ms"
    )


# ==========================================
# 6. AES DECRYPTION PERFORMANCE
# ==========================================

print("\n--- AES Decryption Performance ---")

for size in input_sizes:
    data = get_random_bytes(size)
    nonce, ciphertext, tag = aes_encrypt(data, aes_key)

    aes_decrypt(nonce, ciphertext, tag, aes_key)  # Warm-up

    start_time = time.perf_counter()

    for _ in range(repetitions):
        aes_decrypt(nonce, ciphertext, tag, aes_key)

    end_time = time.perf_counter()
    average_time = (end_time - start_time) / repetitions

    results.append({
        "Algorithm": "AES",
        "Operation": "Decryption",
        "Input Size (Bytes)": size,
        "Average Time (ms)": average_time * 1000
    })

    print(
        f"Input Size: {size:5} bytes | "
        f"Average Decryption Time: {average_time * 1000:.6f} ms"
    )


# ==========================================
# 7. RSA DECRYPTION PERFORMANCE
# ==========================================

print("\n--- RSA Decryption Performance ---")

for size in rsa_input_sizes:
    data = get_random_bytes(size)
    ciphertext = rsa_encrypt(data, rsa_public_key)

    rsa_decrypt(ciphertext, rsa_key)  # Warm-up

    start_time = time.perf_counter()

    for _ in range(repetitions):
        rsa_decrypt(ciphertext, rsa_key)

    end_time = time.perf_counter()
    average_time = (end_time - start_time) / repetitions

    results.append({
        "Algorithm": "RSA",
        "Operation": "Decryption",
        "Input Size (Bytes)": size,
        "Average Time (ms)": average_time * 1000
    })

    print(
        f"Input Size: {size:5} bytes | "
        f"Average Decryption Time: {average_time * 1000:.6f} ms"
    )


# ==========================================
# 8. DISPLAY AND SAVE RESULTS
# ==========================================

results_df = pd.DataFrame(results)

print("\n--- Complete Performance Results ---")
print(results_df.to_string(index=False))

results_df.to_csv("performance_results.csv", index=False)
print("\nResults saved to performance_results.csv")


# ==========================================
# 9. ENCRYPTION PERFORMANCE GRAPH
# ==========================================

encryption_results = results_df[
    results_df["Operation"] == "Encryption"
]

aes_results = encryption_results[
    encryption_results["Algorithm"] == "AES"
]

rsa_results = encryption_results[
    encryption_results["Algorithm"] == "RSA"
]

plt.figure(figsize=(10, 6))

plt.plot(
    aes_results["Input Size (Bytes)"],
    aes_results["Average Time (ms)"],
    marker="o",
    label="AES Encryption"
)

plt.plot(
    rsa_results["Input Size (Bytes)"],
    rsa_results["Average Time (ms)"],
    marker="s",
    label="RSA Encryption"
)

plt.xlabel("Input Size (Bytes)")
plt.ylabel("Average Encryption Time (ms)")
plt.title("AES vs RSA Encryption Performance")
plt.legend()
plt.grid(True)
plt.tight_layout()

plt.savefig("encryption_performance.png", dpi=300)
plt.close()

print("Encryption performance graph saved!")


# ==========================================
# 10. DECRYPTION PERFORMANCE GRAPH
# ==========================================

decryption_results = results_df[
    results_df["Operation"] == "Decryption"
]

aes_decryption = decryption_results[
    decryption_results["Algorithm"] == "AES"
]

rsa_decryption = decryption_results[
    decryption_results["Algorithm"] == "RSA"
]

plt.figure(figsize=(10, 6))

plt.plot(
    aes_decryption["Input Size (Bytes)"],
    aes_decryption["Average Time (ms)"],
    marker="o",
    label="AES Decryption"
)

plt.plot(
    rsa_decryption["Input Size (Bytes)"],
    rsa_decryption["Average Time (ms)"],
    marker="s",
    label="RSA Decryption"
)

plt.xlabel("Input Size (Bytes)")
plt.ylabel("Average Decryption Time (ms)")
plt.title("AES vs RSA Decryption Performance")
plt.legend()
plt.grid(True)
plt.tight_layout()

plt.savefig("decryption_performance.png", dpi=300)
plt.close()

print("Decryption performance graph saved!")

print("\nAll experiments and graph generation completed successfully.")
