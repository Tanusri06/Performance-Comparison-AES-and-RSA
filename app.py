
import time
import pandas as pd
import streamlit as st
import matplotlib.pyplot as plt

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes


# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="AES vs RSA Performance",
    page_icon="🔐",
    layout="wide"
)

st.title("🔐 Performance Comparison of AES and RSA Encryption")
st.write(
    "Compare AES and RSA encryption/decryption execution times "
    "for different input sizes."
)

st.info(
    "AES supports larger inputs. RSA is tested only with small messages "
    "because of its plaintext size limitation."
)


# ==========================================
# 2. SIDEBAR SETTINGS
# ==========================================

st.sidebar.header("Experiment Settings")

repetitions = st.sidebar.selectbox(
    "Repetitions per input size",
    [100, 500, 1000],
    index=1
)

run_button = st.sidebar.button(
    "Run Performance Experiment",
    type="primary"
)


# ==========================================
# 3. ENCRYPTION FUNCTIONS
# ==========================================

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag


def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def rsa_encrypt(data, public_key):
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(data)


def rsa_decrypt(ciphertext, private_key):
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext)


# ==========================================
# 4. TIMING FUNCTION
# ==========================================

def measure_time(function, repetitions):
    function()  # Warm-up

    start = time.perf_counter()

    for _ in range(repetitions):
        function()

    end = time.perf_counter()

    return ((end - start) / repetitions) * 1000


# ==========================================
# 5. BENCHMARK FUNCTION
# ==========================================

def run_benchmark(repetitions):
    aes_key = get_random_bytes(32)

    rsa_key = RSA.generate(2048)
    rsa_public_key = rsa_key.publickey()

    aes_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
    rsa_sizes = [16, 32, 64, 128, 190]

    results = []

    total_steps = len(aes_sizes) * 2 + len(rsa_sizes) * 2
    progress = st.progress(0)
    status = st.empty()
    step = 0

    for algorithm, sizes in [
        ("AES", aes_sizes),
        ("RSA", rsa_sizes)
    ]:
        for operation in ["Encryption", "Decryption"]:
            status.write(
                f"Measuring {algorithm} {operation.lower()}..."
            )

            for size in sizes:
                data = get_random_bytes(size)

                if algorithm == "AES":
                    nonce, ciphertext, tag = aes_encrypt(data, aes_key)

                    if operation == "Encryption":
                        function = lambda d=data: aes_encrypt(d, aes_key)
                    else:
                        function = lambda n=nonce, c=ciphertext, t=tag: (
                            aes_decrypt(n, c, t, aes_key)
                        )

                else:
                    ciphertext = rsa_encrypt(data, rsa_public_key)

                    if operation == "Encryption":
                        function = lambda d=data: rsa_encrypt(
                            d, rsa_public_key
                        )
                    else:
                        function = lambda c=ciphertext: rsa_decrypt(
                            c, rsa_key
                        )

                average_ms = measure_time(function, repetitions)

                results.append({
                    "Algorithm": algorithm,
                    "Operation": operation,
                    "Input Size (Bytes)": size,
                    "Average Time (ms)": average_ms
                })

                step += 1
                progress.progress(step / total_steps)

    status.success("Benchmark completed!")

    return pd.DataFrame(results)


# ==========================================
# 6. RUN BENCHMARK
# ==========================================

if run_button:
    with st.spinner("Running encryption and decryption benchmarks..."):
        st.session_state["results"] = run_benchmark(repetitions)


# ==========================================
# 7. DISPLAY RESULTS AND ANALYSIS
# ==========================================

if "results" in st.session_state:

    results_df = st.session_state["results"]

    st.subheader("Performance Summary")

    aes_enc = results_df[
        (results_df["Algorithm"] == "AES")
        & (results_df["Operation"] == "Encryption")
    ]["Average Time (ms)"].mean()

    rsa_enc = results_df[
        (results_df["Algorithm"] == "RSA")
        & (results_df["Operation"] == "Encryption")
    ]["Average Time (ms)"].mean()

    aes_dec = results_df[
        (results_df["Algorithm"] == "AES")
        & (results_df["Operation"] == "Decryption")
    ]["Average Time (ms)"].mean()

    rsa_dec = results_df[
        (results_df["Algorithm"] == "RSA")
        & (results_df["Operation"] == "Decryption")
    ]["Average Time (ms)"].mean()

    col1, col2 = st.columns(2)

    col1.metric(
        "AES mean encryption time",
        f"{aes_enc:.4f} ms"
    )

    col2.metric(
        "RSA mean encryption time",
        f"{rsa_enc:.4f} ms"
    )

    # ======================================
    # EXTRA FEATURE 1: AUTOMATIC ANALYSIS
    # ======================================

    st.divider()
    st.subheader("🔎 Automatic Performance Analysis")

    col3, col4 = st.columns(2)

    col3.metric(
        "AES mean decryption time",
        f"{aes_dec:.4f} ms"
    )

    col4.metric(
        "RSA mean decryption time",
        f"{rsa_dec:.4f} ms"
    )

    enc_ratio = rsa_enc / aes_enc if aes_enc > 0 else 0
    dec_ratio = rsa_dec / aes_dec if aes_dec > 0 else 0

    col5, col6 = st.columns(2)

    col5.metric(
        "RSA/AES encryption time ratio",
        f"{enc_ratio:.2f}×"
    )

    col6.metric(
        "RSA/AES decryption time ratio",
        f"{dec_ratio:.2f}×"
    )

    st.markdown("#### Interpretation")

    if enc_ratio > 1:
        st.write(
            f"Across the tested input sizes, RSA's mean encryption "
            f"time was {enc_ratio:.2f} times AES's mean encryption time."
        )
    else:
        st.write(
            "RSA's mean encryption time was not higher in this run. "
            "Repeat the experiment to investigate timing variability."
        )

    if dec_ratio > 1:
        st.write(
            f"RSA's mean decryption time was {dec_ratio:.2f} times "
            f"AES's mean decryption time in this run."
        )
    else:
        st.write(
            "RSA's mean decryption time was not higher in this run. "
            "Repeat the experiment to investigate timing variability."
        )

    st.caption(
        "These ratios compare means across the tested sizes. "
        "They are descriptive measurements, not universal speed ratios."
    )

    # ======================================
    # RESULTS TABLE AND CSV DOWNLOAD
    # ======================================

    st.subheader("Complete Results")

    st.dataframe(
        results_df,
        use_container_width=True,
        hide_index=True
    )

    csv_data = results_df.to_csv(index=False).encode("utf-8")

    st.download_button(
        "Download Results CSV",
        data=csv_data,
        file_name="performance_results.csv",
        mime="text/csv"
    )

    # ======================================
    # ENCRYPTION GRAPH
    # ======================================

    st.subheader("Encryption Performance")

    encryption_df = results_df[
        results_df["Operation"] == "Encryption"
    ]

    fig1, ax1 = plt.subplots(figsize=(9, 5))

    for algorithm in ["AES", "RSA"]:
        subset = encryption_df[
            encryption_df["Algorithm"] == algorithm
        ]

        ax1.plot(
            subset["Input Size (Bytes)"],
            subset["Average Time (ms)"],
            marker="o",
            label=algorithm
        )

    ax1.set_xlabel("Input Size (Bytes)")
    ax1.set_ylabel("Average Time (ms)")
    ax1.set_title("AES vs RSA Encryption Performance")
    ax1.legend()
    ax1.grid(True, alpha=0.3)

    fig1.tight_layout()
    st.pyplot(fig1)
    plt.close(fig1)

    # ======================================
    # DECRYPTION GRAPH
    # ======================================

    st.subheader("Decryption Performance")

    decryption_df = results_df[
        results_df["Operation"] == "Decryption"
    ]

    fig2, ax2 = plt.subplots(figsize=(9, 5))

    for algorithm in ["AES", "RSA"]:
        subset = decryption_df[
            decryption_df["Algorithm"] == algorithm
        ]

        ax2.plot(
            subset["Input Size (Bytes)"],
            subset["Average Time (ms)"],
            marker="o",
            label=algorithm
        )

    ax2.set_xlabel("Input Size (Bytes)")
    ax2.set_ylabel("Average Time (ms)")
    ax2.set_title("AES vs RSA Decryption Performance")
    ax2.legend()
    ax2.grid(True, alpha=0.3)

    fig2.tight_layout()
    st.pyplot(fig2)
    plt.close(fig2)

else:
    st.info(
        "Choose your settings and click Run Performance Experiment."
    )


# ==========================================
# 8. EXTRA FEATURE 2: AES TAMPER DETECTION
# ==========================================

st.divider()
st.subheader("🛡️ AES Message Integrity and Tamper Detection")

st.write(
    "AES-EAX provides authenticated encryption. This demonstration "
    "checks whether modified ciphertext or an incorrect authentication "
    "tag is detected during decryption."
)

demo_message = st.text_input(
    "Enter a message for the security test",
    value="Secure message"
)

if st.button("Run Tamper Detection Test"):

    demo_key = get_random_bytes(32)

    nonce, demo_ciphertext, demo_tag = aes_encrypt(
        demo_message.encode("utf-8"),
        demo_key
    )

    st.write("Original ciphertext (hexadecimal):")
    st.code(demo_ciphertext.hex())

    # Correct ciphertext and tag
    try:
        recovered = aes_decrypt(
            nonce,
            demo_ciphertext,
            demo_tag,
            demo_key
        )

        st.success(
            f"Untampered message verified: "
            f"{recovered.decode('utf-8')}"
        )

    except ValueError:
        st.error("Verification unexpectedly failed.")

    # Deliberately change the authentication tag
    altered_tag = bytes([demo_tag[0] ^ 1]) + demo_tag[1:]

    try:
        aes_decrypt(
            nonce,
            demo_ciphertext,
            altered_tag,
            demo_key
        )

        st.error("Tampered data was not detected.")

    except ValueError:
        st.success(
            "Tampering detected: modified authentication tag rejected."
        )


# ==========================================
# 9. FOOTER
# ==========================================

st.divider()

st.caption(
    "Cryptography and Network Security | "
    "AES and RSA Performance Comparison"
)



# --------------------------------------------------
# Hybrid Encryption Demonstration: AES + RSA
# --------------------------------------------------

st.divider()
st.header("🔐 Hybrid Encryption Demonstration")
st.write(
    "AES encrypts the message, while RSA encrypts the AES secret key. "
    "The receiver uses RSA to recover the key and AES to decrypt "
    "and authenticate the original message."
)

hybrid_message = st.text_area(
    "Enter a message to encrypt",
    value="Confidential message for hybrid encryption",
    key="hybrid_message"
)

if st.button("Run Hybrid Encryption", type="primary"):
    try:
        # 1. Generate a temporary RSA key pair
        hybrid_rsa_key = RSA.generate(2048)
        hybrid_public_key = hybrid_rsa_key.publickey()

        # 2. Generate an AES-256 secret key
        hybrid_aes_key = get_random_bytes(32)

        # 3. Encrypt the message using AES-EAX
        message_bytes = hybrid_message.encode("utf-8")
        hybrid_nonce, hybrid_ciphertext, hybrid_tag = aes_encrypt(
            message_bytes, hybrid_aes_key
        )

        # 4. Encrypt the AES secret key using RSA-OAEP
        encrypted_aes_key = rsa_encrypt(
            hybrid_aes_key, hybrid_public_key
        )

        # 5. Receiver decrypts the AES key using the RSA private key
        recovered_aes_key = rsa_decrypt(
            encrypted_aes_key, hybrid_rsa_key
        )

        # 6. Decrypt and authenticate the message using AES-EAX
        recovered_message = aes_decrypt(
            hybrid_nonce,
            hybrid_ciphertext,
            hybrid_tag,
            recovered_aes_key
        ).decode("utf-8")

        st.subheader("Encryption Results")

        st.write("**Original message**")
        st.code(hybrid_message or "(empty message)")

        st.write("**AES-encrypted message (hexadecimal)**")
        st.code(hybrid_ciphertext.hex())

        st.write("**RSA-encrypted AES key (hexadecimal)**")
        st.code(encrypted_aes_key.hex())

        st.write("**Decrypted message**")
        st.code(recovered_message or "(empty message)")

        if recovered_message == hybrid_message:
            st.success(
                "Success! The AES key was recovered using RSA, "
                "and the original message was decrypted and verified."
            )
        else:
            st.error("The recovered message does not match.")

        st.caption(
            "Demonstration only: a temporary RSA key pair is generated "
            "each time. The keys are not saved for later decryption."
        )

    except Exception as error:
        st.error(f"Hybrid encryption demonstration failed: {error}")
