import streamlit as st
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.fernet import Fernet
from PIL import Image
import io
import base64
import numpy as np
import os
import zlib

# Function to derive encryption key
def derive_key(password: str, salt: bytes = b'static_salt'):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# AES-256 Encrypt text
def aes_encrypt_text(text, password):
    # Generate a key from the password
    key = derive_key(password, b'text_salt')[:32]  # Use 32 bytes for AES-256
    
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    
    # Create an encryptor object
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    
    # Pad the text to be a multiple of 16 bytes (AES block size)
    text_bytes = text.encode('utf-8')
    padding_length = 16 - (len(text_bytes) % 16)
    padded_text = text_bytes + bytes([padding_length]) * padding_length
    
    # Encrypt the padded text
    ciphertext = encryptor.update(padded_text) + encryptor.finalize()
    
    # Return IV + ciphertext
    return iv + ciphertext

# AES-256 Decrypt text
def aes_decrypt_text(encrypted_data, password):
    try:
        # Extract IV (first 16 bytes)
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        
        # Derive key from password
        key = derive_key(password, b'text_salt')[:32]  # Use 32 bytes for AES-256
        
        # Create a decryptor object
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        
        # Decrypt the ciphertext
        padded_text = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_text[-1]
        text_bytes = padded_text[:-padding_length]
        
        # Convert bytes to string
        return text_bytes.decode('utf-8')
    except Exception as e:
        st.error(f"Text decryption failed: {e}")
        return None

# Function to embed text in an image using LSB in alpha channel
def embed_text_in_image(img, encrypted_text):
    # Convert image to RGBA if it isn't already
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    # Get image data as a NumPy array (int16 for safety)
    img_array = np.array(img, dtype=np.int16)

    # Prepare header (length of encrypted text as an 8-byte value)
    header = len(encrypted_text).to_bytes(8, byteorder='big')
    data_to_hide = header + encrypted_text

    # Compress data to reduce size
    compressed_data = zlib.compress(data_to_hide)

    # Convert compressed data to Base64, then to binary
    text_b64 = base64.b64encode(compressed_data).decode()
    binary_data = ''.join(format(ord(char), '08b') for char in text_b64)

    # Append EOF marker
    eof_marker = '1111111111111110'
    binary_data += eof_marker

    # Check if the image is large enough to hold the data
    if len(binary_data) > img_array.shape[0] * img_array.shape[1]:
        st.error("Image is too small to hold this message!")
        return None

    # Flatten the alpha channel
    alpha_channel = img_array[:, :, 3].flatten()

    # Debugging: Check min/max values before modifying
    print(f"Before embedding: min={alpha_channel.min()}, max={alpha_channel.max()}")

    # Embed each bit into the LSB of the alpha channel
    for i in range(len(binary_data)):
        if i < len(alpha_channel):
            old_value = alpha_channel[i]
            bit_to_embed = int(binary_data[i])

            # Embed the bit safely
            new_value = (old_value & ~1) | bit_to_embed

            # Ensure new value stays within uint8 range (0-255)
            if new_value < 0 or new_value > 255:
                print(f"Warning! Overflow at index {i}: {new_value}")
                new_value = np.clip(new_value, 0, 255)  # Fix overflow

            alpha_channel[i] = new_value  # Assign safely

    # Debugging: Check min/max values after modifying
    print(f"After embedding: min={alpha_channel.min()}, max={alpha_channel.max()}")

    # Reshape alpha channel and put it back into the image
    img_array[:, :, 3] = alpha_channel.reshape(img_array.shape[0], img_array.shape[1])

    return Image.fromarray(img_array.astype(np.uint8))
# Function to extract text from an image
def extract_text_from_image(img):
    try:
        # Convert image to RGBA if needed
        if img.mode != 'RGBA':
            img = img.convert('RGBA')
        
        # Get image data as numpy array
        img_array = np.array(img)
        
        # Get alpha channel
        alpha_channel = img_array[:, :, 3].flatten()
        
        # Extract LSBs to get binary data
        binary_data = ''
        # First get 64 bits for the header (8 bytes)
        for i in range(min(64, len(alpha_channel))):
            binary_data += str(alpha_channel[i] & 1)
        
        # Convert header to get data length
        header_bytes = int(binary_data[:64], 2).to_bytes(8, byteorder='big')
        data_length = int.from_bytes(header_bytes, byteorder='big')
        
        # Extract the rest of the bits
        total_bits_needed = 64 + (data_length * 8)
        
        if total_bits_needed > len(alpha_channel):
            st.error("Image doesn't contain expected amount of data")
            return None
        
        # Extract remaining bits if needed
        if len(binary_data) < total_bits_needed:
            for i in range(64, total_bits_needed):
                binary_data += str(alpha_channel[i] & 1)
        
        # Convert binary data to bytes (skip header)
        extracted_bytes = bytearray()
        for i in range(64, len(binary_data), 8):
            if i + 8 <= len(binary_data):
                byte = binary_data[i:i+8]
                extracted_bytes.append(int(byte, 2))
        
        return bytes(extracted_bytes)
    except Exception as e:
        st.error(f"Error extracting text: {e}")
        return None

# Function to embed an image inside another using LSB
def embed_image(cover_img, secret_img):
    # Convert cover image to numpy array (int16 to avoid overflow issues)
    cover_pixels = np.array(cover_img, dtype=np.int16)
    cover_capacity = cover_pixels.size * 3  # Each pixel stores 3 bits (RGB)

    # Convert secret image to bytes and compress it
    secret_bytes_io = io.BytesIO()
    secret_img.save(secret_bytes_io, format="PNG")
    secret_bytes = secret_bytes_io.getvalue()
    compressed_bytes = zlib.compress(secret_bytes)  # Compress before embedding

    # Convert compressed bytes to Base64 and then binary
    secret_b64 = base64.b64encode(compressed_bytes).decode()
    secret_bin = ''.join(format(ord(char), '08b') for char in secret_b64)

    # Append EOF marker
    eof_marker = '1111111111111110'
    secret_bin += eof_marker

    # Check if the secret image fits in the cover image
    if len(secret_bin) > cover_capacity:
        st.error("Secret image is too large! Resize and try again.")
        return None

    # Flatten the cover image array for easy bit embedding
    flat_cover = cover_pixels.flatten()

    # Debugging: Check min/max values before modifying
    print(f"Before embedding: min={flat_cover.min()}, max={flat_cover.max()}")

    # Embed the binary secret data into the LSB of the cover image
    for i in range(len(secret_bin)):
        old_value = flat_cover[i]
        bit_to_embed = int(secret_bin[i])

        # Embed the bit safely
        new_value = (old_value & ~1) | bit_to_embed

        # Ensure new value stays within uint8 range (0-255)
        if new_value < 0 or new_value > 255:
            print(f"Warning! Overflow at index {i}: {new_value}")
            new_value = np.clip(new_value, 0, 255)  # Fix overflow

        flat_cover[i] = new_value  # Assign safely

    # Debugging: Check min/max values after modifying
    print(f"After embedding: min={flat_cover.min()}, max={flat_cover.max()}")

    # Reshape back to original cover image dimensions
    stego_image = flat_cover.reshape(cover_pixels.shape).astype(np.uint8)
    return Image.fromarray(stego_image)

# Function to extract a hidden image
def extract_image(cover_image):
    try:
        # Convert image to numpy array
        cover_array = np.array(cover_image)
        flat_cover = cover_array.flatten()
        
        # Extract LSBs from all pixels
        bits = ''
        for i in range(min(8*8, len(flat_cover))):  # Extract header first (8 bytes)
            bits += str(flat_cover[i] & 1)
        
        # Convert first 64 bits to header (8 bytes for length info)
        header_bytes = bytearray()
        for i in range(0, 64, 8):
            if i + 8 <= len(bits):
                byte = bits[i:i+8]
                header_bytes.append(int(byte, 2))
        
        # Decode header to get length of hidden data
        try:
            data_length = int(header_bytes.decode())
            
            # Now we know how many more bits to extract
            total_bits_needed = 64 + (data_length * 8)  # header + actual data
            
            # Extract remaining bits if needed
            if len(bits) < total_bits_needed and len(flat_cover) >= total_bits_needed:
                for i in range(64, total_bits_needed):
                    if i < len(flat_cover):
                        bits += str(flat_cover[i] & 1)
            
            # Extract image data (skip header)
            image_bits = bits[64:total_bits_needed]
            
            # Convert bits to bytes
            extracted_bytes = bytearray()
            for i in range(0, len(image_bits), 8):
                if i + 8 <= len(image_bits):
                    byte = image_bits[i:i+8]
                    extracted_bytes.append(int(byte, 2))
            
            # Create image from bytes
            try:
                img = Image.open(io.BytesIO(extracted_bytes))
                return img
            except Exception as e:
                st.error(f"Error creating image from extracted data: {e}")
                return None
        except ValueError as e:
            st.error(f"Error decoding header: {e}")
            return None
            
    except Exception as e:
        st.error(f"Error during extraction: {e}")
        return None

# Encrypt Image Function
def encrypt_image(image_bytes, password):
    cipher = Fernet(derive_key(password))
    return cipher.encrypt(image_bytes)

# Decrypt Image Function
def decrypt_image(encrypted_data, password):
    try:
        cipher = Fernet(derive_key(password))
        decrypted_data = cipher.decrypt(encrypted_data)
        decrypted_image = Image.open(io.BytesIO(decrypted_data))

        # Extract the hidden image
        extracted_image = extract_image(decrypted_image)

        return decrypted_image, extracted_image
    except Exception as e:
        st.error(f"Decryption failed! Error: {e}")
        return None, None

# Streamlit UI
st.title("Multi-layer Image Steganography")

menu = st.sidebar.radio("Select an Option", ["Encrypt", "Decrypt"])

if menu == "Encrypt":
    st.subheader("Upload a Cover Image")
    base_image = st.file_uploader("Choose a Cover Image", type=["png", "jpg", "jpeg"])

    if base_image:
        st.subheader("Upload a Secret Image")
        secret_image = st.file_uploader("Upload Secret Image", type=["png", "jpg", "jpeg"])

    if base_image and secret_image:
        # Secret text message
        st.subheader("Enter Secret Text Message")
        secret_text = st.text_area("This message will be hidden inside the secret image", 
                                  value="This is a hidden message!", height=100)
        
        # Passwords for both layers
        col1, col2 = st.columns(2)
        with col1:
            text_password = st.text_input("Password for Text Encryption (AES-256)", 
                                       type="password", value="text_password")
        with col2:
            image_password = st.text_input("Password for Image Encryption", 
                                         type="password", value="image_password")

        if st.button("Encrypt and Hide"):
            # Load images
            base_img = Image.open(base_image).convert("RGB")
            secret_img = Image.open(secret_image).convert("RGBA")
            
            # Show original images
            col1, col2 = st.columns(2)
            with col1:
                st.image(base_img, caption="Cover Image")
            with col2:
                st.image(secret_img, caption="Secret Image")
            
            st.text(f"Secret Message: {secret_text}")
            
            # Step 1: Encrypt text with AES-256
            st.info("Step 1: Encrypting text message with AES-256...")
            encrypted_text = aes_encrypt_text(secret_text, text_password)
            
            # Step 2: Embed encrypted text in secret image
            st.info("Step 2: Embedding encrypted text in secret image...")
            secret_with_text = embed_text_in_image(secret_img, encrypted_text)
            
            if secret_with_text:
                # Step 3: Embed secret image in cover image
                st.info("Step 3: Embedding secret image in cover image...")
                stego_image = embed_image(base_img, secret_with_text)
                
                if stego_image:
                    # Step 4: Encrypt final stego image
                    st.info("Step 4: Encrypting final stego image...")
                    image_bytes = io.BytesIO()
                    stego_image.save(image_bytes, format="PNG")
                    final_encrypted_data = encrypt_image(image_bytes.getvalue(), image_password)
                    
                    st.success("Multi-layer encryption successful!")
                    st.image(stego_image, caption="Final Stego Image")
                    st.download_button("Download Encrypted File", 
                                      final_encrypted_data, 
                                      "multi_encrypted_image.enc")

elif menu == "Decrypt":
    st.subheader("Upload Encrypted File")
    encrypted_file = st.file_uploader("Choose an Encrypted File", type=["enc"])
    
    if encrypted_file:
        # Passwords for both layers
        col1, col2 = st.columns(2)
        with col1:
            image_password = st.text_input("Password for Image Decryption", 
                                         type="password", value="image_password")
        with col2:
            text_password = st.text_input("Password for Text Decryption", 
                                       type="password", value="text_password")
        
        if st.button("Decrypt"):
            encrypted_data = encrypted_file.read()
            
            # Step 1: Decrypt the encrypted file
            st.info("Step 1: Decrypting the encrypted file...")
            decrypted_image, extracted_image = decrypt_image(encrypted_data, image_password)
            
            if decrypted_image:
                st.success("Image decryption successful!")
                
                col1, col2 = st.columns(2)
                with col1:
                    st.image(decrypted_image, caption="Decrypted Cover Image")
                
                if extracted_image:
                    with col2:
                        st.image(extracted_image, caption="Extracted Secret Image")
                    
                    # Step 2: Extract hidden text from the secret image
                    st.info("Step 2: Extracting hidden text from secret image...")
                    encrypted_text = extract_text_from_image(extracted_image)
                    
                    if encrypted_text:
                        # Step 3: Decrypt the text with AES-256
                        st.info("Step 3: Decrypting the hidden text...")
                        decrypted_text = aes_decrypt_text(encrypted_text, text_password)
                        
                        if decrypted_text:
                            st.success("Text decryption successful!")
                            st.subheader("Secret Message:")
                            st.write(f"\n{decrypted_text}\n")
                            
                            # Download options
                            col1, col2 = st.columns(2)
                            with col1:
                                extracted_img_bytes = io.BytesIO()
                                extracted_image.save(extracted_img_bytes, format="PNG")
                                extracted_img_bytes.seek(0)
                                st.download_button("Download Secret Image", 
                                                  extracted_img_bytes.getvalue(), 
                                                  "extracted_image.png")
                            
                            with col2:
                                st.download_button("Download Secret Text", 
                                                  decrypted_text, 
                                                  "secret_message.txt")
                        else:
                            st.error("Text decryption failed! Incorrect text password.")
                    else:
                        st.error("No hidden text found in the secret image.")
                else:
                    st.error("No hidden image found or extraction failed.")
            else:
                st.error("Decryption failed! Incorrect image password or corrupted file.")
