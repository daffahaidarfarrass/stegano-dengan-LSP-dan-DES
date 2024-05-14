import binascii
from Crypto.Cipher import DES
import tkinter as tk
import tkinter.messagebox as messagebox
import customtkinter
from PIL import Image
from numpy import pad

customtkinter.set_appearance_mode("System")
customtkinter.set_default_color_theme("green")



class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # configure window
        self.title("Aplikasi Steganografi")
        self.geometry(f"{1200}x{650}")

        # Add widgets
        self.label = customtkinter.CTkLabel(self, text="Aplikasi Steganografi dengan Metode LSB", font=("Helvetica", 16))
        self.label.pack(pady=10)

        self.input_text = customtkinter.CTkEntry(self, placeholder_text="Isi Pesan disini", width=300 )
        self.input_text.pack(pady=10)

        self.input_key = customtkinter.CTkEntry(self, placeholder_text="Isi key disini", width=300 )
        self.input_key.pack(pady=10)

        self.upload_button = customtkinter.CTkButton(self, text="Upload Gambar", command=self.upload_image)
        self.upload_button.pack(pady=10)

        self.hide_button = customtkinter.CTkButton(self, text="Sembunyikan Pesan", command=self.hide_message)
        self.hide_button.pack(pady=10)

        self.extract_button = customtkinter.CTkButton(self, text="Ekstrak Pesan", command=self.extract_message)
        self.extract_button.pack(pady=10)

    def pad(self, text):
        while len(text) % 8 != 0:
            text += ' '
        return text


    def des_encrypt(self, plain_text, key):
        des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
        padded_text = self.pad(plain_text)
        # Convert padded_text to bytes
        padded_text_bytes = padded_text.encode('utf-8')
        encrypted_text = des.encrypt(padded_text_bytes)
        hasil_encrypt = binascii.hexlify(encrypted_text).decode('utf-8')
        return hasil_encrypt

    def des_decrypt(self, encrypted_text, key):
        des = DES.new(key.encode('utf-8'), DES.MODE_ECB)
        encrypted_text_bytes = binascii.unhexlify(encrypted_text)
        decrypted_text = des.decrypt(encrypted_text_bytes)
        hasil_decrypt = decrypted_text.decode('utf-8').rstrip()
        return hasil_decrypt

    def upload_image(self):
        filename = tk.filedialog.askopenfilename()
        if filename:
            self.image = Image.open(filename)
            messagebox.showinfo("Info", "Gambar berhasil diupload")

    def hide_message(self):
        plainteks = (self.input_text.get())
        key = (self.input_key.get())

        hasil_encrypt = self.des_encrypt(plainteks, key)

        if hasattr(self, 'image'):
            message = hasil_encrypt
            if message.strip():
                stego_image = self.lsb_hide(self.image, message)
                messagebox.showinfo("Info", "Pesan berhasil disembunyikan dalam gambar")
                stego_image.save("stego_image.png")
            else:
                messagebox.showwarning("Peringatan", "Masukkan pesan terlebih dahulu")
        else:
            messagebox.showwarning("Peringatan", "Upload gambar terlebih dahulu")

    def extract_message(self):
        if hasattr(self, 'image'):
            extracted_message = self.lsb_extract(self.image)
            hasil_decrypt = self.des_decrypt(extracted_message, self.input_key.get())
            messagebox.showinfo("Pesan Tersembunyi", hasil_decrypt)
        else:
            messagebox.showwarning("Peringatan", "Upload gambar terlebih dahulu")

    
    def lsb_hide(self, image, message):
        # Menambahkan karakter null di akhir pesan
        message += '\0'
        binary_message = ''.join(format(ord(char), '08b') for char in message)
        if len(binary_message) > image.width * image.height:
            raise ValueError("Pesan terlalu besar untuk gambar yang dipilih")

        pixels = image.load()
        encoded_image = image.copy()

        index = 0
        for i in range(image.width):
            for j in range(image.height):
                pixel = list(pixels[i, j])

                for k in range(3):
                    if index < len(binary_message):
                        pixel[k] = pixel[k] & ~1 | int(binary_message[index])
                        index += 1

                encoded_image.putpixel((i, j), tuple(pixel))
            
        return encoded_image

    def lsb_extract(self, image):
        pixels = image.load()
        extracted_bits = ""
        message = ""
        found_null_char = False

        # Iterasi melalui setiap piksel dalam gambar
        for i in range(image.width):
            for j in range(image.height):
                pixel = pixels[i, j]
                # Menambahkan bit paling tidak signifikan (LSB) dari setiap channel warna ke dalam string bit yang diekstrak
                for k in range(3):
                    extracted_bits += str(pixel[k] & 1)
                    # Setiap kali kita mendapatkan 8 bit, kita cek apakah itu karakter null
                    if len(extracted_bits) == 8:
                        byte = extracted_bits
                        extracted_bits = ""
                        character = chr(int(byte, 2))
                        if character == '\0':  # Jika karakter null, berhenti mengekstrak
                            found_null_char = True
                            break
                        message += character
                if found_null_char:
                    break
            if found_null_char:
                break

        return message
    
    
    
if __name__ == "__main__":
    app = App()
    app.mainloop()
