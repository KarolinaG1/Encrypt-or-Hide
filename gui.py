import os
import tkinter as tk
from tkinter.ttk import *
import steganography
import cryptography
from tkinter.filedialog import askopenfilename, Toplevel


class EncryptOrHideApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("580x600")
        self.title("Encrypt or Hide")
        self.resizable(False, False)
        self.file_path1 = ''
        self.file_path2 = ''
        self.password = ''
        self.password_d = ''
        self.message = ''
        self.loss = 111

        container = tk.Frame(self)
        container.pack()
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)

        self.frames = {}
        for fr in (Menu, Steganography, Cryptography):
            window_name = fr.__name__
            frame = fr(parent=container, controller=self)
            self.frames[window_name] = frame
            frame.grid(row=0, column=0, sticky="nesw")

        self.show_window("Menu")

    def show_window(self, window_name):
        frame = self.frames[window_name]
        frame.tkraise()

    def browse_files_h(self, label):
        acceptable_types = [('Digital images', '*.png;')]
        self.file_path1 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path1)[1]

    def browse_files_r(self, label):
        acceptable_types = [('Digital images', '*.png;')]
        self.file_path2 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path2)[1]

    def browse_files_e(self, label):
        acceptable_types = [('Digital images', '*.png;*.jpg;')]
        self.file_path1 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path1)[1]

    def browse_files_d(self, label):
        acceptable_types = [('Digital images', '*.png;*.jpg;')]
        self.file_path2 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path2)[1]

    def hide(self, message, info, label, en_flag):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        if en_flag is False:
            self.message = str(message.get())
        else:
            self.message = self.message.decode('latin-1')
            print("In str: " + self.message)
        if self.message is not '' and self.file_path1 is not '':
            self.loss, output = steganography.get_data(self.file_path1, self.message)
            self.message = ''
            if self.loss != 111 and output is not False:
                text = "Steganographic process completed.\nRoughly " + str(round(self.loss, 2)) \
                               + "% of bits \nof the cover image had to be modified \nin order to hide the secret message." \
                               + "\nThe output file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                self.loss = 111
                self.file_path1 = ''
                message.delete(0, 'end')
                label["text"] = "No file has been chosen"
            else:
                text = "Please, provide the app with your message \n and a digital carrier"
                info.insert(tk.END, text)
        else:
            text = "Please, provide the app with your message \n and a digital carrier"
            info.insert(tk.END, text)
        info.config(state="disabled")

    def hide_cipher(self, message, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        info.config(state="disabled")
        self.message = str(message.get())
        password_window = Toplevel(self)
        password_window.title("Password")
        password_window.geometry("450x150")
        label_top = tk.Label(password_window, text="Input a desired password for your message", font="Verdana 10 bold")
        label_top.grid(column=0, row=1, pady=5, padx=10)
        entry_password = Entry(password_window, width=30, show="*")
        entry_password.grid(column=0, row=2, pady=10)
        button_proceed = tk.Button(password_window, text="PROCEED", font="Verdana 10 bold", command=lambda: self.encrypt_message(entry_password, label, info, password_window, message))
        button_proceed.grid(column=1, row=10, sticky="W", pady=10)

    def encrypt_message(self, pswrd, label, info, window, message):
        password = str(pswrd.get())
        msg = str.encode(self.message)
        self.message = cryptography.encrypt_text(msg, password)
        window.destroy()
        self.hide(message, info, label, True)

    def recover(self, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        recovered = steganography.recover_message(self.file_path2)
        if recovered is not False:
            text = "Recovered secret message is: \n" + str(recovered)
            info.insert(tk.END, text)
            self.file_path2 = ''
            label["text"] = "No file has been chosen"
        else:
            text = "There seems to be no message \n hidden using this application.\n" \
                           "Choose another image."
            info.insert(tk.END, text)
            info["font"] = "Verdana 8 bold"
        info.config(state="disabled")

    def recover_cipher(self, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        info.config(state="disabled")
        password_window = Toplevel(self)
        password_window.title("Password")
        password_window.geometry("450x150")
        label_top = tk.Label(password_window, text="Input a password for chosen carrier", font="Verdana 10 bold")
        label_top.grid(column=0, row=1, pady=5, padx=10)
        entry_password = Entry(password_window, width=30, show="*")
        entry_password.grid(column=0, row=2, pady=10)
        button_proceed = tk.Button(password_window, text="PROCEED", font="Verdana 10 bold", command=lambda: self.recover_message(entry_password, info, label, password_window))
        button_proceed.grid(column=1, row=10, sticky="W", pady=10)

    def recover_message(self, pswrd, info, label, window):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        recovered_c = steganography.recover_message(self.file_path2)
        pswrd = str(pswrd.get())
        window.destroy()
        if recovered_c is not False:
            recovered = cryptography.decrypt_text(recovered_c, pswrd)
            if recovered is not False:
                text = "Recovered secret message is: \n" + recovered
                info.insert(tk.END, text)
                self.file_path2 = ''
                label["text"] = "No file has been chosen"
            else:
                text = "Error has occurred. \nFile and password mismatch."
                info.insert(tk.END, text)
        else:
            text = "There seems to be no message \n hidden using this application.\n" \
                           "Choose another image."
            info.insert(tk.END, text)
            info["font"] = "Verdana 8 bold"
        info.config(state="disabled")

    def encrypt(self, password, info, label):
        info.config(state="normal")
        info.delete('1.0', tk.END)
        self.password = str(password.get())
        if self.password is not '' and self.file_path1 is not '':
            p, k, im = cryptography.get_data(self.file_path1, self.password)
            output = cryptography.encrypt_CBC(p, k, im)
            self.password = ''
            if output is not False:
                text = "Cryptographic process completed.\n"\
                               + "\nThe output file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                self.password = ''
                self.file_path1 = ''
                password.delete(0, 'end')
                label["text"] = "No file has been chosen"

        else:
            text = "  Please, provide the app with an image \n and a password!"
            info.insert(tk.END, text)
        info.config(state="disabled")

    def decrypt(self, password, info, label):
        info.config(state="normal")
        info.delete('1.0', tk.END)
        self.password_d = str(password.get())
        if self.password_d is not '' and self.file_path2 is not '':
            output = cryptography.decrypt_CBC(self.file_path2, self.password_d)
            self.password_d = ''
            if output is not False:
                text = "Cryptographic process completed.\n"\
                               + "\nThe decrypted image file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                self.password_d = ''
                self.file_path2 = ''
                password.delete(0, 'end')
                label["text"] = "No file has been chosen"
            else:
                text = "Error has occurred. \nFile and password mismatch."
                info.insert(tk.END, text)
        else:
            text = "  Please, provide the app with an image \n and a password"
            info.insert(tk.END, text)
        info.config(state="disabled")

    def reset_values(self):
        self.file_path1 = ''
        self.file_path2 = ''
        self.password = ''
        self.password_d = ''
        self.message = ''
        self.loss = 111

    def reset_crypto(self, text1, text2, entry1, entry2, label1, label2):
        text1.config(state="normal")
        text2.config(state="normal")
        text1.delete("1.0", tk.END)
        text2.delete("1.0", tk.END)
        text1.config(state="disabled")
        text2.config(state="disabled")
        entry1.delete(0, 'end')
        entry2.delete(0, 'end')
        label1["text"] = ""
        label2["text"] = ""

    def reset_stegano(self, text1, text2, entry, label1, label2):
        text1.config(state="normal")
        text2.config(state="normal")
        text1.delete("1.0", tk.END)
        text2.delete("1.0", tk.END)
        text1.config(state="disabled")
        text2.config(state="disabled")
        entry.delete(0, 'end')
        label1["text"] = ""
        label2["text"] = ""


class Menu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        label = tk.Label(self, text="Choose what you want to do \n with a secret message", font="Verdana 15 bold")
        label.pack(side="top", fill="x", pady=90)

        button1 = tk.Button(self, text="Hide/Recover \n(steganography)", width=30, font="Verdana 10 italic",
                            command=lambda: controller.show_window("Steganography"))
        button2 = tk.Button(self, text="Encrypt/Decrypt \n(cryptography)", width=30, font="Verdana 10 italic",
                            command=lambda: controller.show_window("Cryptography"))
        button1.pack()
        button2.pack()
        controller.reset_values()


class Steganography(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        # Hiding a message
        label_top = tk.Label(self, text="Hide a secret message in a digital image", font="Verdana 10 bold")
        label_top.grid(column=0, row=1, pady=20, padx=5, sticky="NW")
        label_image = tk.Label(self, text="Choose an image", font="Verdana 10")
        label_image.grid(column=0, row=2, padx=10, sticky="W")
        label_path = tk.Label(self, text="No file has been chosen", font="Verdana 8 italic")
        label_path.grid(column=0, row=3)
        button_search = tk.Button(self, text="Search", font="Verdana 8", command=lambda: controller.browse_files_h(label_path), width=15)
        button_search.grid(column=1, row=2, padx=10)
        label_message = tk.Label(self, text="Type in your secret message: ", font="Verdana 10")
        label_message.grid(column=0, row=4, padx=10, pady=10, sticky="W")
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_message = Entry(self, width=30, xscrollcommand=scrollbar.set)
        entry_message.grid(column=1, row=4, pady=10)
        text_information_hidden = tk.Text(self, height=7, width=40, font="Verdana 8 bold", bg="#F0F0F0", borderwidth=0)
        text_information_hidden.grid(column=0, row=5)
        button_hide = tk.Button(self, text="HIDE", font="Verdana 10 bold", command=lambda: controller.hide(entry_message, text_information_hidden, label_path, False))
        button_hide.grid(column=1, row=5, sticky="W", pady=10)
        button_hide_cipher = tk.Button(self, text="ENCRYPT \n AND HIDE", font="Verdana 8 bold", command=lambda: controller.hide_cipher(entry_message, text_information_hidden, label_path))
        button_hide_cipher.grid(column=1, row=5, sticky="E", pady=10)
        label_info_hiding = tk.Label(self, text="If you want your message to be encrypted before\n the embedding "
                                                "process - press 'ENCRYPT AND HIDE' button", font="Verdana 8 italic",
                                     fg='blue')
        label_info_hiding.grid(column=0, row=6)

        # Recovering a message
        label_top2 = tk.Label(self, text="Recover a secret message from a digital image", font="Verdana 10 bold")
        label_top2.grid(column=0, row=7, pady=30, padx=5, sticky="NW")
        label_image2 = tk.Label(self, text="Choose an image with a secret hidden", font="Verdana 10")
        label_image2.grid(column=0, row=8, padx=10, sticky="W")
        label_path2 = tk.Label(self, text="No file has been chosen", font="Verdana 8 italic")
        label_path2.grid(column=0, row=9)
        button_search2 = tk.Button(self, text="Search", font="Verdana 8", command=lambda: controller.browse_files_r(label_path2), width=15)
        button_search2.grid(column=1, row=8, padx=10, sticky="W")
        text_information_recovered = tk.Text(self, height=7, width=40, font="Verdana 8 bold", bg="#F0F0F0", borderwidth=0)
        text_information_recovered.grid(column=0, row=10)
        button_recover = tk.Button(self, text="RECOVER", font="Verdana 10 bold", command=lambda: controller.recover(text_information_recovered, label_path2))
        button_recover.grid(column=1, row=10, sticky="W", pady=5)
        button_recover_cipher = tk.Button(self, text="RECOVER \n CRYPTOGRAM", font="Verdana 8 bold", command=lambda: controller.recover_cipher(text_information_recovered, label_path2))
        button_recover_cipher.grid(column=1, row=10, sticky="E", pady=5)
        label_info_hiding = tk.Label(self, text="If you want to recover an encrypted message - press\n"
                                                "'RECOVER CRYPTOGRAM' button", font="Verdana 8 italic",
                                     fg='blue')
        label_info_hiding.grid(column=0, row=11)

        button = tk.Button(self, text="Go back to main menu", width=35, font="Verdana 10 italic",
                           command=lambda: [controller.show_window("Menu"), controller.reset_stegano(
                               text_information_hidden, text_information_recovered, entry_message,
                               label_path, label_path2)])
        button.grid(column=0, row=12, pady=10)
        label_info = tk.Label(self, text="FILES USED IN A STEGANOGRAPHY PROCESS MUST BE IN .PNG FORMAT.", font="Verdana 7 italic")
        label_info.grid(column=0, row=13, pady=10, padx=15)


class Cryptography(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller

        # Encrypting an image
        label_top_e = tk.Label(self, text="Encrypt a digital image                    ", font="Verdana 10 bold")
        label_top_e.grid(column=0, row=1, pady=20, padx=5, sticky="NW")
        label_image_e = tk.Label(self, text="Choose an image", font="Verdana 10")
        label_image_e.grid(column=0, row=2, padx=10, sticky="W")
        label_path_e = tk.Label(self, text="No file has been chosen", font="Verdana 8 italic")
        label_path_e.grid(column=0, row=3)
        button_search_e = tk.Button(self, text="Search", font="Verdana 8", command=lambda: controller.browse_files_e(label_path_e), width=15)
        button_search_e.grid(column=1, row=2, padx=10)
        label_password_e = tk.Label(self, text="Type in your password: ", font="Verdana 10")
        label_password_e.grid(column=0, row=4, padx=10, pady=10, sticky="W")
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_password_e = Entry(self, width=30, xscrollcommand=scrollbar.set, show="*")
        entry_password_e.grid(column=1, row=4, pady=10)
        text_information_encrypted = tk.Text(self, height=5, width=40, font="Verdana 8 bold", bg="#F0F0F0", borderwidth=0)
        text_information_encrypted.config(state="disabled")
        text_information_encrypted.grid(column=0, row=5)
        button_encrypt = tk.Button(self, text="ENCRYPT", font="Verdana 10 bold", command=lambda: controller.encrypt(
            entry_password_e, text_information_encrypted, label_path_e))
        button_encrypt.grid(column=1, row=5, sticky="W", pady=10)

        # Decrypting an image
        label_top_d = tk.Label(self, text="Decrypt a digital image                    ", font="Verdana 10 bold")
        label_top_d.grid(column=0, row=7, pady=30, padx=5, sticky="NW")
        label_image_d = tk.Label(self, text="Choose an encrypted image: ", font="Verdana 10")
        label_image_d.grid(column=0, row=8, padx=10, sticky="W")
        label_path_d = tk.Label(self, text="No file has been chosen", font="Verdana 8 italic")
        label_path_d.grid(column=0, row=9)
        button_search_d = tk.Button(self, text="Search", font="Verdana 8", command=lambda: controller.browse_files_d(label_path_d), width=15)
        button_search_d.grid(column=1, row=8, padx=10, sticky="W")
        label_password_d = tk.Label(self, text="Type in your password: ", font="Verdana 10")
        label_password_d.grid(column=0, row=10, padx=10, pady=10, sticky="W")
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_password_d = Entry(self, width=30, xscrollcommand=scrollbar.set, show="*")
        entry_password_d.grid(column=1, row=10, pady=10)
        text_information_decrypted = tk.Text(self, height=5, width=40, font="Verdana 8 bold", bg="#F0F0F0", borderwidth=0)
        text_information_decrypted.grid(column=0, row=11)
        button_decrypt = tk.Button(self, text="DECRYPT", font="Verdana 10 bold", command=lambda: controller.decrypt(
            entry_password_d, text_information_decrypted, label_path_d))
        button_decrypt.grid(column=1, row=11, sticky="W", pady=10)

        button = tk.Button(self, text="Go back to main menu", width=35, font="Verdana 10 italic",
                           command=lambda: [controller.show_window("Menu"), controller.reset_crypto(
                               text_information_decrypted, text_information_encrypted, entry_password_d,
                               entry_password_e, label_path_d, label_path_e)])
        button.grid(column=0, row=12, pady=10)
        label_info = tk.Label(self, text="OUTPUT FILES GET SAVED INTO THE SAME FOLDER AS INPUT FILES.   ", font="Verdana 7 italic")
        label_info.grid(column=0, row=13, pady=10, padx=15)


if __name__ == "__main__":
    app = EncryptOrHideApp()
    app.mainloop()
