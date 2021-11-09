import os
import tkinter as tk
from tkinter import ttk
from tkinter.ttk import *
import steganography
import cryptography
from tkinter.filedialog import askopenfilename, Toplevel


class EncryptOrHideApp(tk.Tk):

    def __init__(self, *args, **kwargs):
        tk.Tk.__init__(self, *args, **kwargs)
        self.geometry("580x650")
        self.title("Encrypt or Hide")
        self.resizable(False, False)
        self.iconbitmap("images/icon.ico")
        self.file_path1 = ''
        self.file_path2 = ''
        self.file_path3 = ''
        self.password = ''
        self.password_d = ''
        self.message = ''
        self.loss = 111
        self.background_image = tk.PhotoImage(file="images/background.png")
        self.back_label = tk.PhotoImage(file="images/background_l.png")
        self.locked = tk.PhotoImage(file="images/lock.png")
        self.unlocked = tk.PhotoImage(file="images/unlock.png")
        self.hiding = tk.PhotoImage(file="images/secret.png")
        self.uncovering = tk.PhotoImage(file="images/unsecret.png")
        self.info = tk.PhotoImage(file="images/info.png")

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

    def show_info(self):
        info_window = Toplevel(self)
        info_window.title("About the application")
        info_window.geometry("420x420")
        info_window.configure(background="black")
        info_window.iconbitmap("images/icon.ico")
        info_window.resizable(False, False)
        with open('description', encoding="utf-8") as f:
            info = f.read()
        text_menu_info = tk.Text(info_window, height=30, width=60, font="Cardo 10", bg="black", borderwidth=0,
                                 wrap=tk.WORD, pady=15, fg="white")
        text_menu_info.insert(tk.END, info)
        text_menu_info.config(state="disabled")
        text_menu_info.pack()

    def browse_files_h(self, text):
        acceptable_types = [('Digital images', '*.png;')]
        self.file_path1 = askopenfilename(filetype=acceptable_types)
        text_capacity, file_capacity = steganography.calculate_capacity(self.file_path1)
        text.config(state="normal")
        text.delete("1.0", tk.END)
        info = "You can hide a plain message with a \nmax length " \
               "of " + str(text_capacity) + " characters or a\nfile with a max size of " + \
               str(file_capacity) + " bytes"
        text.insert(tk.END, info)

    def browse_files_r(self, label):
        acceptable_types = [('Digital images', '*.png;')]
        self.file_path2 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path2)[1]

    def browse_files_h_f(self):
        self.file_path3 = askopenfilename()

    def browse_files_e(self, label):
        acceptable_types = [('Digital images', '*.png;*.jpg;')]
        self.file_path1 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path1)[1]

    def browse_files_d(self, label):
        acceptable_types = [('Digital images', '*.png;*.jpg;')]
        self.file_path2 = askopenfilename(filetype=acceptable_types)
        label["text"] = ".../" + os.path.split(self.file_path2)[1]

    def hide_f(self, info, file_info, stat):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        stat.config(state="normal")
        stat.delete("1.0", tk.END)
        file_info.config(state="normal")
        file_info.delete("1.0", tk.END)
        if self.file_path1 is not '' and self.file_path3 is not '':
            self.loss, output, mse, psnr = steganography.get_data_f(self.file_path1, self.file_path3)
            if self.loss != 111 and output is not False:
                text = "Steganographic process completed. \
                               \nThe output file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                stats = "Embedding statistics: \nPSNR: " + str(round(psnr, 4)) + "dB" + "\nMSE: " + str(
                    round(mse, 4)) + "dB" + "\nBits modified: " + str(round(self.loss, 4)) + "%"
                stat.insert(tk.END, stats)
                self.loss = 111
                self.file_path1 = ''
                self.file_path3 = ''
                file_info.insert(tk.END, "No file has been chosen")
            else:
                text = "Looks like the chosen cover image\ndoesn't have the required  \ncapacity to perform this operation. "
                info.insert(tk.END, text)

        else:
            text = "Please, provide the app with a file \n to be hidden and a digital carrier"
            info.insert(tk.END, text)
        info.config(state="disabled")
        stat.config(state="disabled")
        file_info.config(state="disabled")

    def hide(self, message, info, file_info, en_flag, stat):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        stat.config(state="normal")
        stat.delete("1.0", tk.END)
        file_info.config(state="normal")
        file_info.delete("1.0", tk.END)
        if en_flag is False:
            self.message = str(message.get())
        else:
            self.message = self.message.decode('latin-1')
        if self.message is not '' and self.file_path1 is not '':
            self.loss, output, mse, psnr = steganography.get_data(self.file_path1, self.message)
            self.message = ''
            if self.loss != 111 and output is not False:
                text = "Steganographic process completed. \
                               \nThe output file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                stats = "Embedding statistics: \nPSNR: " + str(round(psnr, 4)) + "dB" + "\nMSE: " + str(
                    round(mse, 4)) + "dB" + "\nBits modified: " + str(round(self.loss, 4)) + "%"
                stat.insert(tk.END, stats)
                self.loss = 111
                self.file_path1 = ''
                message.delete(0, 'end')
                file_info.insert(tk.END, "No file has been chosen")
            else:
                text = "Please, provide the app with your message \n and a digital carrier"
                info.insert(tk.END, text)
        else:
            text = "Please, provide the app with your message \n and a digital carrier"
            info.insert(tk.END, text)
        info.config(state="disabled")
        stat.config(state="disabled")
        file_info.config(state="disabled")

    def hide_cipher(self, message, info, file_info, statistics):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        info.config(state="disabled")
        self.message = str(message.get())
        password_window = Toplevel(self)
        password_window.title("Password and encryption mode")
        password_window.geometry("450x150")
        password_window.configure(background="white")
        password_window.iconbitmap("images/icon.ico")
        password_window.resizable(False, False)
        label_top = tk.Label(password_window, text="Input a desired password \nfor your message",
                             font="Cardo 10 bold", bg="white")
        label_top.grid(column=0, row=1, pady=5, padx=10, sticky="W")
        entry_password = Entry(password_window, width=30, show="*")
        entry_password.grid(column=1, row=1, pady=10, sticky="E")
        label_mode_e = tk.Label(password_window, text="Choose an \n encryption mode: ",
                                bg="white", font="Cardo 10 bold")
        label_mode_e.grid(column=0, row=3, sticky="W", padx=10)
        combo_mode_e = ttk.Combobox(password_window, state="readonly", values=["CBC", "CFB"])
        combo_mode_e.grid(column=1, row=3, sticky="E", padx=10)
        combo_mode_e.current(0)
        button_proceed = tk.Button(password_window, text="PROCEED", font="Cardo 10 bold", bg="black", fg="white",
                                   command=lambda: self.encrypt_message(entry_password, file_info, info,
                                                                        password_window,
                                                                        message, combo_mode_e.get(), statistics))
        button_proceed.grid(column=1, row=5, pady=10)
        label_locked = tk.Label(password_window, image=self.locked, bg='white')
        label_locked.grid(column=0, row=5)

    def encrypt_message(self, pswrd, file_info, info, window, message, mode, statistics):
        password = str(pswrd.get())
        msg = str.encode(self.message)
        self.message = cryptography.encrypt_text(msg, password, mode)
        window.destroy()
        self.hide(message, info, file_info, True, statistics)

    def uncover(self, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        uncovered = steganography.uncover_message(self.file_path2)
        if uncovered is not False:
            text = "Uncovered secret message is: \n" + str(uncovered)
            info.insert(tk.END, text)
            self.file_path2 = ''
            label["text"] = "No file has been chosen"
        else:
            text = "There seems to be no message\nhidden using this application.\n" \
                   "Choose another image."
            info.insert(tk.END, text)
            info["font"] = "Cardo 8 bold"
        info.config(state="disabled")

    def uncover_cipher(self, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        info.config(state="disabled")
        password_window = Toplevel(self)
        password_window.title("Password and encryption mode")
        password_window.geometry("450x150")
        password_window.configure(background="white")
        password_window.iconbitmap("images/icon.ico")
        password_window.resizable(False, False)
        label_top = tk.Label(password_window, text="Input a password \nfor a chosen carrier",
                             font="Cardo 10 bold", bg="white")
        label_top.grid(column=0, row=1, pady=5, padx=10, sticky="W")
        entry_password = Entry(password_window, width=30, show="*")
        entry_password.grid(column=1, row=1, pady=10, sticky="E")
        label_mode_d = tk.Label(password_window, text="Choose an \n encryption mode: ",
                                bg="white", font="Cardo 10 bold")
        label_mode_d.grid(column=0, row=3, sticky="W", padx=10)
        combo_mode_d = ttk.Combobox(password_window, state="readonly", values=["CBC", "CFB"])
        combo_mode_d.grid(column=1, row=3, sticky="E", padx=10)
        combo_mode_d.current(0)

        button_proceed = tk.Button(password_window, text="PROCEED", font="Cardo 10 bold", bg="black", fg="white",
                                   command=lambda: self.uncover_message(entry_password, info, label, password_window,
                                                                        combo_mode_d.get()))
        button_proceed.grid(column=1, row=5, pady=10)
        label_unlocked = tk.Label(password_window, image=self.unlocked, bg='white')
        label_unlocked.grid(column=0, row=5)

    def uncover_message(self, pswrd, info, label, window, mode):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        uncovered_c = steganography.uncover_message(self.file_path2)
        pswrd = str(pswrd.get())
        window.destroy()
        if uncovered_c is not False:
            uncovered = cryptography.decrypt_text(uncovered_c, pswrd, mode)
            if uncovered is not False:
                text = "Uncovered secret message is: \n" + uncovered
                info.insert(tk.END, text)
                self.file_path2 = ''
                label["text"] = "No file has been chosen"
            else:
                text = "Error has occurred. \nPassword or encryption mode mismatch."
                info.insert(tk.END, text)
        else:
            text = "There seems to be no message \n hidden using this application.\n" \
                   "Choose another image."
            info.insert(tk.END, text)
            info["font"] = "Cardo 8 bold"
        info.config(state="disabled")

    def uncover_f(self, info, label):
        info.config(state="normal")
        info.delete("1.0", tk.END)
        uncovered_path = steganography.uncover_file(self.file_path2)
        if uncovered_path is not False:
            text = "Uncovered secret file was saved to: \n" + str(uncovered_path)
            info.insert(tk.END, text)
            self.file_path2 = ''
            label["text"] = "No file has been chosen"
        else:
            text = "There seems to be no file \n hidden using this application.\n" \
                   "Choose another image."
            info.insert(tk.END, text)
            info["font"] = "Cardo 8 bold"
        info.config(state="disabled")

    def encrypt(self, password, info, label, mode):
        info.config(state="normal")
        info.delete('1.0', tk.END)
        self.password = str(password.get())
        if self.password is not '' and self.file_path1 is not '':
            p, k, im = cryptography.get_data(self.file_path1, self.password)
            if mode == 'CBC':
                output = cryptography.encrypt_CBC(p, k, im)
            elif mode == 'CFB':
                output = cryptography.encrypt_CFB(p, k, im)
            else:
                output = False
                text = " Choose an appropriate encryption mode"
                info.insert(tk.END, text)
            self.password = ''
            if output is not False:
                text = "Cryptographic process completed.\n" \
                       + "The output file: \n" + output.split("/")[-1]
                info.insert(tk.END, text)
                self.password = ''
                self.file_path1 = ''
                password.delete(0, 'end')
                label["text"] = "No file has been chosen"
        else:
            text = "  Please, provide the app with an image \n and a password!"
            info.insert(tk.END, text)
        info.config(state="disabled")

    def decrypt(self, password, info, label, mode):
        info.config(state="normal")
        info.delete('1.0', tk.END)
        self.password_d = str(password.get())
        if self.password_d is not '' and self.file_path2 is not '':
            if mode == 'CBC':
                output = cryptography.decrypt_CBC(self.file_path2, self.password_d)
            elif mode == 'CFB':
                output = cryptography.decrypt_CFB(self.file_path2, self.password_d)
            else:
                output = False
                text = " Choose an appropriate encryption mode"
                info.insert(tk.END, text)
            self.password_d = ''
            if output is not False:
                text = "Cryptographic process completed.\n" \
                       + "The decrypted image file: \n" + output.split("/")[-1]
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

    def reset_stegano(self, text1, text2, text3, entry, text4, label):
        text1.config(state="normal")
        text2.config(state="normal")
        text3.config(state="normal")
        text1.delete("1.0", tk.END)
        text2.delete("1.0", tk.END)
        text3.delete("1.0", tk.END)
        text1.config(state="disabled")
        text2.config(state="disabled")
        entry.delete(0, 'end')
        label["text"] = ""
        text4.config(state="normal")
        text4.delete("1.0", tk.END)
        text4.config(state="disabled")

    def limit_input(self, message, capacity):
        if len(message) <= capacity:
            return True
        else:
            return False


class Menu(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.controller.configure(background="black")
        self.configure(background="black")

        label_bg = tk.Label(self, image=controller.background_image, bg='black')
        label_bg.place(x=0, y=0)
        button_info = tk.Button(self, image=controller.info, command=controller.show_info, bg="black")
        button_info.place(x=540, y=3)

        label = tk.Label(self, text="What do you want to do?",
                         font="Averta 20 bold", bg='black', fg='white', image=controller.back_label, compound='center', borderwidth=0)
        label.pack(side="top", fill="x", pady=120)

        button_stegano = tk.Button(self, text="Hide/Uncover \n a message \n(steganography)", width=30,
                                   font="Averta 13",
                                   command=lambda: controller.show_window("Steganography"), fg='black', bg='white')
        button_crypto = tk.Button(self, text="Encrypt/Decrypt \n an image \n(cryptography)",
                                  width=30, font="Averta 13",
                                  command=lambda: controller.show_window("Cryptography"), fg='black', bg='white')

        button_stegano.pack(pady="5")
        button_crypto.pack(pady="5")
        controller.reset_values()


class Steganography(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(background="white")

        # Hiding a message
        label_top = tk.Label(self, text="\t\t\t\t\t   Hide a secret message in a digital image",
                             font="Cardo 10 bold", bg="black", fg="white")
        label_top.grid(column=0, row=1, pady=20, padx=5, sticky="NW", columnspan=2)
        label_image = tk.Label(self, text="Choose a cover image", font="Cardo 10", bg="white")
        label_image.grid(column=0, row=2, padx=5, sticky="W")
        text_path = tk.Text(self, height=3, width=40, font="Cardo 7 italic", bg="white", borderwidth=0)
        text_path.grid(column=0, row=3, padx=10, sticky="W")
        text_path.insert(tk.END, "No file has been chosen")
        text_path.config(state="disabled")
        button_search = tk.Button(self, text="Search", font="Cardo 8 bold", bg="white",
                                  command=lambda: controller.browse_files_h(text_path), width=15)
        button_search.grid(column=0, row=2, padx=50, sticky="E")
        label_message = tk.Label(self, text="Type in your secret message:",
                                 font="Cardo 10", bg="white")
        label_message.grid(column=0, row=5, padx=5, pady=10, sticky="W")
        label_file = tk.Label(self, text="Or choose a file to be hidden: ", font="Cardo 10", bg="white")
        label_file.grid(column=0, row=6, padx=6, pady=7, sticky="W")
        button_search_f = tk.Button(self, text="Search for\na secret file", font="Cardo 8 bold", bg="white",
                                    command=lambda: controller.browse_files_h_f(), width=15)
        button_search_f.grid(column=0, row=6, padx=50, sticky="E")
        button_hide_f = tk.Button(self, text="HIDE A FILE", font="Cardo 10 bold", bg="black", fg="white",
                                  command=lambda: controller.hide_f(text_information_hidden, text_path, text_statistics))
        button_hide_f.grid(column=1, row=4, padx=20)
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_message = Entry(self, width=30, xscrollcommand=scrollbar.set)
        entry_message.grid(column=0, row=5, pady=10, padx=5, sticky="E")
        text_statistics = tk.Text(self, height=4, width=20, font="Cardo 8 bold", bg="white", borderwidth=0)
        text_statistics.grid(column=1, row=2, rowspan=2)
        text_statistics.config(state="disabled")
        text_information_hidden = tk.Text(self, height=5, width=40, font="Cardo 7 bold", bg="white", borderwidth=0)
        text_information_hidden.grid(column=0, row=3, sticky="E")
        text_information_hidden.config(state="disabled")
        button_hide = tk.Button(self, text="HIDE A PLAIN \n MESSAGE", font="Cardo 10 bold", bg="black", fg="white",
                                command=lambda: controller.hide(entry_message, text_information_hidden, text_path,
                                                                False, text_statistics))
        button_hide.grid(column=0, row=4, sticky="W", pady=10, padx=20)
        button_hide_cipher = tk.Button(self, text="ENCRYPT\nAND HIDE", font="Cardo 10 bold", bg="black", fg="white",
                                       command=lambda: controller.hide_cipher(entry_message, text_information_hidden,
                                                                              text_path, text_statistics))
        button_hide_cipher.grid(column=0, row=4, sticky="E", pady=10, padx=50)
        label_hide = tk.Label(self, image=controller.hiding, bg='white')
        label_hide.grid(column=1, row=5, rowspan=2)

        # uncovering a message
        label_top2 = tk.Label(self, text="\t\t\t\t        Uncover a secret message from a digital image",
                              font="Cardo 10 bold", bg="black", fg="white")
        label_top2.grid(column=0, row=7, pady=30, padx=5, sticky="NW", columnspan=2)
        label_image2 = tk.Label(self, text="Choose an image\nwith a secret hidden", font="Cardo 10", bg="white")
        label_image2.grid(column=0, row=8, padx=5, sticky="W")
        label_path2 = tk.Label(self, text="No file has been chosen", font="Cardo 7 italic", bg="white")
        label_path2.grid(column=0, row=9, sticky="NW", padx=5, pady=10)
        button_search2 = tk.Button(self, text="Search", font="Cardo 8 bold", bg="white",
                                   command=lambda: controller.browse_files_r(label_path2), width=15)
        button_search2.grid(column=0, row=8, sticky="E", padx=50)
        text_information_uncovered = tk.Text(self, height=7, width=60, font="Cardo 8 bold", bg="white",
                                             borderwidth=0)
        text_information_uncovered.grid(column=0, row=9, sticky="E", pady=10, padx=10, columnspan=2)
        text_information_uncovered.config(state="disabled")
        button_uncover = tk.Button(self, text="UNCOVER A\nPLAIN MESSAGE", font="Cardo 10 bold", bg="black", fg="white",
                                   command=lambda: controller.uncover(text_information_uncovered, label_path2))
        button_uncover.grid(column=0, row=10, sticky="W", pady=5, padx=20)
        button_uncover_cipher = tk.Button(self, text="UNCOVER\nCRYPTOGRAM", font="Cardo 10 bold", bg="black", fg="white",
                                          command=lambda: controller.uncover_cipher(text_information_uncovered,
                                                                                    label_path2))
        button_uncover_cipher.grid(column=0, row=10, sticky="E", pady=5, padx=45)
        button_uncover_f = tk.Button(self, text="UNCOVER A FILE", font="Cardo 10 bold", bg="black", fg="white",
                                   command=lambda: controller.uncover_f(text_information_uncovered, label_path2))
        button_uncover_f.grid(column=1, row=10, pady=10)
        label_uncover = tk.Label(self, image=controller.uncovering, bg='white')
        label_uncover.grid(column=1, row=8, rowspan=2, pady=20)

        button = tk.Button(self, text="Go back to main menu", width=45, font="Cardo 10 italic",
                           command=lambda: [controller.show_window("Menu"), controller.reset_stegano(
                               text_information_hidden, text_information_uncovered, text_statistics,
                               entry_message, text_path, label_path2)], bg="black", fg="white")
        button.grid(column=0, row=13, pady=30)
        label_info = tk.Label(self, text="FILES USED IN \nA STEGANOGRAPHY PROCESS \nMUST BE IN .PNG FORMAT.",
                              font="Cardo 7 italic", bg="white")
        label_info.grid(column=1, row=12, pady=20, padx=15, rowspan=2)


class Cryptography(tk.Frame):

    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.controller = controller
        self.configure(background='#FFFFFF')

        # Encrypting an image
        label_top_e = tk.Label(self, text="\t\t\t\t\t\t\t   Encrypt a digital image", font="Cardo 10 bold", bg='black', fg='white')
        label_top_e.grid(column=0, row=1, pady=20, padx=5, sticky="NW", columnspan=2)
        label_image_e = tk.Label(self, text="Choose an image", font="Cardo 10", bg="white", fg="black")
        label_image_e.grid(column=0, row=2, padx=10, sticky="W")
        label_path_e = tk.Label(self, text="No file has been chosen", font="Cardo 8 italic", bg="white", fg="black")
        label_path_e.grid(column=0, row=3, sticky="W", padx=5)
        button_search_e = tk.Button(self, text="Search", font="Cardo 8 bold", bg="white", fg="black",
                                    command=lambda: controller.browse_files_e(label_path_e), width=15)
        button_search_e.grid(column=0, row=2, padx=10, sticky="E",)
        label_password_e = tk.Label(self, text="Type in your password: ", font="Cardo 10", bg="white", fg="black")
        label_password_e.grid(column=0, row=4, padx=10, pady=17, sticky="W")
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_password_e = Entry(self, width=30, xscrollcommand=scrollbar.set, show="*")
        entry_password_e.grid(column=0, row=4, pady=10, sticky="E")
        text_information_encrypted = tk.Text(self, height=5, width=40, font="Cardo 8 bold",
                                             borderwidth=0, bg="white", fg="black")
        text_information_encrypted.grid(column=0, row=6)
        text_information_encrypted.config(state="disabled")
        label_mode_e = tk.Label(self, text="Choose an \n encryption mode: ", font="Cardo 9", bg="white", fg="black")
        label_mode_e.grid(column=0, row=5, sticky="W", padx=10)
        combo_mode_e = ttk.Combobox(self, state="readonly", values=["CBC", "CFB"])
        combo_mode_e.grid(column=0, row=5, sticky="E", padx=10)
        combo_mode_e.current(0)
        button_encrypt = tk.Button(self, text="ENCRYPT", font="Cardo 10 bold", command=lambda: controller.encrypt(
            entry_password_e, text_information_encrypted, label_path_e, combo_mode_e.get()), bg="black", fg="white")
        button_encrypt.grid(column=1, row=5, pady=10)
        label_locked = tk.Label(self, image=controller.locked, bg='white')
        label_locked.grid(column=1, row=3, columnspan=2)

        # Decrypting an image
        label_top_d = tk.Label(self, text="\t\t\t\t\t\t\t   Decrypt a digital image", font="Cardo 10 bold", bg='black', fg='white')
        label_top_d.grid(column=0, row=7, pady=15, padx=5, sticky="NW", columnspan=2)
        label_image_d = tk.Label(self, text="Choose an encrypted image ", font="Cardo 10", bg="white")
        label_image_d.grid(column=0, row=8, padx=10, sticky="W")
        label_path_d = tk.Label(self, text="No file has been chosen", font="Cardo 8 italic", bg="white")
        label_path_d.grid(column=0, row=9, sticky="W", padx=5)
        button_search_d = tk.Button(self, text="Search", font="Cardo 8 bold", bg="white",
                                    command=lambda: controller.browse_files_d(label_path_d), width=15)
        button_search_d.grid(column=0, row=8, padx=10, sticky="E")
        label_password_d = tk.Label(self, text="Type in your password: ", font="Cardo 10", bg="white")
        label_password_d.grid(column=0, row=10, padx=10, pady=17, sticky="W")
        scrollbar = tk.Scrollbar(orient="horizontal")
        entry_password_d = Entry(self, width=30, xscrollcommand=scrollbar.set, show="*")
        entry_password_d.grid(column=0, row=10, pady=10, sticky="E")
        text_information_decrypted = tk.Text(self, height=5, width=40, font="Cardo 8 bold", bg="white",
                                             borderwidth=0, wrap=tk.WORD)
        text_information_decrypted.grid(column=0, row=12)
        text_information_decrypted.config(state="disabled")
        label_mode_d = tk.Label(self, text="Choose an \n encryption mode: ", font="Cardo 9", bg="white")
        label_mode_d.grid(column=0, row=11, sticky="W", padx=10)
        combo_mode_d = ttk.Combobox(self, state="readonly", values=["CBC", "CFB"])
        combo_mode_d.grid(column=0, row=11, sticky="E", padx=10)
        combo_mode_d.current(0)
        button_decrypt = tk.Button(self, text="DECRYPT", font="Cardo 10 bold", command=lambda: controller.decrypt(
            entry_password_d, text_information_decrypted, label_path_d, combo_mode_d.get()), bg="black", fg="white")
        button_decrypt.grid(column=1, row=11, pady=5)
        label_unlocked = tk.Label(self, image=controller.unlocked, bg='white')
        label_unlocked.grid(column=1, row=9, columnspan=2)

        button = tk.Button(self, text="Go back to main menu", width=35, font="Cardo 10 italic",
                           command=lambda: [controller.show_window("Menu"), controller.reset_crypto(
                               text_information_decrypted, text_information_encrypted, entry_password_d,
                               entry_password_e, label_path_d, label_path_e)], bg="black", fg="white")
        button.grid(column=0, row=13, pady=3)
        label_info = tk.Label(self, text="OUTPUT FILES GET SAVED INTO \nTHE SAME FOLDER AS INPUT FILES.   ",
                              font="Cardo 6 italic", bg="white")
        label_info.grid(column=1, row=13, pady=5, padx=7)


if __name__ == "__main__":
    app = EncryptOrHideApp()
    app.mainloop()
