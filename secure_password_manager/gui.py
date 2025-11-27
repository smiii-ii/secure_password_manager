import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from steganography import encode_image, decode_image
from database import add_user, verify_login, add_account, get_accounts, delete_account
from utils import hash_password, password_strength, generate_recovery_phrase


class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure Password Manager")
        self.current_user_id = None
        self.output_image_path = None

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TButton', font=('Segoe UI', 12), padding=7, background='#5C5CFF', foreground='#fff')
        style.configure('TLabel', font=('Segoe UI', 11), background='#F4F6FC', foreground='#222')
        style.configure('TFrame', background='#F4F6FC')

        self.build_login_screen()

    def clear_screen(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def build_login_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack()
        ttk.Label(frame, text="Login", font=('Arial', 18, 'bold')).grid(column=0, row=0, columnspan=2, pady=12)
        ttk.Label(frame, text="Username:").grid(column=0, row=1, sticky='w')
        username_entry = ttk.Entry(frame, width=28)
        username_entry.grid(column=1, row=1, pady=6)
        ttk.Label(frame, text="Master Password:").grid(column=0, row=2, sticky='w')
        password_entry = ttk.Entry(frame, width=28, show='*')
        password_entry.grid(column=1, row=2, pady=6)

        def login_action():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if not username or not password:
                messagebox.showwarning("Input Error", "Enter username and password.")
                return
            user_id = verify_login(username, password)
            if user_id:
                self.current_user_id = user_id
                self.build_dashboard()
            else:
                messagebox.showerror("Login Failed", "Invalid credentials.")

        def switch_to_register():
            self.build_register_screen()

        ttk.Button(frame, text="Login", command=login_action).grid(column=0, row=3, pady=18)
        ttk.Button(frame, text="Register", command=switch_to_register).grid(column=1, row=3, pady=18)

    def build_register_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack()
        ttk.Label(frame, text="Register New User", font=('Arial', 18, 'bold')).grid(column=0, row=0, columnspan=2, pady=12)
        ttk.Label(frame, text="Username:").grid(column=0, row=1, sticky='w')
        username_entry = ttk.Entry(frame, width=28)
        username_entry.grid(column=1, row=1, pady=6)
        ttk.Label(frame, text="Master Password:").grid(column=0, row=2, sticky='w')
        password_entry = ttk.Entry(frame, width=28, show='*')
        password_entry.grid(column=1, row=2, pady=6)

        def register_action():
            username = username_entry.get().strip()
            password = password_entry.get().strip()
            if len(username) < 3:
                messagebox.showwarning("Username Error", "Username must be at least 3 characters.")
                return
            if password_strength(password) < 3:
                messagebox.showwarning("Weak Password", "Password must be stronger (min 8 chars, mix cases, digits, symbols).")
                return
            hashed_pw = hash_password(password)
            recovery = generate_recovery_phrase()
            success = add_user(username, hashed_pw, recovery)
            if success:
                messagebox.showinfo(
                    "Registration Successful",
                    f"Account created. Please save this recovery phrase securely:\n\n{recovery}"
                )
                self.build_login_screen()
            else:
                messagebox.showerror("Registration Failed", "Username already exists.")

        ttk.Button(frame, text="Register", command=register_action).grid(column=0, row=3, pady=18)
        ttk.Button(frame, text="Back to Login", command=self.build_login_screen).grid(column=1, row=3, pady=18)

    def build_dashboard(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack()
        ttk.Label(frame, text="Dashboard", font=('Arial', 18, 'bold')).pack(pady=16)
        ttk.Button(frame, text="Add Account", command=self.add_account_screen).pack(pady=10, fill='x')
        ttk.Button(frame, text="Retrieve Account", command=self.retrieve_account_screen).pack(pady=10, fill='x')
        ttk.Button(frame, text="Delete Account", command=self.delete_account_screen).pack(pady=10, fill='x')
        ttk.Button(frame, text="Logout", command=self.logout).pack(pady=14, fill='x')

    def add_account_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack(fill='both', expand=True)

        ttk.Label(frame, text="Add Multiple Accounts", font=('Arial', 16, 'bold')).grid(row=0, column=0, columnspan=4, pady=12)

        ttk.Label(frame, text="Platform").grid(row=1, column=0)
        ttk.Label(frame, text="Username").grid(row=1, column=1)
        ttk.Label(frame, text="Password").grid(row=1, column=2)

        rows = []

        def add_row():
            row_num = len(rows) + 2
            platform = ttk.Entry(frame, width=18)
            platform.grid(row=row_num, column=0, pady=5)
            username = ttk.Entry(frame, width=18)
            username.grid(row=row_num, column=1, pady=5)
            password = ttk.Entry(frame, width=18, show='*')
            password.grid(row=row_num, column=2, pady=5)

            rows.append((platform, username, password))

        add_row()

        def add_more_rows():
            add_row()

        ttk.Button(frame, text="Add Another Account", command=add_more_rows).grid(row=0, column=3, padx=10)

        ttk.Label(frame, text="Choose PNG Image:").grid(row=2, column=3, sticky='n', pady=5)
        image_path_var = tk.StringVar()
        image_entry = ttk.Entry(frame, width=24, textvariable=image_path_var, state='readonly')
        image_entry.grid(row=3, column=3, pady=5)

        def browse_image():
            path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp")])
            if path:
                image_path_var.set(path)

        ttk.Button(frame, text="Browse", command=browse_image).grid(row=4, column=3)

        self.output_image_path = None
        download_button = ttk.Button(frame, text="Download Encrypted Image")

        def download_image():
            if not self.output_image_path:
                messagebox.showwarning("Error", "No encrypted image available to download.")
                return
            save_path = filedialog.asksaveasfilename(defaultextension=".png",
                                                     filetypes=[("PNG Image", "*.png")],
                                                     title="Save Encrypted Image As")
            if save_path:
                try:
                    import shutil
                    shutil.copyfile(self.output_image_path, save_path)
                    messagebox.showinfo("Success", f"Encrypted image saved to {save_path}")
                except Exception as err:
                    messagebox.showerror("Error", f"Failed to save image: {err}")

        download_button.grid(row=5, column=3, pady=20)
        download_button.state(['disabled'])
        download_button.configure(command=download_image)

        def save_accounts():
            image_path = image_path_var.get()
            if not image_path:
                messagebox.showwarning("Error", "Please select an image file.")
                return

            existing_data = {}
            try:
                existing_data = decode_image(image_path)
            except Exception:
                existing_data = {}

            new_data_added = False
            for platform, username, password in rows:
                p = platform.get().strip()
                u = username.get().strip()
                pw = password.get().strip()
                if p and u and pw:
                    key = f"{p}|{u}"
                    new_data_added = True
                    existing_data[key] = pw

            if not new_data_added:
                messagebox.showwarning("No Data", "Please enter at least one complete account.")
                return

            base_name = image_path.split('/')[-1]
            output_path = f"embedded_multi_{base_name}"
            try:
                encode_image(image_path, existing_data, output_path)
                self.output_image_path = output_path  # save for download
                for key in existing_data.keys():
                    p, u = key.split('|', 1)
                    add_account(self.current_user_id, p, u, output_path)
                messagebox.showinfo("Success", f"Accounts saved to image {output_path}")
                download_button.state(['!disabled'])
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save accounts: {e}")

        ttk.Button(frame, text="Save Accounts", command=save_accounts).grid(row=5, column=0, columnspan=3, pady=20)
        ttk.Button(frame, text="Back to Dashboard", command=self.build_dashboard).grid(row=5, column=4, pady=20)

    def retrieve_account_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack()

        ttk.Label(frame, text="Retrieve Account", font=('Arial', 16, 'bold')).pack(pady=10)

        def upload_and_decode():
            path = filedialog.askopenfilename(filetypes=[("Image files", "*.png;*.bmp")])
            if not path:
                return
            accounts = decode_image(path)
            if not accounts:
                messagebox.showinfo("No Data", "No account details found in this image.")
                return
            display = ""
            for k, v in accounts.items():
                plat, user = k.split('|')
                display += f"Platform: {plat}\nUsername: {user}\nPassword: {v}\n\n"
            messagebox.showinfo("Account Found", display)

        ttk.Button(frame, text="Upload Image", command=upload_and_decode).pack(pady=16)
        ttk.Button(frame, text="Back to Dashboard", command=self.build_dashboard).pack(pady=8)

    def delete_account_screen(self):
        self.clear_screen()
        frame = ttk.Frame(self.root, padding=25, style='TFrame')
        frame.pack()

        ttk.Label(frame, text="Delete Account", font=('Arial', 16, 'bold')).pack(pady=10)

        accounts = get_accounts(self.current_user_id)
        listbox = tk.Listbox(frame, width=60, height=8)
        acc_map = {}

        for idx, (acc_id, platform, username, image_path) in enumerate(accounts):
            entry = f"{acc_id}: {platform} | {username} [{image_path}]"
            listbox.insert(tk.END, entry)
            acc_map[idx] = acc_id
        listbox.pack(pady=8)

        def delete_selected():
            sel = listbox.curselection()
            if not sel:
                messagebox.showwarning("Error", "Select account to delete.")
                return
            idx = sel[0]
            acc_id = acc_map[idx]
            confirm = messagebox.askyesno("Confirm", "Are you sure to delete?")
            if confirm:
                delete_account(acc_id)
                messagebox.showinfo("Deleted", "Account deleted.")
                self.delete_account_screen()

        ttk.Button(frame, text="Delete Selected", command=delete_selected).pack(pady=10)
        ttk.Button(frame, text="Back", command=self.build_dashboard).pack(pady=8)

    def logout(self):
        self.current_user_id = None
        self.build_login_screen()


def main():
    root = tk.Tk()
    root.geometry("680x500")
    PasswordManagerGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
