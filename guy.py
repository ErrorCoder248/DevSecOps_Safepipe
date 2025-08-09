import os
import threading
import time
import customtkinter as ctk
from tkinter import filedialog, messagebox
from detect_safepipe import scan_file, scan_directory

# App theme
ctk.set_appearance_mode("dark")  
ctk.set_default_color_theme("green")  

class SafePipeGUI(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("SafePipe Secret Scanner")
        self.geometry("1200x800")  # Bigger window

        # Title
        self.label_title = ctk.CTkLabel(self, text="🔒 SafePipe Secret Scanner", font=("Arial", 32, "bold"))
        self.label_title.pack(pady=25)

        # Path input frame
        self.frame_path = ctk.CTkFrame(self)
        self.frame_path.pack(pady=15)

        self.entry_path = ctk.CTkEntry(self.frame_path, placeholder_text="Select file or directory...", width=700, height=40, font=("Arial", 16))
        self.entry_path.pack(side="left", padx=8)

        self.btn_browse = ctk.CTkButton(self.frame_path, text="Browse", width=120, height=40, font=("Arial", 16), command=self.browse_path)
        self.btn_browse.pack(side="left", padx=5)

        self.btn_scan = ctk.CTkButton(self.frame_path, text="Scan", width=120, height=40, font=("Arial", 16), command=self.start_scan_thread)
        self.btn_scan.pack(side="left", padx=5)

        # Output box
        self.text_output = ctk.CTkTextbox(self, width=1100, height=500, font=("Consolas", 16))
        self.text_output.pack(pady=15)

        # Tag styles
        self.text_output.tag_config("secret", foreground="red")
        self.text_output.tag_config("file", foreground="yellow")
        self.text_output.tag_config("success", foreground="lightgreen")
        self.text_output.tag_config("status", foreground="cyan")

        # Status label
        self.label_status = ctk.CTkLabel(self, text="", font=("Arial", 18, "bold"))
        self.label_status.pack(pady=10)

    def browse_path(self):
        path = filedialog.askopenfilename()
        if not path:
            path = filedialog.askdirectory()
        self.entry_path.delete(0, "end")
        self.entry_path.insert(0, path)

    def start_scan_thread(self):
        """Run scanning in a separate thread to keep UI responsive."""
        t = threading.Thread(target=self.run_scan)
        t.start()

    def run_scan(self):
        target_path = self.entry_path.get().strip()
        self.text_output.delete("1.0", "end")

        if not os.path.exists(target_path):
            messagebox.showerror("Error", "Invalid path.")
            return

        self.show_loading(True)
        time.sleep(0.5)

        if os.path.isfile(target_path):
            findings = scan_file(target_path)
            self.display_results(findings)
        elif os.path.isdir(target_path):
            results = scan_directory(target_path)
            self.display_dir_results(results)

        self.show_loading(False)

    def show_loading(self, is_loading):
        if is_loading:
            self.label_status.configure(text="⏳ Scanning... Please wait.")
        else:
            self.label_status.configure(text="✅ Scan Complete.")

    def display_results(self, findings):
        if findings:
            self.text_output.insert("end", "[!] Secrets found:\n", "secret")
            for secret_type, matches in findings:
                self.text_output.insert("end", f" - {secret_type}: {matches}\n", "secret")
        else:
            self.text_output.insert("end", "[+] No secrets found.\n", "success")

    def display_dir_results(self, results):
        if results:
            self.text_output.insert("end", "[!] Secrets found:\n", "secret")
            for file_path, matches in results.items():
                self.text_output.insert("end", f"\nFile: {file_path}\n", "file")
                for secret_type, found in matches:
                    self.text_output.insert("end", f" - {secret_type}: {found}\n", "secret")
        else:
            self.text_output.insert("end", "[+] No secrets found.\n", "success")


if __name__ == "__main__":
    app = SafePipeGUI()
    app.mainloop()
