import os
import time
import pefile
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

WATCH_FOLDER = r"C:\Users\client01.MYGROUP\Desktop\watched"
LAUNCHER_PATH = r"C:\Users\client01.MYGROUP\Desktop\monitor\runwithdll86.exe"
DLL_PATH = r"C:\Users\client01.MYGROUP\Desktop\watched\mydll32.dll"
LOG_FILE = r"C:\Users\client01.MYGROUP\Desktop\monitor\log.txt"

REQUIRED_SUSPICIOUS_APIS = {
    "CreateProcessA",
    "ReadProcessMemory",
    "VirtualAllocEx",
    "WriteProcessMemory",
    "GetThreadContext",
    "SetThreadContext",
    "ResumeThread",
    "CreateFileA",
    "ReadFile",
    "GetProcAddress",
    "GetModuleHandleA",
    "CloseHandle",
    "GetFileSize",
}

# Ghi kết quả WinAPI vào log file
def log_result(file_path, api_list):
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(f"\n[+] New file: {file_path}\n")
        all_found = set()
        for dll, funcs in api_list.items():
            f.write(f"    {dll}\n")
            for func in funcs:
                f.write(f"       {func}\n")
                if func in REQUIRED_SUSPICIOUS_APIS:
                    all_found.add(func)
        if REQUIRED_SUSPICIOUS_APIS.issubset(all_found):
            f.write("    [SUSPECTED] Full set of suspicious APIs called!\n")

# Trích xuất WinAPI từ PE file
def extract_winapi_from_pe(file_path, retries=5, delay=1):
    for attempt in range(retries):
        try:
            pe = pefile.PE(file_path, fast_load=False)
            api_calls = {}
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("utf-8", errors="ignore")
                funcs = []
                for imp in entry.imports:
                    if imp.name:
                        funcs.append(imp.name.decode("utf-8", errors="ignore"))
                api_calls[dll] = funcs
            pe.close()
            return api_calls
        except Exception as e:
            print(f"[Retry {attempt+1}/{retries}] Error: {e}")
            time.sleep(delay)
    print(f"Cannot access file after {retries} retries.")
    return {}

# Xử lý file nghi ngờ: tạo batch chạy qua launcher & DLL
def handle_suspect(file_path):
    basename = os.path.basename(file_path)
    batch_name = f"run_{basename.replace('.exe', '')}.bat"
    batch_path = os.path.join(WATCH_FOLDER, batch_name)
    with open(batch_path, "w", encoding="utf-8") as f:
        f.write(f'@echo off\n')
        f.write(f'"{LAUNCHER_PATH}" "{file_path}" "{DLL_PATH}"\n')
        f.write(f'pause\n')

class NewFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not event.is_directory and event.src_path.lower().endswith(".exe"):
            print(f"Detected new file: {event.src_path}")
            api_data = extract_winapi_from_pe(event.src_path)
            if api_data:
                all_found = set()
                for funcs in api_data.values():
                    all_found.update(funcs)
                if REQUIRED_SUSPICIOUS_APIS.issubset(all_found):
                    print("[SUSPECTED] File calls full suspicious API set.")
                    handle_suspect(event.src_path)
                else:
                    print("[OK] Not enough suspicious APIs.")
                print(f"Logged WinAPI from: {os.path.basename(event.src_path)}")
            else:
                print(f"[WARNING] No WinAPI found in file.")

if __name__ == "__main__":
    print(f"Monitoring folder: {WATCH_FOLDER}")
    observer = Observer()
    observer.schedule(NewFileHandler(), WATCH_FOLDER, recursive=False)
    observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()
