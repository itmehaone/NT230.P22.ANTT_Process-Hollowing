#include <windows.h>
#include <iostream>

int main(int argc, char* argv[])
{
    if (argc < 3) {
        std::cout << "Usage: runwithdll.exe <target.exe> <your.dll>\n";
        return 1;
    }
    const char* exePath = argv[1];
    const char* dllPath = argv[2];

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    BOOL ok = CreateProcessA(exePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi);
    if (!ok) {
        std::cout << "CreateProcess failed: " << GetLastError() << "\n";
        return 1;
    }
    LPVOID remoteStr = VirtualAllocEx(pi.hProcess, NULL, strlen(dllPath)+1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(pi.hProcess, remoteStr, dllPath, strlen(dllPath)+1, NULL);
    FARPROC pLoadLibrary = GetProcAddress(GetModuleHandleA("kernel32.dll"), "LoadLibraryA");
    HANDLE hRemoteThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, remoteStr, 0, NULL);
    WaitForSingleObject(hRemoteThread, INFINITE);
    ResumeThread(pi.hThread);
    std::cout << "DLL injected and process resumed.\n";
    return 0;
}
