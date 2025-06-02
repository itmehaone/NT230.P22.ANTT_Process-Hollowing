#include <windows.h>
#include <MinHook.h>
#include <sstream>
#include <iomanip>
#include <vector>
#include <fstream>
#include <string>
#include <algorithm>
#include <set>

// ====== Signature struct ======
struct Signature {
    std::vector<unsigned char> bytes;
    std::string toHex() const {
        std::ostringstream oss;
        for (auto b : bytes)
            oss << std::hex << std::setw(2) << std::setfill('0') << (unsigned int)b;
        return oss.str();
    }
    bool operator<(const Signature& rhs) const { return bytes < rhs.bytes; }
};

// ====== Globals ======
std::set<Signature> signatureSet;
std::vector<Signature> signatures;

typedef BOOL(WINAPI* pWriteProcessMemory)(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
);

pWriteProcessMemory original_WPM = NULL;

// ====== Load signatures ======
void LoadSignatures(const char* filename) {
    std::ifstream fin(filename);
    std::string line;
    int total = 0, dup = 0;
    while (std::getline(fin, line)) {
        if (line.empty()) continue;
        Signature sig;
        for (size_t i = 0; i + 1 < line.length(); i += 2) {
            std::string byteString = line.substr(i, 2);
            unsigned char byte = (unsigned char)strtoul(byteString.c_str(), nullptr, 16);
            sig.bytes.push_back(byte);
        }
        if (!sig.bytes.empty()) {
            ++total;
            if (signatureSet.find(sig) == signatureSet.end()) {
                signatureSet.insert(sig);
                signatures.push_back(sig);
            } else {
                ++dup;
                std::string msg = "[WARN] Duplicate signature: " + sig.toHex() + "\n";
                OutputDebugStringA(msg.c_str());
            }
        }
    }
    std::ostringstream oss;
    oss << "[INFO] Signature file loaded: " << filename << "\n";
    oss << "[INFO] Total signatures in file: " << total << "\n";
    oss << "[INFO] Unique signatures loaded: " << signatures.size() << "\n";
    if (dup > 0) oss << "[INFO] Duplicate signatures ignored: " << dup << "\n";
    OutputDebugStringA(oss.str().c_str());
}

// ====== Check signature ======
const Signature* FindMatchedSignature(const unsigned char* buffer, SIZE_T size) {
    for (const auto& sig : signatures) {
        if (sig.bytes.size() > size)
            continue;
        if (std::search(buffer, buffer + size, sig.bytes.begin(), sig.bytes.end()) != buffer + size)
            return &sig;
    }
    return nullptr;
}

// ====== Hook WriteProcessMemory ======
BOOL WINAPI hook_WPM(
    HANDLE hProcess,
    LPVOID lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T nSize,
    SIZE_T* lpNumberOfBytesWritten
)
{
    OutputDebugStringA("[HOOK] WriteProcessMemory called!\n");

    if (lpBuffer && nSize > 0) {
        const Signature* match = FindMatchedSignature(reinterpret_cast<const unsigned char*>(lpBuffer), nSize);
        if (match) {
            std::string msg = "[ALERT] Malicious signature detected: " + match->toHex() + ". Killing process.\n";
            OutputDebugStringA(msg.c_str());
            ExitProcess(0);
        }
    }

    // Print buffer
    if (lpBuffer && nSize > 0 && nSize < 512) {
        std::ostringstream oss;
        oss << "Buffer (" << nSize << " bytes): ";
        for (SIZE_T i = 0; i < nSize; ++i) {
            oss << std::hex << std::setw(2) << std::setfill('0')
                << (static_cast<const unsigned int>(reinterpret_cast<const unsigned char*>(lpBuffer)[i])) << " ";
        }
        oss << "\n";
        OutputDebugStringA(oss.str().c_str());
    }

    return original_WPM(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

// ====== Hook Thread ======
DWORD WINAPI HookThread(LPVOID)
{
    LoadSignatures("signature.txt"); 

    if (MH_Initialize() != MH_OK) {
        OutputDebugStringA("[ERR] MinHook init failed!\n");
        return 1;
    }
    if (MH_CreateHook(
        &WriteProcessMemory,
        &hook_WPM,
        reinterpret_cast<LPVOID*>(&original_WPM)) != MH_OK) {
        OutputDebugStringA("[ERR] MH_CreateHook failed!\n");
        return 1;
    }
    if (MH_EnableHook(&WriteProcessMemory) != MH_OK) {
        OutputDebugStringA("[ERR] MH_EnableHook failed!\n");
        return 1;
    }
    OutputDebugStringA("[INFO] Hook WriteProcessMemory enabled!\n");
    return 0;
}

// ====== DllMain ======
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        CreateThread(nullptr, 0, HookThread, nullptr, 0, nullptr);
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
