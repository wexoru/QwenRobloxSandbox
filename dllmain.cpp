// Make sure to include winsock2.h before windows.h
#include <winsock2.h>
#include <ws2tcpip.h>
#include <Windows.h>
#include <thread>
#include <string>
#include <vector>
#include <mutex>
#include "Roblox.h"

#pragma comment(lib, "ws2_32.lib")

const char* WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const int PORT = 6754;
std::mutex scriptMutex;
std::vector<std::string> scriptQueue;

#pragma region DLL_EXPORTS
extern "C" __declspec(dllexport) LRESULT NextHook(int code, WPARAM wParam, LPARAM lParam) { return CallNextHookEx(nullptr, code, wParam, lParam); }
#pragma endregion 

void main() {
    executor::initialize();
    executor::HookJob("WaitingHybridScriptsJob");
    executor::addScript(R"(print("Hello, World! identity:"))");
    executor::addScript(R"(printidentity())");

    while (true) {
        Sleep(1000);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        std::thread(main).detach();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}