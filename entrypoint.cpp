#include <workspace/auth/auth.hpp>
#include <workspace/auth/utils.hpp>
#include <impl/includes.hpp>
#include <dependencies/cipher/spoof.hpp>
#include <impl/hook/kiero.h>
#include <workspace/unity/core/sdk.hpp>
#include <workspace/game/features/features.hpp>
#include <workspace/game/render/render.hpp>
#include <random>
#include <shlobj.h>
#include <fstream>
#include <dependencies/curl/curl.h>
#include <workspace/auth/json.hpp>
#include <atomic>
#include <future>

std::atomic<int> syncCounter = 0;
std::atomic<bool> authorized = true;

HMODULE DllHandle;
HANDLE MainThreadVariable;

int GetRandomNumber(int min, int max) {
    static std::random_device rd; 
    static std::mt19937 gen(rd()); 
    std::uniform_int_distribution<> distr(min, max);
    return distr(gen);
}

static std::size_t WriteCallback(void* contents, std::size_t size, std::size_t nmemb, std::string* output) {
    std::size_t total = size * nmemb;
    output->append((char*)contents, total);
    return total;
}

std::string GetSID() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        return hash_str("Unknown");
    }

    DWORD size = 0;
    GetTokenInformation(token, TokenUser, nullptr, 0, &size);

    std::vector<BYTE> tokenUserData(size);
    if (!GetTokenInformation(token, TokenUser, tokenUserData.data(), size, &size)) {
        CloseHandle(token);
        return hash_str("Unknown");
    }

    CloseHandle(token);

    TOKEN_USER* tokenUser = reinterpret_cast<TOKEN_USER*>(tokenUserData.data());
    LPSTR sidString = nullptr;

    if (!ConvertSidToStringSidA(tokenUser->User.Sid, &sidString)) {
        return hash_str("Unknown");
    }

    std::string sid(sidString);
    LocalFree(sidString);
    return sid;
}

inline std::string GetMachineGuid()
{
    HKEY hKey = nullptr;
    // (64-bit view)
    if (RegOpenKeyExA(
        HKEY_LOCAL_MACHINE,
        hash_str("SOFTWARE\\Microsoft\\Cryptography"),
        0,
        KEY_READ | KEY_WOW64_64KEY,
        &hKey) != ERROR_SUCCESS)
        return { };

    char guidBuf[64] = {};
    DWORD bufSize = sizeof(guidBuf);
    DWORD type = 0;

    if (RegQueryValueExA(
        hKey,
        hash_str("MachineGuid"),
        nullptr,
        &type,
        reinterpret_cast<BYTE*>(guidBuf),
        &bufSize) != ERROR_SUCCESS
        || type != REG_SZ)
    {
        RegCloseKey(hKey);
        return {};
    }

    RegCloseKey(hKey);

    return std::string(guidBuf);
}
using namespace KeyAuth;
std::string name = hash_str("Hollowvrc");
std::string ownerid = hash_str("7tairE5AO7");
std::string version = hash_str("1.0");
std::string url = hash_str("https://keyauth.win/api/1.3/");
std::string path = hash_str("");
api KeyAuthApp(name, ownerid, version, url, path);

std::string LicenseKey;

namespace LicenseManager
{
    std::string GetModuleDirectory(HMODULE h)
    {
        char buffer[MAX_PATH];
        GetModuleFileNameA(h, buffer, MAX_PATH);
        std::string path(buffer);
        return path.substr(0, path.find_last_of(hash_str("\\/")));
    }

    std::string ReadKeyFromFile(const std::string& path)
    {
        std::ifstream file(path);
        if (!file.is_open()) {
            MessageBoxA(0, (hash_str("Failed to find license directory:\n") + path).c_str(), hash_str("License"), MB_ICONERROR);
            return hash_str("");
        }

        std::string key;
        std::getline(file, key);
        file.close();

        if (key.empty()) {
            MessageBoxA(0, hash_str("License key not found."), hash_str("License"), MB_ICONERROR);
        }

        return key;
    }

	static bool KeyAuthInitialized = false;
	static bool KeyAuthLicenseValidated = false;
    std::string directory = "";

    void ValidateOrExit()
    {
        directory = GetModuleDirectory(DllHandle ? DllHandle : GetModuleHandleA(NULL));
        std::string license_file = directory + hash_str("\\authentication.txt");

        LicenseKey = ReadKeyFromFile(license_file);
        if (LicenseKey.empty()) {
            spoof_call(ExitProcess)(0);
            return;
        }

        CURL* curl = curl_easy_init();
        if (!curl) {
            MessageBoxA(0, hash_str("Failed to initialize curl."), hash_str("CURL"), MB_ICONERROR);
            spoof_call(ExitProcess)(0);
            return;
        }

        std::string userh = GetSID();
        std::string url = hash_str("https://api.hollow.click/login?license=") + LicenseKey + hash_str("&hwid=") + userh;
        std::cout << hash_str("URL: ") << url << std::endl;
        std::string response;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) {
            MessageBoxA(0, hash_str("Failed to perform license check."), hash_str("License"), MB_ICONERROR);
            spoof_call(ExitProcess)(0);
            return;
        }

        try {
            auto json = nlohmann::json::parse(response);

            if (!json.contains(hash_str("success")) || !json["success"].get<bool>()) {
                std::string msg = json.contains(hash_str("message")) ? json["message"].get<std::string>() : hash_str("Unknown Error Occurred");
                MessageBoxA(0, (hash_str("Authentication failed:\n") + msg).c_str(), hash_str("Authentication"), MB_ICONERROR);
                spoof_call(ExitProcess)(0);
                return;
            }
        }
        catch (...) {
            MessageBoxA(0, hash_str("Failed to parse server response."), hash_str("License"), MB_ICONERROR);
            spoof_call(ExitProcess)(0);
            return;
        }
    }

    bool AsyncValidateLicense() {
        std::string license_file = LicenseManager::directory + hash_str("\\authentication.txt");
        std::string LicenseKey = LicenseManager::ReadKeyFromFile(license_file);
        if (LicenseKey.empty()) return false;

        CURL* curl = curl_easy_init();
        if (!curl) return false;

        std::string userh = GetSID();
        std::string url = hash_str("https://api.hollow.click/login?license=") + LicenseKey + hash_str("&hwid=") + userh;
        std::string response;

        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);

        CURLcode res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (res != CURLE_OK) return false;

        try {
            auto json = nlohmann::json::parse(response);

            if (!json.contains(hash_str("success")) || !json[hash_str("success")].get<bool>()) {
                return false;
            }
        }
        catch (...) {
            return false;
        }
        return true;
    }

    void CheckAuthorizationPeriodically() {
        int currentCount = ++syncCounter;

        if (currentCount % 60 == 0) {
            std::async(std::launch::async, []() {
                bool result = AsyncValidateLicense();
                if (!result) {
                    authorized = false;
                    MessageBoxA(0, hash_str("Async authorization failed."), hash_str("Authentication"), MB_ICONERROR);
                    ExitProcess(0);
                }
                });
        }
    }
}

namespace ExceptionBlocker {
    long _stdcall VecExFilter(PEXCEPTION_POINTERS Info) {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    long _stdcall UnhandledExFilter(PEXCEPTION_POINTERS ExPtr) {
        return 0;
    }

    void Initialize() {
        AddVectoredExceptionHandler(1, ExceptionBlocker::VecExFilter);
        SetUnhandledExceptionFilter(ExceptionBlocker::UnhandledExFilter);
    }
}

void CreateConsole( ) {
    AllocConsole( );
    AttachConsole( GetCurrentProcessId( ) );
    SetConsoleTitle(hash_str(L"Hollow - VRChat"));
    FILE* f;
    freopen_s(&f, hash_str("CONOUT$"), hash_str("w"), stdout);
}

void TryLoadCustomLoadingSong() {
    static bool HasLoadingSong = false;

    if (!HasLoadingSong) {
        HasLoadingSong = true;

        try {
            static int Timeout = 1500;
            
            auto BundleRequest = Functions::Game::UnityEngine::Networking::WebRequestGetAssetBundle(
                IL2CPP::String::New(Settings::LoadingScreen::Asset2Url)
            );

            if (BundleRequest) {
                Functions::Game::UnityEngine::Networking::SendWebRequest(BundleRequest);
                
                std::this_thread::sleep_for(std::chrono::milliseconds(Timeout));

                auto LoadingAssetBundle = Functions::Game::UnityEngine::Networking::DownloadHandlerABGetContent(BundleRequest);
                if (LoadingAssetBundle) {
                    auto AllAssetNames = Functions::Game::UnityEngine::AssetBundle::GetAllAssetNames(LoadingAssetBundle);
                    if (AllAssetNames) {
                        Settings::LoadingScreen::String = AllAssetNames->m_Items[0];
                        Settings::LoadingScreen::SongAssetBundle = LoadingAssetBundle;
                        Settings::LoadingScreen::HasLoadingSong = true;
                    }
                }
                else {
                    if (Timeout < 10000)
                        Timeout += 500;
                }
            }
        }
        catch (...) {
            HasLoadingSong = false;
        }
    }
}

bool has_been_ran = false;

DWORD WINAPI MainThread( ) {
    SetThreadPriority( GetCurrentThread( ), THREAD_PRIORITY_HIGHEST );

    Sleep(2000);

    CreateConsole( );
	std::printf(hash_str("[Hollow] Console Attached!\n"));

    LicenseManager::ValidateOrExit();
  /*  if (!has_been_ran) {
        try {
            spoof_call(std::printf)(hash_str("[Hollow] Initialized routine."));
        }
        catch (...) {
            spoof_call(std::printf)(hash_str("[Hollow] Failed to initialize routine."));
        }
        has_been_ran = true;
    }*/
    LicenseManager::CheckAuthorizationPeriodically();

    Offsets::Fetch( );
    Hooks::InitializeHooks( );
    IL2CPP::Callback::Initialize( );

    //std::printf(hash_str("[Hollow] IL2CP::Initialize::Attach Completed!\n"));

    IL2CPP::Callback::OnUpdate::Add( Features::PerformanceCallback );
    IL2CPP::Callback::OnLateUpdate::Add( Features::MainCallback );
    IL2CPP::Callback::OnLateUpdate::Add( Features::ConsoleCallback );

    //std::printf(hash_str("[Hollow] On(Late)Update::Add Finished!\n"));

    kiero::bind( 13, ( void** ) &Render::ImGuiVariables::oResizeBuffers, Render::hkResizeBuffers );
    kiero::bind( 8, ( void** ) &Render::ImGuiVariables::oPresent, Render::PresentHook );

    //std::printf(hash_str("[Hollow] DXGISwapChain::Present Hook Finished!\n"));

    IL2CPP::Thread::Attach(IL2CPP::Domain::Get());

    //std::printf(hash_str("[Hollow] IL2CPP::Attach Finished!\n"));

    return 0;
}

void InitalizeCheat( ) {
    if ( !IL2CPP::Initialize ( true ) ) {
        exit( 0 );
    }

    std::printf(hash_str("[Hollow] IL2CPP::Initialize Finished!\n"));

    MainThread( );
}

bool IsVRChat() {
    char path[MAX_PATH];
    if (GetModuleFileNameA(NULL, path, MAX_PATH) == 0) return false;
    std::string pathStr = path;

    std::string VRChat_String = hash_str("VRChat.exe");

    bool is_vrc = pathStr.find(VRChat_String) != std::string::npos;
    VRChat_String.clear();

    return is_vrc;
}

unsigned __stdcall EntryPoint( void* )  {
    if (!IsVRChat()) {
        FreeLibraryAndExitThread(DllHandle, 0);
        return 0;
    }

    std::printf(hash_str("[Hollow] VRChat Process Found!\n"));

    ExceptionBlocker::Initialize();

    bool InitalizeHook = false;
    do
    {
        if ( kiero::init ( kiero::RenderType::D3D11 ) == kiero::Status::Success )
        {
            InitalizeCheat( );
            InitalizeHook = true;
        }
        else {
            Sleep(500);
        }
    } while ( !InitalizeHook );

    return 0; 
}

static std::uintptr_t __cdecl I_beginthreadex(void* _Security, unsigned _StackSize, _beginthreadex_proc_type _StartAddress, void* _ArgList, unsigned _InitFlag, unsigned* _ThrdAddr) {
    return spoof_call(_beginthreadex).get()(_Security, _StackSize, _StartAddress, _ArgList, _InitFlag, _ThrdAddr);
}

#define _beginthread(MainThreadVariable, DllHandle) I_beginthreadex(0, 0, (_beginthreadex_proc_type)MainThreadVariable, DllHandle, 0, 0);

volatile LONG g_initialized = 0;
extern "C" __declspec( dllexport ) BOOL APIENTRY DllMain( HMODULE module_base,
    DWORD  ul_reason_for_call,
    LPVOID lp_reserved
) {
    switch ( ul_reason_for_call ) {
    case DLL_PROCESS_ATTACH: {
        DisableThreadLibraryCalls(module_base);

        DllHandle = module_base;
        MainThreadVariable = GetCurrentThread();

       auto handle = _beginthread( EntryPoint, module_base );
        if ( handle != 0 ) {
            CloseHandle ( reinterpret_cast< HANDLE >( handle ) );
        }
    } break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
		//kiero::shutdown( );
        break;
    }

    return TRUE;
}