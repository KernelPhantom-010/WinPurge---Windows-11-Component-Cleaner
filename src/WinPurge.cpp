#define NOMINMAX
#include <Windows.h>
#include <iostream>
#include <stdexcept>
#include <stdio.h>
#include <string>
#include <conio.h>
#include <vector>
#include <taskschd.h>
#include <sstream>
#include <iomanip>
#include <istream>
#include <comdef.h>
#include <fstream>
#include <curl.h>
#include <sys/stat.h>
#include <nlohmann/json.hpp>
#include <srrestoreptapi.h>
#include <winrt/Windows.Storage.h>
#include <winrt/Windows.Foundation.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/Windows.Management.Deployment.h>
#include <winrt/Windows.ApplicationModel.h>
#include <filesystem>
#pragma comment(lib, "comsuppw.lib")
#pragma comment(lib, "Sfc.Lib")
#pragma comment(lib, "uuid.lib")
#pragma comment(lib, "taskschd.lib")

using json = nlohmann::json;

struct componentCollect {
    std::string name;
    std::string state;
};
BOOL running; 
winrt::hstring findFamilyNameByFullName(const winrt::hstring& fullName)
{
    winrt::Windows::Management::Deployment::PackageManager packageManager;

    for (auto const& package : packageManager.FindPackages())
    {
        if (package.Id().FullName() == fullName)
            return package.Id().FamilyName();
    }

    return L"";
}
void drawMenu(int selection)
{
    system("cls");

    std::cout << "=== Windows Component Cleaner === \n\n";

    std::string options[] = {
        "Scan System",
        "Remove Component",
        "Create System-Snapshot",
        "Disable Telemetry Reg-Entries",
        "Search for Component",
        "Scan Malware (VirusTotal-API Key required)",
        "Exit"
    };
    for (int x = 0; x < 7; x++)
    {
        if (x == selection)
        {
            printf("[+] %s\n", options[x].c_str());
        }
        else {
            printf("[ ] %s\n", options[x].c_str());
        }
    }

}
std::string exec(const char* cmd)
{
    char buffer[128];
    std::string result;

    FILE* pipe = _popen(cmd, "r");

    if (!pipe)
        throw std::runtime_error("_popen() failed!");

    try
    {
        while (fgets(buffer, sizeof(buffer), pipe) != nullptr)
        {
            result += buffer;
        }
    }
    catch (...)
    {
        _pclose(pipe);
        throw;
    }

    _pclose(pipe);

    return result;
}
std::vector<std::string> split(std::string s, std::string delimiter) {
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    std::string token;
    std::vector<std::string> res;

    while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
        token = s.substr(pos_start, pos_end - pos_start);
        pos_start = pos_end + delim_len;
        res.push_back(token);
    }

    res.push_back(s.substr(pos_start));
    return res;
}
void animationShow()
{
    printf(" ");
    while(running)
    {
        printf("\b-");
        Sleep(20);
        fflush(stdout);
        printf("\b\\");
        Sleep(20);
        fflush(stdout);
        printf("\b|");
        Sleep(20);
        fflush(stdout);
        printf("\b/");
        fflush(stdout);
    }
    return;
}
bool stopAndDisableService(const wchar_t* serviceName)
{
    bool success = true;
    SC_HANDLE hSCManager = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
    if (!hSCManager)
        return false;

    SC_HANDLE hService = OpenServiceW(hSCManager, serviceName, SERVICE_ALL_ACCESS);
    if (hService)
    {
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);

        if (!ChangeServiceConfigW(hService, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr))
            success = false;

        CloseServiceHandle(hService);
    }
    else success = false;

    CloseServiceHandle(hSCManager);
    return success;
}
bool disableScheduledTask(const wchar_t* folderPath, const wchar_t* taskName)
{
    bool success = false;
    ITaskService* pService = nullptr;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, nullptr, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr))
        return false;

    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr))
    {
        pService->Release();
        return false;
    }

    ITaskFolder* pFolder = nullptr;
    hr = pService->GetFolder(_bstr_t(folderPath), &pFolder);
    if (SUCCEEDED(hr))
    {
        IRegisteredTask* pTask = nullptr;
        hr = pFolder->GetTask(_bstr_t(taskName), &pTask);
        if (SUCCEEDED(hr))
        {
            hr = pTask->put_Enabled(VARIANT_FALSE);
            success = SUCCEEDED(hr);
            pTask->Release();
        }
        pFolder->Release();
    }

    pService->Release();
    return success;
}
bool disableEdgeUpdater()
{
    bool success = true;

    if (!stopAndDisableService(L"edgeupdate"))
        success = false;

    if (!stopAndDisableService(L"edgeupdatem"))
        success = false;

    if (!disableScheduledTask(L"\\Microsoft\\EdgeUpdate", L"MicrosoftEdgeUpdateTaskMachineCore"))
        success = false;

    if (!disableScheduledTask(L"\\Microsoft\\EdgeUpdate", L"MicrosoftEdgeUpdateTaskMachineUA"))
        success = false;

    return success;
}
bool preventEdgeReinstall()
{
    HKEY key;
    bool success = false;
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\EdgeUpdate", 0, nullptr, 0, KEY_WRITE, nullptr, &key, nullptr) == ERROR_SUCCESS)
    {
        DWORD value = 1;
        success = (RegSetValueExW(key, L"DoNotUpdateToEdgeWithChromium", 0, REG_DWORD, (const BYTE*)&value, sizeof(value)) == ERROR_SUCCESS);
        RegCloseKey(key);
    }
    return success;
}



int snapshotCreate() {
    
    RESTOREPOINTINFO restoreInfoStruct{ 0 };
    STATEMGRSTATUS state{ 0 };

    restoreInfoStruct.dwEventType = BEGIN_SYSTEM_CHANGE;
    restoreInfoStruct.dwRestorePtType = APPLICATION_INSTALL;
    wcscpy_s(restoreInfoStruct.szDescription, L"RIM-Backup");

    
    if (SRSetRestorePoint(&restoreInfoStruct, &state)) {
        restoreInfoStruct.dwEventType = END_SYSTEM_CHANGE;
        restoreInfoStruct.llSequenceNumber = state.llSequenceNumber;

        SRSetRestorePoint(&restoreInfoStruct, &state);
    }
    else {
        return 1;
    }

    return 0;
}

void remove_Component()
{
    FlushConsoleInputBuffer(GetStdHandle(STD_INPUT_HANDLE));
    std::cout << "\n === Enter the component full-name to remove (e.g. Microsoft.WindowsAppRuntime.2_2.3.1.0_x64__8wekyb3d8bbwe) -> ";
    char componentName[4000];
    fgets(componentName, sizeof(componentName), stdin);
    componentName[strcspn(componentName, "\n")] = '\0';
    std::string tempBuffer = componentName;
    const winrt::hstring name = winrt::to_hstring(tempBuffer);
    winrt::hstring familyName = findFamilyNameByFullName(name);
    std::cout << "\n === Remove all application-data? (Y/N) -> ";
    std::string option;
    std::cin >> option;
    if (option == "Y")
    {
        auto packageManager = winrt::Windows::Management::Deployment::PackageManager();
        running = TRUE;
        std::thread spinner(animationShow);
        if (tempBuffer.find("MicrosoftEdge") != std::string::npos)
        {
            preventEdgeReinstall();
            disableEdgeUpdater();
        }
        if (!familyName.empty())
        {
            auto deprovisionOp = packageManager.DeprovisionPackageForAllUsersAsync(familyName);
            deprovisionOp.get();
        }
        auto ret_val = packageManager.RemovePackageAsync(name, winrt::Windows::Management::Deployment::RemovalOptions::None);
        ret_val.get();
        running = FALSE;
        spinner.join();
        if (ret_val.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
        {
            printf("[RIM] Component successfully removed -> %s", tempBuffer.c_str());
        }
        else {
            auto removalIssueVar = ret_val.GetResults();
            winrt::hstring error_txt = removalIssueVar.ErrorText();
            std::string answer = winrt::to_string(error_txt);
            printf("[RIM] Error -> %s", answer.c_str());
        }
    }
    else if (option == "N")
    {
        auto packageManager = winrt::Windows::Management::Deployment::PackageManager();
        running = TRUE;
        std::thread spinner(animationShow);
        if (tempBuffer.find("MicrosoftEdge") != std::string::npos)
        {
            preventEdgeReinstall();
            disableEdgeUpdater();
        }
        if (!familyName.empty())
        {
            auto deprovisionOp = packageManager.DeprovisionPackageForAllUsersAsync(familyName);
            deprovisionOp.get();
        }
        auto ret_val = packageManager.RemovePackageAsync(name, winrt::Windows::Management::Deployment::RemovalOptions::PreserveApplicationData);
        ret_val.get();
        running = FALSE;
        spinner.join();
        if (ret_val.Status() == winrt::Windows::Foundation::AsyncStatus::Completed)
        {
            printf("[RIM] Component successfully removed -> %s", tempBuffer.c_str());
            return;
        }
        else {
            auto removalIssueVar = ret_val.GetResults();
            winrt::hstring error_txt = removalIssueVar.ErrorText();
            std::string answer = winrt::to_string(error_txt);
        }
    }
    else {
        std::cout << "\n === Invalid option. Exiting..";
        Sleep(1500);
    }
    return;
}

//this hashing-algorithm got implemented by Claude! I did not write that by myself
std::string computeFileHashSHA256(const std::wstring& filePath)
{
    std::string result;

    std::ifstream file(filePath, std::ios::binary);
    if (!file)
        return result;

    BCRYPT_ALG_HANDLE hAlg = nullptr;
    BCRYPT_HASH_HANDLE hHash = nullptr;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) < 0)
        return result;

    DWORD hashObjectSize = 0, dataSize = 0;
    BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&hashObjectSize, sizeof(DWORD), &dataSize, 0);
    std::vector<BYTE> hashObject(hashObjectSize);

    if (BCryptCreateHash(hAlg, &hHash, hashObject.data(), hashObjectSize, nullptr, 0, 0) < 0)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
        return result;
    }

    std::vector<BYTE> buffer(65536);
    while (file)
    {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        std::streamsize bytesRead = file.gcount();
        if (bytesRead > 0)
            BCryptHashData(hHash, buffer.data(), static_cast<ULONG>(bytesRead), 0);
    }

    DWORD hashLength = 0;
    BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&hashLength, sizeof(DWORD), &dataSize, 0);
    std::vector<BYTE> hash(hashLength);
    BCryptFinishHash(hHash, hash.data(), hashLength, 0);

    std::ostringstream oss;
    for (BYTE b : hash)
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    result = oss.str();

    BCryptDestroyHash(hHash);
    BCryptCloseAlgorithmProvider(hAlg, 0);

    return result;
}


std::wstring stringToWString(const std::string& str)
{
    if (str.empty())
        return std::wstring();

    int sizeNeeded = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), nullptr, 0);
    std::wstring result(sizeNeeded, 0);
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), (int)str.size(), &result[0], sizeNeeded);
    return result;
}


size_t writeCallback(void* contents, size_t size, size_t nmemb, std::string* output)
{
    output->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}




int main()
{
    winrt::init_apartment();
    int selected = 0;
    while (1)
    {
        drawMenu(selected);
        int value = _getch();
        if (value == 224)
        {
            value = _getch();

            if (value == 72)
            {
                selected--;

                if (selected < 0)
                    selected = 6;
            }

            if (value == 80)
            {
                selected++;

                if (selected > 6)
                    selected = 0;
            }
        }
        if (value == 13) 
        {
            system("cls");

            switch (selected)
            {
            case 0:
            {
                std::cout << "Scanning system...\n";

                auto packageManager = winrt::Windows::Management::Deployment::PackageManager();
                auto packages = packageManager.FindPackages();
                for (auto const& package : packages)
                {
                    try
                    {
                        std::cout << "\n[+] Package -> "
                            << winrt::to_string(package.Id().Name()) << '\n';

                        std::cout << "[-] Full Name -> "
                            << winrt::to_string(package.Id().FullName()) << '\n';

                        auto v = package.Id().Version();

                        std::cout << "[-] Version -> "
                            << v.Major << '.'
                            << v.Minor << '.'
                            << v.Build << '.'
                            << v.Revision << '\n';

                        std::cout << "[+] Location -> "
                            << winrt::to_string(package.InstalledLocation().Path()) << '\n';
                    }
                    catch (const winrt::hresult_error& e)
                    {
                        std::cout << "Error at package: " << winrt::to_string(e.message()) << '\n';
                    }

                    std::cout << "--------------------------------\n";
                }
                break;
            }

            case 1:
            {
                std::cout << "Removing AppX-component...\n";
                remove_Component();
                break;
            }

            case 2:
            {
                std::cout << "Creating snapshot...\n";
                if (snapshotCreate() != 0)
                {
                    printf("\n[RIM] Snapshot creation failed with error code -> %d\nMaybe your system disabled such changes?\n", GetLastError());
                    Sleep(1500);
                }
                else {
                    std::cout << "\n=== [RIM] Snapshot creation - Succeeded ===" << std::endl;
                }
                break;
            }

            case 3:
            {
                std::cout << "Disabling multiple Telemetry features..\n";
                
                std::vector<const wchar_t*> root_hives{
                L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo",
                L"HKCU\\Software\\Microsoft\\Siuf\\Rules",
                L"HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows",
                };


                for (size_t counter = 0; counter < root_hives.size(); ++counter)
                {
                    if (wcscmp(root_hives[counter], L"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo") == 0)
                    {
                        HKEY currentKey;
                        LSTATUS state = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Windows\\CurrentVersion\\AdvertisingInfo", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, nullptr, &currentKey, nullptr);
                        if (state == ERROR_SUCCESS)
                        {
                            DWORD value = 0;
                            LSTATUS state_final = RegSetValueExW(currentKey, L"Enabled", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
                            if (state_final == ERROR_SUCCESS)
                            {
                                std::wcout << L"\n[RIM] Advertising-ID deactivated successfully.. [" << root_hives[counter] << L"]" << std::endl;
                            }
                            RegCloseKey(currentKey);
                        }
                        else {
                            std::cout << "\n[RIM] Advertising-ID couldn't be deactivated -> " << state;
                        }
                    }
                    else if (wcscmp(root_hives[counter], L"HKCU\\Software\\Microsoft\\Siuf\\Rules") == 0)
                    {
                        HKEY currentKey;
                        LSTATUS state = RegCreateKeyExW(HKEY_CURRENT_USER, L"Software\\Microsoft\\Siuf\\Rules", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, nullptr, &currentKey, nullptr);
                        if (state == ERROR_SUCCESS)
                        {
                            DWORD value = 0;
                            LSTATUS state_final = RegSetValueExW(currentKey, L"NumberOfSIUFInPeriod", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
                            if (state_final == ERROR_SUCCESS)
                            {
                                std::wcout << L"\n[RIM] Feedback-Requests deactivated successfully.. [" << root_hives[counter] << L"]" << std::endl;
                            }
                            RegCloseKey(currentKey);
                        }
                        else {
                            std::cout << "\n[RIM] Feedback-Requests couldn't be deactivated -> " << state;
                        }
                    }
                    else if (wcscmp(root_hives[counter], L"HKLM\\SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows") == 0)
                    {
                        HKEY currentKey;
                        LSTATUS state = RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Policies\\Microsoft\\SQMClient\\Windows", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE | KEY_READ, nullptr, &currentKey, nullptr);
                        if (state == ERROR_SUCCESS)
                        {
                            DWORD value = 0;
                            LSTATUS state_final = RegSetValueExW(currentKey, L"CEIPEnable", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&value), sizeof(value));
                            if (state_final == ERROR_SUCCESS)
                            {
                                std::wcout << L"\n[RIM] CEIP deactivated successfully.. [" << root_hives[counter] << L"]" << std::endl;
                            }
                            RegCloseKey(currentKey);
                        }
                        else {
                            std::cout << "\n[RIM] CEIP couldn't be deactivated -> " << state;
                        }
                    }
                }
                break;
            }

            case 4:
            {
                std::cout << "\n=== Enter the full-component name (e.g. Microsoft.PowerAutomateDesktop_1.0.2117.0_x64__8wekyb3d8bbwe) -> ";
                std::string compName;
                std::cin >> compName;
                auto temp_manager = winrt::Windows::Management::Deployment::PackageManager();
                auto packages = temp_manager.FindPackages();
                BOOL found = FALSE;
                for (const auto& package : packages)
                {
                    std::string packageName = winrt::to_string(package.Id().FullName());
                    if (packageName == compName)
                    {
                        try
                        {
                            std::cout << "\n[+] Package -> "
                                << winrt::to_string(package.Id().Name()) << '\n';

                            std::cout << "[-] Full Name -> "
                                << winrt::to_string(package.Id().FullName()) << '\n';

                            auto v = package.Id().Version();

                            std::cout << "[-] Version -> "
                                << v.Major << '.'
                                << v.Minor << '.'
                                << v.Build << '.'
                                << v.Revision << '\n';

                            std::cout << "[+] Location -> "
                                << winrt::to_string(package.InstalledLocation().Path()) << '\n';
                            found = TRUE;
                        }
                        catch (const winrt::hresult_error& e)
                        {
                            std::cout << "Error at package: " << winrt::to_string(e.message()) << '\n';
                        }

                        std::cout << "--------------------------------\n";
                    }
                }

                if (!found)
                {
                    std::cout << "\n=== The search returned 0 results. This component is not installed. ===\n";
                }
                break;
            }

            case 5:
            {
                std::cout << "VirusTotal-Scanning..\n";
                char path[MAX_PATH];
                GetModuleFileNameA(NULL, path, MAX_PATH);

                std::filesystem::path exepath;
                std::filesystem::path filepath = exepath.parent_path() / "config.dat";
                
                bool exist = std::filesystem::exists(filepath);
                if (exist)
                {
                    std::cout << "API-Key already registered. continuing..\n";
                    std::ifstream readfile("config.dat", std::ios::binary | std::ios::ate);
                    if (!readfile)
                    {
                        std::cout << "\nCouldn't read config.dat -> Are you running RIM as administrator?";
                        return 0;
                    }

                    //get size
                    std::streamsize fileSize = readfile.tellg();
                    readfile.seekg(0, std::ios::beg);

                    std::vector<BYTE> emptyBuffer(fileSize);

                    if (!readfile.read(reinterpret_cast<char*>(emptyBuffer.data()), fileSize)) {
                        std::cout << "\nCouldn't read config.dat -> Are you running RIM as administrator?";
                        return 0;
                    }
                    DATA_BLOB encrypted = { 0 };
                    DATA_BLOB decrypted = { 0 };
                    encrypted.pbData = emptyBuffer.data();
                    encrypted.cbData = static_cast<DWORD>(emptyBuffer.size());
                    CryptUnprotectData(&encrypted, nullptr, nullptr, nullptr, nullptr, 0, &decrypted);
                    std::string magicalKey(reinterpret_cast<char*>(decrypted.pbData), decrypted.cbData);
                   
                    std::cout << "\n[RIM] Enter the path to the file you want to scan -> ";
                    std::cin.clear();
                    std::string pathToFile;
                    std::getline(std::cin, pathToFile);
                    std::cout << "[" << pathToFile << "]\n";
                    Sleep(1500);
                    struct stat sb;
                    if (stat(pathToFile.c_str(), &sb) != 0 || (sb.st_mode & S_IFDIR))
                    {
                        std::cout << "\n[RIM] File-path is invalid!\n";
                        Sleep(1500);
                        return 0;
                    }
                    else
                    {
                        std::cout << "\n[RIM] File-path is valid!\n";
                        std::wstring widePath = stringToWString(pathToFile);
                        std::string hash = computeFileHashSHA256(widePath);

                        if (!hash.empty())
                            std::cout << "[RIM] SHA-256 -> " << hash << "\n";
                        else
                            std::cout << "[RIM] Hashing failed.\n";
                        std::string fullRequest = "https://www.virustotal.com/api/v3/files/" + hash;
                        CURL* hnd = curl_easy_init();
                        std::string response;

                        curl_easy_setopt(hnd, CURLOPT_CUSTOMREQUEST, "GET");
                        curl_easy_setopt(hnd, CURLOPT_WRITEFUNCTION, writeCallback);
                        curl_easy_setopt(hnd, CURLOPT_WRITEDATA, &response);
                        curl_easy_setopt(hnd, CURLOPT_URL, fullRequest.c_str());
                        std::string fullKey = "x-apikey: " + magicalKey;
                        struct curl_slist* headers = NULL;
                        headers = curl_slist_append(headers, "accept: application/json");
                        headers = curl_slist_append(headers, fullKey.c_str());

                        curl_easy_setopt(hnd, CURLOPT_HTTPHEADER, headers);
                        
                        CURLcode ret = curl_easy_perform(hnd);
                        std::cout << "\n\n[RIM] === RESPONSE BY VIRUSTOTAL.COM ===\n\n";

                        json j = json::parse(response);
                        auto& attrs = j["data"]["attributes"];
                        std::cout << "Detailed SHA-256-hash _> " << attrs["sha256"].get<std::string>() << "\n\n";
                        auto& results = attrs["last_analysis_results"];

                        for (auto& [engineName, engine] : results.items())
                        {
                            std::cout << "Engine _> " << engineName << '\n';
                            std::cout << "Category _> "
                                << engine["category"].get<std::string>() << '\n';

                            if (!engine["result"].is_null())
                                std::cout << "Result _> "
                                << engine["result"].get<std::string>() << '\n';
                            else
                                std::cout << "Result _> None\n";

                            std::cout << "Engine Version _> "
                                << engine["engine_version"].get<std::string>() << '\n';

                            std::cout << "Update _> "
                                << engine["engine_update"].get<std::string>() << "\n\n";
                        }
                        auto& stats = attrs["last_analysis_stats"];

                        std::cout << "\n\nMalicious _>   " << stats["malicious"] << '\n';
                        std::cout << "Suspicious _>  " << stats["suspicious"] << '\n';
                        std::cout << "Undetected _>  " << stats["undetected"] << '\n';
                        std::cout << "Failure _>     " << stats["failure"] << '\n';
                        std::cout << "Unsupported _> " << stats["type-unsupported"] << '\n';
                        std::cout  << "\n=======\n";
                        curl_slist_free_all(headers);
                        curl_easy_cleanup(hnd);
                    }
                }
                else {
                    std::cout << "API-Key not found\n[RIM] Please enter your API Key here or get it from (https://www.virustotal.com/gui/sign-in) -> ";
                    std::string api_key;
                    std::cin >> api_key;
                    DATA_BLOB input;
                    input.pbData = (BYTE*)api_key.c_str();
                    input.cbData = strlen(api_key.c_str());

                    DATA_BLOB output;

                    CryptProtectData(&input, L"allkeys", nullptr, nullptr, nullptr, 0, &output);

                    std::ofstream file("config.dat", std::ios::binary);
                    file.write((char*)output.pbData, output.cbData);
                    std::cout << "\n[RIM] API-Key stored! Re-select this option to start scanning for auto-start programs..";
                    Sleep(2000);
                }

                break;
            }
            case 6:
            {
                return 0;
                break;
            }
}
            system("pause");
        }
    }
   
}
