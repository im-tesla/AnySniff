#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <winhttp.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include "debug.h"
#include "depedencies/json.hpp"

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

enum requestCode {
    country,
    city,
    isp
};

class C_Anydesk {
public:
    bool initialize() {
        HRESULT hres;

		// initialize COM library
        hres = CoInitializeEx(0, COINIT_MULTITHREADED);
        if (FAILED(hres)) {
			debug.log(_ERROR, "Failed to initialize COM library.");
            return false;
        }

		// set general COM security levels
        hres = CoInitializeSecurity(
            NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT,
            RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE, NULL);

        if (FAILED(hres)) {
			debug.log(_ERROR, "Failed to initialize security.");
            CoUninitialize();
            return false;
        }

		// obtain the initial locator to WMI
        hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
        if (FAILED(hres)) {
			debug.log(_ERROR, "Failed to create IWbemLocator object.");
            CoUninitialize();
            return false;
        }

		// connect to WMI through the ConnectServer method
        hres = pLoc->ConnectServer(
            _bstr_t(L"ROOT\\CIMV2"), NULL, NULL, 0, NULL, 0, 0, &pSvc);

        if (FAILED(hres)) {
			debug.log(_ERROR, "Could not connect to WMI server.");
            pLoc->Release();
            CoUninitialize();
            return false;
        }

		// set security levels on the proxy
        hres = CoSetProxyBlanket(
            pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL,
            RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);

        if (FAILED(hres)) {
			debug.log(_ERROR, "Could not set proxy blanket.");
            pSvc->Release();
            pLoc->Release();
            CoUninitialize();
            return false;
        }

        initialized = true;
        return true;
    }

    void uninitialize() {
        if (initialized) {
            if (pSvc) pSvc->Release();
            if (pLoc) pLoc->Release();
            CoUninitialize();
            initialized = false;
        }
    }

    std::string getData(std::string ip, requestCode code) {
        bool initialized = true; // Adjust as needed for your setup
        if (!initialized) {
            debug.log(_ERROR, "Anydesk library not initialized.");
            return "";
        }

        std::string output = "";
        std::string url = "/json/" + ip;
        std::wstring server = L"ip-api.com";

        // open WinHTTP session
        HINTERNET hSession = WinHttpOpen(L"anysniff",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);
        if (hSession) {
            // connect to the server
            HINTERNET hConnect = WinHttpConnect(hSession, server.c_str(),
                INTERNET_DEFAULT_HTTP_PORT, 0);
            if (hConnect) {
                // send request
                HINTERNET hRequest = WinHttpOpenRequest(hConnect, L"GET",
                    std::wstring(url.begin(), url.end()).c_str(),
                    NULL, WINHTTP_NO_REFERER,
                    WINHTTP_DEFAULT_ACCEPT_TYPES, 0);

                // valid request?
                if (hRequest) {
                    // send it!
                    if (WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0,
                        WINHTTP_NO_REQUEST_DATA, 0, 0, 0) &&
                        WinHttpReceiveResponse(hRequest, NULL)) {

                        DWORD bytesRead = 0;
                        DWORD size = 0;
                        std::string response;

                        do {
                            // get the size of the response
                            WinHttpQueryDataAvailable(hRequest, &size);
                            char* buffer = new char[size + 1];
                            ZeroMemory(buffer, size + 1);

                            // read the response
                            WinHttpReadData(hRequest, (LPVOID)buffer, size, &bytesRead);
                            response.append(buffer, bytesRead);

                            // mem leaks !
                            delete[] buffer;
                        } while (size > 0);

                        // handle invaild ip / local connection / flood?
                        if (nlohmann::json::parse(response)["status"].get<std::string>() == "fail") {
                            output = "Invaild IP (is it local network?)";
                        }
                        else {
                            // parse the JSON response
                            switch (code) {
                            case requestCode::country:
                                output = nlohmann::json::parse(response)["country"].get<std::string>();
                                break;
                            case requestCode::city:
                                output = nlohmann::json::parse(response)["city"].get<std::string>();
                                break;
                            case requestCode::isp:
                                output = nlohmann::json::parse(response)["isp"].get<std::string>();
                                break;
                            }
                        }
                    }
                    else {
                        debug.log(_ERROR, "Error: Failed to send WinHTTP request.");
                    }
                    WinHttpCloseHandle(hRequest);
                }
                WinHttpCloseHandle(hConnect);
            }
            WinHttpCloseHandle(hSession);
        }
        else {
            debug.log(_ERROR, "Error: Failed to open WinHTTP session.");
        }

        return output;
    }

    std::vector<std::string> sniffCallerIP() {
        std::vector<std::string> ips;
        if (!initialized) {
			debug.log(_ERROR, "Anydesk library not initialized.");
            return ips;
        }

		// use WMI to get the process ID of AnyDesk
        IEnumWbemClassObject* pEnumerator = nullptr;
        HRESULT hres = pSvc->ExecQuery(
            bstr_t("WQL"), bstr_t("SELECT ProcessId, Name FROM Win32_Process"),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY, NULL, &pEnumerator);

        if (FAILED(hres)) {
			debug.log(_ERROR, "Query for AnyDesk process failed.");
            return ips;
        }

        IWbemClassObject* pclsObj = nullptr;
        ULONG uReturn = 0;

        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
            if (0 == uReturn) break;

            VARIANT vtProp;
            pclsObj->Get(L"Name", 0, &vtProp, 0, 0);
            std::wstring processName = vtProp.bstrVal;

            if (processName.find(L"AnyDesk") != std::wstring::npos) {
                pclsObj->Get(L"ProcessId", 0, &vtProp, 0, 0);
                DWORD pid = vtProp.uintVal;

				// get the IP addresses of the established connections by the AnyDesk process (https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable)
                PMIB_TCPTABLE_OWNER_PID pTcpTable;
                ULONG ulSize = 0;
                DWORD dwRetVal = GetExtendedTcpTable(NULL, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
                pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(ulSize);
                dwRetVal = GetExtendedTcpTable(pTcpTable, &ulSize, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

                if (dwRetVal == NO_ERROR) {
                    for (int i = 0; i < (int)pTcpTable->dwNumEntries; i++) {
						// filter out connections that are not established or in SYN_SENT state
                        if (pTcpTable->table[i].dwOwningPid == pid &&
                            (pTcpTable->table[i].dwState == MIB_TCP_STATE_ESTAB || pTcpTable->table[i].dwState == MIB_TCP_STATE_SYN_SENT)) {

                            DWORD ip = pTcpTable->table[i].dwRemoteAddr;
                            std::string ipStr = std::to_string(ip & 0xff) + "." +
                                std::to_string((ip >> 8) & 0xff) + "." +
                                std::to_string((ip >> 16) & 0xff) + "." +
                                std::to_string((ip >> 24) & 0xff);

							// filter out local IP addresses and duplicates
                            if (ipStr.rfind("192.0.0", 0) != 0 && ipStr.rfind("192.168.", 0) != 0 && std::find(ips.begin(), ips.end(), ipStr) == ips.end()) {
								std::string isp = getData(ipStr, requestCode::isp);
								// filter out anydesk servers (no one have internet connection from ovh or dod xd)
								if (isp.find("OVH") == std::string::npos && isp.find("DoD") == std::string::npos) { // npos == not found
                                    ips.push_back(ipStr);
                                }

                            }
                        }
                    }
                }
                free(pTcpTable);
            }

            VariantClear(&vtProp);
            pclsObj->Release();
        }

        pEnumerator->Release();
        return ips;
    }

private:
    IWbemLocator* pLoc;
    IWbemServices* pSvc;
    bool initialized;
};

inline C_Anydesk anydesk = C_Anydesk();