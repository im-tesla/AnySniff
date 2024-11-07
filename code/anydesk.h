#pragma once
#define WIN32_LEAN_AND_MEAN

#include <string>
#include <vector>
#include <windows.h>
#include <iphlpapi.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <iostream>
#include <json.hpp>
#include "debug.h"

#include <httplib.h>
#include <json.hpp>
using json = nlohmann::json;

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

using json = nlohmann::json;

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
        httplib::Client client("http://ip-api.com");
        auto res = client.Get("/json/" + ip);
        
        if (res && res->status == 200) {
			json j = json::parse(res->body);
			if (code == requestCode::country) {
				return j["country"];
			}
			else if (code == requestCode::city) {
				return j["city"];
			}
			else if (code == requestCode::isp) {
				return j["isp"];
			}
        }
        else {
			//debug.log(_ERROR, "Failed to get data from ip-api.com.");
			return "";
        }
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
								if (isp != "" && isp.find("OVH") == std::string::npos && isp.find("DoD") == std::string::npos) { // npos == not found
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