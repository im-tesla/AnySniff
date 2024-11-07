/* AnySniff - Sniff caller IP Address */
#include "anydesk.h"
#include "debug.h"
#include "exiting.h"

std::vector<std::string> alreadySniffed;

int main() {
	// initialize console handler for proper uninitialization
	SetConsoleCtrlHandler(handleUninitialize, TRUE);

	if (anydesk.initialize()) {
		debug.log(_INFO, "Initialized AnyDesk.");
	}

	debug.log(_INFO, "Sniffing caller IP address...");

	while (1 && loop) {
		auto ips = anydesk.sniffCallerIP();

		for (auto ip : ips) {
			if (std::find(alreadySniffed.begin(), alreadySniffed.end(), ip) != alreadySniffed.end()) {
				continue;
			}

			debug.log(_INFO, "---------------");
			debug.log(_WARNING, "New caller IP: ", ip.c_str());
			debug.log(_WARNING, "Country: ", anydesk.getData(ip, country).c_str());
			debug.log(_WARNING, "City: ", anydesk.getData(ip, city).c_str());
			debug.log(_WARNING, "ISP: ", anydesk.getData(ip, isp).c_str());

			alreadySniffed.push_back(ip);
		}

		Sleep(2000);
	}
	
	anydesk.uninitialize();

	return 0;
}

/*
 * This program is created for educational and research purposes only.
 * It is important to ensure that the code is used within legal boundaries
 * and adheres to relevant laws and regulations. Any misuse is not endorsed
 * by the creator and is solely the responsibility of the user.
 * Created by im-tesla.
 */