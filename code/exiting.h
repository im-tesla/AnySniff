#pragma once
#include <csignal>

bool loop = true;

BOOL WINAPI handleUninitialize(DWORD signal) {
	if (signal == CTRL_CLOSE_EVENT || signal == CTRL_C_EVENT) {
		anydesk.uninitialize();
		loop = false;
		debug.log(_INFO, "Goodbye!");
		Sleep(1500);
		exit(0);
	}

	return TRUE;
}
