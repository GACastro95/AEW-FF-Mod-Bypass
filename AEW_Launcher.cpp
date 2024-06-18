// AEW_Launcher.cpp : Contains main logic, memory override for AEW v1.0 @ runtime //
#include "ProcessMain.h"
#include "ReaderUtils.h"
#include <iostream>
#include "AEW_Launcher.h"
#pragma once 

using namespace std;
ProcessMain::ProcessMeta pMeta = { 0,0,0 };

void UpdateAEWModule( DWORD integRVA, DWORD packRVA, DWORD sigRVA ) {
	DWORD64 integFunctionPtr = pMeta.clientBase + integRVA; /* Original ASM terminates if AntiCheat interface is disabled */
	DWORD64 packFunctionPtr = pMeta.clientBase + packRVA; /* Original ASM defines external PAK mounts */
	DWORD64 sigFunctionPtr = pMeta.clientBase + sigRVA; /* Original ASM skips PAK if no SIG file is found */

	// Custom Assembly
	uint8_t asmDataAntiCheat;
	uint32_t asmDataPAK;
	uint16_t asmDataSig;

	// Integrity Override
	ReadProcessMemory(pMeta.pHandle, (LPCVOID)(integFunctionPtr), &asmDataAntiCheat, sizeof(asmDataAntiCheat), NULL);
	if (asmDataAntiCheat == 0x75 || asmDataAntiCheat == 0x74) {
		asmDataAntiCheat = 0xEB; // Changes "JNE" instruction to "JE"
		WriteProcessMemory(pMeta.pHandle, (LPVOID)(integFunctionPtr), &asmDataAntiCheat, sizeof(asmDataAntiCheat), NULL);
	}

	// PAK override	
	ReadProcessMemory(pMeta.pHandle, (LPCVOID)(packFunctionPtr), &asmDataPAK, sizeof(asmDataPAK), NULL);
	if (asmDataPAK == 0x4C304688) {
		asmDataPAK = 0x4C909090; // NOPs flag, allows External PAKs
		WriteProcessMemory(pMeta.pHandle, (LPVOID)(packFunctionPtr), &asmDataPAK, sizeof(asmDataPAK), NULL);
	}

	// SIG override	
	ReadProcessMemory(pMeta.pHandle, (LPCVOID)(sigFunctionPtr), &asmDataSig, sizeof(asmDataSig), NULL);
	if (asmDataSig == 0x840F) {
		DWORD64 asmQWORD = 0x8B4D90000000A7E9; // Alters "JE" instruction to "JMP", bypasses missing sig method
		WriteProcessMemory(pMeta.pHandle, (LPVOID)(sigFunctionPtr), &asmQWORD, sizeof(asmQWORD), NULL);
	}
	
	CloseHandle(pMeta.pHandle);
}



void GetAEWProcess(const char* gamePath, const char* gameName) {
	DWORD pID = 0x0;
	HWND hGameWindow;
	HANDLE pHandle;

	// Open Game
	ProcessMain::LaunchProcessHandle(gamePath);

	// Get Process ID using exe Name
	while (pMeta.processID == 0x0) {
		pMeta = ProcessMain::GetProcessIdFromExeName(gameName);
	}

	pMeta.pHandle = ProcessMain::GetProcessHandle(pMeta.processID, PROCESS_ALL_ACCESS);
}





int RunLauncher(char* gamePath)
{

	// Search for local offsets
	DWORD interfaceOffset = ReaderUtils::GetInterfaceOffset(gamePath);
	DWORD packOffset = ReaderUtils::GetPackOffset(gamePath);
	DWORD sigOffset = ReaderUtils::GetSigOffset(gamePath);

	if (interfaceOffset == 0x0 || packOffset == 0x0 || sigOffset == 0x0) {
		return 0;
	}

	// Collect all RVA's using offset
	interfaceOffset = GetRVAFromFileOffset(gamePath, interfaceOffset);
	packOffset = GetRVAFromFileOffset(gamePath, packOffset);
	sigOffset = GetRVAFromFileOffset(gamePath, sigOffset);

	std::cout << "\n\nRVA: " << std::hex << interfaceOffset << std::endl;
	std::cout << "RVA: " << std::hex << packOffset << std::endl;
	std::cout << "RVA: " << std::hex << sigOffset << std::endl;

	_putenv_s("SteamAppId", std::string("1913210").c_str());

	// Launch process and acquire handle
	std::string path(gamePath);
	std::string gameName(path.substr(path.rfind("\\") + 1));
	GetAEWProcess(gamePath, gameName.c_str());

	TCHAR const* procName = gameName.c_str();
	TCHAR* moduleName = new TCHAR[strlen(gameName.c_str()) + 1];
	_tcscpy_s(moduleName, strlen(gameName.c_str()) + 1, procName);

	//Get Base Address
	while (pMeta.clientBase == 0x0) {
		pMeta.clientBase = dwGetModuleBaseAddress(_T(moduleName), pMeta.processID);
	}

	// Overrides process terminate functions
	UpdateAEWModule( interfaceOffset, packOffset, sigOffset );

	return 0;
}