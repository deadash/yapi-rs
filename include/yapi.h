#pragma once

#include <tchar.h>
#include <windows.h>
#include <vector>
#include <string>

#include "rust/cxx.h"

namespace yapi_rs
{
	uint64_t GetProcAddress(uint64_t hProcess, uint64_t hModule, rust::Str funcName);
	uint64_t GetModuleHandle(uint64_t hProcess, rust::Slice<uint16_t> moduleName);
	uint64_t GetProcAddress64(uint64_t hProcess, uint64_t hModule, rust::Str funcName);
	uint64_t GetModuleHandle64(uint64_t hProcess, rust::Slice<uint16_t> moduleName);
	uint64_t GetNtDll64();
	void SetLastError64(uint64_t status);
	size_t VirtualQueryEx64(uint64_t hProcess, uint64_t lpAddress, rust::Slice<uint8_t> lpBuffer, size_t dwLength);
	uint64_t VirtualAllocEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect);
	bool VirtualFreeEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t dwFreeType);
	bool VirtualProtectEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t& lpflOldProtect);
	bool ReadProcessMemory64(uint64_t hProcess, uint64_t lpBaseAddress, rust::Slice<uint8_t> lpBuffer, size_t& lpNumberOfBytesRead);
	bool WriteProcessMemory64(uint64_t hProcess, uint64_t lpBaseAddress, rust::Slice<uint8_t> lpBuffer, size_t& lpNumberOfBytesWritten);
	uint64_t CreateRemoteThread64(uint64_t hProcess, uint64_t lpStartAddress, uint64_t lpParameter, uint32_t dwCreationFlags, uint32_t& lpThreadId);
	uint64_t GetThreadStartAddress(uint64_t hThread);
    bool Is64BitOS();
}