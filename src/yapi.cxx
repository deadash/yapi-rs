#include "yapi.hpp"

namespace yapi_rs
{
	uint64_t GetProcAddress(uint64_t hProcess, uint64_t hModule, rust::Str funcName) {
		return yapi::GetProcAddress((HANDLE)hProcess, hModule, funcName.data());
	}

	uint64_t GetModuleHandle(uint64_t hProcess, rust::Slice<uint16_t> moduleName) {
		return yapi::GetModuleHandle((HANDLE)hProcess, (const wchar_t *)moduleName.data());
	}

	uint64_t GetProcAddress64(uint64_t hProcess, uint64_t hModule, rust::Str funcName) {
		return yapi::GetProcAddress64((HANDLE)hProcess, hModule, funcName.data());
	}

	uint64_t GetModuleHandle64(uint64_t hProcess, rust::Slice<uint16_t> moduleName) {
		return yapi::GetModuleHandle64((HANDLE)hProcess, (const wchar_t *)moduleName.data());
	}

	uint64_t GetNtDll64() {
		return yapi::GetNtDll64();
	}

	void SetLastError64(uint64_t status) {
		yapi::SetLastError64(status);
	}

	size_t VirtualQueryEx64(uint64_t hProcess, uint64_t lpAddress, rust::Slice<uint8_t> lpBuffer, size_t dwLength) {
		return yapi::VirtualQueryEx64((HANDLE)hProcess, lpAddress, (MEMORY_BASIC_INFORMATION64*)lpBuffer.data(), dwLength);
	}

	uint64_t VirtualAllocEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t flAllocationType, uint32_t flProtect) {
		return yapi::VirtualAllocEx64((HANDLE)hProcess, lpAddress, dwSize, flAllocationType, flProtect);
	}

	bool VirtualFreeEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t dwFreeType) {
		return yapi::VirtualFreeEx64((HANDLE)hProcess, lpAddress, dwSize, dwFreeType);
	}

	bool VirtualProtectEx64(uint64_t hProcess, uint64_t lpAddress, size_t dwSize, uint32_t flNewProtect, uint32_t& lpflOldProtect) {
		return yapi::VirtualProtectEx64((HANDLE)hProcess, lpAddress, dwSize, flNewProtect, (DWORD *)&lpflOldProtect);
	}

	bool ReadProcessMemory64(uint64_t hProcess, uint64_t lpBaseAddress, rust::Slice<uint8_t> lpBuffer, size_t& lpNumberOfBytesRead) {
		return yapi::ReadProcessMemory64((HANDLE)hProcess, lpBaseAddress, lpBuffer.data(), lpBuffer.length(), (SIZE_T*)&lpNumberOfBytesRead);
	}

	bool WriteProcessMemory64(uint64_t hProcess, uint64_t lpBaseAddress, rust::Slice<uint8_t> lpBuffer, size_t& lpNumberOfBytesWritten) {
		return yapi::WriteProcessMemory64((HANDLE)hProcess, lpBaseAddress, lpBuffer.data(), lpBuffer.length(), (SIZE_T*)&lpNumberOfBytesWritten);
	}

	uint64_t CreateRemoteThread64(uint64_t hProcess, uint64_t lpStartAddress, uint64_t lpParameter, uint32_t dwCreationFlags, uint32_t& lpThreadId) {
		return (uint64_t)yapi::CreateRemoteThread64((HANDLE)hProcess, NULL, 0, lpStartAddress, lpParameter, dwCreationFlags, (LPDWORD)&lpThreadId);
	}

	// uint64_t OpenThread64(uint64_t hProcess, uint32_t dwDesiredAccess, bool bInheritHandle, uint32_t dwThreadId)
	// {
	// 	yapi::YAPICall _OpenThread64((HANDLE)hProcess, L"kernel32.dll", "OpenThread");
	// 	return _OpenThread64(dwDesiredAccess, (BOOL)bInheritHandle, dwThreadId);
	// }

	uint64_t GetThreadStartAddress(uint64_t hThread)
	{
		static yapi::X64Call NtQueryInformationThread("NtQueryInformationThread");
		if (!NtQueryInformationThread) return 0;

		DWORD64 address = 0;
		DWORD64 status = NtQueryInformationThread(hThread, 0x09, &address, sizeof(DWORD64), NULL);
		if (!status) return address;

		yapi::SetLastError64(status);
		return NULL;
	}

    bool Is64BitOS()
    {
        return detail::Is64BitOS();
    }
}