#[cxx::bridge(namespace = "yapi_rs")]
mod ffi {
    extern "C++" {
        include!("yapi.h");
        
        unsafe fn GetProcAddress(hProcess: u64, hModule: u64, funcName: &str) -> u64;
        unsafe fn GetModuleHandle(hProcess: u64, moduleName: &mut [u16]) -> u64;
        unsafe fn GetProcAddress64(hProcess: u64, hModule: u64, funcName: &str) -> u64;
        unsafe fn GetModuleHandle64(hProcess: u64, moduleName: &mut [u16]) -> u64;
        unsafe fn GetNtDll64() -> u64;
        
        unsafe fn SetLastError64(status: u64);
        unsafe fn VirtualQueryEx64(hProcess: u64, lpAddress: u64, lpBuffer: &mut [u8], dwLength: usize) -> usize;
        unsafe fn VirtualAllocEx64(hProcess: u64, lpAddress: u64, dwSize: usize, flAllocationType: u32, flProtect: u32) -> u64;
        unsafe fn VirtualFreeEx64(hProcess: u64, lpAddress: u64, dwSize: usize, dwFreeType: u32) -> bool;
        unsafe fn VirtualProtectEx64(hProcess: u64, lpAddress: u64, dwSize: usize, flNewProtect: u32, lpflOldProtect: &mut u32) -> bool;
        unsafe fn ReadProcessMemory64(hProcess: u64, lpBaseAddress: u64, lpBuffer: &mut [u8], lpNumberOfBytesRead: &mut usize) -> bool;
        unsafe fn WriteProcessMemory64(hProcess: u64, lpBaseAddress: u64, lpBuffer: &mut [u8], lpNumberOfBytesWritten: &mut usize) -> bool;
        unsafe fn CreateRemoteThread64(
            hProcess: u64, 
            lpStartAddress: u64, 
            lpParameter: u64, 
            dwCreationFlags: u32, 
            lpThreadId: &mut u32
        ) -> u64;
        // unsafe fn OpenThread64(hProcess: u64, dwDesiredAccess: u32, bInheritHandle: bool, dwThreadId: u32) -> u64;
        unsafe fn GetThreadStartAddress(hThread: u64) -> u64;

        unsafe fn Is64BitOS() ->bool;
    }
}

pub use ffi::*;
