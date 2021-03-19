#include <Windows.h>
#include <polyhook2/ZydisDisassembler.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

#include <cstdarg>
#include <conio.h>

uint64_t hookLoadLibrary = NULL; // original LoadLibrary
// IDA: LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
HMODULE WINAPI hk_LoadLibrary(LPCWSTR lpLibFileName, HANDLE hfile, DWORD dwFlags)
{
	printf("Loading file: %ws HANDLE: %p Flags: %lu\n", lpLibFileName, hfile, dwFlags);
	return PLH::FnCast(hookLoadLibrary, &LoadLibraryExW)(lpLibFileName, hfile, dwFlags);
}

int main()
{
	auto error_log = std::make_shared<PLH::ErrorLog>();
	PLH::Log::registerLogger(error_log);
	PLH::ZydisDisassembler dis(PLH::Mode::x64);

	HMODULE k32 = GetModuleHandleA("kernelbase.dll");
	if (k32 == NULL)
		return 0;
	// all of the loadlibrary functions in kernel32/kernelbase end up calling LoadLibraryExW, which is the last step before ntdll.
	auto load_lib_addr = GetProcAddress(k32, "LoadLibraryExW");
	if (load_lib_addr == NULL)
		return 0;
	printf("LoadLibraryExW address in kernelbase.dll: %p\n", load_lib_addr);

	PLH::x64Detour loadlib_detour(reinterpret_cast<uint64_t>(load_lib_addr), reinterpret_cast<uint64_t>(&hk_LoadLibrary), &hookLoadLibrary, dis);

	loadlib_detour.hook();

	LoadLibraryExW(L"kernel32.dll", 0, 0);

	while (true)
	{
		if (getchar())
			break;
	}

	loadlib_detour.unHook();

	return 0;
}
