// LoadLibraryHook.cpp : Defines the entry point for the application.
//

#include <Windows.h>
#include <LoadLibraryHook.h>
#include <polyhook2/ZydisDisassembler.hpp>
#include <polyhook2/Detour/x64Detour.hpp>
#include <polyhook2/PE/IatHook.hpp>

#include <cstdarg>
#include <conio.h>

uint64_t hookLoadLibrary = NULL; // original LoadLibrary
// IDA: LoadLibraryExW(LPCWSTR lpLibFileName, HANDLE hFile, DWORD dwFlags)
HMODULE WINAPI hk_LoadLibrary(LPCWSTR lpLibFileName, HANDLE hfile, DWORD dwFlags)
{
	printf("Loading file: %ws\n", lpLibFileName);
	return PLH::FnCast(hookLoadLibrary, &LoadLibraryExW)(lpLibFileName, hfile, dwFlags);
}

int getch_noblock()
{
	if (_kbhit())
		return _getch();
	return -1;
}

int main()
{
	PLH::ZydisDisassembler dis(PLH::Mode::x64);

	HMODULE k32 = GetModuleHandle("kernelbase.dll");
	if (k32 == NULL)
		return 0;
	// all of the loadlibrary functions in kernel32/kernelbase end up calling LoadLibraryExW, which is the last step before ntdll.
	auto load_lib_addr = GetProcAddress(k32, "LoadLibraryExW");
	if (load_lib_addr == NULL)
		return 0;
	printf("LoadLibraryExW address in kernelbase.dll: %p\n", load_lib_addr);
	
	std::unique_ptr<PLH::x64Detour> p = 
		std::make_unique<PLH::x64Detour>(reinterpret_cast<uint64_t>(load_lib_addr), reinterpret_cast<uint64_t>(&hk_LoadLibrary), &hookLoadLibrary, dis);	
	
	p->hook();
	//LoadLibraryA("F:\\vs_projects\\test_inject\\x64\\Debug\\test_inject.dll");

	while (true)
	{
		if (getch_noblock() != -1)
			break;
	}
	p->unHook();
	return 0;	
}
