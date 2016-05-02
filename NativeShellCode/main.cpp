#define _CRT_SECURE_NO_WARNINGS
#include <Windows.h>
#include <stdio.h>

inline int __stdcall my_strcmpA(const char * str1, const char * str2);
inline int __stdcall my_strcmpW(const wchar_t * str1, const wchar_t * str2);
inline DWORD __stdcall MyGetProcAddress(HMODULE hModuleBase, LPCSTR lpzFunctionName);

typedef struct my_iobuf
{
	void* _Placeholder;
} MY_FILE;

inline int START_SHELLCODE(int value, char * str1, char * str2)
{
	// test asm
	short test_value = 100;
	
	__asm mov ax, test_value;
	__asm add ax, 1;
	__asm mov test_value, ax;
	
	HMODULE(__stdcall *MyLoadLibraryA)(LPCSTR);
	char func_LoadLibraryA[] = { 'L', 'o','a','d','L','i','b','r','a','r','y','A', 0 };
	HMODULE kernel32_dll = (HMODULE)value;
	MyLoadLibraryA = (HMODULE(__stdcall *)(LPCSTR))MyGetProcAddress(kernel32_dll, func_LoadLibraryA);
	/*
	int(__stdcall *MyMessageBoxA)(HWND, LPCSTR, LPCSTR, UINT);
	char szUser32Dll[] = { 'u','s','e','r','3','2','.','d','l','l',0 };
	char func_MessageBoxA[] = { 'M','e','s','s','a','g','e','B','o','x','A',0 };
	HMODULE user32_dll = MyLoadLibraryA(szUser32Dll);
	MyMessageBoxA = (int(__stdcall *)(HWND, LPCSTR, LPCSTR, UINT))MyGetProcAddress(user32_dll, func_MessageBoxA);
	MyMessageBoxA(NULL, str1, str2, MB_OK);
	*/
	/*
	char szShell32[] = { 's','h','e','l','l','3','2','.','d','l','l', 0 };
	char func_ShellExecuteA[] = { 'S','h','e','l','l','E','x','e','c','u','t','e','A',0 };
	char szString1[] = { 'o','p','e','n',0 };
	char szString2[] = { 'c','m','d','.','e','x','e',0 };
	HMODULE hShell32 = MyLoadLibraryA(szShell32);
	HINSTANCE(__stdcall *MyShellExecuteA)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT);
	MyShellExecuteA = (HINSTANCE(__stdcall *)(HWND, LPCSTR, LPCSTR, LPCSTR, LPCSTR, INT))MyGetProcAddress(hShell32, func_ShellExecuteA);
	MyShellExecuteA(NULL, szString1, szString2, NULL, NULL, SW_SHOW);
	*/
	char szCrtdll[] = { 'c','r','t','d','l','l','.','d','l','l',0 };
	char func_system[] = { 's','y','s','t','e','m',0 };
	char szCommand[] = { 'c','m','d','.','e','x','e',' ','/','C',' ','w','h','o','a','m','i',' ','>',' ','C',':','\\','T','e','m','p','\\','\\','t','e','s','t','.','t','x','t',0 };
	HMODULE hCrtdll = MyLoadLibraryA(szCrtdll);
	int(__cdecl *my_system)(const char *);
	my_system = (int(__cdecl *)(const char *))MyGetProcAddress(hCrtdll, func_system);
	my_system(szCommand);

	return (int)test_value;
} // end func

inline int __stdcall my_strcmpA(const char * str1, const char * str2)
{
	for (; *str1 == *str2; str1++, str2++)
	{
		if (*str1 == 0)
			return 0;
	} // end for

	return (unsigned char *)str1 > (unsigned char *)str2 ? 1 : -1;
} // end func

inline int __stdcall my_strcmpW(const wchar_t * str1, const wchar_t * str2)
{
	for (; *str1 == *str2; str1++, str2++)
	{
		if (*str1 == 0)
			return 0;
	} // end for

	return (wchar_t *)str1 > (wchar_t *)str2 ? 1 : -1;
} // end func

inline DWORD __stdcall MyGetProcAddress(HMODULE hModuleBase, LPCSTR lpzFunctionName)
{
	DWORD					pFunctionAddress = NULL;
	SIZE_T					size = 0;
	PIMAGE_DOS_HEADER		dos = (PIMAGE_DOS_HEADER)hModuleBase;
	PIMAGE_NT_HEADERS		nt = (PIMAGE_NT_HEADERS)((SIZE_T)hModuleBase + dos->e_lfanew);
	PIMAGE_DATA_DIRECTORY	expdir = (PIMAGE_DATA_DIRECTORY)(nt->OptionalHeader.DataDirectory + IMAGE_DIRECTORY_ENTRY_EXPORT);
	SIZE_T					addr = expdir->VirtualAddress;
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((SIZE_T)hModuleBase + addr);
	PULONG					functions = (PULONG)((SIZE_T)hModuleBase + exports->AddressOfFunctions);
	PSHORT					ordinals = (PSHORT)((SIZE_T)hModuleBase + exports->AddressOfNameOrdinals);
	PULONG					names = (PULONG)((SIZE_T)hModuleBase + exports->AddressOfNames);
	SIZE_T					max_name = exports->NumberOfNames;
	SIZE_T					max_func = exports->NumberOfFunctions;

	for (SIZE_T i = 0; i < max_name; i++)
	{
		SIZE_T ord = ordinals[i];

		if (i >= max_name || ord >= max_func)
		{
			return NULL;
		} // end if
		if (functions[ord] < addr || functions[ord] >= addr + size)
		{
			if (my_strcmpA((PCHAR)hModuleBase + names[i], lpzFunctionName) == 0)
			{
				pFunctionAddress = (DWORD)((PCHAR)hModuleBase + functions[ord]);
				break;
			} // end if
		} // end if
	} // end for

	return pFunctionAddress;
} // end func

void __declspec(naked) END_SHELLCODE(void) {}

int __cdecl main(void)
{
	int shell_code_size = (int)END_SHELLCODE - (int)START_SHELLCODE;

	// write binary
	FILE *output_file = fopen("shellcode.bin", "w");
	fwrite(START_SHELLCODE, (int)END_SHELLCODE - (int)START_SHELLCODE, 1, output_file);
	fclose(output_file);
	START_SHELLCODE((int)LoadLibraryA("kernel32.dll"), "Test1", "Test2");
	// read binary to character
	FILE *input_file = fopen("shellcode.bin", "r");
	FILE *output_shell_code = fopen("shellcode.txt", "w");

	while (true)
	{
		BYTE data = 0;
		fread(&data, 1, 1, input_file);
		fprintf(output_shell_code, "\\x%02X", data);

		if (feof(input_file))
			break;
	} // end while

	fclose(input_file);
	fclose(output_shell_code);
	system("pause");
	return 0;
} // end main