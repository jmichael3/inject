#include <stdio.h>
#include <Windows.h>
#include <Tlhelp32.h>


int RemoteThreadInject(int pid, char* dllpath)
{

	// open handle to process
	HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid);

	// initialize memory
	void* buf = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// write buffer to memory
	WriteProcessMemory(hProcess, buf, dllpath, strlen(dllpath), nullptr);

	// create remote thread
	HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
		(LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32"), "LoadLibraryA"),
		buf, 0, nullptr);

	// cleanup
	CloseHandle(hProcess);
	CloseHandle(hThread);

	return 0;
}

int APCInject(int pid, char* dllpath)
{
	// create handle to process. Only need memory and write access this time
	printf("[*]Opening handle to process with pid %d\n", pid);
	HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, false, pid);

	// initialize memory
	printf("[*]Initializing memory\n");
	void* buf = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	// write buffer to memory
	printf("[*]Writing dllpath to memory\n");
	WriteProcessMemory(hProcess, buf, dllpath, strlen(dllpath), nullptr);

	// get list of threads in process
	printf("[*]Opening handle to process with pid %d for thread enumeration\n", pid);
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, pid);
	THREADENTRY32 te = { sizeof(te) };
	if (Thread32First(hSnapshot, &te))
	{
		do{
			HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, false, te.th32ThreadID);

			QueueUserAPC((PAPCFUNC)GetProcAddress(GetModuleHandleA("kernel32"), "LoadLibraryA"),
				hThread, (ULONG_PTR)buf);
			CloseHandle(hThread);;
			Sleep(2000);
		} while (Thread32Next(hSnapshot, &te));
	}

	return 0;
}

int main(int argc, char *argv[])
{

	// get required args and print usage
	if (argc < 4)
	{
		printf("\n[*]Usage: %s <pid> <dll_path> <1-4>\n\n", argv[0]);
		printf(" 1        RemoteThreadInject (CreateRemoteThread)\n");
		printf(" 2        APCInject          (Asyncchrnonous Procedure Call)\n");
		return 0;
	}

	int pid = atoi(argv[1]);
	char *dllpath = argv[2];
	int method = atoi(argv[3]);

	// choose method for dll injection
	switch (method)
	{
	case 1 :
		printf("[*]Injecting %s into PID: %d using method 1 (RemoteThreadInject)\n", dllpath, pid);
		RemoteThreadInject(pid, dllpath);
		break;

	case 2:
		printf("[*]Injecting %s into PID: %d using method 2 (APCInject)\n", dllpath, pid);
		APCInject(pid, dllpath);
		break;

	default :
		printf("[-]Invalid method\n");
		break;
	}



	return 0;
}