/* Replace "dll.h" with the name of your header */
#define _WIN32_WINNT 0x0500 
#include <windows.h>   
#include <stdio.h>
#include <conio.h>
#include <tlhelp32.h> 
#include <shlwapi.h> 
#include <iostream>
#include <winioctl.h>

typedef LONG    NTSTATUS;   
typedef NTSTATUS (WINAPI *pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);   
#define STATUS_SUCCESS    ((NTSTATUS)0x000000000L)   
#define ThreadQuerySetWin32StartAddress 9  

unsigned char *call_terminateThread;

void config_ini();
int Sleeped;
char PATH_FILE_TMP[FILENAME_MAX];

void myTerminateThread()
{
 asm("mov eax, %0 \n"
 //"mov eax, dword ptr ds:[eax]\n"
 //"add eax, 3\n"
 //7C81CB3E   8BEC             MOV EBP,ESP

  "jmp eax" :: "d" (call_terminateThread)); //7C81CB3E   8BEC             MOV EBP,ESP
}

DWORD WINAPI GetThreadStartAddress(HANDLE hThread)   
{   
    NTSTATUS ntStatus;   
    HANDLE hDupHandle;   
    DWORD dwStartAddress;   
   
    pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle("ntdll.dll"), "NtQueryInformationThread");   
    if(NtQueryInformationThread == NULL) return 0;   
   
    HANDLE hCurrentProcess = GetCurrentProcess();   
    if(!DuplicateHandle(hCurrentProcess, hThread, hCurrentProcess, &hDupHandle, THREAD_QUERY_INFORMATION, FALSE, 0)){   
        SetLastError(ERROR_ACCESS_DENIED);   
        return 0;   
    }   
    ntStatus = NtQueryInformationThread(hDupHandle, ThreadQuerySetWin32StartAddress, &dwStartAddress, sizeof(DWORD), NULL);   
    CloseHandle(hDupHandle);   
   
    if(ntStatus != STATUS_SUCCESS) return 0;   
    return dwStartAddress;   
} 

void CreateThreadFunction();
BOOL EnumThread(DWORD dwProcessId);

DWORD GetProcessID(const char* szExeName)
{
	PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if(Process32First(hSnapshot, &pe))
		while(Process32Next(hSnapshot, &pe))
			if(!strcmp(pe.szExeFile, szExeName))
				return pe.th32ProcessID;

	return 0;
}

DWORD XTrapVa;

BOOL Teste = true;
HANDLE mInstance;

unsigned char buffer[3];

BOOL APIENTRY DllMain (HINSTANCE hInst, DWORD reason, LPVOID reserved)
{  
     if(Teste)
     {
      mInstance = hInst;
      //config_ini();
      bool test = 0;
      //char buffer_msg[] = "\x6A\x00\x68\xB5\x95\xB8\x00\x68\xB5\x95\xB8\x00\xFF\x15\x60\x34\xCF\x00\xC3\x46\x69\x72\x65\x66\x6F\x78\x00";
      //test = WriteProcessMemory((void*)-1, (void*)0x00B895A2, buffer_msg, sizeof(buffer_msg), 0);
      //if(test == -1)
       //MessageBox(0, 0, 0, 0);
       
      MessageBox(0, "[Bypass XTrapGC] Criado por Firefox [PressEnter]", "Criado por Firefox [PressEnter]", 0);
      CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CreateThreadFunction, NULL, 0, NULL);
      Teste = false;
     }
    /* Returns TRUE on success, FALSE on failure */
    return TRUE;
}

void config_ini()
{
 int i;
 char PATH_FILE[FILENAME_MAX];
 
 GetModuleFileName((HINSTANCE)mInstance, PATH_FILE, FILENAME_MAX);
 
 i = strlen(PATH_FILE);
 
 for(i; i > 0; i--)
 {
  if(PATH_FILE[i] == '\\')
  {
   break;
  }
 }
 
 strncpy(PATH_FILE_TMP, PATH_FILE, i+1);
 PATH_FILE_TMP[i+1] = '\0';
 strcat(PATH_FILE_TMP, "config.ini");
 
 Sleeped = GetPrivateProfileInt("AntiXTrapbyFirefox", "Sleep", 25000, PATH_FILE_TMP);
}

HANDLE hProcess;
DWORD pID;

BOOLEAN testes = true;

FILE * pFile;

void CreateThreadFunction()
{
 DWORD myPID = GetCurrentProcessId();
 //HANDLE tprocess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, myPID);
 DWORD address = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), "TerminateThread");
 call_terminateThread = (unsigned char*)address;
 call_terminateThread += 3;
 
 buffer[0] = 0x0C2;
 buffer[1] = 0x08;
 buffer[2] = 0x00;
 
 WriteProcessMemory((void*)-1, (void*)address, buffer, 3, 0);
 
 char buffer_msg[] = "\x6A\x00\x68\xB5\x95\xB8\x00\x68\xB5\x95\xB8\x00\xFF\x15\x60\x34\xCF\x00\xC3\x46\x69\x72\x65\x66\x6F\x78\x00";
 
 int test = 0;
 
 // Coloca um interrupt no codigo, "Remover proteção na Driver"
 test = WriteProcessMemory((void*)-1, (void*)0x00B895A2, buffer_msg, sizeof(buffer_msg), 0);
 
 if(test == -1)
  MessageBox(0, 0, 0, 0);
 
 char SVCNAME[] = "ExamplesDriver";
 #define IOCTL_UNKNOWN_BASE					FILE_DEVICE_UNKNOWN
 #define UnHookXTrapbyFirefox	CTL_CODE(IOCTL_UNKNOWN_BASE, 0x0803, METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
 DWORD hFile     = 0;
 DWORD dwReturn  = 0;
 
 //while(true)
 //{
              
  //Sleep(25000);
             
  while(true)
  {
   XTrapVa = (DWORD)GetModuleHandleA("XTrapVa.dll");
   /*hFile = (DWORD)CreateFile("\\\\.\\Example", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL); 
   DeviceIoControl((void*)hFile, UnHookXTrapbyFirefox, NULL, 0, 0, 0, &dwReturn, NULL);
   CloseHandle((void*)hFile);*/
     
   if(testes)
   {
    pFile = fopen ("ADDRESS_MAIN.txt","a+");
    fprintf(pFile, "Xtrap.dll -> [%x]\n", XTrapVa);
    EnumThread(myPID);
    fprintf(pFile, "********************\n"); 
    fclose(pFile);
    //MessageBox(0, 0, 0, 0);
   }
   /*else
   {
    Sleep(30000);
    MessageBox(0, "XTrap.xt foi Removido!!!", "XTrap.xt foi Removido!!!", 0);
    pID = GetProcessID("XTrap.xt");
    hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pID);
    TerminateProcess(hProcess, 0);
   }*/
   
   Sleep(1000);
  }
  
  //FreeLibrary((HINSTANCE)XTrapVa);
  Sleep(100);
 //}
}

HANDLE hThread;
HANDLE hThreadOne;
DWORD dwThreadStartAddress;
HANDLE hModuleSnap;
THREADENTRY32 TE32 = {0}; 
char buffers[20];

int soma = 0;
bool active_all = 0;

BOOL EnumThread(DWORD dwProcessId){     
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, dwProcessId);       
    if (hModuleSnap == INVALID_HANDLE_VALUE)          
        return FALSE;    TE32.dwSize = sizeof(THREADENTRY32); 
    
    if(!Thread32First(hModuleSnap, &TE32))    
    {        
        CloseHandle(hModuleSnap);        
        return FALSE;
    }     
    do   
    {     
        if(TE32.th32OwnerProcessID != dwProcessId)    
            continue;   
            
        hThreadOne = OpenThread(THREAD_QUERY_INFORMATION, FALSE, TE32.th32ThreadID);
        dwThreadStartAddress = GetThreadStartAddress(hThreadOne); 
        hThread = (HANDLE)OpenThread(THREAD_ALL_ACCESS, FALSE, TE32.th32ThreadID);               
 
        //itoa(dwThreadStartAddress, buffers, 16);
        //MessageBox(0, buffers, buffers, 0);
        
        fprintf(pFile, "ADDRESS THREAD -> [%x]\n", dwThreadStartAddress); 
        
        if(dwThreadStartAddress == (DWORD)0x00DF5D70)
        {
         LoadLibrary("StopProgramming.dll");
         MessageBox(0, 0, 0, 0);
         active_all = true;
         asm("push %0" :: "d" (0));
         asm("push %0" :: "d" (hThread));
         myTerminateThread();
        }
        if(active_all == true)
        {
         if(dwThreadStartAddress == (DWORD)0xEFB360)
         {
          soma++;
          //strcpy(buffers, "0xeaaf30");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
         if(dwThreadStartAddress == 0x00C6295F)
         {
          //strcpy(buffers, "0xea9be0");
          //MessageBox(0, buffers, buffers, 0);
          soma++;
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
         if(dwThreadStartAddress == 0x0DF5D70) // OK
         {
          soma++;
          //strcpy(buffers, "0xdaaaa0");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
         if(dwThreadStartAddress == 0x0EF5BA0) // OK
         {
          soma++;
          //strcpy(buffers, "0xeaf3a0");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
         if(dwThreadStartAddress == 0x0EF6EF0) // OK
         {
          soma++;
          //strcpy(buffers, "0xc179cf");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
        
         //if(dwThreadStartAddress == XTrapVa+0x468F0 && soma == 5) // ok
         if(dwThreadStartAddress == XTrapVa+0x13B10) // ok
         {
          //strcpy(buffers, "XTrapVa+0x3f370");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
          MessageBox(0, 0, 0, 0);
         }
         //if(dwThreadStartAddress == XTrapVa+0x17C0 && soma == 5) // ok
         if(dwThreadStartAddress == XTrapVa+0x13C90)
         {
          //strcpy(buffers, "XTrapVa+0x17e0");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
          MessageBox(0, 0, 0, 0);
         }
         if(dwThreadStartAddress == XTrapVa+0x17C0 && soma == 5) // ok
         {
          //strcpy(buffers, "XTrapVa+0x17e0");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread();
         }
         if(dwThreadStartAddress == XTrapVa+0x422E0 && soma == 5) // ok
         {
          testes = 0x00;
          //strcpy(buffers, "XTrapVa+0x3A4b0");
          //MessageBox(0, buffers, buffers, 0);
          asm("push %0" :: "d" (0));
          asm("push %0" :: "d" (hThread));
          myTerminateThread(); 
         }
        }
        
        CloseHandle(hThreadOne);
        CloseHandle(hThread);   
    } while (Thread32Next(hModuleSnap, &TE32));    
    CloseHandle(hModuleSnap);                             
    return TRUE;
}   
