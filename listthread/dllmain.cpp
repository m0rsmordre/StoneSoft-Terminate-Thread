#pragma warning(disable:4996)
#include "pch.h"
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <TlHelp32.h>
#include <psapi.h>
#include <winternl.h>


using namespace std;
#define ThreadQuerySetWin32StartAddress 9 //Bazı nedenlerden dolayı bunu winternl.h headerından çekip enum olarak yazamıyorsunuz çok saçma..
typedef NTSTATUS(WINAPI* pNtQIT)(HANDLE, LONG, PVOID, ULONG, PULONG);


void ModulleriGetir(DWORD pid)
{
    HANDLE hModuleSnap = INVALID_HANDLE_VALUE;
    MODULEENTRY32 me32;
    hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
    if (hModuleSnap == INVALID_HANDLE_VALUE) return;
    DWORD base = (DWORD)GetModuleHandle(L"StoneSoft.dll");
    me32.dwSize = sizeof(MODULEENTRY32);
    if (!Module32First(hModuleSnap, &me32))
    {
        CloseHandle(hModuleSnap);
        cout << "Hata";
    }

    do
    {

        if ((DWORD)me32.modBaseAddr == base) {
            wprintf(L"%s 0x%08X %s\n", me32.szExePath, me32.modBaseAddr, me32.szModule);
            DWORD hedef = me32.th32ProcessID;
            HANDLE threadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, hedef);
            
            if (threadSnap != INVALID_HANDLE_VALUE)
            {
                THREADENTRY32 te;
                PROCESSENTRY32 pe;
                uint64_t nThreadStartAddress = 0;

                te.dwSize = sizeof(te);
                if (Thread32First(threadSnap, &te))
                {
                    do
                    {
                        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID))
                        {
                            if (te.th32OwnerProcessID == hedef )
                            {

                                DWORD startAddress = 0;
                                pNtQIT NtQueryInformationThread = (pNtQIT)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationThread");
                                
                                HANDLE threac = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                                NTSTATUS queryThread = NtQueryInformationThread(threac, (THREADINFOCLASS)ThreadQuerySetWin32StartAddress, &startAddress, sizeof(startAddress), NULL);


                                DWORD base = (DWORD)GetModuleHandle(L"StoneSoft.dll");

                                HMODULE dllBase = (HMODULE)(base + 0x00098d90);


                                if ((DWORD)startAddress == (DWORD)dllBase) {
                                    wprintf(L"Thread ID: %d Process ID: %d Start add 0x%08X 0x%08X\n", te.th32ThreadID, pe.th32ProcessID, startAddress);
                                    DWORD bulunan = (DWORD)te.th32ThreadID;
                                    DWORD exitCode;


                                    CloseHandle(threac);

                                    HANDLE handle = OpenThread(THREAD_TERMINATE, FALSE, (DWORD)te.th32ThreadID);

                                        wprintf(L"Gorusuruz stonesoft : )) %d %d\n",bulunan,handle);
                                        TerminateThread((HANDLE)handle, 0);

                                        CloseHandle(handle);

  
                                }
                                
                            }
                        }
                        
                    } while (Thread32Next(threadSnap, &te));
                }
            }
                CloseHandle(threadSnap);
                

            }
       
        } while (Module32Next(hModuleSnap, &me32));
        
        CloseHandle(hModuleSnap);
}

void getModules()
{
    
    cout << "Morsmordre" <<endl;

    
    cout << "0x" << hex << GetCurrentProcessId() << endl;
    ModulleriGetir(GetCurrentProcessId());
    
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        
        AllocConsole();
        freopen("CONOUT$", "w", stdout);
        
        CreateThread(0, 0, (LPTHREAD_START_ROUTINE)&getModules, 0, 0, 0);
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

