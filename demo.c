//simple POC to demonstrate use
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "syscall.h"
typedef NTSTATUS(NTAPI *pdef_NtRaiseHardError)(NTSTATUS ErrorStatus, ULONG NumberOfParameters, ULONG UnicodeStringParameterMask OPTIONAL, PULONG_PTR Parameters, ULONG ResponseOption, PULONG Response);
typedef NTSTATUS(NTAPI *pdef_RtlAdjustPrivilege)(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);
//yes i am aware NtRaiseHardError is a pretty odd function to use, but it was the function i had on hand when writing this
int getprivs(){ //get privs to NtRaiseHardError
    BOOLEAN bEnabled;
    LPVOID lpFuncAddress = GetProcAddress(LoadLibraryA("ntdll.dll"), "RtlAdjustPrivilege"); //rtl so we don't syscall
    pdef_RtlAdjustPrivilege NtCall = (pdef_RtlAdjustPrivilege)lpFuncAddress;
    NTSTATUS NtRet = NtCall(19, TRUE, FALSE, &bEnabled);
    return 0;
}

int throwerr(){
    ULONG uResp;
    pdef_NtRaiseHardError NtCall2 = (pdef_NtRaiseHardError)sysc;
    printf("Syscall: %x\n", getSysId("NtRaiseHardError"));
    setSyscall("NtRaiseHardError"); //use the asm macro
    NtCall2(0xbeef, 0, 0, 0, 6, &uResp); //this'll make it just show alert instead of bsod
    printf("Called\n");
    return 0;
}

int main(){
    hunt();
    getprivs();
    throwerr();
    return 0;
}
