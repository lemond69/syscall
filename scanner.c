//Program scans for ntdll functions that start with Nt but not Ntdll, but do not syscall. Currently only known function is NtGetTickCount.
//Only run this on systems without EDR/ntdll hooks, as it relies on the integrity of ntdll functions being preserved.
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
int main(){
    HMODULE peBase = LoadLibraryA("ntdll.dll"); //easier than parsing PEB, but less stealth
  
    //boilerplate DLL header and EAT parsing code
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)imageDosHeader + imageDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&imageNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY imageExportDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)peBase + imageExportDataDirectory->VirtualAddress);
    DWORD numberOfNames = imageExportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNames);

    //loop thru all exported functions in ntdll
    for (int nameIndex = 0; nameIndex < numberOfNames; nameIndex++){
        char* name = (char*)((unsigned char*)peBase + exportNamePointerTable[nameIndex]);
        if(memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0){ //generally functions that start with Nt but not Ntdll have syscalls, we look for exceptions
            WORD ordinal = nameOrdinalsPointer[nameIndex];
            unsigned char* targetFunctionAddress = ((unsigned char*)peBase + exportAddressTable[ordinal]);
            unsigned char* marker = 0; //we need to look for this as not all ntdll syscalling funcs start with a "mov r10,rcx"
            while(1){
                //now we look for the following asm stub:
                // mov r10, rcx
                // mov eax, [syscall number]
                if(memcmp(targetFunctionAddress, "\x4c\x8b\xd1\xb8", 4)==0) marker = targetFunctionAddress;
                if(targetFunctionAddress[0] == (unsigned char)'\xc3') break; //break if we hit return
                targetFunctionAddress++;
            }
            if(marker==0){ //if we could not find the syscall setup asm stub, probably does not syscall
                printf("%s does not syscall!\n", name);
            }
        }
    }
    return 0;
}
