#include <windows.h>
#include <winternl.h>
// use this macro, mov the syscall number to ebx (which is later mov to eax in rop.S), mov the location of the rop we are using to r11, which will be jmp to in rop.S
#define setSyscall(x) asm __volatile__("mov ebx, %0\n\t":: "a" (getSysId(x)): "%ebx"); register long long my_var __asm__ ("r11") = rop
char* names[10000]={0};
int totalFns=0;
unsigned long long int rop = 0; //address of rop we will use in ntdll
//generic bubblesort algo
void bubbleSort(long long int arr[], char* nm[], int n){ 
    int i, j; 
    for (i = 0; i < n - 1; i++){
        for (j = 0; j < n - i - 1; j++){
            if (arr[j] > arr[j + 1]){
                long long int tmp = arr[j];
                arr[j]=arr[j+1];
                arr[j+1]=tmp;
                char* tmp2 = nm[j];
                nm[j]=nm[j+1];
                nm[j+1]=tmp2;
            }
        }
    }
} 
//taken from HellsGate implementation. better way to pull PEB than the NtQueryInformationProcess API, too noisy
void* getNtdllAddr(){
    PPEB ProcessInformation = (PPEB)(__readgsqword(0x60));
    void* ntdll = (ProcessInformation->Ldr->InMemoryOrderModuleList.Flink->Flink); //linked list, ntdll is 2nd loaded obj after image
    ntdll+=0x20; //go to ImageBase field
    unsigned long long int base = 0;
    memcpy(&base, ntdll, 8); //get the base addr of ntdll
    return (void*) base;
}
int hunt(){
    long long int ps[10000]={0};
    HMODULE peBase = getNtdllAddr();//basically LoadLibraryA("ntdll.dll");
    //generic EAT parse code
    PIMAGE_DOS_HEADER imageDosHeader = (PIMAGE_DOS_HEADER)peBase;
    PIMAGE_NT_HEADERS imageNtHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)imageDosHeader + imageDosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER imageOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&imageNtHeaders->OptionalHeader;
    PIMAGE_DATA_DIRECTORY imageExportDataDirectory = &(imageOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
    PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((unsigned char*)peBase + imageExportDataDirectory->VirtualAddress);
    DWORD numberOfNames = imageExportDirectory->NumberOfNames;
    PDWORD exportAddressTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfFunctions);
    PWORD nameOrdinalsPointer = (PWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNameOrdinals);
    PDWORD exportNamePointerTable = (PDWORD)((unsigned char*)peBase + imageExportDirectory->AddressOfNames);
    int c=0;
    int nameIndex = 0;
    //loop through individual EAT entries
    for (nameIndex = 0; nameIndex < numberOfNames; nameIndex++){
        char* name = (char*)((unsigned char*)peBase + exportNamePointerTable[nameIndex]);
        if(memcmp(name, "Nt", 2)==0 && memcmp(name, "Ntdll", 5)!=0 && strcmp(name, "NtGetTickCount")!=0){ //NtGetTickCount is only exception known, see scanner.c for more info
            WORD ordinal = nameOrdinalsPointer[nameIndex];
            unsigned char* targetFunctionAddress = ((unsigned char*)peBase + exportAddressTable[ordinal]);
            ps[c] = (long long int)targetFunctionAddress; //add name-address pair to list
            names[c] = calloc(strlen(name)+1,1);
            strcpy(names[c], name);
            c++;
        }
    }
    bubbleSort(ps, names, c); //sort both name and address
    totalFns=c;
    //now rophunt, find syscall-ret gadget, 0f 05 c3
    unsigned char* va = (unsigned char*)ps[0];
    unsigned char* vmax = (unsigned char*)ps[c-1];
    while (va <= vmax && (va[0]!='\x0f' || memcmp(va, "\x0f\x05\xc3", 3)!=0)) va++;
    if (va!=vmax) rop = (unsigned long long int)va; //if rop fails, rop will be 0. error handling omitted for simplicity
    return 0;
}
int getSysId(const char* name){
    for(int i=0;i<totalFns;i++){
        if(strcmp(name, names[i])==0) return i; //lookup syscall id
    }
    return -1;
}

extern void* sysc(); //exported from rop.S
