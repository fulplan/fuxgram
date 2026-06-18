
#include <windows.h>
#include <stdio.h>

typedef DWORD (*DllMainFunc)(HINSTANCE, DWORD, LPVOID);

typedef struct {
    WORD  Magic;
    BYTE  Machine;
    BYTE  NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD  SizeOfOptionalHeader;
    WORD  Characteristics;
} PE_FILE_HEADER;

typedef struct {
    WORD  Magic;
    BYTE  MajorLinkerVersion;
    BYTE  MinorLinkerVersion;
    DWORD SizeOfCode;
    DWORD SizeOfInitializedData;
    DWORD SizeOfUninitializedData;
    DWORD AddressOfEntryPoint;
    DWORD BaseOfCode;
    DWORD BaseOfData;
    DWORD ImageBase;
    DWORD SectionAlignment;
    DWORD FileAlignment;
    WORD  MajorOperatingSystemVersion;
    WORD  MinorOperatingSystemVersion;
    WORD  MajorImageVersion;
    WORD  MinorImageVersion;
    WORD  MajorSubsystemVersion;
    WORD  MinorSubsystemVersion;
    DWORD Win32VersionValue;
    DWORD SizeOfImage;
    DWORD SizeOfHeaders;
    DWORD CheckSum;
    WORD  Subsystem;
    WORD  DllCharacteristics;
    DWORD SizeOfStackReserve;
    DWORD SizeOfStackCommit;
    DWORD SizeOfHeapReserve;
    DWORD SizeOfHeapCommit;
    DWORD LoaderFlags;
    DWORD NumberOfRvaAndSizes;
} PE_OPTIONAL_HEADER32;

typedef struct {
    DWORD VirtualAddress;
    DWORD Size;
} PE_DATA_DIRECTORY;

typedef struct {
    BYTE  Name[8];
    DWORD VirtualSize;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD  NumberOfRelocations;
    WORD  NumberOfLinenumbers;
    DWORD Characteristics;
} PE_SECTION_HEADER;

BOOL ReflectiveLoadDLL(LPVOID pData, DWORD dwDataLen, LPVOID* ppDllBuffer) {
    if (!pData || !ppDllBuffer) return FALSE;

    // Step1: Parse DOS header
    PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)pData;
    if (pDos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    // Step2: Validate PE signature
    PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS)((LPBYTE)pData + pDos->e_lfanew);
    if (pNt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    // Step3: Allocate memory for image
    LPVOID pImage = VirtualAlloc(
        (LPVOID)pNt->OptionalHeader.ImageBase,
        pNt->OptionalHeader.SizeOfImage,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    if (!pImage) {
        pImage = VirtualAlloc(
            NULL,
            pNt->OptionalHeader.SizeOfImage,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE
        );
        if (!pImage) return FALSE;
    }

    // Step4: Copy headers
    CopyMemory(pImage, pData, pNt->OptionalHeader.SizeOfHeaders);

    // Step5: Copy sections
    PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNt);
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        CopyMemory(
            (LPBYTE)pImage + pSection[i].VirtualAddress,
            (LPBYTE)pData + pSection[i].PointerToRawData,
            pSection[i].SizeOfRawData
        );
    }

    // Step6: Fix imports (simplified)
    PIMAGE_IMPORT_DESCRIPTOR pImportDir = NULL;
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0) {
        pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(
            (LPBYTE)pImage + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress
        );
        while (pImportDir->Name != 0) {
            LPCSTR szModName = (LPCSTR)((LPBYTE)pImage + pImportDir->Name);
            HMODULE hMod = LoadLibraryA(szModName);
            if (hMod) {
                PIMAGE_THUNK_DATA pThunk = NULL;
                if (pImportDir->OriginalFirstThunk != 0) {
                    pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImage + pImportDir->OriginalFirstThunk);
                } else {
                    pThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImage + pImportDir->FirstThunk);
                }
                PIMAGE_THUNK_DATA pFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)pImage + pImportDir->FirstThunk);
                while (pThunk->u1.AddressOfData != 0) {
                    if (IMAGE_SNAP_BY_ORDINAL(pThunk->u1.Ordinal)) {
                        pFirstThunk->u1.Function = (ULONGLONG)GetProcAddress(hMod, (LPCSTR)IMAGE_ORDINAL(pThunk->u1.Ordinal));
                    } else {
                        PIMAGE_IMPORT_BY_NAME pName = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)pImage + pThunk->u1.AddressOfData);
                        pFirstThunk->u1.Function = (ULONGLONG)GetProcAddress(hMod, (LPCSTR)pName->Name);
                    }
                    pThunk++;
                    pFirstThunk++;
                }
            }
            pImportDir++;
        }
    }

    // Step7: Process relocations (simplified)
    PIMAGE_BASE_RELOCATION pRelocDir = NULL;
    if (pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0) {
        pRelocDir = (PIMAGE_BASE_RELOCATION)(
            (LPBYTE)pImage + pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress
        );
        DWORD delta = (DWORD)((LPBYTE)pImage - pNt->OptionalHeader.ImageBase);
        while (pRelocDir->VirtualAddress != 0) {
            DWORD numEntries = (pRelocDir->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            PWORD pEntry = (PWORD)((LPBYTE)pRelocDir + sizeof(IMAGE_BASE_RELOCATION));
            for (DWORD i = 0; i < numEntries; i++) {
                WORD type = pEntry[i] >> 12;
                if (type == IMAGE_REL_BASED_HIGHLOW || type == IMAGE_REL_BASED_DIR64) {
                    DWORD offset = pEntry[i] & 0xFFF;
                    PDWORD_PTR pPatch = (PDWORD_PTR)((LPBYTE)pImage + pRelocDir->VirtualAddress + offset);
                    *pPatch += delta;
                }
            }
            pRelocDir = (PIMAGE_BASE_RELOCATION)((LPBYTE)pRelocDir + pRelocDir->SizeOfBlock);
        }
    }

    // Step8: Set section permissions (simplified)
    for (WORD i = 0; i < pNt->FileHeader.NumberOfSections; i++) {
        DWORD prot = PAGE_READONLY;
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            prot = PAGE_EXECUTE_READ;
        }
        if (pSection[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            prot = (prot == PAGE_EXECUTE_READ) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE;
        }
        DWORD oldProt;
        VirtualProtect(
            (LPBYTE)pImage + pSection[i].VirtualAddress,
            pSection[i].Misc.VirtualSize,
            prot,
            &oldProt
        );
    }

    // Step9: Call DllMain
    if (pNt->OptionalHeader.AddressOfEntryPoint != 0) {
        DllMainFunc pDllMain = (DllMainFunc)((LPBYTE)pImage + pNt->OptionalHeader.AddressOfEntryPoint);
        pDllMain((HINSTANCE)pImage, DLL_PROCESS_ATTACH, NULL);
    }

    *ppDllBuffer = pImage;
    return TRUE;
}

