#include <stdio.h>
#include <windows.h>

#define DEBUG 1

#define Main_Title()                                                  \
  printf("######################################################\n"); \
  printf("##             Mal_Dropper_tool_v0.3                ##\n"); \
  printf("##                                                  ##\n"); \
  printf("##                            Developed by nam3z1p  ##\n"); \
  printf("##                                         2020.05  ##\n"); \
  printf("######################################################\n");

#define Menu()                                                \
  printf("\n[+] Usage : Mal_Dropper_Tools_v0.3.exe -M[D]\n"); \
  printf("\nex) %s -M[D]\n", argv[0]);                        \
  printf("\n[-M, -D]\n");                                     \
  printf("  -M                Files Merge Mode\n");           \
  printf("  -D                Files Div Mode\n");

typedef struct _FILE_DATA
{
  DWORD dwFileCounts;
  PDWORD pSizeData;
  PBYTE *pContentsData;
} FILEDATA, *PFILEDATA;

void EncryptFileData(PBYTE pData, DWORD pDataSize)
{
  for (int i = 0; i < pDataSize; ++i)
  {
    pData[i] += 0xCC;
  }
}

void DecryptFileData(PBYTE pData, DWORD pDataSize)
{
  for (int i = 0; i < pDataSize; ++i)
  {
    pData[i] -= 0xCC;
  }
}

PFILEDATA GetFileInfo(CHAR szFileName[][256], DWORD dwFileCounts)
{
  HANDLE hRead = INVALID_HANDLE_VALUE;
  PFILEDATA pFileData = {0};
  DWORD i, nRead = 0;

  pFileData = malloc(sizeof(FILEDATA));
  memset(pFileData, 0, sizeof(FILEDATA));

  // Malloc for the file size
  pFileData->pSizeData = (PDWORD)malloc(sizeof(DWORD) * dwFileCounts);
  memset(pFileData->pSizeData, 0, sizeof(DWORD) * dwFileCounts);

  // Malloc for the contents contents data
  pFileData->pContentsData = (PBYTE *)malloc(sizeof(PBYTE) * dwFileCounts);
  memset(pFileData->pContentsData, 0, sizeof(PBYTE) * dwFileCounts);

  for (i = 0; i < dwFileCounts; ++i)
  {
    // Read the file
    hRead = CreateFileA(szFileName[i], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hRead == INVALID_HANDLE_VALUE)
    {
      printf("[!] It's not found the CreateFile hRead !!\n");
      return FALSE;
    }

    // Get the file size
    pFileData->pSizeData[i] = GetFileSize(hRead, NULL);

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

    if (DEBUG)
    {
      printf("[+] Target [%d] : %s \n", i + 1, szFileName[i]);
      printf("[+] Size   [%d] : %d\n", i + 1, pFileData->pSizeData[i]);
    }

    CloseHandle(hRead);
  }
  if (DEBUG)
  {
    printf("==========================================\n");
  }
  pFileData->dwFileCounts = dwFileCounts;

  return pFileData;
}

BOOL MergeFile(PFILEDATA pFileData, LPCTSTR szFileName)
{
  HANDLE hWrite = INVALID_HANDLE_VALUE;
  DWORD nWrite, i = 0;
  PBYTE pFileSize = 0;

  // Write the merge file
  hWrite = CreateFileA(szFileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);
  if (hWrite == INVALID_HANDLE_VALUE)
  {
    printf("[!] It's not found the CreateFileA hWrite !!\n");
    return FALSE;
  }

  // Malloc for the contents size
  pFileSize = (PBYTE)malloc(sizeof(DWORD) * (pFileData->dwFileCounts + 1));
  memset(pFileSize, 0, sizeof(DWORD) * (pFileData->dwFileCounts + 1));

  for (i = 0; i < pFileData->dwFileCounts; i++)
  {
    if (i > 0)
    {
      // Encrypt the file data
      EncryptFileData(pFileData->pContentsData[i], pFileData->pSizeData[i]);
    }

    // Write the file data
    WriteFile(hWrite, pFileData->pContentsData[i], pFileData->pSizeData[i], &nWrite, NULL);
    memcpy(pFileSize + (i * sizeof(DWORD)), &pFileData->pSizeData[i], sizeof(DWORD));
  }

  // Write the file size
  memcpy(pFileSize + (i * sizeof(DWORD)), &pFileData->dwFileCounts, sizeof(DWORD));
  WriteFile(hWrite, pFileSize, sizeof(DWORD) * (pFileData->dwFileCounts + 1), &nWrite, NULL);

  if (DEBUG)
  {
    printf("[+] Output : %s\n", szFileName);
    printf("==========================================\n");
  }

  CloseHandle(hWrite);
  free(pFileSize);

  return TRUE;
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
  }

  if (DEBUG)
  {
    printf("[+] Target : %s \n", szFileName);
    printf("==========================================\n");
  }

  CloseHandle(hRead);
  return pFileData;
}

BOOL DivFile(PFILEDATA pFileData, CHAR szFileName[][256])
{
  HANDLE hWrite = INVALID_HANDLE_VALUE;
  DWORD nWrite, i = 0;

  for (i = 0; i < pFileData->dwFileCounts; ++i)
  {
    // Write the div files.
    hWrite = CreateFileA(szFileName[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    if (hWrite == INVALID_HANDLE_VALUE)
    {
      printf("[!] It's not found the CreateFileA hWrite !!\n");
      return FALSE;
    }

    if (i > 0)
    {
      // Decrypt the file data
      DecryptFileData(pFileData->pContentsData[i], pFileData->pSizeData[i]);
    }

    // Write the file data
    WriteFile(hWrite, pFileData->pContentsData[i], pFileData->pSizeData[i], &nWrite, NULL);

    if (DEBUG)
    {
      printf("[+] Output [%d] : %s\n", i + 1, szFileName[i]);
      printf("[+] Size   [%d] : %d\n", i + 1, pFileData->pSizeData[i]);
    }

    CloseHandle(hWrite);
  }

  if (DEBUG)
  {
    printf("==========================================\n");
  }

  return TRUE;
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

int main(int argc, char **argv)
{

  if (argc == 1 || argc > 2)
  {
    Menu();
    exit(1);
  }
  else
    Main_Title();

  PFILEDATA pFileData = {0};
  CHAR szMergeInputFileName[3][256], szMergeOutputFileName[256], systemPath[256] = {0};
  CHAR szDivInputFileName[256], szDivOutputFileName[3][256] = {0};
  GetSystemDirectory(systemPath, 256);

  if (!strcmp(argv[1], "-M"))
  {
    // input files
    sprintf(szMergeInputFileName[0], "C:\\Malware_Test\\Mal_Main.exe");
    sprintf(szMergeInputFileName[1], "C:\\Malware_Test\\Mal_Target.exe");
    sprintf(szMergeInputFileName[2], "%s\\calc.exe", systemPath);

    // output file
    sprintf(szMergeOutputFileName, "C:\\Malware_Test\\Output_Mal_Test.exe");

    printf("[+] Get the file info.\n");
    if (!(pFileData = GetFileInfo(szMergeInputFileName, 3)))
    {
      printf("[!] It's not found the GetFileInfo !!\n");
      return FALSE;
    }

    printf("[+] Merge the files.\n");
    if (!MergeFile(pFileData, szMergeOutputFileName))
    {
      printf("[!] It's not found the MergeFile !!\n");
      return FALSE;
    }
  }
  else if (!strcmp(argv[1], "-D"))
  {
    // input file
    sprintf(szDivInputFileName, "C:\\Malware_Test\\Output_Mal_Test.exe");

    // output files
    sprintf(szDivOutputFileName[0], "C:\\Malware_Test\\Mal_Main.exe");
    sprintf(szDivOutputFileName[1], "C:\\Malware_Test\\Mal_Target.exe");
    sprintf(szDivOutputFileName[2], "C:\\Malware_Test\\calc.exe");

    printf("[+] Get the file div info.\n");
    if (!(pFileData = GetFileDivInfo(szDivInputFileName)))
    {
      printf("[!] It's not found the GetFileDivInfo !!\n");
      return FALSE;
    }

    printf("[+] Div the files.\n");
    if (!DivFile(pFileData, szDivOutputFileName))
    {
      printf("[!] It's not found the DivFile !!\n");
      return FALSE;
    }
  }

  ClearHandle(pFileData);
  printf("[+] Done.\n");

  return 0;
}
