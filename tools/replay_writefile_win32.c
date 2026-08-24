// Native Win32 replay helper for captured 4097-byte TFT WriteFile buffers.
// It only replays a previously captured slot; it does not generate protocol data.
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <stdio.h>

#define PACKET_SIZE 4097
#define PACKETS 16

typedef struct {
    OVERLAPPED ov;
    HANDLE event;
    unsigned char *buffer;
} Pending;

int wmain(int argc, wchar_t **argv) {
    if (argc != 4 || wcscmp(argv[3], L"--confirm") != 0) {
        fwprintf(stderr, L"usage: replay_writefile_win32.exe <hid-path> <slot.bin> --confirm\n");
        return 2;
    }
    HANDLE input = CreateFileW(argv[2], GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"slot open failed: %lu\n", GetLastError());
        return 3;
    }
    unsigned char data[PACKETS][PACKET_SIZE];
    DWORD got = 0;
    for (int i = 0; i < PACKETS; ++i) {
        if (!ReadFile(input, data[i], PACKET_SIZE, &got, NULL) || got != PACKET_SIZE) {
            fwprintf(stderr, L"slot read failed at %d: %lu\n", i + 1, GetLastError());
            CloseHandle(input);
            return 4;
        }
    }
    CloseHandle(input);

    HANDLE hid = CreateFileW(argv[1], GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE,
                             NULL, OPEN_EXISTING, FILE_FLAG_OVERLAPPED, NULL);
    if (hid == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"HID open failed: %lu\n", GetLastError());
        return 5;
    }
    Pending pending[PACKETS] = {0};
    for (int i = 0; i < PACKETS; ++i) {
        pending[i].event = CreateEventW(NULL, TRUE, FALSE, NULL);
        pending[i].ov.hEvent = pending[i].event;
        pending[i].buffer = data[i];
        DWORD written = 0;
        BOOL ok = WriteFile(hid, data[i], PACKET_SIZE, &written, &pending[i].ov);
        DWORD error = ok ? ERROR_SUCCESS : GetLastError();
        if (!ok && error != ERROR_IO_PENDING) {
            fwprintf(stderr, L"WriteFile %d failed: %lu\n", i + 1, error);
            CloseHandle(hid);
            return 6;
        }
        wprintf(L"%02d/%02d queued (%s)\n", i + 1, PACKETS, ok ? L"complete" : L"pending");
        Sleep(30);
    }
    Sleep(3000);
    for (int i = 0; i < PACKETS; ++i) CloseHandle(pending[i].event);
    CloseHandle(hid);
    return 0;
}
