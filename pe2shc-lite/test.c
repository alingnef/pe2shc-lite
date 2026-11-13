#define WIN32_LEAN_AND_MEAN
#include <windows.h>

static const char message[] = "Flag: flag{Hello_from_WinAPI!}";
static const char title[] = "This is your gift";
static const char *volatile message_ptr = message;
static const char *volatile title_ptr = title;

int __cdecl entry(void)
{
    return MessageBoxA(
        NULL,
        message_ptr,
        title_ptr,
        MB_OK
    ) ? 0 : 1;
}