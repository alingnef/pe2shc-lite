/* Local runner for pe2shc.py output. Build x64 or x86; see README.md. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv)
{
    FILE *file;
    long size;
    unsigned char *image;
    DWORD nt, loader;
    WORD machine, flags;
    int result, exit_code = 1;
#ifdef _WIN64
    const WORD expected = IMAGE_FILE_MACHINE_AMD64;
    const size_t immediate = 19, loader_size = 1536;
    const unsigned char prefix[] = {0x4d,0x5a,0x45,0x52,0xe8,0,0,0,0,0x59,0x48,0x83,0xe9,9,0x48,0x8b,0xc1,0x48,5};
#else
    const WORD expected = IMAGE_FILE_MACHINE_I386;
    const size_t immediate = 15, loader_size = 1024;
    const unsigned char prefix[] = {0x4d,0x5a,0x45,0x52,0xe8,0,0,0,0,0x58,0x83,0xe8,9,0x50,5};
#endif
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <input.exe.shc>\n",
                sizeof(void *) == 8 ? "runshc.exe" : "runshc32.exe");
        return 1;
    }
    file = _wfopen(argv[1], L"rb");
    if (!file) { perror("Open input"); return 1; }
    if (fseek(file, 0, SEEK_END) || (size = ftell(file)) < 64
        || size > 268437504L || fseek(file, 0, SEEK_SET)) {
        fprintf(stderr, "Invalid input size\n"); fclose(file); return 1;
    }
    image = (unsigned char *)VirtualAlloc(NULL, (SIZE_T)size,
                         MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!image) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        fclose(file); return 1;
    }
    if (fread(image, 1, (size_t)size, file) != (size_t)size) {
        fprintf(stderr, "Read failed\n"); fclose(file); goto done;
    }
    fclose(file);
    memcpy(&nt, image + 0x3c, sizeof(nt));
    if (nt < 64 || nt > (DWORD)size - 24 || memcmp(image + nt, "PE\0\0", 4)) {
        fprintf(stderr, "Invalid PE header\n"); goto done;
    }
    memcpy(&machine, image + nt + 4, sizeof(machine));
    memcpy(&flags, image + nt + 22, sizeof(flags));
    if (machine != expected) {
        fprintf(stderr, "Architecture mismatch: use runshc.exe for x64, runshc32.exe for x86\n");
        goto done;
    }
    memcpy(&loader, image + immediate, sizeof(loader));
    if (flags & IMAGE_FILE_DLL || memcmp(image, prefix, sizeof(prefix))
        || memcmp(image + immediate + 4, "\xff\xd0\xc3\0", 4) || image[0x20] != 0
        || loader < 4096 || loader % 4096 || loader > (DWORD)size
        || (size_t)size - loader != loader_size) {
        fprintf(stderr, "Expected a fresh EXE converted by pe2shc.py\n"); goto done;
    }
    if (!FlushInstructionCache(GetCurrentProcess(), image, (SIZE_T)size)) {
        fprintf(stderr, "FlushInstructionCache failed: %lu\n", GetLastError()); goto done;
    }
    printf("[*] Running %u-bit shellcode (%ld bytes)\n", (unsigned)(sizeof(void *) * 8), size);
    fflush(stdout);
    result = ((int (__cdecl *)(void))(void *)image)();
    printf("[+] Entry returned %d; loader status=%u\n", result, image[0x20]);
    exit_code = image[0x20] == 2 ? 0 : 1;
done:
    VirtualFree(image, 0, MEM_RELEASE);
    return exit_code;
}
