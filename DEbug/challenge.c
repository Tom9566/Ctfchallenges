#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// Simple reverse-engineering challenge
// The real flag is stored encrypted in the binary after the 'blob' array.
// To solve: find the sentinel 0xFEEDFACE in the binary, read following bytes,
// XOR with 0x3f to recover the flag.

unsigned char blob[] = {
    /* sentinel */ 0xFE,0xED,0xFA,0xCE,
    /* encrypted flag */ 0x4f, 0x5e, 0x5e, 0x49, 0x5e, 0x56, 0x7c, 0x6b, 0x79, 0x44, 0x4e, 0x51, 0x54, 0x0f, 0x0b, 0x52, 0x09, 0x45, 0x4d, 0x55, 0x5d, 0x0a, 0x46, 0x4a, 0x47, 0x5e, 0x42
};

int check_serial(const char *s) {
    // simple check: compare input directly with flag
    // (we don't include flag in cleartext in source)
    extern unsigned char blob[]; // linker provides it
    unsigned char *p = blob + 4; // skip sentinel
    size_t L = sizeof(blob) - 4;
    char *dec = malloc(L+1);
    if(!dec) return 0;
    for(size_t i=0;i<L;i++) dec[i] = p[i] ^ 0x3f;
    dec[L] = 0;
    int ok = (strcmp(dec, s) == 0);
    free(dec);
    return ok;
}

int main() {
    char buf[256];
    printf("Enter serial: ");
    fflush(stdout);
    if(!fgets(buf, sizeof(buf), stdin)) return 0;
    // strip newline
    buf[strcspn(buf, "\n")] = 0;
    if(check_serial(buf)) {
        printf("Access granted: %s\n", buf);
    } else {
        printf("Access denied.\n");
    }
    return 0;
}
