#include <stdio.h>

int main(void) {
    FILE *source = fopen("/workspace/src/lib.rs", "r");
    if (source == NULL) {
        return 11;
    }
    char buffer[256];
    const size_t read_count = fread(buffer, 1, sizeof(buffer), source);
    fclose(source);
    return read_count > 0 ? 0 : 12;
}
