/*
 * Intentionally unsafe classroom sample.
 *
 * Compile it only in an isolated learning environment. The web application
 * performs static analysis and never runs this program.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void unsafe_copy(const char *input) {
    char small_buffer[16];
    char message[48];

    strcpy(small_buffer, input);
    sprintf(message, "Student input: %s", small_buffer);
    printf(message);
    putchar('\n');
}

int main(int argc, char **argv) {
    const char *demo_url = "https://training.example.invalid/binary-lab";
    const char *demo_path = "/tmp/revlearn-demo";

    puts(demo_url);
    puts(demo_path);
    if (argc > 1) {
        unsafe_copy(argv[1]);
    }

    if (getenv("REVLEARN_NEVER_SET") != NULL) {
        system("echo educational-demo");
    }
    return 0;
}

