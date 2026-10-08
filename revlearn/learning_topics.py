"""Advanced, defensive laboratory content for the sixteen learning topics."""

ADVANCED_TOPICS = {
    "elf_structure": {
        "technical_details": "An ELF header identifies class, byte order, machine, file type, and entry point. Program headers describe runtime mappings, while section headers organize linker and analysis data. A section can exist without being loaded, so runtime claims must be based primarily on segments.",
        "lab_exercise": "Save each program as demo.c. Build both commands in the comments, analyze the outputs, and compare ELF type, entry point, section table, and program headers with readelf -h -l -S.",
        "expected_observations": "Both files contain similar source-level behavior, but the hardened build should be ET_DYN/PIE with stronger loader metadata. Section names alone do not determine runtime permissions.",
        "vulnerable_example": """#include <stdio.h>

int global_count = 7;

int main(void) {
    printf("count=%d\\n", global_count);
    return 0;
}

/* Build: gcc -O0 -fno-PIE -no-pie demo.c -o elf-fixed */""",
        "secure_example": """#include <stdio.h>

static const int initial_count = 7;

int main(void) {
    printf("count=%d\\n", initial_count);
    return 0;
}

/* Build: gcc -O2 -fPIE -pie demo.c -o elf-pie */""",
        "review_steps": "Identify e_type, e_machine, and e_entry. Map .text, .rodata, .data, and .bss into PT_LOAD segments. Explain why program-header flags are stronger runtime evidence than section names.",
    },
    "program_headers": {
        "technical_details": "PT_LOAD entries define page-aligned file-to-memory mappings and R/W/X permissions. PT_GNU_STACK communicates stack executability, and PT_GNU_RELRO identifies memory intended to become read-only after relocation.",
        "lab_exercise": "Build the same program once with execstack and once with noexecstack. Compare readelf -l output and the analyzer's NX evidence; do not execute unknown files.",
        "expected_observations": "The weak build requests an RWE GNU_STACK. The secure build should show RW without execute. Ordinary code and data PT_LOAD segments should remain separated by permissions.",
        "vulnerable_example": """#include <stdio.h>

int main(void) {
    char message[] = "program headers";
    puts(message);
    return 0;
}

/* Build: gcc demo.c -Wl,-z,execstack -o stack-rwx */""",
        "secure_example": """#include <stdio.h>

int main(void) {
    const char message[] = "program headers";
    puts(message);
    return 0;
}

/* Build: gcc demo.c -Wl,-z,noexecstack -o stack-nx */""",
        "review_steps": "Locate PT_GNU_STACK and compare its flags. Then inspect every PT_LOAD entry for unexpected W+X. Relate file size versus memory size to zero-filled data such as .bss.",
    },
    "dynamic_section": {
        "technical_details": "The dynamic table drives dependency loading, symbol lookup, relocation, search paths, and binding policy. DT_NEEDED names dependencies; DT_RUNPATH/RPATH changes lookup; BIND_NOW supports full RELRO by resolving symbols before protected relocation memory is locked.",
        "lab_exercise": "Build both programs with -ldl. Inspect DT_NEEDED, imported dlopen/dlsym symbols, and any RUNPATH. Use only trusted system libraries in this controlled exercise.",
        "expected_observations": "The weak program accepts a library name from external input. The secure program fixes both library and symbol. Static analysis can show loader APIs and strings but cannot know which argument arrives at runtime.",
        "vulnerable_example": """#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    void *handle = dlopen(argv[1], RTLD_NOW);
    puts(handle ? "loaded" : dlerror());
    if (handle) dlclose(handle);
    return handle ? 0 : 1;
}
/* Build: gcc demo.c -ldl -o dynamic-input */""",
        "secure_example": """#include <dlfcn.h>
#include <stdio.h>

int main(void) {
    void *handle = dlopen("libm.so.6", RTLD_NOW | RTLD_LOCAL);
    if (!handle) { puts(dlerror()); return 1; }
    void *symbol = dlsym(handle, "cos");
    printf("approved symbol: %s\\n", symbol ? "yes" : "no");
    dlclose(handle);
    return symbol ? 0 : 1;
}
/* Build: gcc demo.c -ldl -Wl,-z,now -o dynamic-fixed */""",
        "review_steps": "Trace the library name and symbol name to their trust source. Inspect DT_NEEDED and binding flags. Explain why an imported dlopen is evidence for review rather than proof of unsafe loading.",
    },
    "strings": {
        "technical_details": "Printable strings reveal constants embedded in data sections and sometimes immediate instruction data. They can expose endpoints, paths, formats, commands, and credentials, but they do not prove reachability or runtime use.",
        "lab_exercise": "Build both programs, analyze their string categories, and confirm with strings -a. Use only the fake classroom credential shown here.",
        "expected_observations": "The weak binary exposes the fake token and internal URL. The secure binary retains configuration variable names but not a credential value; getenv should appear as an import.",
        "vulnerable_example": """#include <stdio.h>

int main(void) {
    const char *token = "TRAINING_TOKEN=demo-secret-123";
    const char *url = "https://internal.example.test/api";
    printf("%s -> %s\\n", token, url);
    return 0;
}""",
        "secure_example": """#include <stdio.h>
#include <stdlib.h>

int main(void) {
    const char *url = getenv("APP_API_URL");
    const char *token = getenv("APP_API_TOKEN");
    if (!url || !token) { fputs("configuration missing\\n", stderr); return 1; }
    printf("configured endpoint: %s\\n", url);
    return 0;
}""",
        "review_steps": "Classify each string, then confirm whether code references it. Treat discovered real secrets as compromised: remove them from source and history, rotate them, and use a secret-management mechanism.",
    },
    "unsafe_functions": {
        "technical_details": "Risk comes from how a function is called: destination capacity, source termination, format control, integer conversion, and error handling. Symbol imports are triage signals because the same API can be used safely or unsafely.",
        "lab_exercise": "Build both programs with -Wall -Wextra. Analyze imported functions, then test only with short benign strings. Compare strcpy with the explicit length gate and memcpy.",
        "expected_observations": "The weak build should flag strcpy. The secure build may still flag memcpy for review, illustrating that context and checked bounds matter more than the function name alone.",
        "vulnerable_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[16];
    if (argc != 2) return 1;
    strcpy(name, argv[1]);
    printf("name=%s\\n", name);
    return 0;
}""",
        "secure_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char name[16];
    if (argc != 2) return 1;
    size_t length = strnlen(argv[1], sizeof name);
    if (length == sizeof name) { fputs("name too long\\n", stderr); return 1; }
    memcpy(name, argv[1], length + 1);
    printf("name=%s\\n", name);
    return 0;
}""",
        "review_steps": "Follow argv[1] into the copy. State the destination capacity, maximum accepted length, and termination rule. Check every error path and distinguish a risky import from a confirmed unsafe call site.",
    },
    "canary": {
        "technical_details": "A compiler places a guard between selected stack objects and control data, checks it before return, and calls a failure routine if it changed. Coverage depends on compiler heuristics and flags; a canary detects some overwrites but does not prevent the write.",
        "lab_exercise": "Build both programs using the commands shown. Analyze imports for __stack_chk_fail and compare disassembly around main. Use only normal short input while reviewing.",
        "expected_observations": "The weak build contains an unbounded strcpy and may lack canary evidence. The secure build rejects oversized input and should show canary evidence when built with -fstack-protector-strong.",
        "vulnerable_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buffer[24];
    if (argc != 2) return 1;
    strcpy(buffer, argv[1]);
    puts(buffer);
    return 0;
}
/* Build: gcc -O0 -fno-stack-protector demo.c -o no-canary */""",
        "secure_example": """#include <stdio.h>

int main(int argc, char **argv) {
    char buffer[24];
    if (argc != 2) return 1;
    int written = snprintf(buffer, sizeof buffer, "%s", argv[1]);
    if (written < 0 || (size_t)written >= sizeof buffer) {
        fputs("input too long\\n", stderr); return 1;
    }
    puts(buffer);
    return 0;
}
/* Build: gcc -O2 -fstack-protector-strong demo.c -o with-canary */""",
        "review_steps": "Confirm both source-level bounds and binary-level canary evidence. Find the guard load/check in disassembly. Explain why enabling a canary without fixing strcpy leaves the root defect present.",
    },
    "nx": {
        "technical_details": "NX relies on page permissions and hardware execute-disable support to prevent instruction fetch from writable regions. In ELF, PT_GNU_STACK communicates the requested stack policy; segment W/X separation provides additional evidence.",
        "lab_exercise": "Compile the two complete programs with their linker flags and compare PT_GNU_STACK using the analyzer and readelf -W -l.",
        "expected_observations": "Program behavior is identical, but the weak build requests an executable stack while the secure build requests a non-executable stack. Neither result proves the source is free of memory errors.",
        "vulnerable_example": """#include <stdio.h>

int main(void) {
    char message[32] = "executable-stack build";
    puts(message);
    return 0;
}
/* Build: gcc demo.c -Wl,-z,execstack -o nx-weak */""",
        "secure_example": """#include <stdio.h>

int main(void) {
    const char message[] = "non-executable-stack build";
    puts(message);
    return 0;
}
/* Build: gcc demo.c -Wl,-z,noexecstack -o nx-secure */""",
        "review_steps": "Compare GNU_STACK R/W/X flags and all loadable segments. Record whether the linker honored the option. Keep mitigation evidence separate from conclusions about source-level memory safety.",
    },
    "pie": {
        "technical_details": "A PIE is usually ET_DYN with position-independent code and dynamic relocations suitable for loading at varied base addresses. ASLR is an operating-system policy; PIE enables randomization of the main executable but does not guarantee it is active.",
        "lab_exercise": "Build both programs, run readelf -h, and inspect analyzer PIE status. In an authorized local shell, repeated address output can illustrate relocation, but static evidence alone should be documented first.",
        "expected_observations": "The fixed build should be ET_EXEC and the PIE build ET_DYN. Function-address constants and relocation layout differ even though source behavior is equivalent.",
        "vulnerable_example": """#include <stdio.h>

static void lesson(void) { puts("fixed executable"); }

int main(void) {
    lesson();
    printf("lesson address=%p\\n", (void *)lesson);
    return 0;
}
/* Build: gcc -fno-PIE -no-pie demo.c -o pie-fixed */""",
        "secure_example": """#include <stdio.h>

static void lesson(void) { puts("position independent"); }

int main(void) {
    lesson();
    printf("lesson address=%p\\n", (void *)lesson);
    return 0;
}
/* Build: gcc -fPIE -pie demo.c -o pie-enabled */""",
        "review_steps": "Compare ELF type, relocation evidence, and entry point. Explain the dependency between PIE and OS ASLR. Avoid claiming that address randomization fixes unsafe source behavior.",
    },
    "relro": {
        "technical_details": "RELRO groups selected relocation and loader data into PT_GNU_RELRO. With immediate binding, the loader resolves symbols early and changes those pages to read-only, producing full RELRO rather than partial protection.",
        "lab_exercise": "Build the programs with norelro and full-RELRO options. Compare PT_GNU_RELRO, DT_BIND_NOW/FLAGS, and analyzer status.",
        "expected_observations": "The weak file should lack RELRO evidence. The secure file should include a GNU_RELRO segment and immediate-binding flags. Imported puts remains dynamically linked in both.",
        "vulnerable_example": """#include <stdio.h>

int main(void) {
    puts("relocation lesson");
    return 0;
}
/* Build: gcc demo.c -Wl,-z,norelro -o relro-none */""",
        "secure_example": """#include <stdio.h>

int main(void) {
    puts("relocation lesson");
    return 0;
}
/* Build: gcc demo.c -Wl,-z,relro,-z,now -o relro-full */""",
        "review_steps": "Find PT_GNU_RELRO and binding flags, then distinguish partial from full RELRO. Describe what becomes read-only and why lazy binding affects the result.",
    },
    "fortify": {
        "technical_details": "Fortify uses compiler-known object sizes to replace selected libc calls with checked variants. It generally requires optimization and supported headers/libc. Checks can fail at compile time or runtime, but unknown sizes and unsupported operations remain outside coverage.",
        "lab_exercise": "Build the weak program at O0 without Fortify and the secure program at O2 with _FORTIFY_SOURCE=2. Compare imported symbols and warnings.",
        "expected_observations": "The weak build exposes strcpy. The secure program performs its own length check and may show fortified printf-family evidence depending on compiler and libc version.",
        "vulnerable_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char output[12];
    if (argc != 2) return 1;
    strcpy(output, argv[1]);
    puts(output);
    return 0;
}
/* Build: gcc -O0 -U_FORTIFY_SOURCE demo.c -o fortify-off */""",
        "secure_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char output[12];
    if (argc != 2) return 1;
    size_t length = strlen(argv[1]);
    if (length >= sizeof output) { fputs("too long\\n", stderr); return 1; }
    memcpy(output, argv[1], length + 1);
    puts(output);
    return 0;
}
/* Build: gcc -O2 -D_FORTIFY_SOURCE=2 demo.c -o fortify-on */""",
        "review_steps": "Verify optimization, macro level, compiler, and libc. Identify checked imports if present. Show which explicit source check still protects the copy when Fortify cannot infer a size.",
    },
    "rpath": {
        "technical_details": "RPATH and RUNPATH embed dependency search locations. $ORIGIN is resolved relative to the executable. Security depends on directory ownership, writability, execution context, and loader rules—not merely the presence of a path.",
        "lab_exercise": "Build both small programs, one with a classroom-relative RUNPATH and one without. Analyze dynamic tags and confirm using readelf -d.",
        "expected_observations": "The weak build should expose $ORIGIN/training-libs as RUNPATH. The secure build should have no custom loader path and rely on controlled deployment configuration.",
        "vulnerable_example": """#include <math.h>
#include <stdio.h>

int main(void) {
    printf("sqrt(9)=%.0f\\n", sqrt(9.0));
    return 0;
}
/* Build: gcc demo.c -lm -Wl,-rpath,'$ORIGIN/training-libs' -o rpath-relative */""",
        "secure_example": """#include <math.h>
#include <stdio.h>

int main(void) {
    printf("sqrt(9)=%.0f\\n", sqrt(9.0));
    return 0;
}
/* Build: gcc demo.c -lm -Wl,-z,origin -o rpath-none */""",
        "review_steps": "List DT_NEEDED and RPATH/RUNPATH. Resolve each path as deployed and determine who can write it. Explain why a trusted read-only application directory differs from a user-writable directory.",
    },
    "risk_score": {
        "technical_details": "The score is a deterministic prioritization model over supported indicators. Weighted deductions summarize missing hardening, review-worthy imports, and selected strings; correlated findings and unsupported behavior mean it is not a probability or safety proof.",
        "lab_exercise": "Build the two programs and compare score factors. Change one compiler flag at a time so each deduction can be explained rather than treating the total as opaque.",
        "expected_observations": "The weak program should combine an unsafe format-string call with weaker build evidence. The secure build should improve supported indicators, while the score notes still limit interpretation.",
        "vulnerable_example": """#include <stdio.h>

int main(int argc, char **argv) {
    if (argc == 2) printf(argv[1]);
    return 0;
}
/* Build: gcc -O0 -fno-stack-protector -no-pie demo.c -o score-weak */""",
        "secure_example": """#include <stdio.h>

int main(int argc, char **argv) {
    if (argc == 2) printf("%s\\n", argv[1]);
    return 0;
}
/* Build: gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now demo.c -o score-strong */""",
        "review_steps": "Open score transparency and cite every deduction. Separate source correction from build mitigation. State at least three behaviors the scoring model does not measure.",
    },
    "comparison_mode": {
        "technical_details": "A controlled binary comparison holds source and toolchain constant while changing one independent variable. This supports causal reasoning about compiler flags, imports, segments, strings, and score deltas; unrelated binaries create confounding differences.",
        "lab_exercise": "Save the program once and run both build commands. Upload weak as Baseline and hardened as Comparison. Repeat with one flag added at a time.",
        "expected_observations": "Program output stays the same. The hardened file should improve PIE, RELRO, NX, Canary, and possibly Fortify evidence. Exact imports vary with optimization and libc.",
        "vulnerable_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char message[32] = "hello";
    if (argc == 2) snprintf(message, sizeof message, "%s", argv[1]);
    puts(message);
    return 0;
}
/* Baseline: gcc -O0 -fno-stack-protector -no-pie demo.c -Wl,-z,norelro -o baseline */""",
        "secure_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char message[32] = "hello";
    if (argc == 2 && snprintf(message, sizeof message, "%s", argv[1]) >= (int)sizeof message) return 1;
    puts(message);
    return 0;
}
/* Comparison: gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack demo.c -o hardened */""",
        "review_steps": "Confirm source equivalence before attributing differences. Create a table mapping each changed report row to a flag. Record toolchain versions and explain any unexpected unchanged status.",
    },
    "static_limits": {
        "technical_details": "Static analysis observes stored bytes and structure, not live inputs, environment, network state, decrypted code, generated code, or scheduling. Optimization, stripping, packing, and indirect calls can remove or obscure high-level intent.",
        "lab_exercise": "Build both programs and predict behavior from static evidence. Then, only in an authorized isolated lab, run with and without TRAINING_MODE to compare possible runtime paths.",
        "expected_observations": "Both branches and the environment variable name are visible statically, but the report cannot know which branch will execute. The secure program validates and reports configuration explicitly.",
        "vulnerable_example": """#include <stdio.h>
#include <stdlib.h>

int main(void) {
    if (getenv("TRAINING_MODE")) puts("alternate runtime path");
    else puts("default runtime path");
    return 0;
}""",
        "secure_example": """#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    const char *mode = getenv("TRAINING_MODE");
    if (!mode) { puts("mode=default"); return 0; }
    if (strcmp(mode, "enabled") != 0) { fputs("invalid mode\\n", stderr); return 1; }
    puts("mode=enabled");
    return 0;
}""",
        "review_steps": "List facts the binary proves and runtime facts it cannot prove. Identify environment-dependent control flow, indirect behavior, and missing external state. Propose authorized dynamic tests without calling the static result a verdict.",
    },
    "secure_elf_build": {
        "technical_details": "A hardened baseline combines warnings, optimization, Fortify, stack protection, PIE, full RELRO, non-executable stack, and disciplined dependency paths. Each layer addresses a different stage and must be verified in the produced ELF.",
        "lab_exercise": "Compile both complete programs. Analyze individually and in Compare mode, then confirm with readelf. Treat compiler warnings as build failures during the secure build.",
        "expected_observations": "The hardened output should show stronger protection evidence. Source validation in the secure program remains necessary even when all supported build mitigations are present.",
        "vulnerable_example": """#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char label[20];
    if (argc != 2) return 1;
    strcpy(label, argv[1]);
    printf(label);
    return 0;
}
/* Build: gcc -O0 demo.c -o build-weak */""",
        "secure_example": """#include <stdio.h>

int main(int argc, char **argv) {
    char label[20];
    if (argc != 2) return 1;
    int n = snprintf(label, sizeof label, "%s", argv[1]);
    if (n < 0 || (size_t)n >= sizeof label) return 1;
    printf("%s\\n", label);
    return 0;
}
/* Build: gcc -O2 -Wall -Wextra -Werror -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack demo.c -o build-secure */""",
        "review_steps": "Verify every expected protection in the output. Explain the role of each flag, review warnings, and identify the two source defects corrected independently of hardening.",
    },
    "secure_coding_practices": {
        "technical_details": "Secure parsing treats external data as typed, bounded, and fallible. Robust code defines length and range policies, keeps format strings constant, checks conversions and return values, avoids ambiguous truncation, and keeps data separate from commands.",
        "lab_exercise": "Build both programs with warnings enabled. Review imports and source data flow. Test only benign values such as 42, -1, 9999, and text to exercise success and error paths.",
        "expected_observations": "The weak program accepts partial numeric text and uses user-controlled formatting. The secure program rejects trailing characters and out-of-policy ranges while using a constant format.",
        "vulnerable_example": """#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    int value = atoi(argv[1]);
    printf(argv[1]);
    printf(" -> %d\\n", value);
    return 0;
}""",
        "secure_example": """#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    if (argc != 2) return 1;
    errno = 0; char *end = NULL;
    long value = strtol(argv[1], &end, 10);
    if (errno || end == argv[1] || *end != '\\0' || value < 0 || value > 1000) {
        fputs("expected an integer from 0 to 1000\\n", stderr); return 1;
    }
    printf("validated value=%ld\\n", value);
    return 0;
}""",
        "review_steps": "Define the input policy before parsing. Trace conversion errors, trailing data, and range checks. Verify the constant format string and every return path, then compile with sanitizers during development.",
    },
}
