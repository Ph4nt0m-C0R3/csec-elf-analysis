"""Small SQLite learning-content store."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from flask import current_app, g

from .learning_topics import ADVANCED_TOPICS


SCHEMA = """
CREATE TABLE IF NOT EXISTS learning_content (
    content_id INTEGER PRIMARY KEY AUTOINCREMENT,
    topic TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    explanation TEXT NOT NULL,
    risk TEXT NOT NULL,
    recommendation TEXT NOT NULL
);
"""


AUTH_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'student'
        CHECK (role IN ('student', 'instructor', 'admin')),
    active INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0, 1)),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_login_at TEXT
);

CREATE TABLE IF NOT EXISTS audit_log (
    audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_user_id INTEGER,
    action TEXT NOT NULL,
    target_type TEXT,
    target_id TEXT,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (actor_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_log_actor
    ON audit_log(actor_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_log_action
    ON audit_log(action, created_at DESC);
"""


PROGRESS_SCHEMA = """
CREATE TABLE IF NOT EXISTS learning_progress (
    user_id INTEGER NOT NULL,
    topic TEXT NOT NULL,
    completed INTEGER NOT NULL DEFAULT 0 CHECK (completed IN (0, 1)),
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, topic),
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
    FOREIGN KEY (topic) REFERENCES learning_content(topic) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_learning_progress_user
    ON learning_progress(user_id, completed, updated_at DESC);
"""


EXAMPLES_SCHEMA = """
CREATE TABLE IF NOT EXISTS binary_examples (
    example_id INTEGER PRIMARY KEY AUTOINCREMENT,
    slug TEXT NOT NULL UNIQUE COLLATE NOCASE,
    title TEXT NOT NULL,
    summary TEXT NOT NULL,
    difficulty TEXT NOT NULL
        CHECK (difficulty IN ('beginner', 'intermediate', 'advanced')),
    architecture TEXT NOT NULL,
    source_code TEXT NOT NULL,
    build_command TEXT NOT NULL,
    expected_findings TEXT NOT NULL,
    walkthrough TEXT NOT NULL,
    published INTEGER NOT NULL DEFAULT 0 CHECK (published IN (0, 1)),
    author_user_id INTEGER,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author_user_id) REFERENCES users(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_binary_examples_published
    ON binary_examples(published, difficulty, title);
"""


STUDENT_HISTORY_SCHEMA = """
ALTER TABLE learning_content
    ADD COLUMN vulnerable_example TEXT NOT NULL DEFAULT '';
ALTER TABLE learning_content
    ADD COLUMN secure_example TEXT NOT NULL DEFAULT '';
ALTER TABLE learning_content
    ADD COLUMN review_steps TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS analysis_records (
    record_id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL UNIQUE,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    file_size INTEGER NOT NULL,
    architecture TEXT NOT NULL,
    score INTEGER NOT NULL,
    rating TEXT NOT NULL,
    result_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analysis_records_user
    ON analysis_records(user_id, created_at DESC, record_id DESC);
"""


ADVANCED_LEARNING_SCHEMA = """
ALTER TABLE learning_content
    ADD COLUMN technical_details TEXT NOT NULL DEFAULT '';
ALTER TABLE learning_content
    ADD COLUMN lab_exercise TEXT NOT NULL DEFAULT '';
ALTER TABLE learning_content
    ADD COLUMN expected_observations TEXT NOT NULL DEFAULT '';
"""


MIGRATION_SCHEMA = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


LATEST_SCHEMA_VERSION = 6

LEARNING_TOPIC_ORDER = (
    "elf_structure",
    "program_headers",
    "dynamic_section",
    "strings",
    "unsafe_functions",
    "canary",
    "nx",
    "pie",
    "relro",
    "fortify",
    "rpath",
    "risk_score",
    "comparison_mode",
    "static_limits",
    "secure_elf_build",
    "secure_coding_practices",
)


TOPIC_EXAMPLE_ROWS = [
    ("canary", "void copy(const char *s) { char b[16]; strcpy(b, s); }", "int copy(const char *s) { char b[16]; int n = snprintf(b, sizeof b, \"%s\", s); return n >= 0 && (size_t)n < sizeof b ? 0 : -1; }", "Compare builds with and without -fstack-protector-strong. A canary is a mitigation; the bounded copy is the source-level fix."),
    ("nx", "// Build requesting an executable stack\n// gcc demo.c -Wl,-z,execstack -o demo", "// Keep data non-executable\n// gcc demo.c -Wl,-z,noexecstack -o demo", "Inspect PT_GNU_STACK permissions. NX reduces code execution from writable memory but does not remove the underlying memory bug."),
    ("pie", "// Fixed-address executable\n// gcc demo.c -fno-PIE -no-pie -o demo", "// Position-independent executable\n// gcc demo.c -fPIE -pie -o demo", "Compare ELF type and PIE status. PIE supports address randomization; it does not validate input or prevent corruption."),
    ("relro", "// Partial or missing RELRO\n// gcc demo.c -Wl,-z,norelro -o demo", "// Full RELRO\n// gcc demo.c -Wl,-z,relro,-z,now -o demo", "Compare program headers and dynamic flags. Full RELRO hardens relocation data after startup."),
    ("fortify", "char out[8]; strcpy(out, input);", "char out[8];\nif (snprintf(out, sizeof out, \"%s\", input) >= (int)sizeof out) { return -1; }", "Build with optimization and -D_FORTIFY_SOURCE=2 or 3 where supported. Fortify is an added check, not a substitute for correct bounds logic."),
    ("rpath", "// Searches a relative writable directory\n// gcc app.c -Wl,-rpath,'$ORIGIN/plugins' -o app", "// Prefer trusted system paths or a validated deployment-specific absolute path\n// gcc app.c -o app", "Inspect DT_RPATH and DT_RUNPATH. Determine who can write each referenced directory before deciding whether it is risky."),
    ("unsafe_functions", "char name[16]; gets(name);", "char name[16];\nif (!fgets(name, sizeof name, stdin)) { return 1; }\nname[strcspn(name, \"\\n\")] = '\\0';", "Find the import, then inspect arguments and bounds in source. An imported function is review evidence, not proof of exploitation."),
    ("strings", "const char *token = \"API_KEY=training-secret\";", "const char *token = getenv(\"APP_API_KEY\");\nif (!token) { return 1; }", "Search strings for credentials, paths, URLs, and commands. Remove embedded secrets and rotate any real credential that was exposed."),
    ("static_limits", "if (getenv(\"TRIGGER\")) { hidden_runtime_action(); }", "// Combine static review with authorized tests in isolation\nvalidate_configuration();\nrun_security_tests();", "Explain which behavior is visible in the file and which depends on runtime state. Never treat a static report as a safety verdict."),
    ("elf_structure", "// Incorrect assumption: section names alone describe runtime memory", "// Review ELF header, program headers, sections, dynamic entries, imports, and strings as separate evidence", "Locate the entry point and compare section data with loadable segment permissions. Program headers govern runtime mapping."),
    ("program_headers", "// RWX load segment allows writing and execution in one mapping", "// Separate code as R-X and writable data as RW-; keep PT_GNU_STACK non-executable", "Review type, offset, virtual address, file and memory sizes, alignment, and R/W/X flags for each segment."),
    ("dynamic_section", "// Untrusted loader search configuration\n// -Wl,-rpath,/tmp/demo-libs", "// Remove unnecessary search paths and enable immediate binding\n// -Wl,-z,relro,-z,now", "Inspect DT_NEEDED, RPATH/RUNPATH, and binding flags together. Confirm dependency locations on the actual deployment system."),
    ("risk_score", "// Incorrect: if (score > 80) puts(\"This binary is safe\");", "// Correct: use the score to prioritize review, then cite each evidence row and limitation", "Change one build flag at a time and observe the score deduction. Explain why the score measures supported indicators, not exploitability."),
    ("comparison_mode", "// Compare unrelated programs and attribute every difference to hardening", "// Build the same source twice, changing only documented compiler/linker flags", "Use controlled weak and hardened builds. Connect each changed protection to the exact flag and note compiler-dependent variation."),
    ("secure_elf_build", "gcc -O0 demo.c -o demo", "gcc -O2 -Wall -Wextra -Wformat -Wformat-security -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack demo.c -o demo", "Verify the output rather than assuming flags worked. Record compiler version and compare Canary, NX, PIE, RELRO, and Fortify evidence."),
    ("secure_coding_practices", "printf(user_input);\nmemcpy(dst, src, user_length);", "printf(\"%s\", user_input);\nif (user_length > dst_size || user_length > src_size) { return -1; }\nmemcpy(dst, src, user_length);", "Trace untrusted input through parsing, formatting, copying, and command execution. Check lengths, types, ranges, encodings, return values, and error paths."),
]


EXAMPLE_SEED_ROWS = [
    (
        "unsafe-format-string",
        "Unsafe Format String",
        "Compare an unsafe printf call with a constant-format alternative and identify the imported-function evidence.",
        "beginner",
        "x86-64 ELF",
        '#include <stdio.h>\n\nint main(int argc, char **argv) {\n    if (argc > 1) {\n        printf(argv[1]);\n    }\n    return 0;\n}',
        "gcc -O0 -Wall -Wextra format_demo.c -o format_demo",
        "The report should flag printf for review. The string passed as the format is controlled by argv, which can allow unintended format directives.",
        "Start with the imported-functions table, then confirm the call in source. Replace printf(argv[1]) with printf(\"%s\", argv[1]). Rebuild and explain why imported-function presence alone does not prove unsafe use.",
        1,
    ),
    (
        "weak-vs-hardened-build",
        "Weak vs Hardened ELF Build",
        "Build the same small C program twice to observe how compiler and linker flags change binary hardening evidence.",
        "intermediate",
        "x86-64 ELF",
        '#include <stdio.h>\n#include <string.h>\n\nint main(int argc, char **argv) {\n    char buffer[32] = {0};\n    if (argc > 1) {\n        strncpy(buffer, argv[1], sizeof(buffer) - 1);\n    }\n    puts(buffer);\n    return 0;\n}',
        "Weak: gcc -O0 demo.c -o demo-weak\nHardened: gcc -O2 -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -pie -Wl,-z,relro,-z,now -Wl,-z,noexecstack demo.c -o demo-hardened",
        "The hardened build should provide stronger evidence for Stack Canary, PIE, full RELRO, NX, and Fortify. Exact imports can vary by compiler and C library.",
        "Analyze both files with Compare mode. Connect each changed report row to its compiler or linker flag, and remember that hardening reduces exploitability but does not replace source review.",
        1,
    ),
]


SEED_ROWS = [
    (
        "canary",
        "Stack Canary",
        "Protection",
        "A secret value placed near control data helps detect some stack overwrites before a function returns.",
        "Without it, some stack-based memory corruption may be harder to detect.",
        "Compile supported code with -fstack-protector-strong or an equivalent compiler option.",
    ),
    (
        "nx",
        "NX / Non-executable Stack",
        "Protection",
        "NX asks the operating system not to execute instructions from writable data areas such as the stack.",
        "An executable stack can make some memory-corruption attacks easier.",
        "Use a non-executable stack and avoid compiler or linker options that request an executable stack.",
    ),
    (
        "pie",
        "Position Independent Executable",
        "Protection",
        "PIE allows the operating system to place the main program at a randomized address when ASLR is enabled.",
        "A fixed program address can make code-reuse attacks more predictable.",
        "Compile and link executables with PIE support, such as -fPIE -pie.",
    ),
    (
        "relro",
        "RELRO",
        "Protection",
        "RELRO makes relocation-related memory harder to modify after the loader has initialized the program.",
        "No or partial RELRO can leave some linkage data writable.",
        "Prefer full RELRO with linker options such as -Wl,-z,relro,-z,now.",
    ),
    (
        "fortify",
        "Fortify Source",
        "Protection",
        "Fortified C-library calls add checks to some operations when the compiler knows destination sizes.",
        "Missing fortified calls removes one useful layer, but their presence does not prove all operations are safe.",
        "Use optimization with _FORTIFY_SOURCE where supported and still perform explicit bounds checking.",
    ),
    (
        "rpath",
        "RPATH / RUNPATH",
        "Loader",
        "Embedded library search paths tell the dynamic loader where else to look for shared libraries.",
        "Writable or untrusted search locations can allow unintended libraries to be loaded.",
        "Avoid unnecessary embedded paths and never rely on user-writable library directories.",
    ),
    (
        "unsafe_functions",
        "Potentially Unsafe Functions",
        "Functions",
        "Some C and process-launching functions require careful length, format, and input control.",
        "Unsafe use can contribute to buffer overflows, format-string bugs, or command injection.",
        "Use bounded APIs, validate inputs, avoid shell interpretation, and review each call in source code.",
    ),
    (
        "strings",
        "Printable Strings",
        "Analysis",
        "Readable byte sequences can reveal URLs, paths, commands, messages, and compiler information.",
        "A string is only a clue; it does not prove that code uses it or that the program is malicious.",
        "Use strings to guide further authorized review and confirm findings with code or disassembly.",
    ),
    (
        "static_limits",
        "Limits of Static Analysis",
        "Analysis",
        "Static inspection studies file content and structure without running the program.",
        "Packing, stripping, optimization, obfuscation, and runtime-generated behavior can hide important details.",
        "Treat results as observations and combine them with controlled testing when authorization and isolation allow.",
    ),
    (
        "elf_structure",
        "ELF Structure",
        "Analysis",
        "An ELF file is organized around a file header, program headers used by the loader, and section headers used by linkers and analysis tools.",
        "Misreading these structures can lead to wrong conclusions about architecture, entry point, memory permissions, or whether a section is actually loaded.",
        "Start with the ELF header, then compare program headers, dynamic entries, sections, imports, and strings as separate pieces of evidence.",
    ),
    (
        "program_headers",
        "Program Headers",
        "Analysis",
        "Program headers describe how the operating system maps parts of the file into memory, including loadable segments and GNU hardening metadata.",
        "Security properties such as executable stack and RELRO are often visible through program headers rather than only section names.",
        "Review segment type, memory permissions, virtual address, file size, memory size, and alignment before drawing conclusions.",
    ),
    (
        "dynamic_section",
        "Dynamic Section",
        "Loader",
        "The dynamic section lists loader metadata such as needed libraries, symbol tables, relocation behavior, RPATH, RUNPATH, and binding flags.",
        "Loader configuration can affect hardening, dependency trust, and whether library search paths introduce risk.",
        "Inspect dynamic tags together with imported symbols and program headers, especially DT_NEEDED, DT_RPATH, DT_RUNPATH, and binding flags.",
    ),
    (
        "risk_score",
        "ELF Security Score",
        "Analysis",
        "The security score starts at 100 and subtracts deductions for missing hardening, flagged imports, and selected string indicators.",
        "A higher score means the uploaded ELF looks stronger in the supported static checks, but it cannot prove exploitability or safety.",
        "Use the score to explain how secure the ELF appears, then support every claim with concrete evidence from the report.",
    ),
    (
        "comparison_mode",
        "Weak vs Hardened Comparison",
        "Analysis",
        "Comparing two builds side by side makes compiler and linker protections easier to understand because the changed evidence is visible.",
        "A comparison can still miss source-level vulnerabilities or runtime behavior, so a hardened build is not automatically secure.",
        "Compile controlled samples with different flags, compare the report rows, and explain which compiler option changed each protection.",
    ),
    (
        "secure_elf_build",
        "Secure ELF Build Baseline",
        "Developer Practice",
        "A hardened ELF build combines compiler diagnostics, stack protection, PIE, full RELRO, non-executable stack, and Fortify where supported.",
        "Missing build hardening can make a separate source-code defect easier to exploit or harder to detect during review.",
        "Use warnings, -fstack-protector-strong, -fPIE -pie, -Wl,-z,relro,-z,now, non-executable stack settings, and Fortify with optimization.",
    ),
    (
        "secure_coding_practices",
        "Secure Coding Practices",
        "Developer Practice",
        "Most binary-level findings become meaningful only when connected to source behavior such as input validation, memory handling, formatting, and process execution.",
        "Unsafe parsing, unchecked lengths, format-string misuse, command construction, and ignored return values can create vulnerabilities even when hardening is enabled.",
        "Validate input, use size-aware APIs, keep format strings constant, avoid shell invocation for untrusted data, check return values, and test with sanitizers.",
    ),
]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        Path(current_app.config["DATABASE"]).parent.mkdir(
            parents=True, exist_ok=True
        )
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db() -> None:
    db = get_db()
    run_migrations(db)
    db.executemany(
        """
        INSERT INTO learning_content
            (topic, title, category, explanation, risk, recommendation)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(topic) DO NOTHING
        """,
        SEED_ROWS,
    )
    db.executemany(
        """
        INSERT INTO binary_examples(
            slug, title, summary, difficulty, architecture, source_code,
            build_command, expected_findings, walkthrough, published
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(slug) DO NOTHING
        """,
        EXAMPLE_SEED_ROWS,
    )
    advanced_rows = [
        (
            content["vulnerable_example"], content["secure_example"],
            content["review_steps"], content["technical_details"],
            content["lab_exercise"], content["expected_observations"], topic,
        )
        for topic, content in ADVANCED_TOPICS.items()
    ]
    db.executemany(
        """
        UPDATE learning_content
        SET vulnerable_example = CASE WHEN vulnerable_example = '' THEN ? ELSE vulnerable_example END,
            secure_example = CASE WHEN secure_example = '' THEN ? ELSE secure_example END,
            review_steps = CASE WHEN review_steps = '' THEN ? ELSE review_steps END,
            technical_details = CASE WHEN technical_details = '' THEN ? ELSE technical_details END,
            lab_exercise = CASE WHEN lab_exercise = '' THEN ? ELSE lab_exercise END,
            expected_observations = CASE WHEN expected_observations = '' THEN ? ELSE expected_observations END
        WHERE topic = ?
        """,
        advanced_rows,
    )
    legacy_by_topic = {
        topic: (vulnerable, secure, steps)
        for topic, vulnerable, secure, steps in TOPIC_EXAMPLE_ROWS
    }
    db.executemany(
        """
        UPDATE learning_content
        SET vulnerable_example = ?, secure_example = ?, review_steps = ?
        WHERE topic = ? AND vulnerable_example = ?
          AND secure_example = ? AND review_steps = ?
        """,
        [
            (
                content["vulnerable_example"], content["secure_example"],
                content["review_steps"], topic, *legacy_by_topic[topic],
            )
            for topic, content in ADVANCED_TOPICS.items()
        ],
    )
    db.commit()


def run_migrations(db: sqlite3.Connection | None = None) -> int:
    """Apply ordered, idempotent schema changes and return the current version."""
    connection = db or get_db()
    connection.executescript(MIGRATION_SCHEMA)
    applied = {
        row["version"]
        for row in connection.execute(
            "SELECT version FROM schema_migrations"
        ).fetchall()
    }
    migrations = (
        (1, SCHEMA),
        (2, AUTH_SCHEMA),
        (3, PROGRESS_SCHEMA),
        (4, EXAMPLES_SCHEMA),
        (5, STUDENT_HISTORY_SCHEMA),
        (6, ADVANCED_LEARNING_SCHEMA),
    )
    for version, script in migrations:
        if version in applied:
            continue
        connection.executescript(script)
        connection.execute(
            "INSERT INTO schema_migrations(version) VALUES (?)",
            (version,),
        )
    connection.commit()
    return get_schema_version(connection)


def get_schema_version(db: sqlite3.Connection | None = None) -> int:
    connection = db or get_db()
    row = connection.execute(
        "SELECT COALESCE(MAX(version), 0) AS version FROM schema_migrations"
    ).fetchone()
    return int(row["version"])


def create_user(
    *,
    email: str,
    display_name: str,
    password_hash: str,
    role: str = "student",
) -> dict:
    if role not in {"student", "instructor", "admin"}:
        raise ValueError("Invalid user role")
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO users(email, display_name, password_hash, role)
        VALUES (?, ?, ?, ?)
        """,
        (email.strip().lower(), display_name.strip(), password_hash, role),
    )
    db.commit()
    return get_user_by_id(cursor.lastrowid)


def get_user_by_id(user_id: int) -> dict | None:
    row = get_db().execute(
        """
        SELECT user_id, email, display_name, password_hash, role, active,
               created_at, last_login_at
        FROM users
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()
    return dict(row) if row else None


def get_user_by_email(email: str) -> dict | None:
    row = get_db().execute(
        """
        SELECT user_id, email, display_name, password_hash, role, active,
               created_at, last_login_at
        FROM users
        WHERE email = ? COLLATE NOCASE
        """,
        (email.strip(),),
    ).fetchone()
    return dict(row) if row else None


def mark_user_login(user_id: int) -> None:
    db = get_db()
    db.execute(
        "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE user_id = ?",
        (user_id,),
    )
    db.commit()


def list_users() -> list[dict]:
    rows = get_db().execute(
        """
        SELECT user_id, email, display_name, role, active, created_at,
               last_login_at
        FROM users
        ORDER BY created_at DESC, user_id DESC
        """
    ).fetchall()
    return [dict(row) for row in rows]


def set_user_access(
    *,
    target_user_id: int,
    role: str,
    active: bool,
    acting_user_id: int,
) -> dict:
    if role not in {"student", "instructor", "admin"}:
        raise ValueError("Select a valid account role.")
    if target_user_id == acting_user_id:
        raise ValueError("Administrators cannot change their own role or status.")

    db = get_db()
    target = get_user_by_id(target_user_id)
    if target is None:
        raise ValueError("The selected account no longer exists.")
    removes_active_admin = (
        target["role"] == "admin"
        and target["active"]
        and (role != "admin" or not active)
    )
    if removes_active_admin:
        active_admins = db.execute(
            """
            SELECT COUNT(*) AS total
            FROM users
            WHERE role = 'admin' AND active = 1
            """
        ).fetchone()["total"]
        if active_admins <= 1:
            raise ValueError("At least one active administrator must remain.")

    db.execute(
        "UPDATE users SET role = ?, active = ? WHERE user_id = ?",
        (role, int(active), target_user_id),
    )
    db.commit()
    return get_user_by_id(target_user_id)


def record_audit_event(
    action: str,
    *,
    actor_user_id: int | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    details: str | None = None,
) -> None:
    db = get_db()
    db.execute(
        """
        INSERT INTO audit_log(
            actor_user_id, action, target_type, target_id, details
        )
        VALUES (?, ?, ?, ?, ?)
        """,
        (actor_user_id, action, target_type, target_id, details),
    )
    db.commit()


def get_recent_audit_events(limit: int = 50) -> list[dict]:
    safe_limit = max(1, min(int(limit), 200))
    rows = get_db().execute(
        """
        SELECT audit_log.audit_id, audit_log.action, audit_log.target_type,
               audit_log.target_id, audit_log.details, audit_log.created_at,
               users.email AS actor_email
        FROM audit_log
        LEFT JOIN users ON users.user_id = audit_log.actor_user_id
        ORDER BY audit_log.audit_id DESC
        LIMIT ?
        """,
        (safe_limit,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_learning_content() -> list[dict]:
    rows = get_db().execute(
        """
        SELECT topic, title, category, explanation, risk, recommendation,
               vulnerable_example, secure_example, review_steps,
               technical_details, lab_exercise, expected_observations
        FROM learning_content
        ORDER BY category, title
        """
    ).fetchall()
    order = {topic: index for index, topic in enumerate(LEARNING_TOPIC_ORDER)}
    return sorted(
        (dict(row) for row in rows),
        key=lambda row: (order.get(row["topic"], len(order)), row["title"]),
    )


def get_learning_map() -> dict[str, dict]:
    return {row["topic"]: row for row in get_learning_content()}


def get_completed_topics(user_id: int) -> set[str]:
    rows = get_db().execute(
        """
        SELECT topic
        FROM learning_progress
        WHERE user_id = ? AND completed = 1
        """,
        (user_id,),
    ).fetchall()
    return {row["topic"] for row in rows}


def set_learning_progress(user_id: int, topic: str, completed: bool) -> None:
    db = get_db()
    if topic not in get_learning_map():
        raise ValueError("The selected learning topic does not exist.")
    db.execute(
        """
        INSERT INTO learning_progress(user_id, topic, completed, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(user_id, topic) DO UPDATE SET
            completed = excluded.completed,
            updated_at = CURRENT_TIMESTAMP
        """,
        (user_id, topic, int(completed)),
    )
    db.commit()


def update_learning_topic(
    topic: str,
    *,
    title: str,
    category: str,
    explanation: str,
    risk: str,
    recommendation: str,
    vulnerable_example: str,
    secure_example: str,
    review_steps: str,
    technical_details: str,
    lab_exercise: str,
    expected_observations: str,
) -> dict:
    db = get_db()
    cursor = db.execute(
        """
        UPDATE learning_content
        SET title = ?, category = ?, explanation = ?, risk = ?,
            recommendation = ?, vulnerable_example = ?,
            secure_example = ?, review_steps = ?, technical_details = ?,
            lab_exercise = ?, expected_observations = ?
        WHERE topic = ?
        """,
        (
            title, category, explanation, risk, recommendation,
            vulnerable_example, secure_example, review_steps,
            technical_details, lab_exercise, expected_observations, topic,
        ),
    )
    if cursor.rowcount != 1:
        db.rollback()
        raise ValueError("The selected learning topic does not exist.")
    db.commit()
    return get_learning_map()[topic]


def save_analysis_record(user_id: int, result: dict) -> dict:
    encoded = json.dumps(result, ensure_ascii=True, separators=(",", ":"))
    db = get_db()
    db.execute(
        """
        INSERT INTO analysis_records(
            analysis_id, user_id, filename, file_size, architecture,
            score, rating, result_json
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(analysis_id) DO NOTHING
        """,
        (
            result["analysis_id"], user_id, result["filename"],
            result["file_size"], result["metadata"]["architecture"],
            result["risk_summary"]["score"],
            result["risk_summary"]["rating"], encoded,
        ),
    )
    db.commit()
    return get_analysis_record(user_id, result["analysis_id"])


def list_analysis_records(user_id: int) -> list[dict]:
    rows = get_db().execute(
        """
        SELECT record_id, analysis_id, filename, file_size, architecture,
               score, rating, created_at
        FROM analysis_records
        WHERE user_id = ?
        ORDER BY record_id DESC
        """,
        (user_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_analysis_record(user_id: int, analysis_id: str) -> dict | None:
    row = get_db().execute(
        """
        SELECT record_id, analysis_id, filename, file_size, architecture,
               score, rating, result_json, created_at
        FROM analysis_records
        WHERE user_id = ? AND analysis_id = ?
        """,
        (user_id, analysis_id),
    ).fetchone()
    if row is None:
        return None
    record = dict(row)
    record["result"] = json.loads(record.pop("result_json"))
    return record


def delete_analysis_record(user_id: int, analysis_id: str) -> bool:
    db = get_db()
    cursor = db.execute(
        "DELETE FROM analysis_records WHERE user_id = ? AND analysis_id = ?",
        (user_id, analysis_id),
    )
    db.commit()
    return cursor.rowcount == 1


def list_binary_examples(*, include_unpublished: bool = False) -> list[dict]:
    where = "" if include_unpublished else "WHERE binary_examples.published = 1"
    rows = get_db().execute(
        f"""
        SELECT binary_examples.example_id, binary_examples.slug,
               binary_examples.title, binary_examples.summary,
               binary_examples.difficulty, binary_examples.architecture,
               binary_examples.published, binary_examples.created_at,
               binary_examples.updated_at, users.display_name AS author_name
        FROM binary_examples
        LEFT JOIN users ON users.user_id = binary_examples.author_user_id
        {where}
        ORDER BY binary_examples.published DESC,
                 CASE binary_examples.difficulty
                    WHEN 'beginner' THEN 1
                    WHEN 'intermediate' THEN 2
                    ELSE 3
                 END,
                 binary_examples.title
        """
    ).fetchall()
    return [dict(row) for row in rows]


def get_binary_example_by_slug(
    slug: str, *, include_unpublished: bool = False
) -> dict | None:
    publication_clause = "" if include_unpublished else "AND binary_examples.published = 1"
    row = get_db().execute(
        f"""
        SELECT binary_examples.*, users.display_name AS author_name
        FROM binary_examples
        LEFT JOIN users ON users.user_id = binary_examples.author_user_id
        WHERE binary_examples.slug = ? COLLATE NOCASE {publication_clause}
        """,
        (slug,),
    ).fetchone()
    return dict(row) if row else None


def create_binary_example(*, author_user_id: int, **values) -> dict:
    db = get_db()
    cursor = db.execute(
        """
        INSERT INTO binary_examples(
            slug, title, summary, difficulty, architecture, source_code,
            build_command, expected_findings, walkthrough, published,
            author_user_id
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            values["slug"], values["title"], values["summary"],
            values["difficulty"], values["architecture"],
            values["source_code"], values["build_command"],
            values["expected_findings"], values["walkthrough"],
            int(values["published"]), author_user_id,
        ),
    )
    db.commit()
    row = db.execute(
        "SELECT slug FROM binary_examples WHERE example_id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return get_binary_example_by_slug(row["slug"], include_unpublished=True)


def update_binary_example(example_id: int, **values) -> dict:
    db = get_db()
    cursor = db.execute(
        """
        UPDATE binary_examples
        SET slug = ?, title = ?, summary = ?, difficulty = ?,
            architecture = ?, source_code = ?, build_command = ?,
            expected_findings = ?, walkthrough = ?, published = ?,
            updated_at = CURRENT_TIMESTAMP
        WHERE example_id = ?
        """,
        (
            values["slug"], values["title"], values["summary"],
            values["difficulty"], values["architecture"],
            values["source_code"], values["build_command"],
            values["expected_findings"], values["walkthrough"],
            int(values["published"]), example_id,
        ),
    )
    if cursor.rowcount != 1:
        db.rollback()
        raise ValueError("The selected binary example no longer exists.")
    db.commit()
    return get_binary_example_by_slug(values["slug"], include_unpublished=True)


def init_app(app) -> None:
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
