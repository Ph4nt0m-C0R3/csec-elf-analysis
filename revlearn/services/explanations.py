"""Translate technical findings into cautious educational guidance."""

from __future__ import annotations


PROTECTION_TITLES = {
    "canary": "Stack Canary",
    "nx": "NX",
    "pie": "PIE",
    "relro": "RELRO",
    "rpath": "RPATH / RUNPATH",
    "fortify": "Fortify",
}

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

PROTECTION_CONTEXT = {
    "canary": {
        "title": "Possible stack memory-corruption exposure",
        "standard": "CWE-121 context",
        "severity": "medium",
        "attack": (
            "If a stack overflow exists, an attacker may be able to crash the "
            "process, corrupt control data, or redirect program execution."
        ),
        "prevention": (
            "Enable stack protection, replace unbounded copies, validate input "
            "lengths, and use memory-safe components where practical."
        ),
    },
    "nx": {
        "title": "Executable stack exposure",
        "standard": "Memory-execution hardening gap",
        "severity": "high",
        "attack": (
            "A separate memory-corruption flaw may be easier to turn into code "
            "injection when attacker-controlled stack data can execute."
        ),
        "prevention": (
            "Require a non-executable stack, remove executable-stack linker "
            "options, and correct the underlying memory-safety defects."
        ),
    },
    "pie": {
        "title": "Predictable main-program addresses",
        "standard": "ASLR hardening gap",
        "severity": "medium",
        "attack": (
            "Stable code addresses can help an attacker reuse existing code "
            "after another vulnerability provides memory control."
        ),
        "prevention": (
            "Build executables with PIE and keep operating-system ASLR enabled."
        ),
    },
    "relro": {
        "title": "Writable relocation data",
        "standard": "Dynamic-linker hardening gap",
        "severity": "high",
        "attack": (
            "If an attacker already has a memory-write primitive, writable "
            "linkage data may provide a target for redirecting function calls."
        ),
        "prevention": (
            "Prefer full RELRO with immediate binding and fix all arbitrary or "
            "out-of-bounds memory-write vulnerabilities."
        ),
    },
    "rpath": {
        "title": "Potential uncontrolled library search path",
        "standard": "CWE-427 context",
        "severity": "high",
        "attack": (
            "If an embedded path is attacker-writable, library search-order "
            "hijacking could cause an unintended library to load."
        ),
        "prevention": (
            "Remove unnecessary RPATH/RUNPATH entries and use trusted, "
            "administrator-controlled library directories."
        ),
    },
    "fortify": {
        "title": "Reduced C-library bounds-checking coverage",
        "standard": "Compiler hardening gap",
        "severity": "low",
        "attack": (
            "Unsafe buffer operations may be less likely to stop early, which "
            "can increase the impact of an existing memory-safety defect."
        ),
        "prevention": (
            "Enable supported Fortify options with optimization, check every "
            "buffer length explicitly, and do not treat Fortify as a substitute "
            "for safe code."
        ),
    },
}

FUNCTION_CONTEXT = {
    "gets": ("Unbounded input buffer overflow", "CWE-120", "critical"),
    "strcpy": ("Possible unbounded copy", "CWE-120", "high"),
    "strcat": ("Possible unbounded append", "CWE-120", "high"),
    "sprintf": ("Possible formatted-output overflow", "CWE-120", "high"),
    "vsprintf": ("Possible formatted-output overflow", "CWE-120", "high"),
    "scanf": ("Possible input-width validation weakness", "CWE-120", "medium"),
    "__isoc99_scanf": (
        "Possible input-width validation weakness",
        "CWE-120",
        "medium",
    ),
    "system": ("Possible OS command injection", "CWE-78", "high"),
    "popen": ("Possible OS command injection", "CWE-78", "high"),
    "memcpy": ("Possible out-of-bounds memory copy", "CWE-787", "medium"),
    "strncpy": ("Possible truncation or termination error", "CWE-170", "medium"),
    "printf": ("Possible uncontrolled format string", "CWE-134", "low"),
}


def build_education(
    protections: dict,
    function_results: dict,
    string_results: dict,
    learning: dict[str, dict],
) -> dict:
    explanations = []
    for topic, finding in protections.items():
        content = learning.get(topic, {})
        explanations.append(
            {
                "topic": topic,
                "title": content.get("title", PROTECTION_TITLES[topic]),
                "status": finding["status"],
                "explanation": content.get("explanation", ""),
                "risk": content.get("risk", ""),
            }
        )

    observations = _observations(protections, function_results, string_results)
    recommendations = _recommendations(
        protections, function_results, learning
    )
    vulnerabilities = _vulnerability_context(
        protections, function_results, string_results
    )
    return {
        "explanations": explanations,
        "observations": observations,
        "recommendations": recommendations,
        "vulnerabilities": vulnerabilities,
        "disclaimer": (
            "These are static-analysis observations, not proof that the file is "
            "safe, malicious, or exploitable."
        ),
    }


def _observations(protections, functions, strings) -> list[dict]:
    rows = []
    for key, finding in protections.items():
        if finding["level"] in {"warn", "danger"}:
            rows.append(
                {
                    "severity": (
                        "high" if finding["level"] == "danger" else "medium"
                    ),
                    "title": f"{PROTECTION_TITLES[key]}: {finding['status']}",
                    "detail": finding["evidence"],
                }
            )
    if functions["warnings"]:
        rows.append(
            {
                "severity": "high",
                "title": "Functions requiring source-level review",
                "detail": (
                    f"{len(functions['warnings'])} imported function(s) were "
                    "flagged because unsafe use can create vulnerabilities."
                ),
            }
        )
    if strings["suspicious"] or strings["commands"]:
        rows.append(
            {
                "severity": "info",
                "title": "Interesting printable strings found",
                "detail": (
                    "String matches are leads for further analysis and do not "
                    "show that the corresponding behavior is reachable."
                ),
            }
        )
    if not rows:
        rows.append(
            {
                "severity": "info",
                "title": "No highlighted weakness in the supported checks",
                "detail": (
                    "The limited checks did not produce a warning. This does "
                    "not prove that the program is secure."
                ),
            }
        )
    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            item["title"].lower(),
        )
    )
    return rows


def _vulnerability_context(protections, functions, strings) -> list[dict]:
    """Describe defensive attack context without providing exploitation steps."""
    rows = []
    conditions = {
        "canary": protections["canary"]["status"] != "Enabled",
        "nx": protections["nx"]["status"] == "Disabled",
        "pie": protections["pie"]["status"] == "Disabled",
        "relro": protections["relro"]["status"] != "Full",
        "rpath": protections["rpath"]["status"] == "Present",
        "fortify": protections["fortify"]["status"] != "Detected",
    }
    for topic, present in conditions.items():
        if not present:
            continue
        context = PROTECTION_CONTEXT[topic]
        rows.append(
            {
                **context,
                "source": PROTECTION_TITLES[topic],
                "evidence": protections[topic]["evidence"],
                "qualification": (
                    "This is a hardening or exposure indicator. It does not "
                    "prove that an exploitable vulnerability exists."
                ),
            }
        )

    for warning in functions["warnings"]:
        name = warning["name"]
        title, standard, severity = FUNCTION_CONTEXT.get(
            name,
            ("Function requiring security review", "Contextual indicator", warning["severity"]),
        )
        if name in {"system", "popen"}:
            attack = (
                "If untrusted input reaches the command argument, an attacker "
                "may cause unauthorized operating-system commands to run."
            )
            prevention = (
                "Avoid shell invocation, use fixed argument arrays, allow-list "
                "accepted values, and keep untrusted input out of commands."
            )
        elif name == "printf":
            attack = (
                "If attacker-controlled text becomes the format string, it may "
                "disclose memory, crash the process, or corrupt memory."
            )
            prevention = (
                "Use a constant format string such as printf(\"%s\", value) and "
                "enable compiler format-security warnings."
            )
        else:
            attack = (
                "Incorrect length handling may let oversized input crash the "
                "process, corrupt memory, disclose data, or redirect execution."
            )
            prevention = (
                "Review the call in source code, validate all lengths, size the "
                "destination correctly, and use safer bounded abstractions."
            )
        rows.append(
            {
                "title": title,
                "standard": standard,
                "severity": severity,
                "source": f"Imported function: {name}()",
                "evidence": warning["explanation"],
                "attack": attack,
                "prevention": prevention,
                "qualification": (
                    "An imported symbol alone does not prove that the function "
                    "is called unsafely or is reachable by an attacker."
                ),
            }
        )

    if strings["suspicious"] or strings["commands"]:
        rows.append(
            {
                "title": "Possible information exposure or command clue",
                "standard": "Contextual string indicator",
                "severity": "low",
                "source": "Printable-string analysis",
                "evidence": (
                    "The file contains categorized command or sensitive-keyword strings."
                ),
                "attack": (
                    "Exposed credentials, internal paths, endpoints, or commands "
                    "can support reconnaissance or reveal sensitive configuration."
                ),
                "prevention": (
                    "Do not embed secrets, remove unnecessary diagnostic text, "
                    "protect configuration externally, and rotate any exposed credentials."
                ),
                "qualification": (
                    "A matching string may be unused documentation or test data; "
                    "confirm it through authorized source review."
                ),
            }
        )
    rows.sort(
        key=lambda item: (
            SEVERITY_ORDER.get(item["severity"], 99),
            item["title"].lower(),
        )
    )
    return rows


def _recommendations(protections, functions, learning) -> list[dict]:
    rows = []
    conditions = {
        "canary": protections["canary"]["status"] != "Enabled",
        "nx": protections["nx"]["status"] == "Disabled",
        "pie": protections["pie"]["status"] == "Disabled",
        "relro": protections["relro"]["status"] != "Full",
        "fortify": protections["fortify"]["status"] != "Detected",
        "rpath": protections["rpath"]["status"] == "Present",
    }
    for topic, needed in conditions.items():
        if not needed:
            continue
        content = learning.get(topic, {})
        rows.append(
            {
                "priority": (
                    "High"
                    if topic in {"nx", "relro", "canary"}
                    else "Medium"
                ),
                "action": content.get(
                    "recommendation",
                    f"Review the {PROTECTION_TITLES[topic]} configuration.",
                ),
                "reason": protections[topic]["evidence"],
            }
        )
    if functions["warnings"]:
        content = learning.get("unsafe_functions", {})
        rows.append(
            {
                "priority": "High",
                "action": content.get(
                    "recommendation",
                    "Review flagged function calls and validate all lengths and inputs.",
                ),
                "reason": (
                    "Imported names include functions whose safe use depends on "
                    "source-level validation."
                ),
            }
        )
    if not rows:
        rows.append(
            {
                "priority": "Advisory",
                "action": (
                    "Continue with authorized source review, dependency review, "
                    "and controlled testing."
                ),
                "reason": (
                    "Supported hardening checks cannot identify every software vulnerability."
                ),
            }
        )
    priority_order = {"High": 0, "Medium": 1, "Low": 2, "Advisory": 3}
    rows.sort(
        key=lambda item: (
            priority_order.get(item["priority"], 99),
            item["action"].lower(),
        )
    )
    return rows
