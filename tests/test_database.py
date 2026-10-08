from revlearn.database import (
    LATEST_SCHEMA_VERSION,
    get_learning_content,
    get_schema_version,
    get_learning_map,
    init_db,
)


def test_learning_database_is_seeded(app):
    with app.app_context():
        rows = get_learning_content()
        topic_map = get_learning_map()

    assert len(rows) >= 9
    assert "canary" in topic_map
    assert "static_limits" in topic_map
    assert len(rows) == 16
    assert all(row["vulnerable_example"] for row in rows)
    assert all(row["secure_example"] for row in rows)
    assert all(row["review_steps"] for row in rows)
    assert all(row["technical_details"] for row in rows)
    assert all(row["lab_exercise"] for row in rows)
    assert all(row["expected_observations"] for row in rows)
    assert all("int main" in row["vulnerable_example"] for row in rows)
    assert all("int main" in row["secure_example"] for row in rows)


def test_database_migrations_create_v2_role_and_progress_tables(app):
    with app.app_context():
        version = get_schema_version()
        from revlearn.database import get_db

        tables = {
            row["name"]
            for row in get_db().execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }

    assert version == LATEST_SCHEMA_VERSION
    assert {
        "schema_migrations",
        "users",
        "audit_log",
        "learning_progress",
        "binary_examples",
        "analysis_records",
    } <= tables


def test_topic_reseeding_preserves_instructor_custom_programs(app):
    custom_program = "#include <stdio.h>\nint main(void) { puts(\"custom\"); return 0; }"
    with app.app_context():
        from revlearn.database import get_db

        get_db().execute(
            "UPDATE learning_content SET vulnerable_example = ? WHERE topic = 'canary'",
            (custom_program,),
        )
        get_db().commit()
        init_db()
        topic = get_learning_map()["canary"]

    assert topic["vulnerable_example"] == custom_program
    assert topic["technical_details"]
