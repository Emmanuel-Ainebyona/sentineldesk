"""Command line helper: python manage.py [migrate|seed|run|<task>]"""
import importlib
import os
import sys

from app import create_app


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "help"
    app = create_app()  # also applies pending migrations
    db_path = app.config["DATABASE_PATH"]
    tasks = {}
    try:
        tasks = importlib.import_module("app.tasks").COMMANDS
    except ModuleNotFoundError:
        pass
    if cmd == "migrate":
        print("Migrations up to date:", db_path)
    elif cmd == "seed":
        from app.seed import seed
        print("Seeded demo data." if seed(db_path) else "Database already has users; nothing seeded.")
    elif cmd == "run":
        app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", 8000)), debug=False)
    elif cmd in tasks:
        tasks[cmd](db_path, *argv[2:])
    else:
        print(__doc__, "tasks:", ", ".join(tasks) or "none")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
