import os

# The test suite always runs on local SQLite, even when a Postgres URL (e.g. Supabase) is configured
# in .env, so tests can never write fixtures into a real database.
os.environ["HONEYGRID_FORCE_SQLITE"] = "1"
