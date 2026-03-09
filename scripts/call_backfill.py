"""
Call the Flask CLI backfill-conversations command programmatically.
Run with: python scripts/call_backfill.py
"""
import os
from app import app

# Ensure FLASK_APP env so Flask CLI uses our app
os.environ['FLASK_APP'] = 'app'

from click.testing import CliRunner
from app import backfill_conversations_cmd

runner = CliRunner()
res = runner.invoke(backfill_conversations_cmd)
print(res.output)
if res.exit_code != 0:
    raise SystemExit(res.exit_code)
