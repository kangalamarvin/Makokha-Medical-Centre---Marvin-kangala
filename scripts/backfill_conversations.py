"""
Backfill conversations and conversation_members from existing messages.
This script is idempotent: it will skip pairs that already have a conversation.
Run from project root (where instance/clinic.db lives):
    & .\MMC\Scripts\Activate.ps1
    python scripts\backfill_conversations.py
"""
import sqlite3
import os
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

EAT = ZoneInfo('Africa/Nairobi')

DB = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance', 'clinic.db')
if not os.path.exists(DB):
    print('Database not found at', DB)
    raise SystemExit(1)

conn = sqlite3.connect(DB)
cur = conn.cursor()

# Find distinct unordered user pairs from messages
cur.execute("""
SELECT DISTINCT
  CASE WHEN sender_id < recipient_id THEN sender_id ELSE recipient_id END AS user_a,
  CASE WHEN sender_id < recipient_id THEN recipient_id ELSE sender_id END AS user_b
FROM messages
WHERE sender_id IS NOT NULL AND recipient_id IS NOT NULL
""")
pairs = cur.fetchall()
print('Found pairs:', pairs)

created = 0
attached_msgs = 0
for a, b in pairs:
    # check if conversation already exists linking both users
    cur.execute("""
    SELECT cm1.conversation_id FROM conversation_members cm1
    JOIN conversation_members cm2 ON cm1.conversation_id = cm2.conversation_id
    WHERE cm1.user_id = ? AND cm2.user_id = ? LIMIT 1
    """, (a, b))
    row = cur.fetchone()
    if row:
        conv_id = row[0]
        print(f'Conversation already exists for ({a},{b}) -> {conv_id}')
        # ensure messages for this pair have conversation_id set
        cur.execute("""
        UPDATE messages SET conversation_id = ?
        WHERE ((sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?))
          AND (conversation_id IS NULL OR conversation_id = '')
        """, (conv_id, a, b, b, a))
        attached_msgs += cur.rowcount
        conn.commit()
        continue

    # determine created_at as earliest message between them
    cur.execute("""
    SELECT MIN(created_at) FROM messages
    WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
    """, (a, b, b, a))
    min_created = cur.fetchone()[0]
    if min_created:
        created_at = min_created
    else:
        created_at = datetime.now(EAT).isoformat()

    # insert conversation (normalize pair order into first_user_id / second_user_id)
    conv_uuid = str(uuid.uuid4())
    fu = min(a, b)
    su = max(a, b)
    cur.execute("INSERT INTO conversations (uuid, title, is_group, created_at, updated_at, first_user_id, second_user_id) VALUES (?,?,?,?,?,?,?)",
                (conv_uuid, None, 0, created_at, created_at, fu, su))
    conv_id = cur.lastrowid

    # insert conversation members
    now = created_at
    cur.execute("INSERT INTO conversation_members (conversation_id, user_id, last_read_at, created_at) VALUES (?,?,?,?)",
                (conv_id, a, None, now))
    cur.execute("INSERT INTO conversation_members (conversation_id, user_id, last_read_at, created_at) VALUES (?,?,?,?)",
                (conv_id, b, None, now))

    # attach existing messages to conversation
    cur.execute("""
    UPDATE messages SET conversation_id = ?
    WHERE (sender_id = ? AND recipient_id = ?) OR (sender_id = ? AND recipient_id = ?)
    """, (conv_id, a, b, b, a))
    affected = cur.rowcount

    conn.commit()
    print(f'Created conversation {conv_id} for pair ({a},{b}), attached {affected} messages')
    created += 1
    attached_msgs += affected

print(f'Done. Conversations created: {created}, messages attached: {attached_msgs}')
conn.close()
