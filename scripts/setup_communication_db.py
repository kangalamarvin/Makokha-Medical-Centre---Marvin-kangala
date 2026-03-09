"""
Communication System - Complete Database Setup Script
Run this after updating app.py to create all new tables and indexes
"""

from app import app, db
from sqlalchemy import text

def setup_communication_database():
    """Create all communication tables and indexes"""
    
    with app.app_context():
        print("Creating all database tables...")
        db.create_all()
        print("✓ Tables created")
        
        print("\nCreating database indexes for performance...")
        
        indexes = [
            # Message indexes
            "CREATE INDEX IF NOT EXISTS idx_messages_sender_recipient ON messages(sender_id, recipient_id)",
            "CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(conversation_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_messages_unread ON messages(recipient_id, is_read) WHERE is_read = false",
            "CREATE INDEX IF NOT EXISTS idx_messages_search ON messages USING gin(to_tsvector('english', content))",
            
            # Conversation indexes
            "CREATE INDEX IF NOT EXISTS idx_conversations_users ON conversations(user1_id, user2_id)",
            "CREATE INDEX IF NOT EXISTS idx_conversations_last_message ON conversations(last_message_at DESC)",
            
            # Group message indexes  
            "CREATE INDEX IF NOT EXISTS idx_group_messages_group ON group_messages(group_id, created_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_group_messages_sender ON group_messages(sender_id)",
            
            # Group member indexes
            "CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id, is_active)",
            "CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id, is_active)",
            
            # Call log indexes
            "CREATE INDEX IF NOT EXISTS idx_call_logs_users ON call_logs(caller_id, receiver_id, started_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_call_logs_status ON call_logs(call_status, started_at DESC)",
            
            # Online status indexes
            "CREATE INDEX IF NOT EXISTS idx_user_online_status_user ON user_online_status(user_id, is_online)",
            
            # Message queue indexes
            "CREATE INDEX IF NOT EXISTS idx_message_queue_recipient ON message_queue(recipient_id, delivered_at)",
            
            # Blocked users indexes
            "CREATE INDEX IF NOT EXISTS idx_blocked_users_blocker ON blocked_users(blocker_id)",
            "CREATE INDEX IF NOT EXISTS idx_blocked_users_blocked ON blocked_users(blocked_id)",
            
            # Conversation settings indexes
            "CREATE INDEX IF NOT EXISTS idx_conversation_settings_user ON conversation_settings(user_id, conversation_id)",

            # Advanced message feature indexes
            "CREATE INDEX IF NOT EXISTS idx_message_edits_message ON message_edits(message_id, edited_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_message_reactions_message ON message_reactions(message_id)",
            "CREATE INDEX IF NOT EXISTS idx_message_reactions_user ON message_reactions(user_id)",
            "CREATE INDEX IF NOT EXISTS idx_message_stars_user ON message_stars(user_id, starred_at DESC)",
            "CREATE INDEX IF NOT EXISTS idx_message_stars_message ON message_stars(message_id)",
            "CREATE INDEX IF NOT EXISTS idx_message_deletions_message ON message_deletions(message_id)",
            "CREATE INDEX IF NOT EXISTS idx_message_replies_message ON message_replies(message_id)",
            "CREATE INDEX IF NOT EXISTS idx_message_replies_target ON message_replies(replied_to_message_id)",
        ]
        
        for idx_sql in indexes:
            try:
                db.session.execute(text(idx_sql))
                print(f"✓ {idx_sql.split('idx_')[1].split(' ')[0]}")
            except Exception as e:
                print(f"✗ Error creating index: {e}")
        
        db.session.commit()
        
        print("\n✓ All indexes created successfully!")
        print("\nDatabase setup complete. Communication system ready!")

if __name__ == '__main__':
    setup_communication_database()
