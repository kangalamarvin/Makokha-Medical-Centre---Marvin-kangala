"""
Email Notifications for Communication System
Sends email notifications for missed messages and calls
"""
import os
from flask import current_app, render_template_string
from datetime import datetime, timedelta
from utils.email_production import send_email


def get_eat_now():
    """Get current time in EAT timezone"""
    from pytz import timezone
    eat = timezone('Africa/Nairobi')
    return datetime.now(eat)


class CommunicationEmailNotifications:
    """Handle email notifications for communication system"""
    
    @staticmethod
    def should_send_email(user, message_type='message'):
        """
        Check if user wants email notifications
        
        Args:
            user: User object
            message_type: 'message' or 'call'
            
        Returns:
            bool: Whether to send email
        """
        # Check if user has notification preferences
        if hasattr(user, 'notification_preference'):
            prefs = user.notification_preference
            
            # Check DND mode
            if prefs.do_not_disturb:
                # Check if within DND time window
                now = get_eat_now().time()
                if prefs.dnd_start_time and prefs.dnd_end_time:
                    if prefs.dnd_start_time <= now <= prefs.dnd_end_time:
                        return False
            
            # Check if email notifications enabled
            return prefs.email_notifications
        
        # Default: send emails if no preferences set
        return True
    
    @staticmethod
    def send_new_message_email(recipient_user, sender_name, message_content, conversation_url):
        """
        Send email notification for new message
        
        Args:
            recipient_user: User receiving the message
            sender_name: Name of sender
            message_content: Message text
            conversation_url: URL to open conversation
            
        Returns:
            bool: Success status
        """
        if not CommunicationEmailNotifications.should_send_email(recipient_user, 'message'):
            return False
        
        # Check if user has notification preferences for message preview
        show_preview = True
        if hasattr(recipient_user, 'notification_preference'):
            show_preview = recipient_user.notification_preference.message_preview
        
        subject = f'New message from {sender_name} - Makokha Medical Centre'
        
        # Message preview - Security: Limit preview length to prevent large content injection
        preview = message_content[:100] if show_preview else '[Message content hidden]'
        
        # Security Note: render_template_string() is used here but all variables are
        # explicitly escaped using |e filter. The template string itself is hardcoded (not user input).
        # Template variables: sender_name, message_preview, conversation_url are all escaped.
        html_body = render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #2e3192 0%, #1e88e5 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">💬 New Message</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e0e0e0;">
        <p style="font-size: 16px; margin-bottom: 20px;">
            You have a new message from <strong>{{ sender_name|e }}</strong>:
        </p>
        
        <div style="background: white; padding: 15px; border-left: 4px solid #2e3192; margin: 20px 0; border-radius: 4px;">
            <p style="margin: 0; color: #666; font-style: italic;">"{{ message_preview|e }}"</p>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{ conversation_url|e }}" style="display: inline-block; background: #2e3192; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                View Message
            </a>
        </p>
        
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        
        <p style="font-size: 12px; color: #999; text-align: center;">
            Makokha Medical Centre - Communication System<br>
            <a href="{{ settings_url|e }}" style="color: #2e3192;">Manage notification preferences</a>
        </p>
    </div>
</body>
</html>
        ''', 
            sender_name=sender_name,
            message_preview=preview,
            conversation_url=conversation_url,
            settings_url=f"{conversation_url.split('/')[0]}//communication/settings"
        )
        
        text_body = f'''
New Message from {sender_name}

Message: "{preview}"

View the full conversation at: {conversation_url}

---
Makokha Medical Centre - Communication System
Manage notification preferences at: {conversation_url.split('/')[0]}//communication/settings
        '''
        
        try:
            send_email(
                to_email=recipient_user.email,
                subject=subject,
                body=text_body,
                html_body=html_body
            )
            return True
        except Exception as e:
            current_app.logger.error(f'Failed to send message notification email: {e}')
            return False
    
    @staticmethod
    def send_missed_call_email(recipient_user, caller_name, call_type, timestamp):
        """
        Send email notification for missed call
        
        Args:
            recipient_user: User who missed the call
            caller_name: Name of caller
            call_type: 'voice' or 'video'
            timestamp: When the call was initiated
            
        Returns:
            bool: Success status
        """
        if not CommunicationEmailNotifications.should_send_email(recipient_user, 'call'):
            return False
        
        subject = f'Missed {call_type} call from {caller_name} - Makokha Medical Centre'
        
        html_body = render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #d32f2f 0%, #c62828 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">
            {% if call_type == 'video' %}📹{% else %}📞{% endif %} Missed Call
        </h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e0e0e0;">
        <p style="font-size: 16px; margin-bottom: 20px;">
            You missed a <strong>{{ call_type|e }}</strong> call from <strong>{{ caller_name|e }}</strong>
        </p>
        
        <div style="background: white; padding: 15px; margin: 20px 0; border-radius: 4px; text-align: center;">
            <p style="margin: 0; color: #666;">
                <strong>Time:</strong> {{ timestamp }}
            </p>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{ call_back_url|e }}" style="display: inline-block; background: #d32f2f; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                Call Back
            </a>
        </p>
        
        <hr style="border: none; border-top: 1px solid #e0e0e0; margin: 30px 0;">
        
        <p style="font-size: 12px; color: #999; text-align: center;">
            Makokha Medical Centre - Communication System<br>
            <a href="{{ settings_url|e }}" style="color: #d32f2f;">Manage notification preferences</a>
        </p>
    </div>
</body>
</html>
        ''',
            caller_name=caller_name,
            call_type=call_type,
            timestamp=timestamp.strftime('%B %d, %Y at %I:%M %p EAT'),
            call_back_url=f"{os.getenv('APP_URL', 'http://localhost:5000')}/communication",
            settings_url=f"{os.getenv('APP_URL', 'http://localhost:5000')}/communication/settings"
        )
        
        text_body = f'''
Missed {call_type.title()} Call

You missed a {call_type} call from {caller_name}
Time: {timestamp.strftime('%B %d, %Y at %I:%M %p EAT')}

Call back at: {os.getenv('APP_URL', 'http://localhost:5000')}/communication

---
Makokha Medical Centre - Communication System
        '''
        
        try:
            send_email(
                to_email=recipient_user.email,
                subject=subject,
                body=text_body,
                html_body=html_body
            )
            return True
        except Exception as e:
            current_app.logger.error(f'Failed to send missed call email: {e}')
            return False
    
    @staticmethod
    def send_daily_digest_email(user, unread_count, missed_calls_count):
        """
        Send daily digest of missed messages and calls
        
        Args:
            user: User object
            unread_count: Number of unread messages
            missed_calls_count: Number of missed calls
            
        Returns:
            bool: Success status
        """
        if unread_count == 0 and missed_calls_count == 0:
            return False
        
        subject = f'Daily Communication Digest - {unread_count} unread messages, {missed_calls_count} missed calls'
        
        html_body = render_template_string('''
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
</head>
<body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 600px; margin: 0 auto; padding: 20px;">
    <div style="background: linear-gradient(135deg, #2e3192 0%, #1e88e5 100%); padding: 30px; text-align: center; border-radius: 10px 10px 0 0;">
        <h1 style="color: white; margin: 0; font-size: 24px;">📊 Daily Digest</h1>
    </div>
    
    <div style="background: #f9f9f9; padding: 30px; border-radius: 0 0 10px 10px; border: 1px solid #e0e0e0;">
        <p style="font-size: 16px;">Hi <strong>{{ user_name|e }}</strong>,</p>
        
        <p>Here's your communication summary for today:</p>
        
        <div style="display: flex; gap: 20px; margin: 30px 0;">
            <div style="flex: 1; background: white; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #2e3192;">
                <h2 style="color: #2e3192; margin: 0; font-size: 32px;">{{ unread_count }}</h2>
                <p style="margin: 10px 0 0; color: #666;">Unread Messages</p>
            </div>
            
            <div style="flex: 1; background: white; padding: 20px; border-radius: 8px; text-align: center; border: 2px solid #d32f2f;">
                <h2 style="color: #d32f2f; margin: 0; font-size: 32px;">{{ missed_calls }}</h2>
                <p style="margin: 10px 0 0; color: #666;">Missed Calls</p>
            </div>
        </div>
        
        <p style="text-align: center; margin: 30px 0;">
            <a href="{{ app_url|e }}/communication" style="display: inline-block; background: #2e3192; color: white; padding: 12px 30px; text-decoration: none; border-radius: 5px; font-weight: bold;">
                View All Messages
            </a>
        </p>
    </div>
</body>
</html>
        ''',
            user_name=user.username,
            unread_count=unread_count,
            missed_calls=missed_calls_count,
            app_url=os.getenv('APP_URL', 'http://localhost:5000')
        )
        
        try:
            send_email(
                to_email=user.email,
                subject=subject,
                body=f"You have {unread_count} unread messages and {missed_calls_count} missed calls.",
                html_body=html_body
            )
            return True
        except Exception as e:
            current_app.logger.error(f'Failed to send digest email: {e}')
            return False


# Helper functions
def notify_new_message_via_email(recipient_user, sender_name, message_content):
    """Send email notification for new message"""
    app_url = os.getenv('APP_URL', 'http://localhost:5000')
    conversation_url = f'{app_url}/communication'
    
    return CommunicationEmailNotifications.send_new_message_email(
        recipient_user,
        sender_name,
        message_content,
        conversation_url
    )


def notify_missed_call_via_email(recipient_user, caller_name, call_type, timestamp):
    """Send email notification for missed call"""
    return CommunicationEmailNotifications.send_missed_call_email(
        recipient_user,
        caller_name,
        call_type,
        timestamp
    )


# Usage in app.py:
#
# from utils.communication_emails import notify_new_message_via_email, notify_missed_call_via_email
#
# # In send_message route (if user is offline):
# notify_new_message_via_email(
#     recipient_user=receiver,
#     sender_name=current_user.username,
#     message_content=content
# )
#
# # In reject_call or missed call handler:
# notify_missed_call_via_email(
#     recipient_user=receiver,
#     caller_name=current_user.username,
#     call_type=call_type,
#     timestamp=call.started_at
# )
