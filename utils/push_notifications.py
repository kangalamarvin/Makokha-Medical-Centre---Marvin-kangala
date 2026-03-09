"""
Push Notifications Module - Firebase Cloud Messaging (FCM)
Sends push notifications to mobile devices and web browsers
"""
import os
import requests
import json
from flask import current_app


class PushNotificationService:
    """Handle push notifications via Firebase Cloud Messaging"""
    
    def __init__(self):
        self.fcm_server_key = os.getenv('FCM_SERVER_KEY')
        self.fcm_sender_id = os.getenv('FCM_SENDER_ID')
        self.fcm_url = 'https://fcm.googleapis.com/fcm/send'
    
    def is_enabled(self):
        """Check if FCM is configured"""
        return bool(self.fcm_server_key and self.fcm_sender_id)
    
    def send_notification(self, device_token, title, body, data=None, priority='high'):
        """
        Send push notification to a device
        
        Args:
            device_token: FCM device registration token
            title: Notification title
            body: Notification body text
            data: Optional additional data dict
            priority: Notification priority ('high' or 'normal')
            
        Returns:
            bool: Success status
        """
        if not self.is_enabled():
            current_app.logger.warning('FCM not configured - skipping push notification')
            return False
        
        if not device_token:
            return False
        
        headers = {
            'Authorization': f'key={self.fcm_server_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'to': device_token,
            'priority': priority,
            'notification': {
                'title': title,
                'body': body,
                'icon': '/static/icons/icon-192x192.png',
                'badge': '/static/icons/badge-72x72.png',
                'click_action': '/communication',
                'sound': 'default'
            }
        }
        
        if data:
            payload['data'] = data
        
        try:
            response = requests.post(
                self.fcm_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                success = result.get('success', 0) > 0
                
                if success:
                    current_app.logger.info(f'Push notification sent successfully to {device_token[:20]}...')
                else:
                    current_app.logger.warning(f'Push notification failed: {result.get("failure")}')
                
                return success
            else:
                current_app.logger.error(f'FCM request failed: {response.status_code} - {response.text}')
                return False
                
        except Exception as e:
            current_app.logger.error(f'Push notification error: {e}')
            return False
    
    def send_notification_to_multiple(self, device_tokens, title, body, data=None):
        """
        Send notification to multiple devices
        
        Args:
            device_tokens: List of FCM device tokens
            title: Notification title
            body: Notification body text
            data: Optional additional data dict
            
        Returns:
            int: Number of successful sends
        """
        if not self.is_enabled():
            return 0
        
        if not device_tokens:
            return 0
        
        headers = {
            'Authorization': f'key={self.fcm_server_key}',
            'Content-Type': 'application/json'
        }
        
        payload = {
            'registration_ids': device_tokens,
            'priority': 'high',
            'notification': {
                'title': title,
                'body': body,
                'icon': '/static/icons/icon-192x192.png',
                'click_action': '/communication',
                'sound': 'default'
            }
        }
        
        if data:
            payload['data'] = data
        
        try:
            response = requests.post(
                self.fcm_url,
                headers=headers,
                data=json.dumps(payload),
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                success_count = result.get('success', 0)
                current_app.logger.info(f'Sent {success_count}/{len(device_tokens)} push notifications')
                return success_count
            else:
                current_app.logger.error(f'Batch FCM request failed: {response.status_code}')
                return 0
                
        except Exception as e:
            current_app.logger.error(f'Batch push notification error: {e}')
            return 0
    
    def send_message_notification(self, user, sender_name, message_preview):
        """
        Send notification for new message
        
        Args:
            user: User object to send notification to
            sender_name: Name of message sender
            message_preview: Preview of message content
            
        Returns:
            bool: Success status
        """
        # Get user's FCM device token (you'll need to add this field to User model)
        device_token = getattr(user, 'fcm_device_token', None)
        
        if not device_token:
            return False
        
        title = f'New message from {sender_name}'
        body = message_preview[:100]  # Limit preview length
        
        data = {
            'type': 'message',
            'sender_id': str(user.id),
            'timestamp': str(int(time.time()))
        }
        
        return self.send_notification(device_token, title, body, data)
    
    def send_call_notification(self, user, caller_name, call_type):
        """
        Send notification for incoming call
        
        Args:
            user: User object to send notification to
            caller_name: Name of caller
            call_type: 'voice' or 'video'
            
        Returns:
            bool: Success status
        """
        device_token = getattr(user, 'fcm_device_token', None)
        
        if not device_token:
            return False
        
        title = f'Incoming {call_type} call'
        body = f'{caller_name} is calling...'
        
        data = {
            'type': 'call',
            'call_type': call_type,
            'caller_name': caller_name,
            'timestamp': str(int(time.time()))
        }
        
        return self.send_notification(device_token, title, body, data, priority='high')


# Convenience instance
push_service = PushNotificationService()


# Helper functions
def send_new_message_notification(recipient_user, sender_name, message_content):
    """
    Quick function to send new message notification
    
    Args:
        recipient_user: User object receiving the message
        sender_name: Name of sender
        message_content: Message text
    """
    try:
        return push_service.send_message_notification(
            recipient_user,
            sender_name,
            message_content
        )
    except Exception as e:
        current_app.logger.error(f'Failed to send message notification: {e}')
        return False


def send_incoming_call_notification(recipient_user, caller_name, call_type):
    """
    Quick function to send call notification
    
    Args:
        recipient_user: User object receiving the call
        caller_name: Name of caller
        call_type: 'voice' or 'video'
    """
    try:
        return push_service.send_call_notification(
            recipient_user,
            caller_name,
            call_type
        )
    except Exception as e:
        current_app.logger.error(f'Failed to send call notification: {e}')
        return False


# Usage in app.py:
#
# from utils.push_notifications import send_new_message_notification
#
# # In send_message route:
# send_new_message_notification(
#     recipient_user=receiver,
#     sender_name=current_user.username,
#     message_content=content
# )
#
# # In initiate_call route:
# send_incoming_call_notification(
#     recipient_user=receiver,
#     caller_name=current_user.username,
#     call_type=call_type
# )


import time
