/**
 * Real-time Communication System
 * Handles messaging, voice calls, and video calls
 */

class CommunicationSystem {
    constructor() {
        this.socket = null;
        this.currentUserId = null;
        this.currentUser = null;
        this.activeConversation = null;
        this.activeChatUserId = null;
        this.peerConnection = null;
        this.localStream = null;
        this.remoteStream = null;
        this.callType = null;
        this.callId = null;
        this.isMuted = false;
        this.isVideoEnabled = true;
        this.callDurationInterval = null;
        this._callRingTimeout = null;
        this.typingTimeout = null;
        this.eatTimezone = (window.__mmcTimezone) || 'Africa/Nairobi'; // User-configurable timezone

        // Audio (ringtones) + WebRTC configuration
        this._audioContext = null;
        this._toneStopFn = null;
        this._iceServersCache = null;
        this._callRole = null; // 'caller' | 'callee'

        // Messaging UX state
        this._messageCache = new Map();
        this._usersCache = new Map();
        this._replyToMessageId = null;
        this._isChatBlocked = false;
        this._emojiPickerEl = null;
        this._messageActionsEl = null;
        this._chatSettingsEl = null;

        // Communication settings (per-user, per-device)
        this._commSettingsKey = null;
        this._commSettings = null;

        // Offline send queue (best-effort)
        this._offlineQueueKey = null;

        // Call history UI state
        this._callHistory = [];
        this._callHistoryFilter = 'all';

        // Sent-message plaintext cache (localStorage). The sender encrypts
        // messages with the RECIPIENT's public key, so they cannot decrypt
        // their own messages when reloading conversation history. We cache
        // the plaintext locally so the sender always sees their own messages.
        this._sentCacheKey = null;

        // E2E messaging state (true end-to-end): keys live client-side.
        this._e2eReady = false;
        this._e2eKeyCache = new Map(); // userId -> {kid, alg, public_jwk}
        
        this.init();

        // Listen for settings changes to update timezone
        window.addEventListener('mmc-settings-changed', (e) => {
            if (e.detail && e.detail.timezone) {
                this.eatTimezone = e.detail.timezone;
            }
        });
    }

    init() {
        // Initialize Socket.IO connection
        this.socket = io();
        
        // Get current user info from the page
        this.currentUserId = this.getCurrentUserId();
        
        // Setup Socket.IO event listeners
        this.setupSocketListeners();
        
        // Setup UI event listeners
        this.setupUIListeners();

        // Offline queue support
        this._offlineQueueKey = this.currentUserId ? `mmc_comm_offline_queue_v1_${this.currentUserId}` : 'mmc_comm_offline_queue_v1';
        this._sentCacheKey = this.currentUserId ? `mmc_sent_cache_v1_${this.currentUserId}` : 'mmc_sent_cache_v1';
        this._commSettingsKey = this.currentUserId ? `mmc_comm_settings_v1_${this.currentUserId}` : 'mmc_comm_settings_v1';
        this._commSettings = this._loadCommSettings();
        this.setupOfflineQueueHandlers();
        
        // Setup drag functionality
        this.setupDragFunctionality();
        
        // Load users list
        this.loadUsers().then(() => this.updateFloatIconBadge()).catch(() => {});
        
        // Request notification permission (best-effort; user can disable notifications in settings)
        this.requestNotificationPermission();

        // Best-effort: initialize true E2E messaging keys (won't break if unsupported)
        if (this._isZeroKnowledgeEnabled()) {
            this.initE2E().catch(() => {});
        }

        // Prepare audio context on first user gesture (autoplay policies)
        this.armAudioOnFirstGesture();
    }

    _isZeroKnowledgeEnabled() {
        try {
            const meta = document.querySelector('meta[name=\"mmc-zero-knowledge-enabled\"]');
            if (!meta) return true;
            const v = String(meta.getAttribute('content') || '').trim().toLowerCase();
            if (!v) return true;
            return !(v === '0' || v === 'false' || v === 'off' || v === 'no');
        } catch (_) {
            return true;
        }
    }

    // =============================
    // TRUE END-TO-END MESSAGING (WebCrypto)
    // =============================

    async initE2E() {
        try {
            if (!this.currentUserId) return;
            if (!window.crypto || !window.crypto.subtle) return;
            await this.ensureE2EKeypair();
            this._e2eReady = true;
        } catch (e) {
            this._e2eReady = false;
        }
    }

    _b64(bytes) {
        const bin = String.fromCharCode(...bytes);
        return btoa(bin);
    }

    _b64ToBytes(b64) {
        const bin = atob(b64);
        const bytes = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        return bytes;
    }

    async _kidFromJwk(jwk) {
        const s = JSON.stringify(jwk);
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
        const bytes = new Uint8Array(digest);
        // short-ish base64url-ish id
        return this._b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '').slice(0, 22);
    }

    async ensureE2EKeypair() {
        const privRaw = localStorage.getItem('mmc_e2e_rsa_private_jwk_v1');
        const pubRaw = localStorage.getItem('mmc_e2e_rsa_public_jwk_v1');
        const kidRaw = localStorage.getItem('mmc_e2e_rsa_kid_v1');

        if (privRaw && pubRaw && kidRaw) {
            // Best-effort sanity
            const priv = JSON.parse(privRaw);
            const pub = JSON.parse(pubRaw);

            // Best-effort: ensure server has our public key.
            fetch('/api/communication/e2e/register_key', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    kid: kidRaw,
                    alg: 'RSA-OAEP-256',
                    public_jwk: pub
                })
            }).catch(() => {});
            return;
        }

        const keyPair = await crypto.subtle.generateKey(
            {
                name: 'RSA-OAEP',
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: 'SHA-256'
            },
            true,
            ['encrypt', 'decrypt']
        );

        const publicJwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey);
        const privateJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        const kid = await this._kidFromJwk(publicJwk);

        localStorage.setItem('mmc_e2e_rsa_public_jwk_v1', JSON.stringify(publicJwk));
        localStorage.setItem('mmc_e2e_rsa_private_jwk_v1', JSON.stringify(privateJwk));
        localStorage.setItem('mmc_e2e_rsa_kid_v1', kid);

        // Register public key to server (best-effort)
        await fetch('/api/communication/e2e/register_key', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': this.getCSRFToken()
            },
            body: JSON.stringify({
                kid,
                alg: 'RSA-OAEP-256',
                public_jwk: publicJwk
            })
        }).catch(() => {});
    }

    async _getMyPrivateKey() {
        const privRaw = localStorage.getItem('mmc_e2e_rsa_private_jwk_v1');
        if (!privRaw) return null;
        const jwk = JSON.parse(privRaw);
        return crypto.subtle.importKey('jwk', jwk, { name: 'RSA-OAEP', hash: 'SHA-256' }, false, ['decrypt']);
    }

    async _getRecipientKey(userId) {
        if (!this._e2eReady) return null;
        if (this._e2eKeyCache.has(userId)) return this._e2eKeyCache.get(userId);

        const resp = await fetch(`/api/communication/e2e/public_key/${userId}`, {
            headers: { 'X-CSRFToken': this.getCSRFToken() }
        });
        if (!resp.ok) return null;
        const data = await resp.json();
        if (!data || !data.success || !data.key || !data.key.public_jwk) {
            this._e2eKeyCache.set(userId, null);
            return null;
        }
        this._e2eKeyCache.set(userId, data.key);
        return data.key;
    }

    _tryParseE2E(content) {
        if (typeof content !== 'string') return null;
        const s = content.trim();
        if (!s.startsWith('{') || !s.endsWith('}')) return null;
        try {
            const obj = JSON.parse(s);
            if (obj && obj.e2e === true) return obj;
        } catch (_) {}
        return null;
    }

    async encryptForRecipient(recipientId, plaintext) {
        if (!this._e2eReady) return plaintext;
        const keyInfo = await this._getRecipientKey(recipientId);
        if (!keyInfo || !keyInfo.public_jwk) return plaintext;

        const publicKey = await crypto.subtle.importKey(
            'jwk',
            keyInfo.public_jwk,
            { name: 'RSA-OAEP', hash: 'SHA-256' },
            false,
            ['encrypt']
        );

        const aesKey = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const pt = new TextEncoder().encode(plaintext);

        const ctBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, pt);
        const rawAes = await crypto.subtle.exportKey('raw', aesKey);
        const ekBuf = await crypto.subtle.encrypt({ name: 'RSA-OAEP' }, publicKey, rawAes);

        const payload = {
            v: 1,
            e2e: true,
            alg: 'RSA-OAEP-256+A256GCM',
            kid: keyInfo.kid,
            iv: this._b64(new Uint8Array(iv)),
            ek: this._b64(new Uint8Array(ekBuf)),
            ct: this._b64(new Uint8Array(ctBuf))
        };

        return JSON.stringify(payload);
    }

    async decryptIfNeeded(content) {
        const obj = this._tryParseE2E(content);
        if (!obj) return content;

        const privKey = await this._getMyPrivateKey();
        if (!privKey) return '[Encrypted message]';

        try {
            const iv = this._b64ToBytes(obj.iv);
            const ek = this._b64ToBytes(obj.ek);
            const ct = this._b64ToBytes(obj.ct);

            const rawAes = await crypto.subtle.decrypt({ name: 'RSA-OAEP' }, privKey, ek);
            const aesKey = await crypto.subtle.importKey('raw', rawAes, { name: 'AES-GCM' }, false, ['decrypt']);
            const ptBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
            return new TextDecoder().decode(ptBuf);
        } catch (e) {
            return '[Encrypted message]';
        }
    }

    async prepareMessageForDisplay(message) {
        if (!message) return message;
        const display = { ...message };

        // For sender's own messages: prefer the local plaintext cache
        // because the ciphertext was encrypted to the RECIPIENT's key
        // and the sender cannot decrypt it.
        if (display.sender_id === this.currentUserId && !display._raw_content) {
            const cached = this._getSentPlaintext(display.message_id);
            if (cached) display._raw_content = cached;
        }

        if (typeof display.content === 'string') {
            // Preserve whether the original payload was E2E-encrypted so notifications can
            // avoid leaking plaintext even after decryption.
            display._was_e2e = !!this._tryParseE2E(display.content);
            display.content = await this.decryptIfNeeded(display.content);
        } else {
            display._was_e2e = false;
        }

        if (display.replied_to && typeof display.replied_to.content === 'string') {
            display.replied_to = { ...display.replied_to };
            display.replied_to.content = await this.decryptIfNeeded(display.replied_to.content);
        }

        return display;
    }

    armAudioOnFirstGesture() {
        const enable = () => {
            try {
                if (!this._audioContext) {
                    const AudioCtx = window.AudioContext || window.webkitAudioContext;
                    if (AudioCtx) this._audioContext = new AudioCtx();
                }
                if (this._audioContext && this._audioContext.state === 'suspended') {
                    this._audioContext.resume().catch(() => {});
                }
            } catch (_) {
                // no-op
            }
            document.removeEventListener('click', enable, true);
            document.removeEventListener('touchstart', enable, true);
            document.removeEventListener('keydown', enable, true);
        };

        document.addEventListener('click', enable, true);
        document.addEventListener('touchstart', enable, true);
        document.addEventListener('keydown', enable, true);
    }

    getCurrentUserId() {
        // Try to get user ID from data attribute or meta tag
        const userIdElement = document.querySelector('[data-user-id]');
        if (userIdElement) {
            return parseInt(userIdElement.getAttribute('data-user-id'));
        }
        
        // Fallback: try to get from meta tag
        const metaUserId = document.querySelector('meta[name="user-id"]');
        if (metaUserId) {
            return parseInt(metaUserId.content);
        }
        
        return null;
    }

    setupSocketListeners() {
        // Connection events
        this.socket.on('connect', () => {
            console.log('Connected to Socket.IO server');
            if (this.currentUserId) {
                this.socket.emit('user_connected', { user_id: this.currentUserId });
            }

            // Refresh unread badge on (re)connect
            this.updateFloatIconBadge().catch(() => {});

            // Best-effort: flush queued messages after reconnect
            this.flushOfflineQueue().catch(() => {});
        });

        this.socket.on('disconnect', () => {
            console.log('Disconnected from Socket.IO server');
        });

        // Message events
        this.socket.on('new_message', (data) => {
            this.handleNewMessage(data);
        });

        this.socket.on('message_delivered', (data) => {
            this.handleMessageDelivered(data);
        });

        this.socket.on('message_read', (data) => {
            this.handleMessageRead(data);
        });

        this.socket.on('typing_status', (data) => {
            this.handleTypingStatus(data);
        });

        // User status events
        this.socket.on('user_status_update', (data) => {
            this.handleUserStatusUpdate(data);
        });

        // Call events
        this.socket.on('incoming_call', (data) => {
            this.handleIncomingCall(data);
        });

        this.socket.on('call_accepted', (data) => {
            this.handleCallAccepted(data);
        });

        this.socket.on('call_rejected', (data) => {
            this.handleCallRejected(data);
        });

        this.socket.on('call_ended', (data) => {
            this.handleCallEnded(data);
        });

        this.socket.on('call_failed', (data) => {
            this.handleCallFailed(data);
        });

        // WebRTC signaling events
        this.socket.on('webrtc_offer', (data) => {
            this.handleWebRTCOffer(data);
        });

        this.socket.on('webrtc_answer', (data) => {
            this.handleWebRTCAnswer(data);
        });

        this.socket.on('webrtc_ice_candidate', (data) => {
            this.handleWebRTCIceCandidate(data);
        });
    }

    setupOfflineQueueHandlers() {
        try {
            window.addEventListener('online', () => {
                this.flushOfflineQueue().catch(() => {});
            });
        } catch (_) {
            // no-op
        }
    }

    _readOfflineQueue() {
        try {
            const raw = localStorage.getItem(this._offlineQueueKey || 'mmc_comm_offline_queue_v1');
            const parsed = raw ? JSON.parse(raw) : [];
            return Array.isArray(parsed) ? parsed : [];
        } catch (_) {
            return [];
        }
    }

    _writeOfflineQueue(queue) {
        try {
            localStorage.setItem(this._offlineQueueKey || 'mmc_comm_offline_queue_v1', JSON.stringify(queue || []));
        } catch (_) {
            // no-op
        }
    }

    _enqueueOfflineMessage(entry) {
        const q = this._readOfflineQueue();
        q.push(entry);
        this._writeOfflineQueue(q);
    }

    _removeOfflineMessageByTempId(tempId) {
        const q = this._readOfflineQueue();
        const next = q.filter(x => String(x.temp_id) !== String(tempId));
        this._writeOfflineQueue(next);
    }

    _removePendingMessageFromUI(tempId) {
        try {
            const el = document.querySelector(`[data-message-id="tmp_${tempId}"]`);
            if (el && el.parentNode) el.parentNode.removeChild(el);
        } catch (_) {
            // no-op
        }
    }

    async flushOfflineQueue() {
        if (!this.currentUserId) return;
        if (!navigator.onLine) return;

        const q = this._readOfflineQueue();
        if (!q.length) return;

        // Send in order
        for (const entry of [...q]) {
            if (!entry || !entry.receiver_id || !entry.content_to_send) continue;
            try {
                const response = await fetch('/api/communication/send_message', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'X-CSRFToken': this.getCSRFToken()
                    },
                    body: JSON.stringify({
                        receiver_id: entry.receiver_id,
                        content: entry.content_to_send,
                        reply_to_message_id: entry.reply_to_message_id || null
                    })
                });

                if (!response.ok) {
                    // Keep queued
                    continue;
                }

                const data = await response.json().catch(() => null);
                this._removeOfflineMessageByTempId(entry.temp_id);

                // Update UI if we're still in that chat
                if (this.activeChatUserId && Number(this.activeChatUserId) === Number(entry.receiver_id)) {
                    this._removePendingMessageFromUI(entry.temp_id);
                    if (data && data.message) {
                        // Cache plaintext from the queued entry
                        if (data.message.sender_id === this.currentUserId && entry.content_to_send) {
                            this._cacheSentPlaintext(data.message.message_id, entry.content_to_send);
                        }
                        const displayMsg = await this.prepareMessageForDisplay(data.message);
                        this.appendMessage(displayMsg);
                    }
                }

                // Emit socket event for real-time delivery
                if (data && data.message && this.socket && this.socket.connected) {
                    this.socket.emit('send_message', {
                        message: data.message,
                        receiver_id: entry.receiver_id
                    });
                }
            } catch (_) {
                // Keep queued
            }
        }
    }

    /* ---- Sent-message plaintext cache ---- */
    _cacheSentPlaintext(messageId, plaintext) {
        if (!messageId || !plaintext) return;
        try {
            const key = this._sentCacheKey;
            const raw = localStorage.getItem(key);
            const cache = raw ? JSON.parse(raw) : {};
            cache[String(messageId)] = plaintext;
            // Keep the cache bounded (last 500 messages)
            const keys = Object.keys(cache);
            if (keys.length > 500) {
                const toRemove = keys.slice(0, keys.length - 500);
                toRemove.forEach(k => delete cache[k]);
            }
            localStorage.setItem(key, JSON.stringify(cache));
        } catch (_) {}
    }

    _getSentPlaintext(messageId) {
        if (!messageId) return null;
        try {
            const raw = localStorage.getItem(this._sentCacheKey);
            if (!raw) return null;
            const cache = JSON.parse(raw);
            return cache[String(messageId)] || null;
        } catch (_) { return null; }
    }

    /* ---- Communication settings (localStorage) ---- */
    _defaultCommSettings() {
        return {
            notifications_enabled: true,
            sounds_enabled: true,
            message_tone: 'chime',      // chime | pop | beep | none
            call_ringtone: 'classic'    // classic | fast | slow | none
        };
    }

    _normalizeCommSettings(raw) {
        const defaults = this._defaultCommSettings();
        const s = { ...defaults, ...(raw && typeof raw === 'object' ? raw : {}) };

        s.notifications_enabled = !!s.notifications_enabled;
        s.sounds_enabled = !!s.sounds_enabled;

        const allowedMsgTones = new Set(['chime', 'pop', 'beep', 'none']);
        const allowedCallTones = new Set(['classic', 'fast', 'slow', 'none']);
        if (!allowedMsgTones.has(String(s.message_tone))) s.message_tone = defaults.message_tone;
        if (!allowedCallTones.has(String(s.call_ringtone))) s.call_ringtone = defaults.call_ringtone;

        return s;
    }

    _loadCommSettings() {
        const defaults = this._defaultCommSettings();
        try {
            const key = this._commSettingsKey || 'mmc_comm_settings_v1';
            const raw = localStorage.getItem(key);
            if (!raw) return { ...defaults };
            const parsed = JSON.parse(raw);
            return this._normalizeCommSettings(parsed);
        } catch (_) {
            return { ...defaults };
        }
    }

    getCommSettings() {
        if (!this._commSettings) this._commSettings = this._loadCommSettings();
        return this._commSettings;
    }

    setCommSettings(patch) {
        const current = this.getCommSettings();
        const next = this._normalizeCommSettings({ ...current, ...(patch || {}) });
        this._commSettings = next;
        try {
            const key = this._commSettingsKey || 'mmc_comm_settings_v1';
            localStorage.setItem(key, JSON.stringify(next));
        } catch (_) {
            // no-op
        }
        return next;
    }

    setupUIListeners() {
        // Float icon click
        const floatIcon = document.getElementById('communication-float-icon');
        if (floatIcon) {
            floatIcon.addEventListener('click', () => this.toggleCommunicationModal());
        }

        // Float icon settings (gear)
        const floatSettingsBtn = document.getElementById('communication-float-settings-btn');
        if (floatSettingsBtn) {
            floatSettingsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.openCommSettings();
            });
        }

        // Close and minimize buttons
        const closeBtn = document.getElementById('close-chat');
        const minimizeBtn = document.getElementById('minimize-chat');
        
        if (closeBtn) {
            closeBtn.addEventListener('click', () => this.closeCommunicationModal());
        }
        
        if (minimizeBtn) {
            minimizeBtn.addEventListener('click', () => this.minimizeCommunicationModal());
        }

        // Search users
        const searchInput = document.getElementById('search-users');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => this.searchUsers(e.target.value));
        }

        // Send message
        const sendBtn = document.getElementById('send-message-btn');
        const messageInput = document.getElementById('message-input');
        
        if (sendBtn) {
            sendBtn.addEventListener('click', () => this.sendMessage());
        }
        
        if (messageInput) {
            // Textarea UX:
            // - Enter sends
            // - Shift+Enter inserts newline
            messageInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    this.sendMessage();
                }
            });
            
            messageInput.addEventListener('input', () => {
                this.handleTyping();
                // Auto-grow
                try {
                    messageInput.style.height = 'auto';
                    messageInput.style.height = Math.min(messageInput.scrollHeight, 140) + 'px';
                } catch (_) {
                    // no-op
                }
            });
        }

        // Call buttons
        const voiceCallBtn = document.getElementById('voice-call-btn');
        const videoCallBtn = document.getElementById('video-call-btn');
        
        if (voiceCallBtn) {
            voiceCallBtn.addEventListener('click', () => this.initiateCall('voice'));
        }
        
        if (videoCallBtn) {
            videoCallBtn.addEventListener('click', () => this.initiateCall('video'));
        }

        // Call control buttons
        const acceptCallBtn = document.getElementById('accept-call-btn');
        const rejectCallBtn = document.getElementById('reject-call-btn');
        const endCallBtn = document.getElementById('end-call-btn');
        const muteBtn = document.getElementById('mute-btn');
        const toggleVideoBtn = document.getElementById('toggle-video-btn');
        
        if (acceptCallBtn) {
            acceptCallBtn.addEventListener('click', () => this.acceptCall());
        }
        
        if (rejectCallBtn) {
            rejectCallBtn.addEventListener('click', () => this.rejectCall());
        }
        
        if (endCallBtn) {
            endCallBtn.addEventListener('click', () => this.endCall());
        }

        const cancelCallBtn = document.getElementById('cancel-call-btn');
        if (cancelCallBtn) {
            cancelCallBtn.addEventListener('click', () => this.endCall());
        }
        
        if (muteBtn) {
            muteBtn.addEventListener('click', () => this.toggleMute());
        }
        
        if (toggleVideoBtn) {
            toggleVideoBtn.addEventListener('click', () => this.toggleVideo());
        }

        // Call history UI
        const openCallHistoryBtn = document.getElementById('open-call-history');
        if (openCallHistoryBtn) {
            openCallHistoryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleCallHistory(true);
            });
        }

        // Communication settings UI
        const openCommSettingsBtn = document.getElementById('open-comm-settings');
        if (openCommSettingsBtn) {
            openCommSettingsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleCommSettings(true);
            });
        }

        const closeCommSettingsBtn = document.getElementById('close-comm-settings');
        if (closeCommSettingsBtn) {
            closeCommSettingsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleCommSettings(false);
            });
        }

        this.setupCommSettingsControls();

        const closeCallHistoryBtn = document.getElementById('close-call-history');
        if (closeCallHistoryBtn) {
            closeCallHistoryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleCallHistory(false);
            });
        }

        const refreshCallHistoryBtn = document.getElementById('refresh-call-history');
        if (refreshCallHistoryBtn) {
            refreshCallHistoryBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.loadCallHistory().catch(() => {});
            });
        }

        document.querySelectorAll('[data-call-filter]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                e.preventDefault();
                const filter = btn.getAttribute('data-call-filter') || 'all';
                this.setCallHistoryFilter(filter);
            });
        });

        const emojiBtn = document.getElementById('emoji-btn');
        if (emojiBtn) {
            emojiBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.toggleEmojiPicker(emojiBtn);
            });
        }

        const replyCancelBtn = document.getElementById('reply-cancel-btn');
        if (replyCancelBtn) {
            replyCancelBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.clearReply();
            });
        }

        const chatSearchBtn = document.getElementById('chat-search-btn');
        const chatSearchClose = document.getElementById('chat-search-close');
        if (chatSearchBtn) {
            chatSearchBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleChatSearch(true);
            });
        }
        if (chatSearchClose) {
            chatSearchClose.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleChatSearch(false);
            });
        }

        const chatSearchInput = document.getElementById('chat-search-input');
        if (chatSearchInput) {
            let searchTimer = null;
            chatSearchInput.addEventListener('input', () => {
                if (!this.activeChatUserId) return;
                if (searchTimer) clearTimeout(searchTimer);
                searchTimer = setTimeout(() => this.searchMessages(chatSearchInput.value), 300);
            });
        }

        const chatSettingsBtn = document.getElementById('chat-settings-btn');
        if (chatSettingsBtn) {
            chatSettingsBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.toggleChatSettings(chatSettingsBtn);
            });
        }

        // Mobile responsive handlers
        this.setupMobileHandlers();
    }

    setupMobileHandlers() {
        // Add back button functionality for mobile
        const backToUsersBtn = document.getElementById('back-to-users');
        if (backToUsersBtn) {
            backToUsersBtn.addEventListener('click', (e) => {
                e.preventDefault();
                e.stopPropagation();
                this.showUsersList();
            });
        }

        const chatHeader = document.querySelector('.chat-header');
        if (chatHeader && window.innerWidth <= 767) {
            chatHeader.style.cursor = 'pointer';
            chatHeader.addEventListener('click', (e) => {
                if (e.target.closest('.chat-actions')) return;
                if (e.target.closest('#back-to-users')) return;
                this.showUsersList();
            });
        }

        // Handle window resize
        window.addEventListener('resize', () => {
            this.handleResize();
        });

        // Handle orientation change
        window.addEventListener('orientationchange', () => {
            setTimeout(() => this.handleResize(), 100);
        });
    }

    handleResize() {
        const isMobile = window.innerWidth <= 767;
        const chatHeader = document.querySelector('.chat-header');
        
        if (isMobile && chatHeader) {
            chatHeader.style.cursor = 'pointer';
        } else if (chatHeader) {
            chatHeader.style.cursor = 'default';
        }
    }

    showUsersList() {
        const usersSidebar = document.getElementById('users-sidebar');
        const chatArea = document.getElementById('chat-area');
        
        if (usersSidebar && chatArea) {
            usersSidebar.classList.remove('hidden');
            chatArea.style.display = 'none';
        }
    }

    hideUsersList() {
        const usersSidebar = document.getElementById('users-sidebar');
        const chatArea = document.getElementById('chat-area');
        
        if (window.innerWidth <= 767) {
            if (usersSidebar) {
                usersSidebar.classList.add('hidden');
            }
            if (chatArea) {
                chatArea.style.display = 'flex';
            }
        }
    }

    toggleCommunicationModal() {
        const modal = document.getElementById('communication-modal');
        if (modal) {
            if (modal.style.display === 'none') {
                modal.style.display = 'flex';
            } else {
                modal.style.display = 'none';
            }
        }
    }

    closeCommunicationModal() {
        const modal = document.getElementById('communication-modal');
        if (modal) {
            modal.style.display = 'none';
        }

        // Ensure overlays don't remain open between modal toggles
        try {
            const callPanel = document.getElementById('call-history-panel');
            if (callPanel) callPanel.style.display = 'none';
            const settingsPanel = document.getElementById('comm-settings-panel');
            if (settingsPanel) settingsPanel.style.display = 'none';
        } catch (_) {
            // no-op
        }
    }

    minimizeCommunicationModal() {
        const modal = document.getElementById('communication-modal');
        if (modal) {
            modal.classList.toggle('minimized');
        }
    }

    async loadUsers() {
        try {
            const response = await fetch('/api/communication/users', {
                headers: {
                    'X-CSRFToken': this.getCSRFToken()
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to load users');
            }
            
            const data = await response.json();
            this.displayUsers(data.users);
        } catch (error) {
            console.error('Error loading users:', error);
            this.showError('Failed to load users');
        }
    }

    displayUsers(users) {
        const usersList = document.getElementById('users-list');
        if (!usersList) return;
        
        usersList.innerHTML = '';
        this._usersCache.clear();
        
        if (users.length === 0) {
            usersList.innerHTML = '<div class="text-center text-muted py-4"><p>No users found</p></div>';
            return;
        }

        try {
            (users || []).forEach(u => {
                if (u && typeof u.id !== 'undefined') {
                    this._usersCache.set(Number(u.id), u);
                }
            });
        } catch (_) {
            // no-op
        }
        
        const sortedUsers = [...users].sort((a, b) => {
            const ap = a.is_pinned ? 1 : 0;
            const bp = b.is_pinned ? 1 : 0;
            if (ap !== bp) return bp - ap;
            const au = a.unread_count || 0;
            const bu = b.unread_count || 0;
            if (au !== bu) return bu - au;
            return String(a.username || '').localeCompare(String(b.username || ''));
        });

        sortedUsers.forEach(user => {
            const userItem = document.createElement('div');
            userItem.className = 'user-item';
            userItem.dataset.userId = user.id;
            
            const onlineBadge = user.is_online ? '<span class="online-badge"></span>' : '';
            const picUrl = this._profilePicUrl(user.profile_picture);
            const avatarInner = picUrl
                ? `<img src="${this.escapeHtml(picUrl)}" alt="">`
                : '<i class="bi bi-person-circle"></i>';
            
            const pinBadge = user.is_pinned ? '<span class="badge bg-warning text-dark ms-2">Pinned</span>' : '';
            const archivedBadge = user.is_archived ? '<span class="badge bg-secondary ms-2">Archived</span>' : '';
            const blockedBadge = (user.blocked_by_me || user.blocked_me) ? '<span class="badge bg-danger ms-2">Blocked</span>' : '';

            userItem.innerHTML = `
                <div class="user-avatar">
                    ${avatarInner}
                    ${onlineBadge}
                </div>
                <div class="user-info">
                    <div class="user-name">${this.escapeHtml(user.username)}${pinBadge}${archivedBadge}${blockedBadge}</div>
                    <div class="user-role">${this.escapeHtml(user.role)}</div>
                </div>
                ${user.unread_count > 0 ? `<span class="unread-badge">${user.unread_count}</span>` : ''}
            `;
            
            userItem.addEventListener('click', () => this.openChat(user));
            usersList.appendChild(userItem);
        });
    }

    searchUsers(query) {
        const userItems = document.querySelectorAll('.user-item');
        const lowerQuery = query.toLowerCase();
        
        userItems.forEach(item => {
            const username = item.querySelector('.user-name').textContent.toLowerCase();
            const role = item.querySelector('.user-role').textContent.toLowerCase();
            
            if (username.includes(lowerQuery) || role.includes(lowerQuery)) {
                item.style.display = 'flex';
            } else {
                item.style.display = 'none';
            }
        });
    }

    async openChat(user, options) {
        const opts = options || {};
        const preloadConversation = opts.preloadConversation !== false;
        this.activeChatUserId = user.id;
        this.currentUser = user;
        this._isChatBlocked = !!(user.blocked_by_me || user.blocked_me);
        this.clearReply();
        
        // Hide users list on mobile
        this.hideUsersList();
        
        // Update UI
        const noChatSelected = document.querySelector('.no-chat-selected');
        const activeChat = document.getElementById('active-chat');
        
        if (noChatSelected) noChatSelected.style.display = 'none';
        if (activeChat) activeChat.style.display = 'flex';
        
        // Update chat header
        document.getElementById('chat-user-name').textContent = user.username;
        const statusElement = document.getElementById('chat-user-status');
        if (statusElement) {
            if (user.is_online) {
                statusElement.textContent = 'online';
                statusElement.className = 'text-success';
            } else if (user.last_seen) {
                statusElement.textContent = `last seen ${this.formatDateTimeEAT(user.last_seen)}`;
                statusElement.className = 'text-muted';
            } else {
                statusElement.textContent = 'offline';
                statusElement.className = 'text-muted';
            }
        }

        const avatarEl = document.getElementById('chat-user-avatar');
        if (avatarEl) {
            const picUrl = this._profilePicUrl(user.profile_picture);
            avatarEl.innerHTML = picUrl
                ? `<img src="${this.escapeHtml(picUrl)}" alt="">`
                : '<i class="bi bi-person-circle"></i>';
        }

        this.applyChatBlockedUI();
        
        // Mark user item as active
        document.querySelectorAll('.user-item').forEach(item => {
            item.classList.remove('active');
        });
        document.querySelector(`.user-item[data-user-id="${user.id}"]`)?.classList.add('active');
        
        // Load conversation (optional background preload for faster actions like calling back)
        if (preloadConversation) {
            await this.loadConversation(user.id);
        } else {
            this.loadConversation(user.id).catch(() => {});
        }
        
        // Join conversation room
        this.socket.emit('join_conversation', {
            user_id: this.currentUserId,
            other_user_id: user.id
        });
    }

    // =============================
    // Communication Settings UI
    // =============================

    openCommSettings() {
        // Ensure the modal is visible, then show settings overlay.
        try {
            const modal = document.getElementById('communication-modal');
            if (modal) {
                modal.style.display = 'flex';
                modal.classList.remove('minimized');
            }
        } catch (_) {
            // no-op
        }
        this.toggleCommSettings(true);
    }

    toggleCommSettings(show) {
        const panel = document.getElementById('comm-settings-panel');
        if (!panel) return;

        if (show) {
            // Close call log if open (avoid stacked overlays)
            try {
                const callPanel = document.getElementById('call-history-panel');
                if (callPanel) callPanel.style.display = 'none';
            } catch (_) {}

            panel.style.display = 'flex';
            this._syncCommSettingsForm();
        } else {
            panel.style.display = 'none';
            // If a ringtone preview is playing, stop it.
            this.stopAllTones();
        }
    }

    _syncCommSettingsForm() {
        const s = this.getCommSettings();
        const notif = document.getElementById('comm-enable-notifications');
        const sounds = document.getElementById('comm-enable-sounds');
        const msgTone = document.getElementById('comm-message-tone');
        const callTone = document.getElementById('comm-call-ringtone');

        if (notif) notif.checked = !!s.notifications_enabled;
        if (sounds) sounds.checked = !!s.sounds_enabled;
        if (msgTone) msgTone.value = String(s.message_tone || 'chime');
        if (callTone) callTone.value = String(s.call_ringtone || 'classic');
    }

    setupCommSettingsControls() {
        const panel = document.getElementById('comm-settings-panel');
        if (!panel) return;
        if (panel.dataset.bound === '1') return;
        panel.dataset.bound = '1';

        const notif = document.getElementById('comm-enable-notifications');
        const sounds = document.getElementById('comm-enable-sounds');
        const msgTone = document.getElementById('comm-message-tone');
        const callTone = document.getElementById('comm-call-ringtone');
        const testMsg = document.getElementById('comm-test-message-tone');
        const testCall = document.getElementById('comm-test-call-ringtone');
        const reset = document.getElementById('comm-reset-settings');

        // Initial sync
        this._syncCommSettingsForm();

        if (notif) {
            notif.addEventListener('change', () => {
                this.setCommSettings({ notifications_enabled: !!notif.checked });
            });
        }

        if (sounds) {
            sounds.addEventListener('change', () => {
                this.setCommSettings({ sounds_enabled: !!sounds.checked });
            });
        }

        if (msgTone) {
            msgTone.addEventListener('change', () => {
                this.setCommSettings({ message_tone: String(msgTone.value || 'chime') });
            });
        }

        if (callTone) {
            callTone.addEventListener('change', () => {
                this.setCommSettings({ call_ringtone: String(callTone.value || 'classic') });
            });
        }

        if (testMsg) {
            testMsg.addEventListener('click', (e) => {
                e.preventDefault();
                this.playMessageTone(null, { force: true, toneId: msgTone ? msgTone.value : null });
            });
        }

        if (testCall) {
            testCall.addEventListener('click', (e) => {
                e.preventDefault();
                this.playRingtone({ force: true, ringtoneId: callTone ? callTone.value : null });
                setTimeout(() => this.stopAllTones(), 2200);
            });
        }

        if (reset) {
            reset.addEventListener('click', (e) => {
                e.preventDefault();
                this.setCommSettings(this._defaultCommSettings());
                this._syncCommSettingsForm();
            });
        }
    }

    // =============================
    // Call History UI
    // =============================

    toggleCallHistory(show) {
        const panel = document.getElementById('call-history-panel');
        if (!panel) return;
        if (show) {
            // Close settings if open (avoid stacked overlays)
            try {
                const settingsPanel = document.getElementById('comm-settings-panel');
                if (settingsPanel) settingsPanel.style.display = 'none';
            } catch (_) {}
            panel.style.display = 'flex';
            this.loadCallHistory().catch(() => {});
        } else {
            panel.style.display = 'none';
        }
    }

    setCallHistoryFilter(filter) {
        const normalized = String(filter || 'all').toLowerCase();
        this._callHistoryFilter = normalized;

        document.querySelectorAll('[data-call-filter]').forEach(btn => {
            const f = String(btn.getAttribute('data-call-filter') || '').toLowerCase();
            btn.classList.toggle('active', f === normalized);
        });

        this.renderCallHistory();
    }

    _profilePicUrl(relPath) {
        const raw = String(relPath || '').replace(/\\/g, '/').trim();
        if (!raw) return '';
        const normalized = raw.startsWith('uploads/') ? raw.slice('uploads/'.length) : raw;
        if (!normalized.startsWith('profile_pictures/')) return '';
        const safePath = normalized.split('/').map(encodeURIComponent).join('/');
        return `/uploads/${safePath}`;
    }

    _badge(text, cls) {
        const b = document.createElement('span');
        b.className = `badge ${cls}`;
        b.textContent = text;
        return b;
    }

    _callStatusLabel(call) {
        const status = String(call?.call_status || '').toLowerCase();
        const direction = String(call?.direction || '').toLowerCase();

        if (status === 'failed') return { text: 'Failed', cls: 'bg-danger' };
        if (status === 'rejected') return { text: 'Declined', cls: 'bg-warning text-dark' };
        if (status === 'missed') return { text: direction === 'outgoing' ? 'No answer' : 'Missed', cls: 'bg-danger' };
        if (status === 'canceled') return { text: direction === 'outgoing' ? 'Canceled' : 'Missed', cls: 'bg-secondary' };
        if (status === 'answered') return { text: direction === 'outgoing' ? 'Answered' : 'Received', cls: 'bg-success' };
        if (status === 'ended') return { text: 'Ended', cls: 'bg-success' };
        if (status === 'ringing') return { text: 'Ringing', cls: 'bg-info text-dark' };
        if (status === 'initiated') return { text: 'Calling', cls: 'bg-info text-dark' };
        return { text: status ? status : 'Unknown', cls: 'bg-secondary' };
    }

    async loadCallHistory() {
        const meta = document.getElementById('call-history-meta');
        const list = document.getElementById('call-history-list');
        if (meta) meta.textContent = 'Loading...';
        if (list) {
            list.innerHTML = '<div class="text-center text-muted py-4"><div class="spinner-border spinner-border-sm" role="status"><span class="visually-hidden">Loading...</span></div><p class="mt-2 small">Loading call history...</p></div>';
        }

        try {
            const response = await fetch('/api/communication/calls/history', {
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error((data && data.error) ? data.error : 'Failed to load call history');
            }

            this._callHistory = Array.isArray(data.calls) ? data.calls : [];
            if (meta) meta.textContent = `${this._callHistory.length} calls`;
            this.renderCallHistory();
        } catch (e) {
            console.error('Error loading call history:', e);
            if (meta) meta.textContent = 'Failed to load';
            if (list) list.innerHTML = `<div class="text-center text-danger py-4"><p class="small mb-0">${this.escapeHtml(e.message || 'Failed to load call history')}</p></div>`;
        }
    }

    renderCallHistory() {
        const list = document.getElementById('call-history-list');
        if (!list) return;

        const filter = String(this._callHistoryFilter || 'all').toLowerCase();
        let calls = Array.isArray(this._callHistory) ? [...this._callHistory] : [];

        if (filter === 'missed') {
            calls = calls.filter(c => {
                const st = String(c?.call_status || '').toLowerCase();
                const dir = String(c?.direction || '').toLowerCase();
                if (st === 'missed') return true;
                // Incoming canceled = effectively missed for receiver
                if (st === 'canceled' && dir === 'incoming') return true;
                return false;
            });
        } else if (filter === 'incoming' || filter === 'outgoing') {
            calls = calls.filter(c => String(c?.direction || '').toLowerCase() === filter);
        } else if (filter === 'failed') {
            calls = calls.filter(c => String(c?.call_status || '').toLowerCase() === 'failed');
        }

        list.textContent = '';
        if (!calls.length) {
            list.innerHTML = '<div class="text-center text-muted py-4"><p class="small mb-0">No calls found.</p></div>';
            return;
        }

        const frag = document.createDocumentFragment();

        calls.forEach(call => {
            const item = document.createElement('div');
            item.className = 'call-item';
            item.dataset.callId = String(call.call_id || '');

            const avatar = document.createElement('div');
            avatar.className = 'call-avatar';
            const picUrl = this._profilePicUrl(call.other_user_profile_picture);
            if (picUrl) {
                const img = document.createElement('img');
                img.src = picUrl;
                img.alt = '';
                avatar.appendChild(img);
            } else {
                const icon = document.createElement('i');
                icon.className = 'bi bi-person-circle';
                icon.style.fontSize = '24px';
                icon.style.color = '#6c757d';
                avatar.appendChild(icon);
            }

            const details = document.createElement('div');
            details.className = 'call-details';

            const top = document.createElement('div');
            top.className = 'call-top';

            const name = document.createElement('div');
            name.className = 'call-name';
            name.textContent = call.other_user_name || `User ${call.other_user_id || ''}`;

            const time = document.createElement('div');
            time.className = 'call-time';
            try {
                time.textContent = call.started_at ? this.formatDateTimeEAT(call.started_at) : '';
            } catch (_) {
                time.textContent = '';
            }

            top.appendChild(name);
            top.appendChild(time);

            const badges = document.createElement('div');
            badges.className = 'call-badges';

            const direction = String(call.direction || '').toLowerCase();
            if (direction) {
                badges.appendChild(this._badge(direction === 'outgoing' ? 'Outgoing' : 'Incoming', direction === 'outgoing' ? 'bg-primary' : 'bg-secondary'));
            }

            const type = String(call.call_type || '').toLowerCase();
            if (type) {
                badges.appendChild(this._badge(type === 'video' ? 'Video' : 'Voice', type === 'video' ? 'bg-info text-dark' : 'bg-light text-dark'));
            }

            const status = this._callStatusLabel(call);
            badges.appendChild(this._badge(status.text, status.cls));

            details.appendChild(top);
            details.appendChild(badges);

            const actions = document.createElement('div');
            actions.className = 'call-actions';

            const voiceBtn = document.createElement('button');
            voiceBtn.type = 'button';
            voiceBtn.className = 'btn btn-sm btn-outline-primary';
            voiceBtn.title = 'Call (voice)';
            voiceBtn.innerHTML = '<i class="bi bi-telephone-fill"></i>';
            voiceBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                await this.callBackFromHistory(call, 'voice');
            });

            const videoBtn = document.createElement('button');
            videoBtn.type = 'button';
            videoBtn.className = 'btn btn-sm btn-outline-primary';
            videoBtn.title = 'Call (video)';
            videoBtn.innerHTML = '<i class="bi bi-camera-video-fill"></i>';
            videoBtn.addEventListener('click', async (e) => {
                e.preventDefault();
                e.stopPropagation();
                await this.callBackFromHistory(call, 'video');
            });

            actions.appendChild(voiceBtn);
            actions.appendChild(videoBtn);

            item.appendChild(avatar);
            item.appendChild(details);
            item.appendChild(actions);

            frag.appendChild(item);
        });

        list.appendChild(frag);
    }

    async callBackFromHistory(call, type) {
        const otherUserId = call && call.other_user_id ? Number(call.other_user_id) : null;
        if (!otherUserId) return;

        try {
            const cached = this._usersCache.get(otherUserId);
            if (cached) {
                await this.openChat(cached, { preloadConversation: false });
            } else {
                await this.loadUsers();
                const cached2 = this._usersCache.get(otherUserId);
                if (cached2) {
                    await this.openChat(cached2, { preloadConversation: false });
                } else {
                    this.activeChatUserId = otherUserId;
                    this.currentUser = { id: otherUserId, username: call.other_user_name || 'User', is_online: false };
                }
            }

            this.toggleCallHistory(false);
            await this.initiateCall(type);
        } catch (e) {
            console.error('Error calling back from history:', e);
            this.showError('Failed to start call');
        }
    }

    async loadConversation(otherUserId) {
        try {
            const response = await fetch(`/api/communication/conversation/${otherUserId}`, {
                headers: {
                    'X-CSRFToken': this.getCSRFToken()
                }
            });
            
            if (!response.ok) {
                throw new Error('Failed to load conversation');
            }
            
            const data = await response.json();
            this.activeConversation = data.conversation;
            await this.displayMessages(data.messages);
            
            // Mark messages as read
            this.markMessagesAsRead(otherUserId);
        } catch (error) {
            console.error('Error loading conversation:', error);
        }
    }

    async displayMessages(messages) {
        const messagesContainer = document.getElementById('messages-container');
        if (!messagesContainer) return;
        
        messagesContainer.innerHTML = '';
        
        if (messages.length === 0) {
            messagesContainer.innerHTML = '<div class="text-center text-muted py-4"><p class="small">No messages yet. Start the conversation!</p></div>';
            return;
        }
        
        for (const message of messages) {
            const displayMsg = await this.prepareMessageForDisplay(message);
            this.appendMessage(displayMsg, false);
        }
        
        // Scroll to bottom
        messagesContainer.scrollTop = messagesContainer.scrollHeight;
    }

    appendMessage(message, scrollToBottom = true) {
        const messagesContainer = document.getElementById('messages-container');
        if (!messagesContainer) return;

        if (message && message.message_id) {
            this._messageCache.set(message.message_id, message);
        }
        
        const isSent = message.sender_id === this.currentUserId;
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isSent ? 'sent' : 'received'}`;
        messageDiv.dataset.messageId = message.message_id;
        
        // Format time in EAT timezone
        const time = this.formatTimeEAT(message.created_at);
        
        // Generate tick marks for sent messages
        let tickMarks = '';
        if (isSent) {
            if (message.is_pending) {
                tickMarks = '<span class="message-ticks pending"><i class="bi bi-clock"></i></span>';
            } else
            if (message.is_read) {
                // Two blue ticks for read
                tickMarks = '<span class="message-ticks read"><i class="bi bi-check-all"></i></span>';
            } else if (message.is_delivered) {
                // Two grey ticks for delivered
                tickMarks = '<span class="message-ticks delivered"><i class="bi bi-check-all"></i></span>';
            } else {
                // One grey tick for sent
                tickMarks = '<span class="message-ticks sent"><i class="bi bi-check"></i></span>';
            }
        }
        
        const deletedText = '<em class="text-muted">This message was deleted</em>';
        const rawReply = (message && message.replied_to && typeof message.replied_to.content === 'string') ? message.replied_to.content : '';
        const replyIsE2E = typeof rawReply === 'string' && this._tryParseE2E(rawReply);
        const repliedTo = message.replied_to ? `
            <div class="message-reply-preview">
                <div class="reply-snippet">${this.escapeHtml(replyIsE2E ? '[Encrypted message]' : (rawReply || ''))}</div>
            </div>
        ` : '';

        const reactionsHtml = (message.reactions && message.reactions.length) ? `
            <div class="message-reactions">
                ${message.reactions.map(r => `<span class="reaction-chip">${this.escapeHtml(r.emoji)} ${r.count}</span>`).join('')}
            </div>
        ` : '';

        const editedLabel = message.is_edited ? '<span class="message-edited">edited</span>' : '';
        const starLabel = message.is_starred ? '<i class="bi bi-star-fill message-star" title="Starred"></i>' : '';

        const rawContent = (message && typeof message._raw_content === 'string') ? message._raw_content : message.content;
        const contentIsE2E = typeof rawContent === 'string' && this._tryParseE2E(rawContent);
        const contentHtml = message.is_deleted
            ? deletedText
            : this.escapeHtml(contentIsE2E ? '[Encrypted message]' : (rawContent || ''));

        messageDiv.innerHTML = `
            <div class="message-bubble">
                ${repliedTo}
                <div class="message-content">${contentHtml}</div>
                ${reactionsHtml}
                <div class="message-time">
                    ${editedLabel}
                    ${starLabel}
                    ${time}
                    ${tickMarks}
                </div>
            </div>
        `;

        if (contentIsE2E && !message.is_deleted) {
            this.decryptIfNeeded(rawContent).then((pt) => {
                const el = messageDiv.querySelector('.message-content');
                if (el) el.innerHTML = this.escapeHtml(pt || '[Encrypted message]');
            });
        }

        if (replyIsE2E && message.replied_to) {
            this.decryptIfNeeded(rawReply).then((pt) => {
                const el = messageDiv.querySelector('.reply-snippet');
                if (el) el.innerHTML = this.escapeHtml(pt || '[Encrypted message]');
            });
        }

        this.attachMessageInteractionHandlers(messageDiv);
        
        messagesContainer.appendChild(messageDiv);
        
        if (scrollToBottom) {
            messagesContainer.scrollTop = messagesContainer.scrollHeight;
        }
    }

    async sendMessage() {
        const messageInput = document.getElementById('message-input');
        if (!messageInput) return;
        
        const content = messageInput.value.trim();
        if (!content || !this.activeChatUserId) return;
        if (this._isChatBlocked) {
            this.showError('You cannot message this user (blocked).');
            return;
        }
        
        const tempId = `${Date.now()}_${Math.random().toString(16).slice(2)}`;
        const createdAt = new Date().toISOString();
        const receiverId = this.activeChatUserId;
        const replyToId = this._replyToMessageId;

        // Clear input early for snappy UX
        messageInput.value = '';
        try {
            messageInput.style.height = 'auto';
        } catch (_) {}

        // Append a pending message immediately
        this.appendMessage({
            message_id: `tmp_${tempId}`,
            sender_id: this.currentUserId,
            receiver_id: receiverId,
            content,
            _raw_content: content,
            created_at: createdAt,
            is_pending: true,
            is_delivered: false,
            is_read: false,
            is_edited: false,
            is_starred: false,
            reactions: []
        });

        // Clear reply state
        this.clearReply();

        try {
            // Best-effort: encrypt for recipient if they have an E2E public key.
            const outgoingContent = await this.encryptForRecipient(receiverId, content);

            // If offline, queue and exit
            if (!navigator.onLine) {
                this._enqueueOfflineMessage({
                    temp_id: tempId,
                    receiver_id: receiverId,
                    content_to_send: outgoingContent,
                    reply_to_message_id: replyToId,
                    created_at: createdAt
                });
                this.showError('Offline: message queued and will send when back online.');
                return;
            }

            const response = await fetch('/api/communication/send_message', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    receiver_id: receiverId,
                    content: outgoingContent,
                    reply_to_message_id: replyToId
                })
            });

            if (!response.ok) {
                throw new Error('Failed to send message');
            }

            const data = await response.json().catch(() => null);

            // Replace pending with server message
            this._removePendingMessageFromUI(tempId);
            if (data && data.message) {
                // Preserve what the sender typed locally so their UI never flashes ciphertext.
                // Ciphertext is still sent/stored and used for delivery.
                if (data.message.sender_id === this.currentUserId) {
                    data.message._raw_content = content;
                    // Cache plaintext so future loads of this conversation show it.
                    this._cacheSentPlaintext(data.message.message_id, content);
                }
                const displayMsg = await this.prepareMessageForDisplay(data.message);
                this.appendMessage(displayMsg);
            }

            // Emit socket event for real-time delivery
            if (this.socket) {
                this.socket.emit('send_message', {
                    // Important: emit raw server payload (ciphertext) for receiver.
                    message: data ? data.message : null,
                    receiver_id: receiverId
                });
            }
        } catch (error) {
            // Queue on failure (including transient network errors)
            try {
                const outgoingContent = await this.encryptForRecipient(receiverId, content);
                this._enqueueOfflineMessage({
                    temp_id: tempId,
                    receiver_id: receiverId,
                    content_to_send: outgoingContent,
                    reply_to_message_id: replyToId,
                    created_at: createdAt
                });
                this.showError('Message queued and will retry automatically.');
            } catch (_) {
                this.showError('Failed to send message');
            }
            console.error('Error sending message:', error);
        }
    }

    handleNewMessage(data) {
        const message = data.message;
        
        // Emit message received confirmation
        this.socket.emit('message_received', {
            message_id: message.message_id,
            sender_id: message.sender_id
        });
        
        // If message is from current conversation, append it
        if (message.sender_id === this.activeChatUserId) {
            this.prepareMessageForDisplay(message).then((displayMsg) => {
                this.appendMessage(displayMsg);
            });
            
            // Mark as read immediately
            this.markMessagesAsRead(this.activeChatUserId);
        } else {
            // Update unread count
            this.updateUnreadCount(message.sender_id);

            // Respect per-chat mute/block settings (best-effort from cached user list)
            const senderId = Number(message.sender_id);
            const cached = this._usersCache.get(senderId);
            const suppress = !!(cached && (cached.is_muted || cached.blocked_by_me || cached.blocked_me));

            // Show notification + play tone
            this.prepareMessageForDisplay(message).then((displayMsg) => {
                if (!suppress) {
                    this.playMessageTone(displayMsg);
                    this.showNotification(displayMsg);
                }
            });
        }
    }

    handleMessageDelivered(data) {
        // Update tick marks for delivered message
        const messageDiv = document.querySelector(`[data-message-id="${data.message_id}"]`);
        if (messageDiv) {
            const ticksElement = messageDiv.querySelector('.message-ticks');
            if (ticksElement) {
                ticksElement.className = 'message-ticks delivered';
                ticksElement.innerHTML = '<i class="bi bi-check-all"></i>';
            }
        }
    }

    handleMessageRead(data) {
        // Update tick marks for read message
        const messageDiv = document.querySelector(`[data-message-id="${data.message_id}"]`);
        if (messageDiv) {
            const ticksElement = messageDiv.querySelector('.message-ticks');
            if (ticksElement) {
                ticksElement.className = 'message-ticks read';
                ticksElement.innerHTML = '<i class="bi bi-check-all"></i>';
            }
        }
    }

    handleTyping() {
        if (!this.activeChatUserId) return;
        
        // Emit typing event
        this.socket.emit('typing', {
            receiver_id: this.activeChatUserId,
            is_typing: true
        });
        
        // Clear existing timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
        }
        
        // Stop typing after 2 seconds of inactivity
        this.typingTimeout = setTimeout(() => {
            this.socket.emit('typing', {
                receiver_id: this.activeChatUserId,
                is_typing: false
            });
        }, 2000);
    }

    handleTypingStatus(data) {
        if (data.user_id !== this.activeChatUserId) return;
        
        const typingIndicator = document.getElementById('typing-indicator');
        if (!typingIndicator) return;
        
        if (data.is_typing) {
            typingIndicator.style.display = 'flex';
        } else {
            typingIndicator.style.display = 'none';
        }
    }

    async markMessagesAsRead(senderId) {
        try {
            const resp = await fetch('/api/communication/mark_read', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    sender_id: senderId
                })
            });

            if (resp && resp.ok) {
                // Clear per-user unread badge in the sidebar (best-effort)
                try {
                    const userItem = document.querySelector(`.user-item[data-user-id="${senderId}"]`);
                    const badge = userItem ? userItem.querySelector('.unread-badge') : null;
                    if (badge) badge.remove();
                } catch (_) {
                    // no-op
                }

                // Update cached user state
                try {
                    const cached = this._usersCache.get(Number(senderId));
                    if (cached) cached.unread_count = 0;
                } catch (_) {
                    // no-op
                }

                // Refresh float icon badge
                this.updateFloatIconBadge().catch(() => {});
            }
        } catch (error) {
            console.error('Error marking messages as read:', error);
        }
    }

    handleUserStatusUpdate(data) {
        // Update user status in the list
        const userItem = document.querySelector(`.user-item[data-user-id="${data.user_id}"]`);
        if (userItem) {
            const avatar = userItem.querySelector('.user-avatar');
            const existingBadge = avatar.querySelector('.online-badge');
            
            if (data.is_online) {
                if (!existingBadge) {
                    avatar.innerHTML += '<span class="online-badge"></span>';
                }
            } else {
                if (existingBadge) {
                    existingBadge.remove();
                }
            }
        }
        
        // Update chat header if this is the active user
        if (this.activeChatUserId === data.user_id) {
            const statusElement = document.getElementById('chat-user-status');
            if (statusElement) {
                if (data.is_online) {
                    statusElement.textContent = 'online';
                    statusElement.className = 'text-success';
                } else if (data.last_seen) {
                    statusElement.textContent = `last seen ${this.formatDateTimeEAT(data.last_seen)}`;
                    statusElement.className = 'text-muted';
                } else {
                    statusElement.textContent = 'offline';
                    statusElement.className = 'text-muted';
                }
            }
        }
    }

    applyChatBlockedUI() {
        const messageInput = document.getElementById('message-input');
        const sendBtn = document.getElementById('send-message-btn');
        const voiceBtn = document.getElementById('voice-call-btn');
        const videoBtn = document.getElementById('video-call-btn');

        if (messageInput) messageInput.disabled = this._isChatBlocked;
        if (sendBtn) sendBtn.disabled = this._isChatBlocked;
        if (voiceBtn) voiceBtn.disabled = this._isChatBlocked;
        if (videoBtn) videoBtn.disabled = this._isChatBlocked;

        if (messageInput) {
            messageInput.placeholder = this._isChatBlocked ? 'Messaging disabled (blocked)' : 'Type a message...';
        }
    }

    attachMessageInteractionHandlers(messageDiv) {
        const messageId = messageDiv.dataset.messageId;
        if (!messageId) return;

        // Desktop: right-click
        messageDiv.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            this.openMessageActions(messageId, e.clientX, e.clientY);
        });

        // Desktop: double click
        messageDiv.addEventListener('dblclick', (e) => {
            this.openMessageActions(messageId, e.clientX, e.clientY);
        });

        // Mobile/tablet: long press
        let pressTimer = null;
        messageDiv.addEventListener('touchstart', (e) => {
            if (!e.touches || !e.touches[0]) return;
            const t = e.touches[0];
            pressTimer = setTimeout(() => {
                this.openMessageActions(messageId, t.clientX, t.clientY);
            }, 500);
        }, { passive: true });
        messageDiv.addEventListener('touchend', () => {
            if (pressTimer) clearTimeout(pressTimer);
        });
        messageDiv.addEventListener('touchmove', () => {
            if (pressTimer) clearTimeout(pressTimer);
        });
    }

    openMessageActions(messageId, x, y) {
        const message = this._messageCache.get(messageId);
        if (!message) return;
        if (message.is_deleted) return;

        if (!this._messageActionsEl) {
            const el = document.createElement('div');
            el.className = 'message-actions-popover';
            el.id = 'message-actions-popover';
            el.style.position = 'fixed';
            el.style.zIndex = '10001';
            el.style.display = 'none';
            document.body.appendChild(el);
            this._messageActionsEl = el;

            document.addEventListener('click', (e) => {
                if (this._messageActionsEl && this._messageActionsEl.style.display === 'block') {
                    if (!this._messageActionsEl.contains(e.target)) {
                        this._messageActionsEl.style.display = 'none';
                    }
                }
            });
        }

        const isSent = message.sender_id === this.currentUserId;
        const buttons = [];

        buttons.push({ label: 'Reply', icon: 'bi-reply', action: () => this.setReplyTo(message) });
        buttons.push({ label: message.is_starred ? 'Unstar' : 'Star', icon: message.is_starred ? 'bi-star-fill' : 'bi-star', action: () => this.toggleStar(messageId) });

        if (isSent) {
            buttons.push({ label: 'Edit', icon: 'bi-pencil', action: () => this.editMessage(messageId) });
            buttons.push({ label: 'Delete', icon: 'bi-trash', action: () => this.deleteMessage(messageId) });
        }

        const quickReactions = ['👍', '❤️', '😂', '😮', '😢', '🙏'];

        this._messageActionsEl.innerHTML = `
            <div class="quick-reactions">
                ${quickReactions.map(e => `<button type="button" class="quick-reaction-btn" data-emoji="${this.escapeHtml(e)}">${this.escapeHtml(e)}</button>`).join('')}
            </div>
            <div>
                ${buttons.map((b, idx) => `
                    <button type="button" class="btn" data-action-idx="${idx}">
                        <i class="bi ${b.icon}"></i>${this.escapeHtml(b.label)}
                    </button>
                `).join('')}
            </div>
        `;

        // Bind emoji buttons
        this._messageActionsEl.querySelectorAll('.quick-reaction-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const emoji = e.currentTarget.getAttribute('data-emoji');
                this.reactToMessage(messageId, emoji);
                this._messageActionsEl.style.display = 'none';
            });
        });

        // Bind action buttons
        this._messageActionsEl.querySelectorAll('button[data-action-idx]').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const idx = parseInt(e.currentTarget.getAttribute('data-action-idx'));
                const b = buttons[idx];
                if (b && b.action) b.action();
                this._messageActionsEl.style.display = 'none';
            });
        });

        const margin = 8;
        const w = 240;
        const h = 220;
        const left = Math.max(margin, Math.min(x, window.innerWidth - w - margin));
        const top = Math.max(margin, Math.min(y, window.innerHeight - h - margin));
        this._messageActionsEl.style.left = `${left}px`;
        this._messageActionsEl.style.top = `${top}px`;
        this._messageActionsEl.style.display = 'block';
    }

    setReplyTo(message) {
        this._replyToMessageId = message.message_id;
        const preview = document.getElementById('reply-preview');
        const text = document.getElementById('reply-preview-text');
        if (preview && text) {
            const raw = (message && typeof message._raw_content === 'string') ? message._raw_content : message.content;
            if (typeof raw === 'string' && this._tryParseE2E(raw)) {
                text.textContent = '[Encrypted message]';
                this.decryptIfNeeded(raw).then((pt) => {
                    text.textContent = (pt || '[Encrypted message]').slice(0, 160);
                });
            } else {
                text.textContent = (message.content || '').slice(0, 160);
            }
            preview.style.display = 'flex';
        }
    }

    clearReply() {
        this._replyToMessageId = null;
        const preview = document.getElementById('reply-preview');
        if (preview) preview.style.display = 'none';
    }

    async editMessage(messageId) {
        const msg = this._messageCache.get(messageId);
        if (!msg) return;
        const next = prompt('Edit message:', msg.content || '');
        if (next === null) return;

        try {
            const recipientId = msg.recipient_id;
            const outgoingContent = recipientId ? await this.encryptForRecipient(recipientId, next) : next;
            const response = await fetch(`/api/communication/message/${messageId}/edit`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ content: outgoingContent })
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to edit message');
            }

            // Keep plaintext for UI; stash raw ciphertext separately.
            msg._raw_content = data.message.content;
            msg.content = await this.decryptIfNeeded(data.message.content);
            msg.is_edited = true;
            this._messageCache.set(messageId, msg);
            this.updateMessageElement(messageId);
        } catch (e) {
            console.error('Edit message failed:', e);
            this.showError('Failed to edit message');
        }
    }

    async deleteMessage(messageId) {
        if (!confirm('Delete this message for everyone?')) return;
        try {
            const response = await fetch(`/api/communication/message/${messageId}/delete`, {
                method: 'POST',
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to delete message');
            }
            const msg = this._messageCache.get(messageId);
            if (msg) {
                msg.is_deleted = true;
                msg.content = '';
                this._messageCache.set(messageId, msg);
                this.updateMessageElement(messageId);
            }
        } catch (e) {
            console.error('Delete message failed:', e);
            this.showError('Failed to delete message');
        }
    }

    async reactToMessage(messageId, emoji) {
        try {
            const response = await fetch(`/api/communication/message/${messageId}/react`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({ emoji })
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to react');
            }

            // Optimistic local update: bump count for emoji (single-user view)
            const msg = this._messageCache.get(messageId);
            if (msg) {
                msg.my_reaction = data.my_reaction;
                // Force refresh by reloading conversation for accurate counts
                await this.loadConversation(this.activeChatUserId);
            }
        } catch (e) {
            console.error('React failed:', e);
        }
    }

    async toggleStar(messageId) {
        try {
            const response = await fetch(`/api/communication/message/${messageId}/star`, {
                method: 'POST',
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Failed to star');
            }

            const msg = this._messageCache.get(messageId);
            if (msg) {
                msg.is_starred = !!data.is_starred;
                this._messageCache.set(messageId, msg);
                this.updateMessageElement(messageId);
            }
        } catch (e) {
            console.error('Star failed:', e);
        }
    }

    updateMessageElement(messageId) {
        const el = document.querySelector(`[data-message-id="${messageId}"]`);
        const msg = this._messageCache.get(messageId);
        if (!el || !msg) return;

        const rawContent = (typeof msg._raw_content === 'string') ? msg._raw_content : msg.content;
        const isE2E = !!this._tryParseE2E(rawContent);
        const contentHtml = msg.is_deleted
            ? '<em class="text-muted">This message was deleted</em>'
            : this.escapeHtml(isE2E ? '[Encrypted message]' : (rawContent || ''));

        // Re-render using the same logic as appendMessage
        const isSent = msg.sender_id === this.currentUserId;
        el.className = `message ${isSent ? 'sent' : 'received'}`;

        const time = this.formatTimeEAT(msg.created_at);
        let tickMarks = '';
        if (isSent) {
            if (msg.is_read) tickMarks = '<span class="message-ticks read"><i class="bi bi-check-all"></i></span>';
            else if (msg.is_delivered) tickMarks = '<span class="message-ticks delivered"><i class="bi bi-check-all"></i></span>';
            else tickMarks = '<span class="message-ticks sent"><i class="bi bi-check"></i></span>';
        }

        const rawReply = (msg && msg.replied_to && typeof msg.replied_to.content === 'string') ? msg.replied_to.content : '';
        const replyIsE2E = typeof rawReply === 'string' && this._tryParseE2E(rawReply);
        const repliedTo = msg.replied_to ? `
            <div class="message-reply-preview">
                <div class="reply-snippet">${this.escapeHtml(replyIsE2E ? '[Encrypted message]' : (rawReply || ''))}</div>
            </div>
        ` : '';

        const reactionsHtml = (msg.reactions && msg.reactions.length) ? `
            <div class="message-reactions">
                ${msg.reactions.map(r => `<span class="reaction-chip">${this.escapeHtml(r.emoji)} ${r.count}</span>`).join('')}
            </div>
        ` : '';

        const editedLabel = msg.is_edited ? '<span class="message-edited">edited</span>' : '';
        const starLabel = msg.is_starred ? '<i class="bi bi-star-fill message-star" title="Starred"></i>' : '';

        el.innerHTML = `
            <div class="message-bubble">
                ${repliedTo}
                <div class="message-content">${contentHtml}</div>
                ${reactionsHtml}
                <div class="message-time">
                    ${editedLabel}
                    ${starLabel}
                    ${time}
                    ${tickMarks}
                </div>
            </div>
        `;

        if (isE2E && !msg.is_deleted) {
            this.decryptIfNeeded(rawContent).then((pt) => {
                const c = el.querySelector('.message-content');
                if (c) c.innerHTML = this.escapeHtml(pt || '[Encrypted message]');
            });
        }

        if (replyIsE2E && msg.replied_to) {
            this.decryptIfNeeded(rawReply).then((pt) => {
                const c = el.querySelector('.reply-snippet');
                if (c) c.innerHTML = this.escapeHtml(pt || '[Encrypted message]');
            });
        }

        this.attachMessageInteractionHandlers(el);
    }

    toggleEmojiPicker(anchorEl) {
        if (!this._emojiPickerEl) {
            const el = document.createElement('div');
            el.id = 'emoji-picker';
            el.style.position = 'fixed';
            el.style.zIndex = '10001';
            el.style.background = '#fff';
            el.style.border = '1px solid rgba(0,0,0,0.12)';
            el.style.borderRadius = '12px';
            el.style.boxShadow = '0 8px 24px rgba(0,0,0,0.18)';
            el.style.padding = '10px';
            el.style.display = 'none';
            el.style.maxWidth = '260px';
            document.body.appendChild(el);
            this._emojiPickerEl = el;

            document.addEventListener('click', (e) => {
                if (this._emojiPickerEl && this._emojiPickerEl.style.display === 'block') {
                    if (!this._emojiPickerEl.contains(e.target) && !(anchorEl && anchorEl.contains(e.target))) {
                        this._emojiPickerEl.style.display = 'none';
                    }
                }
            });
        }

        if (this._emojiPickerEl.style.display === 'block') {
            this._emojiPickerEl.style.display = 'none';
            return;
        }

        const emojis = [
            // Smileys & Emotion
            '😀','😃','😄','😁','😆','😅','🤣','😂','🙂','🙃','😉','😊','😇','🥰','😍','🤩','😘','😗','😚','😙',
            '😋','😛','😜','🤪','😝','🤑','🤗','🤭','🤫','🤔','🤐','🤨','😐','😑','😶','😏','😒','🙄','😬','🤥',
            '😌','😔','😪','🤤','😴','😷','🤒','🤕','🤢','🤮','🤧','🥵','🥶','🥴','😵','🤯','🤠','🥳','😎','🤓',
            '🧐','😕','😟','🙁','☹️','😮','😯','😲','😳','🥺','😦','😧','😨','😰','😥','😢','😭','😱','😖','😣',
            '😞','😓','😩','😫','🥱','😤','😡','😠','🤬','😈','👿','💀','☠️','💩','🤡','👹','👺','👻','👽','👾',
            '🤖','😺','😸','😹','😻','😼','😽','🙀','😿','😾',
            
            // Hearts & Love
            '❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💟',
            
            // Hand Gestures
            '👋','🤚','🖐️','✋','🖖','👌','🤌','🤏','✌️','🤞','🤟','🤘','🤙','👈','👉','👆','🖕','👇','☝️','👍',
            '👎','✊','👊','🤛','🤜','👏','🙌','👐','🤲','🤝','🙏','✍️','💅','🤳',
            
            // Body & People
            '💪','🦾','🦿','🦵','🦶','👂','🦻','👃','🧠','🦷','🦴','👀','👁️','👅','👄','💋',
            
            // Nature & Animals
            '🐶','🐱','🐭','🐹','🐰','🦊','🐻','🐼','🐨','🐯','🦁','🐮','🐷','🐸','🐵','🙈','🙉','🙊','🐔','🐧',
            '🐦','🐤','🐣','🐥','🦆','🦅','🦉','🦇','🐺','🐗','🐴','🦄','🐝','🐛','🦋','🐌','🐞','🐜','🦟','🦗',
            
            // Food & Drink
            '🍏','🍎','🍐','🍊','🍋','🍌','🍉','🍇','🍓','🫐','🍈','🍒','🍑','🥭','🍍','🥥','🥝','🍅','🍆','🥑',
            '🥦','🥬','🥒','🌶️','🫑','🌽','🥕','🫒','🧄','🧅','🥔','🍠','🥐','🥯','🍞','🥖','🥨','🧀','🥚','🍳',
            '🧈','🥞','🧇','🥓','🥩','🍗','🍖','🦴','🌭','🍔','🍟','🍕','🫓','🥪','🥙','🧆','🌮','🌯','🫔','🥗',
            '🍿','🧈','🧂','🥫','🍱','🍘','🍙','🍚','🍛','🍜','🍝','🍠','🍢','🍣','🍤','🍥','🥮','🍡','🥟','🥠',
            '🥡','🦀','🦞','🦐','🦑','🦪','🍦','🍧','🍨','🍩','🍪','🎂','🍰','🧁','🥧','🍫','🍬','🍭','🍮','🍯',
            '🍼','🥛','☕','🫖','🍵','🍶','🍾','🍷','🍸','🍹','🍺','🍻','🥂','🥃','🥤','🧋','🧃','🧉','🧊',
            
            // Activities & Sports
            '⚽','🏀','🏈','⚾','🥎','🎾','🏐','🏉','🥏','🎱','🪀','🏓','🏸','🏒','🏑','🥍','🏏','🥅','⛳','🪁',
            '🏹','🎣','🤿','🥊','🥋','🎽','🛹','🛼','🛷','⛸️','🥌','🎿','⛷️','🏂','🪂','🏋️','🤼','🤸','🤺','⛹️',
            '🤾','🏌️','🏇','🧘','🏊','🤽','🚣','🧗','🚴','🚵','🎪','🎭','🎨','🎬','🎤','🎧','🎼','🎹','🥁','🎷',
            '🎺','🎸','🪕','🎻','🎲','♟️','🎯','🎳','🎮','🎰','🧩',
            
            // Travel & Places
            '🚗','🚕','🚙','🚌','🚎','🏎️','🚓','🚑','🚒','🚐','🛻','🚚','🚛','🚜','🦯','🦽','🦼','🛴','🚲','🛵',
            '🏍️','🛺','🚨','🚔','🚍','🚘','🚖','🚡','🚠','🚟','🚃','🚋','🚞','🚝','🚄','🚅','🚈','🚂','🚆','🚇',
            '🚊','🚉','✈️','🛫','🛬','🛩️','💺','🛰️','🚁','🛸','🚀','🛶','⛵','🚤','🛥️','🛳️','⛴️','🚢','⚓','⛽',
            '🚧','🚦','🚥','🚏','🗺️','🗿','🗽','🗼','🏰','🏯','🏟️','🎡','🎢','🎠','⛲','⛱️','🏖️','🏝️','🏜️','🌋',
            '⛰️','🏔️','🗻','🏕️','⛺','🏠','🏡','🏘️','🏚️','🏗️','🏭','🏢','🏬','🏣','🏤','🏥','🏦','🏨','🏪','🏫',
            
            // Objects
            '⌚','📱','📲','💻','⌨️','🖥️','🖨️','🖱️','🖲️','🕹️','🗜️','💾','💿','📀','📼','📷','📸','📹','🎥','📽️',
            '🎞️','📞','☎️','📟','📠','📺','📻','🎙️','🎚️','🎛️','🧭','⏱️','⏲️','⏰','🕰️','⌛','⏳','📡','🔋','🔌',
            '💡','🔦','🕯️','🪔','🧯','🛢️','💸','💵','💴','💶','💷','💰','💳','💎','⚖️','🪜','🧰','🪛','🔧','🔨',
            '⚒️','🛠️','⛏️','🪚','🔩','⚙️','🪤','🧱','⛓️','🧲','🔫','💣','🧨','🪓','🔪','🗡️','⚔️','🛡️','🚬','⚰️',
            '⚱️','🏺','🔮','📿','🧿','💈','⚗️','🔭','🔬','🕳️','🩹','🩺','💊','💉','🩸','🧬','🦠','🧫','🧪','🌡️',
            '🧹','🧺','🧻','🚽','🚰','🚿','🛁','🛀','🧼','🪒','🧽','🧴','🛎️','🔑','🗝️','🚪','🪑','🛋️','🛏️','🛌',
            '🧸','🖼️','🛍️','🛒','🎁','🎈','🎏','🎀','🎊','🎉','🎎','🏮','🎐','🧧','✉️','📩','📨','📧','💌','📥',
            '📤','📦','🏷️','📪','📫','📬','📭','📮','📯','📜','📃','📄','📑','🧾','📊','📈','📉','🗒️','🗓️','📆',
            '📅','🗑️','📇','🗃️','🗳️','🗄️','📋','📁','📂','🗂️','🗞️','📰','📓','📔','📒','📕','📗','📘','📙','📚',
            
            // Symbols & Flags
            '❤️','🧡','💛','💚','💙','💜','🖤','🤍','🤎','💔','❣️','💕','💞','💓','💗','💖','💘','💝','💟','☮️',
            '✝️','☪️','🕉️','☸️','✡️','🔯','🕎','☯️','☦️','🛐','⛎','♈','♉','♊','♋','♌','♍','♎','♏','♐','♑',
            '♒','♓','🆔','⚛️','🉑','☢️','☣️','📴','📳','🈶','🈚','🈸','🈺','🈷️','✴️','🆚','💮','🉐','㊙️','㊗️',
            '🈴','🈵','🈹','🈲','🅰️','🅱️','🆎','🆑','🅾️','🆘','❌','⭕','🛑','⛔','📛','🚫','💯','💢','♨️','🚷',
            '🚯','🚳','🚱','🔞','📵','🚭','❗','❕','❓','❔','‼️','⁉️','🔅','🔆','〽️','⚠️','🚸','🔱','⚜️','🔰',
            '♻️','✅','🈯','💹','❇️','✳️','❎','🌐','💠','Ⓜ️','🌀','💤','🏧','🚾','♿','🅿️','🈳','🈂️','🛂','🛃',
            '🛄','🛅','🚹','🚺','🚼','🚻','🚮','🎦','📶','🈁','🔣','ℹ️','🔤','🔡','🔠','🆖','🆗','🆙','🆒','🆕',
            '🆓','0️⃣','1️⃣','2️⃣','3️⃣','4️⃣','5️⃣','6️⃣','7️⃣','8️⃣','9️⃣','🔟','🔢','#️⃣','*️⃣','⏏️','▶️','⏸️','⏯️','⏹️','⏺️',
            '⏭️','⏮️','⏩','⏪','⏫','⏬','◀️','🔼','🔽','➡️','⬅️','⬆️','⬇️','↗️','↘️','↙️','↖️','↕️','↔️','↪️',
            '↩️','⤴️','⤵️','🔀','🔁','🔂','🔄','🔃','🎵','🎶','➕','➖','➗','✖️','♾️','💲','💱','™️','©️','®️',
            '〰️','➰','➿','🔚','🔙','🔛','🔝','🔜','✔️','☑️','🔘','🔴','🟠','🟡','🟢','🔵','🟣','⚫','⚪','🟤',
            '🔺','🔻','🔸','🔹','🔶','🔷','🔳','🔲','▪️','▫️','◾','◽','◼️','◻️','🟥','🟧','🟨','🟩','🟦','🟪',
            '⬛','⬜','🟫','🔈','🔇','🔉','🔊','🔔','🔕','📣','📢','💬','💭','🗯️','♠️','♣️','♥️','♦️','🃏','🎴',
            '🀄','🕐','🕑','🕒','🕓','🕔','🕕','🕖','🕗','🕘','🕙','🕚','🕛','🕜','🕝','🕞','🕟','🕠','🕡','🕢',
            '🕣','🕤','🕥','🕦','🕧'
        ];

        // Build the picker contents safely (avoid innerHTML).
        if (this._emojiPickerEl.dataset.built !== '1') {
            this._emojiPickerEl.textContent = '';
            const grid = document.createElement('div');
            grid.className = 'emoji-grid';
            const frag = document.createDocumentFragment();

            emojis.forEach((emoji) => {
                const item = document.createElement('span');
                item.className = 'emoji-item';
                item.setAttribute('data-emoji', emoji);
                item.textContent = emoji;
                frag.appendChild(item);
            });

            grid.appendChild(frag);
            this._emojiPickerEl.appendChild(grid);
            this._emojiPickerEl.dataset.built = '1';

            // Event delegation for performance (single handler).
            this._emojiPickerEl.addEventListener('click', (e) => {
                const target = e.target && e.target.closest ? e.target.closest('.emoji-item') : null;
                if (!target) return;
                const emoji = target.getAttribute('data-emoji') || target.textContent || '';
                const input = document.getElementById('message-input');
                if (input && emoji) {
                    input.value = `${input.value || ''}${emoji}`;
                    input.focus();
                }
                this._emojiPickerEl.style.display = 'none';
            });
        }

        const rect = anchorEl.getBoundingClientRect();
        const left = Math.max(8, Math.min(rect.left, window.innerWidth - 280));
        const top = Math.max(8, rect.top - 170);
        this._emojiPickerEl.style.left = `${left}px`;
        this._emojiPickerEl.style.top = `${top}px`;
        this._emojiPickerEl.style.display = 'block';
    }

    toggleChatSearch(show) {
        const bar = document.getElementById('chat-search-bar');
        const input = document.getElementById('chat-search-input');
        const meta = document.getElementById('chat-search-meta');
        if (!bar) return;

        if (show) {
            bar.style.display = 'block';
            if (meta) meta.style.display = 'none';
            if (input) {
                input.value = '';
                input.focus();
            }
        } else {
            bar.style.display = 'none';
        }
    }

    async searchMessages(query) {
        const meta = document.getElementById('chat-search-meta');
        if (!query || !query.trim()) {
            if (meta) meta.style.display = 'none';
            return;
        }
        try {
            const response = await fetch(`/api/communication/search?q=${encodeURIComponent(query)}&other_user_id=${this.activeChatUserId}`, {
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            const data = await response.json();
            if (!response.ok || !data.success) {
                throw new Error(data.error || 'Search failed');
            }

            try {
                if (Array.isArray(data.messages) && data.messages.length) {
                    await Promise.all(data.messages.map(m => this.prepareMessageForDisplay(m)));
                }
            } catch (_) {
                // no-op
            }
            if (meta) {
                meta.style.display = 'block';
                meta.textContent = `${data.messages.length} result(s)`;
            }
        } catch (e) {
            console.error('Search failed:', e);
        }
    }

    toggleChatSettings(anchorEl) {
        if (!this.activeChatUserId || !this.currentUser) return;
        if (!this._chatSettingsEl) {
            const el = document.createElement('div');
            el.id = 'chat-settings-popover';
            el.style.position = 'fixed';
            el.style.zIndex = '10001';
            el.style.minWidth = '170px';
            el.style.background = '#fff';
            el.style.border = '1px solid rgba(0,0,0,0.12)';
            el.style.borderRadius = '10px';
            el.style.boxShadow = '0 8px 24px rgba(0,0,0,0.18)';
            el.style.padding = '8px';
            el.style.display = 'none';
            document.body.appendChild(el);
            this._chatSettingsEl = el;

            document.addEventListener('click', (e) => {
                if (this._chatSettingsEl && this._chatSettingsEl.style.display === 'block') {
                    if (!this._chatSettingsEl.contains(e.target) && e.target !== anchorEl) {
                        this._chatSettingsEl.style.display = 'none';
                    }
                }
            });
        }

        if (this._chatSettingsEl.style.display === 'block') {
            this._chatSettingsEl.style.display = 'none';
            return;
        }

        const user = this.currentUser;
        const isMuted = !!user.is_muted;
        const isPinned = !!user.is_pinned;
        const isArchived = !!user.is_archived;
        const blockedByMe = !!user.blocked_by_me;

        this._chatSettingsEl.innerHTML = `
            <div style="font-weight:600; font-size:12px; margin-bottom:6px;">Chat Settings</div>
            <div style="display:flex; flex-direction:column; gap:6px;">
                <button type="button" class="btn btn-sm btn-light text-start" style="padding:6px 8px; font-size:12px;" data-setting="mute">${isMuted ? 'Unmute' : 'Mute'}</button>
                <button type="button" class="btn btn-sm btn-light text-start" style="padding:6px 8px; font-size:12px;" data-setting="pin">${isPinned ? 'Unpin' : 'Pin'}</button>
                <button type="button" class="btn btn-sm btn-light text-start" style="padding:6px 8px; font-size:12px;" data-setting="archive">${isArchived ? 'Unarchive' : 'Archive'}</button>
                <button type="button" class="btn btn-sm btn-danger text-start" style="padding:6px 8px; font-size:12px;" data-setting="block">${blockedByMe ? 'Unblock user' : 'Block user'}</button>
            </div>
        `;

        this._chatSettingsEl.querySelectorAll('button[data-setting]').forEach(btn => {
            btn.addEventListener('click', async (e) => {
                const key = e.currentTarget.getAttribute('data-setting');
                this._chatSettingsEl.style.display = 'none';

                if (key === 'block') {
                    await this.toggleBlockUser();
                } else {
                    await this.updateConversationSettings(key);
                }
            });
        });

        const rect = anchorEl.getBoundingClientRect();
        const left = Math.max(8, Math.min(rect.left - 120, window.innerWidth - 220));
        const top = Math.max(8, rect.bottom + 8);
        this._chatSettingsEl.style.left = `${left}px`;
        this._chatSettingsEl.style.top = `${top}px`;
        this._chatSettingsEl.style.display = 'block';
    }

    async updateConversationSettings(key) {
        const user = this.currentUser;
        if (!user) return;

        const patch = {};
        if (key === 'mute') patch.is_muted = !user.is_muted;
        if (key === 'pin') patch.is_pinned = !user.is_pinned;
        if (key === 'archive') patch.is_archived = !user.is_archived;

        try {
            const response = await fetch(`/api/communication/conversation/${user.id}/settings`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify(patch)
            });
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.error || 'Failed');

            user.is_muted = data.settings.is_muted;
            user.is_pinned = data.settings.is_pinned;
            user.is_archived = data.settings.is_archived;
            this.currentUser = user;
            await this.loadUsers();
        } catch (e) {
            console.error('Update settings failed:', e);
        }
    }

    async toggleBlockUser() {
        const user = this.currentUser;
        if (!user) return;
        try {
            const response = await fetch(`/api/communication/user/${user.id}/block`, {
                method: 'POST',
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            const data = await response.json();
            if (!response.ok || !data.success) throw new Error(data.error || 'Failed');
            user.blocked_by_me = data.blocked;
            this.currentUser = user;
            this._isChatBlocked = !!(user.blocked_by_me || user.blocked_me);
            this.applyChatBlockedUI();
            await this.loadUsers();
        } catch (e) {
            console.error('Block toggle failed:', e);
        }
    }

    updateUnreadCount(senderId) {
        const userItem = document.querySelector(`.user-item[data-user-id="${senderId}"]`);
        if (userItem) {
            let badge = userItem.querySelector('.unread-badge');
            if (!badge) {
                badge = document.createElement('span');
                badge.className = 'unread-badge';
                badge.textContent = '1';
                userItem.appendChild(badge);
            } else {
                badge.textContent = parseInt(badge.textContent) + 1;
            }
        }
        
        // Update float icon badge
        this.updateFloatIconBadge();
    }

    async updateFloatIconBadge() {
        try {
            const response = await fetch('/api/communication/unread_count', {
                headers: {
                    'X-CSRFToken': this.getCSRFToken()
                }
            });
            
            if (!response.ok) return;
            
            const data = await response.json();
            const badge = document.getElementById('unread-messages-count');
            const floatIcon = document.getElementById('communication-float-icon');
            
            if (badge && floatIcon) {
                if (data.unread_count > 0) {
                    badge.textContent = data.unread_count;
                    badge.style.display = 'block';
                    floatIcon.classList.add('has-unread');
                } else {
                    badge.textContent = '';
                    badge.style.display = 'none';
                    floatIcon.classList.remove('has-unread');
                }
            }
        } catch (error) {
            console.error('Error updating unread count:', error);
        }
    }

    // Call functionality
    async initiateCall(type) {
        if (!this.activeChatUserId) return;
        
        this.callType = type;
        this._callRole = 'caller';
        
        try {
            // Request media permissions
            const constraints = {
                audio: true,
                video: type === 'video'
            };
            
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            
            // Create call record
            const response = await fetch('/api/communication/initiate_call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    receiver_id: this.activeChatUserId,
                    call_type: type
                })
            });
            
            if (!response.ok) {
                throw new Error('Failed to initiate call');
            }
            
            const data = await response.json();
            this.callId = data.call_id;
            
            // Emit call signal
            this.socket.emit('initiate_call', {
                receiver_id: this.activeChatUserId,
                call_type: type,
                call_id: this.callId,
                caller_name: 'You'
            });
            
            // Show call UI (waiting for answer)
            this.showCallUI(type, 'outgoing');
            this.playOutgoingTone();
            this.startOutgoingCallTimeout();
            
        } catch (error) {
            console.error('Error initiating call:', error);
            this.clearOutgoingCallTimeout();
            this.showError('Failed to initiate call. Please check your media permissions.');
        }
    }

    startOutgoingCallTimeout() {
        this.clearOutgoingCallTimeout();
        // Auto-end unanswered outgoing calls (marks as missed on server).
        this._callRingTimeout = setTimeout(() => {
            try {
                if (this._callRole !== 'caller' || !this.callId) return;
                // If still waiting, end as timeout/missed.
                this.endCall('timeout');
                this.showError('No answer (missed call).');
            } catch (_) {
                // no-op
            }
        }, 35000);
    }

    clearOutgoingCallTimeout() {
        if (this._callRingTimeout) {
            clearTimeout(this._callRingTimeout);
            this._callRingTimeout = null;
        }
    }

    handleIncomingCall(data) {
        this.callId = data.call_id;
        this.callType = data.call_type;
        this.activeChatUserId = data.caller_id;
        this._callRole = 'callee';

        // Ensure we have a currentUser context for call UI
        this.currentUser = {
            id: data.caller_id,
            username: data.caller_name || 'Unknown',
            is_online: true
        };
        
        // Show incoming call UI
        const callModal = document.getElementById('call-modal');
        const incomingCall = document.getElementById('incoming-call');
        
        if (callModal && incomingCall) {
            callModal.style.display = 'flex';
            incomingCall.style.display = 'block';
            
            document.getElementById('incoming-caller-name').textContent = data.caller_name || 'Unknown';
            document.getElementById('incoming-call-type').textContent = 
                `Incoming ${data.call_type === 'video' ? 'Video' : 'Voice'} Call`;
        }

        // Render avatar (best-effort)
        try {
            const avatarBox = document.querySelector('#incoming-call .caller-avatar');
            if (avatarBox) {
                const picUrl = this._profilePicUrl(data && data.caller_profile_picture);
                avatarBox.innerHTML = picUrl
                    ? `<img src="${this.escapeHtml(picUrl)}" alt="" style="width:96px;height:96px;border-radius:50%;object-fit:cover;">`
                    : '<i class="bi bi-person-circle display-1"></i>';
            }
        } catch (_) {
            // no-op
        }
        
        // Play ringtone (optional)
        this.playRingtone();

        // OS notification (best-effort; requires Notification permission).
        this.showIncomingCallNotification(data);
    }

    showIncomingCallNotification(data) {
        try {
            const s = this.getCommSettings();
            if (!s.notifications_enabled) return;
            if (!('Notification' in window) || Notification.permission !== 'granted') return;
            const callerName = (data && data.caller_name) ? String(data.caller_name) : 'Unknown';
            const callType = (data && data.call_type) ? String(data.call_type) : 'voice';
            const title = `Incoming ${callType === 'video' ? 'Video' : 'Voice'} Call`;
            const notification = new Notification(title, {
                body: `From ${callerName}`,
                icon: '/static/images/icon-192.png',
                badge: '/static/images/icon-192.png'
            });
            notification.onclick = () => {
                try {
                    window.focus();
                    // Ensure call modal is visible
                    const callModal = document.getElementById('call-modal');
                    const incomingCall = document.getElementById('incoming-call');
                    if (callModal) callModal.style.display = 'flex';
                    if (incomingCall) incomingCall.style.display = 'block';
                } catch (_) {
                    // no-op
                }
            };
        } catch (_) {
            // no-op
        }
    }

    async acceptCall() {
        try {
            this.stopAllTones();
            this.clearOutgoingCallTimeout();
            // Request media permissions
            const constraints = {
                audio: true,
                video: this.callType === 'video'
            };
            
            this.localStream = await navigator.mediaDevices.getUserMedia(constraints);
            
            // Update call status
            await fetch('/api/communication/answer_call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    call_id: this.callId
                })
            });
            
            // Emit accept signal
            this.socket.emit('accept_call', {
                call_id: this.callId,
                receiver_id: this.activeChatUserId
            });
            
            // Setup peer connection (callee waits for offer)
            await this.ensurePeerConnection();
            
            // Show active call UI
            this.showCallUI(this.callType, 'active');
            
        } catch (error) {
            console.error('Error accepting call:', error);
            this.showError('Failed to accept call');
        }
    }

    async rejectCall() {
        try {
            this.stopAllTones();
            this.clearOutgoingCallTimeout();
            await fetch('/api/communication/reject_call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    call_id: this.callId
                })
            });
            
            this.socket.emit('reject_call', {
                call_id: this.callId,
                receiver_id: this.activeChatUserId
            });
            
            this.hideCallUI();
            this.cleanupCall();
            
        } catch (error) {
            console.error('Error rejecting call:', error);
        }
    }

    async endCall(reason) {
        try {
            this.stopAllTones();
            this.clearOutgoingCallTimeout();
            await fetch('/api/communication/end_call', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-CSRFToken': this.getCSRFToken()
                },
                body: JSON.stringify({
                    call_id: this.callId,
                    reason: reason || ''
                })
            });
            
            this.socket.emit('end_call', {
                call_id: this.callId,
                receiver_id: this.activeChatUserId
            });
            
            this.cleanupCall();
            
        } catch (error) {
            console.error('Error ending call:', error);
        }
    }

    handleCallAccepted(data) {
        this.stopAllTones();
        this.clearOutgoingCallTimeout();
        // Caller starts WebRTC offer after callee accepts
        this.startCallerWebRTC();
        this.showCallUI(this.callType, 'active');
    }

    handleCallRejected(data) {
        this.stopAllTones();
        this.clearOutgoingCallTimeout();
        this.showError('Call was rejected');
        this.cleanupCall();
    }

    handleCallEnded(data) {
        this.stopAllTones();
        this.clearOutgoingCallTimeout();
        this.cleanupCall();
    }

    handleCallFailed(data) {
        this.stopAllTones();
        this.clearOutgoingCallTimeout();
        const reason = (data && data.reason) ? String(data.reason) : 'failed';
        if (reason === 'offline') {
            this.showError('User is offline. Call failed.');
        } else {
            this.showError('Call failed.');
        }
        this.cleanupCall();
    }

    async fetchIceServers() {
        if (this._iceServersCache) return this._iceServersCache;
        try {
            const response = await fetch('/api/communication/ice_servers', {
                headers: { 'X-CSRFToken': this.getCSRFToken() }
            });
            if (response.ok) {
                const data = await response.json();
                if (data && Array.isArray(data.ice_servers) && data.ice_servers.length) {
                    this._iceServersCache = data.ice_servers;
                    return this._iceServersCache;
                }
            }
        } catch (e) {
            // fall back
        }
        this._iceServersCache = [
            { urls: 'stun:stun.l.google.com:19302' },
            { urls: 'stun:stun1.l.google.com:19302' }
        ];
        return this._iceServersCache;
    }

    async ensurePeerConnection() {
        if (this.peerConnection) return;

        const iceServers = await this.fetchIceServers();
        const configuration = { iceServers };

        this.peerConnection = new RTCPeerConnection(configuration);

        if (this.localStream) {
            this.localStream.getTracks().forEach(track => {
                this.peerConnection.addTrack(track, this.localStream);
            });
        }

        this.peerConnection.ontrack = (event) => {
            if (event.streams && event.streams[0]) {
                this.remoteStream = event.streams[0];
                const ct = String(this.callType || '').toLowerCase();
                const remoteVideo = document.getElementById('remote-video');
                if (remoteVideo) {
                    remoteVideo.srcObject = this.remoteStream;
                    try { remoteVideo.muted = (ct === 'voice'); } catch (_) {}
                    try { remoteVideo.play && remoteVideo.play().catch(() => {}); } catch (_) {}
                }

                // For voice calls, keep a dedicated audio element so audio isn't lost when the video UI is hidden.
                const remoteAudio = document.getElementById('remote-audio');
                if (remoteAudio) {
                    if (ct === 'voice') {
                        remoteAudio.srcObject = this.remoteStream;
                        try { remoteAudio.play && remoteAudio.play().catch(() => {}); } catch (_) {}
                    } else {
                        try { remoteAudio.pause && remoteAudio.pause(); } catch (_) {}
                        try { remoteAudio.srcObject = null; } catch (_) {}
                    }
                }
            }
        };

        this.peerConnection.onicecandidate = (event) => {
            if (event.candidate) {
                this.socket.emit('webrtc_ice_candidate', {
                    candidate: event.candidate,
                    receiver_id: this.activeChatUserId,
                    call_id: this.callId
                });
            }
        };
    }

    async startCallerWebRTC() {
        try {
            this._callRole = 'caller';
            await this.ensurePeerConnection();
            if (!this.peerConnection) return;

            const offer = await this.peerConnection.createOffer({
                offerToReceiveAudio: true,
                offerToReceiveVideo: this.callType === 'video'
            });
            await this.peerConnection.setLocalDescription(offer);

            this.socket.emit('webrtc_offer', {
                offer,
                receiver_id: this.activeChatUserId,
                call_id: this.callId
            });
        } catch (e) {
            console.error('Error starting caller WebRTC:', e);
            this.showError('WebRTC failed to start. Please try again.');
        }
    }

    async handleWebRTCOffer(data) {
        try {
            // Callee receives offer, creates answer
            if (!this.peerConnection) {
                await this.ensurePeerConnection();
            }
            if (!this.peerConnection) return;

            await this.peerConnection.setRemoteDescription(new RTCSessionDescription(data.offer));

            const answer = await this.peerConnection.createAnswer();
            await this.peerConnection.setLocalDescription(answer);

            this.socket.emit('webrtc_answer', {
                answer,
                receiver_id: data.caller_id,
                call_id: data.call_id || this.callId
            });
        } catch (e) {
            console.error('Error handling WebRTC offer:', e);
        }
    }

    async handleWebRTCAnswer(data) {
        if (this.peerConnection) {
            await this.peerConnection.setRemoteDescription(new RTCSessionDescription(data.answer));
        }
    }

    async handleWebRTCIceCandidate(data) {
        if (this.peerConnection && data.candidate) {
            try {
                await this.peerConnection.addIceCandidate(new RTCIceCandidate(data.candidate));
            } catch (error) {
                console.error('Error adding ICE candidate:', error);
            }
        }
    }

    showCallUI(type, status) {
        const callModal = document.getElementById('call-modal');
        const outgoingCall = document.getElementById('outgoing-call');
        const incomingCall = document.getElementById('incoming-call');
        const activeCall = document.getElementById('active-call');
        const videoContainer = document.getElementById('video-container');
        const voiceCallDisplay = document.getElementById('voice-call-display');
        const toggleVideoBtn = document.getElementById('toggle-video-btn');
        
        if (!callModal || !activeCall) return;
        
        callModal.style.display = 'flex';

        // Reset sections
        if (outgoingCall) outgoingCall.style.display = 'none';
        if (incomingCall) incomingCall.style.display = 'none';
        activeCall.style.display = 'none';
        
        if (status === 'outgoing') {
            if (outgoingCall) outgoingCall.style.display = 'block';
            const calleeName = document.getElementById('outgoing-callee-name');
            const outgoingStatus = document.getElementById('outgoing-call-status');
            if (calleeName) calleeName.textContent = this.currentUser?.username || 'User';
            if (outgoingStatus) outgoingStatus.textContent = type === 'video' ? 'Calling (video)...' : 'Calling...';

            // Render callee avatar (best-effort)
            try {
                const avatarBox = document.querySelector('#outgoing-call .caller-avatar');
                if (avatarBox) {
                    const picUrl = this._profilePicUrl(this.currentUser && this.currentUser.profile_picture);
                    avatarBox.innerHTML = picUrl
                        ? `<img src="${this.escapeHtml(picUrl)}" alt="" style="width:96px;height:96px;border-radius:50%;object-fit:cover;">`
                        : '<i class="bi bi-person-circle display-1"></i>';
                }
            } catch (_) {
                // no-op
            }
            return;
        }

        if (status === 'active') {
            activeCall.style.display = 'block';
            
            if (type === 'video') {
                videoContainer.style.display = 'block';
                voiceCallDisplay.style.display = 'none';
                toggleVideoBtn.style.display = 'block';
                
                // Set local video
                const localVideo = document.getElementById('local-video');
                if (localVideo && this.localStream) {
                    localVideo.srcObject = this.localStream;
                }
            } else {
                videoContainer.style.display = 'none';
                voiceCallDisplay.style.display = 'block';
                toggleVideoBtn.style.display = 'none';
                
                document.getElementById('active-caller-name').textContent = 
                    this.currentUser?.username || 'Unknown';

                // Best-effort avatar for voice calls
                try {
                    const avatarBox = voiceCallDisplay ? voiceCallDisplay.querySelector('.caller-avatar') : null;
                    if (avatarBox) {
                        const picUrl = this._profilePicUrl(this.currentUser && this.currentUser.profile_picture);
                        avatarBox.innerHTML = picUrl
                            ? `<img src="${this.escapeHtml(picUrl)}" alt="" style="width:96px;height:96px;border-radius:50%;object-fit:cover;">`
                            : '<i class="bi bi-person-circle display-1"></i>';
                    }
                } catch (_) {
                    // no-op
                }
            }
            
            // Start call duration timer
            this.startCallDurationTimer();
        }
    }

    hideCallUI() {
        const callModal = document.getElementById('call-modal');
        if (callModal) {
            callModal.style.display = 'none';
        }
    }

    startCallDurationTimer() {
        let seconds = 0;
        this.callDurationInterval = setInterval(() => {
            seconds++;
            const minutes = Math.floor(seconds / 60);
            const secs = seconds % 60;
            const durationText = `${String(minutes).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
            
            const durationElement = document.getElementById('call-duration');
            if (durationElement) {
                durationElement.textContent = durationText;
            }
        }, 1000);
    }

    toggleMute() {
        if (!this.localStream) return;
        
        const audioTrack = this.localStream.getAudioTracks()[0];
        if (audioTrack) {
            audioTrack.enabled = !audioTrack.enabled;
            this.isMuted = !audioTrack.enabled;
            
            const muteBtn = document.getElementById('mute-btn');
            if (muteBtn) {
                const icon = muteBtn.querySelector('i');
                if (icon) {
                    icon.className = this.isMuted ? 'bi bi-mic-mute-fill' : 'bi bi-mic-fill';
                }
            }
        }
    }

    toggleVideo() {
        if (!this.localStream) return;
        
        const videoTrack = this.localStream.getVideoTracks()[0];
        if (videoTrack) {
            videoTrack.enabled = !videoTrack.enabled;
            this.isVideoEnabled = videoTrack.enabled;
            
            const toggleVideoBtn = document.getElementById('toggle-video-btn');
            if (toggleVideoBtn) {
                const icon = toggleVideoBtn.querySelector('i');
                if (icon) {
                    icon.className = this.isVideoEnabled ? 'bi bi-camera-video-fill' : 'bi bi-camera-video-off-fill';
                }
            }
        }
    }

    cleanupCall() {
        this.stopAllTones();
        // Stop all tracks
        if (this.localStream) {
            this.localStream.getTracks().forEach(track => track.stop());
            this.localStream = null;
        }
        
        if (this.remoteStream) {
            this.remoteStream.getTracks().forEach(track => track.stop());
            this.remoteStream = null;
        }
        
        // Close peer connection
        if (this.peerConnection) {
            this.peerConnection.close();
            this.peerConnection = null;
        }
        
        // Clear call duration timer
        if (this.callDurationInterval) {
            clearInterval(this.callDurationInterval);
            this.callDurationInterval = null;
        }
        
        // Hide call UI
        this.hideCallUI();
        
        // Reset call state
        this.callId = null;
        this.callType = null;
        this._callRole = null;
        this.isMuted = false;
        this.isVideoEnabled = true;
    }

    _playToneSequence(steps, baseGain) {
        if (!this._audioContext) return;
        try {
            let t = this._audioContext.currentTime;
            (steps || []).forEach((step) => {
                const freq = Number(step.frequency || 440);
                const durationMs = Math.max(30, Number(step.durationMs || 120));
                const gapMs = Math.max(0, Number(step.gapMs || 0));
                const gain = (typeof step.gain === 'number') ? step.gain : baseGain;

                const osc = this._audioContext.createOscillator();
                const g = this._audioContext.createGain();

                osc.type = 'sine';
                osc.frequency.setValueAtTime(freq, t);

                // Small envelope to reduce clicks
                const start = t;
                const end = t + durationMs / 1000;
                const safeGain = Math.max(0.0001, Number(gain || 0.06));
                g.gain.setValueAtTime(0.0001, start);
                g.gain.exponentialRampToValueAtTime(safeGain, Math.min(end, start + 0.01));
                g.gain.exponentialRampToValueAtTime(0.0001, end);

                osc.connect(g);
                g.connect(this._audioContext.destination);

                osc.start(start);
                osc.stop(end + 0.02);

                t += (durationMs + gapMs) / 1000;
            });
        } catch (_) {
            // no-op
        }
    }

    playMessageTone(_message, opts = {}) {
        const s = this.getCommSettings();
        const force = !!opts.force;
        if (!force && !s.sounds_enabled) return;
        if (this.callId) return; // don't interrupt calls

        const toneId = String(opts.toneId || s.message_tone || 'chime');
        if (!toneId || toneId === 'none') return;

        if (toneId === 'pop') {
            this._playToneSequence([
                { frequency: 740, durationMs: 70, gapMs: 0 }
            ], 0.06);
            return;
        }

        if (toneId === 'beep') {
            this._playToneSequence([
                { frequency: 520, durationMs: 65, gapMs: 40 },
                { frequency: 520, durationMs: 65, gapMs: 0 }
            ], 0.05);
            return;
        }

        // Default: chime
        this._playToneSequence([
            { frequency: 880, durationMs: 85, gapMs: 55 },
            { frequency: 1320, durationMs: 120, gapMs: 0 }
        ], 0.055);
    }

    playRingtone(opts = {}) {
        const s = this.getCommSettings();
        const force = !!opts.force;
        if (!force && !s.sounds_enabled) return;

        const ringtoneId = String(opts.ringtoneId || s.call_ringtone || 'classic');
        if (!ringtoneId || ringtoneId === 'none') return;

        const patterns = {
            classic: { frequency: 440, onMs: 700, offMs: 1300, gain: 0.08 },
            fast: { frequency: 520, onMs: 350, offMs: 550, gain: 0.07 },
            slow: { frequency: 392, onMs: 900, offMs: 1700, gain: 0.08 }
        };

        this.stopAllTones();
        this._toneStopFn = this.startBeepPattern(patterns[ringtoneId] || patterns.classic);
    }

    playOutgoingTone() {
        const s = this.getCommSettings();
        if (!s.sounds_enabled) return;
        this.stopAllTones();
        this._toneStopFn = this.startBeepPattern({
            frequency: 480,
            onMs: 180,
            offMs: 180,
            gain: 0.05
        });
    }

    stopAllTones() {
        if (this._toneStopFn) {
            try { this._toneStopFn(); } catch (_) {}
            this._toneStopFn = null;
        }
    }

    startBeepPattern({ frequency, onMs, offMs, gain }) {
        if (!this._audioContext) return () => {};

        let stopped = false;
        let osc = null;
        let g = null;
        let timer = null;

        const startOsc = () => {
            if (stopped) return;
            try {
                osc = this._audioContext.createOscillator();
                g = this._audioContext.createGain();
                osc.type = 'sine';
                osc.frequency.value = frequency;
                g.gain.value = gain;
                osc.connect(g);
                g.connect(this._audioContext.destination);
                osc.start();
                timer = setTimeout(stopOsc, onMs);
            } catch (_) {
                // no-op
            }
        };

        const stopOsc = () => {
            if (stopped) return;
            try {
                if (osc) {
                    osc.stop();
                    osc.disconnect();
                    osc = null;
                }
                if (g) {
                    g.disconnect();
                    g = null;
                }
            } catch (_) {
                // no-op
            }
            timer = setTimeout(startOsc, offMs);
        };

        startOsc();

        return () => {
            stopped = true;
            if (timer) clearTimeout(timer);
            try {
                if (osc) {
                    osc.stop();
                    osc.disconnect();
                }
                if (g) g.disconnect();
            } catch (_) {}
        };
    }

    requestNotificationPermission() {
        if ('Notification' in window && Notification.permission === 'default') {
            Notification.requestPermission();
        }
    }

    showNotification(message) {
        const s = this.getCommSettings();
        if (!s.notifications_enabled) return;

        if (!('Notification' in window) || Notification.permission !== 'granted') return;

        const senderId = message ? Number(message.sender_id) : null;
        const cached = senderId ? this._usersCache.get(senderId) : null;
        const senderName = cached && cached.username ? String(cached.username) : '';

        const body = (message && message._was_e2e)
            ? '[Encrypted message]'
            : (message && message.content ? String(message.content) : '');

        const title = senderName ? `New message from ${senderName}` : 'New Message';
        const notification = new Notification(title, {
            body: body.length > 160 ? body.slice(0, 157) + '...' : body,
            icon: '/static/images/icon-192.png',
            badge: '/static/images/icon-192.png'
        });

        notification.onclick = () => {
            try { window.focus(); } catch (_) {}

            // Ensure the communication modal is visible (do not toggle closed).
            try {
                const modal = document.getElementById('communication-modal');
                if (modal) {
                    modal.style.display = 'flex';
                    modal.classList.remove('minimized');
                }
            } catch (_) {}

            // Open chat with sender (best-effort)
            const openSender = () => {
                const userItem = document.querySelector(`.user-item[data-user-id="${senderId}"]`);
                if (userItem) userItem.click();
            };

            openSender();
            if (senderId && !document.querySelector(`.user-item[data-user-id="${senderId}"]`)) {
                this.loadUsers().then(() => openSender()).catch(() => {});
            }
        };
    }

    showError(message) {
        // You can implement a better error display mechanism
        console.error(message);
        alert(message);
    }

    escapeHtml(text) {
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;'
        };
        return text.replace(/[&<>"']/g, m => map[m]);
    }

    getCSRFToken() {
        const meta = document.querySelector('meta[name="csrf-token"]');
        return meta ? meta.content : '';
    }

    _normalizeIsoForJs(dateString) {
        // Normalize common Python/SQL formats into an ISO string JS Date can parse reliably.
        // - Converts space to 'T'
        // - Truncates microseconds to milliseconds
        // - If no timezone info is present, assumes EAT (+03:00)
        if (typeof dateString !== 'string') return '';
        let s = dateString.trim();
        if (!s) return '';

        if (s.includes(' ') && !s.includes('T')) {
            s = s.replace(' ', 'T');
        }

        // Truncate fractional seconds to milliseconds (JS Date precision)
        s = s.replace(/\.(\d{3})\d+(?=(Z|[+-]\d{2}:?\d{2})?$)/, '.$1');

        const hasTz = /([zZ]|[+-]\d{2}:?\d{2})$/.test(s);
        const looksLikeIso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?$/.test(s);
        if (!hasTz && looksLikeIso) {
            s = `${s}+03:00`;
        }

        return s;
    }

    _parseServerDate(value) {
        if (!value) return null;
        if (value instanceof Date) return value;

        if (typeof value === 'number') return new Date(value);

        if (typeof value === 'string') {
            const trimmed = value.trim();
            if (!trimmed) return null;
            if (/^\d+$/.test(trimmed)) {
                return new Date(parseInt(trimmed, 10));
            }
            const normalized = this._normalizeIsoForJs(trimmed);
            const d = new Date(normalized || trimmed);
            return isNaN(d.getTime()) ? null : d;
        }

        try {
            const d = new Date(value);
            return isNaN(d.getTime()) ? null : d;
        } catch (_) {
            return null;
        }
    }

    formatTimeEAT(dateString) {
        /**
         * Format time to EAT (East Africa Time) timezone
         * Converts ISO timestamp to EAT and displays in 24-hour HH:MM format
         */
        try {
            const date = this._parseServerDate(dateString);
            if (!date) return '';
            
            // Get time in EAT timezone using Intl.DateTimeFormat
            const eatTime = new Intl.DateTimeFormat('en-GB', {
                timeZone: this.eatTimezone,
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            }).format(date);
            
            return eatTime;
        } catch (error) {
            console.error('Error formatting time:', error);
            // Fallback to local time if timezone conversion fails
            const date = this._parseServerDate(dateString) || new Date();
            const hours = date.getHours().toString().padStart(2, '0');
            const minutes = date.getMinutes().toString().padStart(2, '0');
            return `${hours}:${minutes}`;
        }
    }

    formatDateTimeEAT(dateString) {
        /**
         * Format full date and time to EAT timezone
         * Used for detailed timestamps
         */
        try {
            const date = this._parseServerDate(dateString);
            if (!date) return '';
            
            return date.toLocaleString('en-US', {
                timeZone: this.eatTimezone,
                year: 'numeric',
                month: 'short',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                hour12: false
            });
        } catch (error) {
            console.error('Error formatting datetime:', error);
            const d = this._parseServerDate(dateString);
            return d ? d.toLocaleString() : '';
        }
    }

    setupDragFunctionality() {
        const modal = document.getElementById('communication-modal');
        const dragHandle = document.getElementById('communication-drag-handle');
        
        if (!modal || !dragHandle) return;
        
        // Disable drag on mobile devices
        if (window.innerWidth <= 767) {
            return;
        }
        
        let isDragging = false;
        let currentX;
        let currentY;
        let initialX;
        let initialY;
        let xOffset = 0;
        let yOffset = 0;

        // Mouse events
        dragHandle.addEventListener('mousedown', dragStart);
        document.addEventListener('mousemove', drag);
        document.addEventListener('mouseup', dragEnd);

        // Touch events for tablets
        dragHandle.addEventListener('touchstart', touchStart, { passive: false });
        document.addEventListener('touchmove', touchMove, { passive: false });
        document.addEventListener('touchend', touchEnd);

        function dragStart(e) {
            // Don't drag if clicking on buttons or on mobile
            if (e.target.closest('button') || window.innerWidth <= 767) return;
            
            initialX = e.clientX - xOffset;
            initialY = e.clientY - yOffset;

            if (e.target === dragHandle || dragHandle.contains(e.target)) {
                isDragging = true;
            }
        }

        function touchStart(e) {
            // Don't drag on mobile
            if (window.innerWidth <= 767) return;
            if (e.target.closest('button')) return;

            const touch = e.touches[0];
            initialX = touch.clientX - xOffset;
            initialY = touch.clientY - yOffset;

            if (e.target === dragHandle || dragHandle.contains(e.target)) {
                isDragging = true;
            }
        }

        function drag(e) {
            if (isDragging && window.innerWidth > 767) {
                e.preventDefault();
                
                currentX = e.clientX - initialX;
                currentY = e.clientY - initialY;

                xOffset = currentX;
                yOffset = currentY;

                // Update modal position
                modal.style.transform = `translate(calc(-50% + ${currentX}px), calc(-50% + ${currentY}px))`;
            }
        }

        function touchMove(e) {
            if (isDragging && window.innerWidth > 767) {
                e.preventDefault();
                
                const touch = e.touches[0];
                currentX = touch.clientX - initialX;
                currentY = touch.clientY - initialY;

                xOffset = currentX;
                yOffset = currentY;

                // Update modal position
                modal.style.transform = `translate(calc(-50% + ${currentX}px), calc(-50% + ${currentY}px))`;
            }
        }

        function dragEnd(e) {
            initialX = currentX;
            initialY = currentY;
            isDragging = false;
        }

        function touchEnd(e) {
            dragEnd(e);
        }

        // Re-check on window resize
        window.addEventListener('resize', () => {
            if (window.innerWidth <= 767) {
                isDragging = false;
                // Reset position for mobile
                modal.style.transform = '';
            }
        });
    }
}

// Initialize communication system when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    window.communicationSystem = new CommunicationSystem();
});
