use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::Instant,
};

use crate::{
    network::PeerMapper,
    types::{SessionId, TssMessage},
    ecdsa::ECDSAPhase,
};

pub struct RetryMechanism {
    // Time to wait before requesting retry (in seconds)
    retry_timeout: u64,
    // Maximum retry attempts per participant
    max_retry_attempts: u8,
    // Track received messages per session/phase/round/participant
    received_messages: Arc<Mutex<HashMap<(SessionId, ECDSAPhase, u8, String), Instant>>>,
    // Track retry attempts per session/phase/round/participant
    retry_attempts: Arc<Mutex<HashMap<(SessionId, ECDSAPhase, u8, String), u8>>>,
    // Track when retry requests were sent per session/phase/round
    retry_request_timestamps: Arc<Mutex<HashMap<(SessionId, ECDSAPhase, u8), Instant>>>,
    // Track round start timestamps for timeout enforcement
    round_timestamps: Arc<Mutex<HashMap<(SessionId, ECDSAPhase, u8), Instant>>>,
    // Store sent messages for retry responses per session/phase/round/participant
    sent_messages: Arc<Mutex<HashMap<(SessionId, ECDSAPhase, u8, String), Vec<u8>>>>,
    // Enable/disable retry mechanism
    enabled: bool,
    // Local peer id
    local_peer_id: Vec<u8>,
}

impl RetryMechanism {
    pub fn new(
        retry_timeout: u64,
        max_retry_attempts: u8,
        enabled: bool,
        local_peer_id: Vec<u8>,
    ) -> Self {
        Self {
            retry_timeout,
            max_retry_attempts,
            received_messages: Arc::new(Mutex::new(HashMap::new())),
            retry_attempts: Arc::new(Mutex::new(HashMap::new())),
            retry_request_timestamps: Arc::new(Mutex::new(HashMap::new())),
            round_timestamps: Arc::new(Mutex::new(HashMap::new())),
            sent_messages: Arc::new(Mutex::new(HashMap::new())),
            enabled,
            local_peer_id,
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Track that we sent a message for a specific session/phase/round/participant
    pub fn track_sent_message(
        &self,
        session_id: SessionId,
        phase: ECDSAPhase,
        round: u8,
        participant_index: String,
        message_data: Vec<u8>,
    ) {
        if !self.enabled {
            return;
        }
        let key = (session_id, phase, round, participant_index);
        let mut sent_messages = self.sent_messages.lock().unwrap();
        sent_messages.insert(key, message_data);
    }

    /// Track that we received a message from a specific session/phase/round/participant
    pub fn track_received_message(
        &self,
        session_id: SessionId,
        phase: ECDSAPhase,
        round: u8,
        participant_index: String,
    ) {
        if !self.enabled {
            return;
        }
        let key = (session_id, phase, round, participant_index);
        let mut received_messages = self.received_messages.lock().unwrap();
        received_messages.insert(key, Instant::now());
    }

    /// Track when a round starts for timeout enforcement
    pub fn track_round_start(&self, session_id: SessionId, phase: ECDSAPhase, round: u8) {
        if !self.enabled {
            return;
        }
        let key = (session_id, phase, round);
        let mut round_timestamps = self.round_timestamps.lock().unwrap();
        round_timestamps.entry(key).or_insert_with(Instant::now);
    }

    /// Get expected participants from session data (all participants should participate in DKG)
    fn get_expected_participants(
        &self,
        session_id: SessionId,
        peer_mapper: &Arc<Mutex<PeerMapper>>,
    ) -> Vec<String> {
        let peer_mapper = peer_mapper.lock().unwrap();
        let session_participants = peer_mapper.sessions_participants_u16.lock().unwrap();

        if let Some(participants) = session_participants.get(&session_id) {
            participants.keys().map(|id| id.to_string()).collect()
        } else {
            Vec::new()
        }
    }

    /// Check for missing messages and trigger retry requests if needed
    pub fn check_and_request_retries(
        &self,
        session_id: SessionId,
        phase: ECDSAPhase,
        round: u8,
        peer_mapper: &Arc<Mutex<PeerMapper>>,
    ) -> Option<TssMessage> {
        if !self.enabled {
            return None;
        }

        let expected_participants = self.get_expected_participants(session_id, peer_mapper);

        if expected_participants.is_empty() {
            return None; // No participants found for this session
        }

        let mut missing_participants = Vec::new();
        let received_messages = self.received_messages.lock().unwrap();

        for participant in expected_participants.iter() {
            let message_key = (session_id, phase.clone(), round, participant.clone());
            if !received_messages.contains_key(&message_key) {
                missing_participants.push(participant.clone());
            }
        }
        drop(received_messages);

        if missing_participants.is_empty() {
            return None; // All participants have sent their messages
        }

        let should_retry = {
            let round_timestamps = self.round_timestamps.lock().unwrap();
            let round_key = (session_id, phase.clone(), round);
            if let Some(round_start) = round_timestamps.get(&round_key) {
                round_start.elapsed().as_secs() >= self.retry_timeout
            } else {
                false // Round hasn't started or timestamp not tracked
            }
        };

        if !should_retry {
            return None;
        }

        let should_send_retry = {
            let mut retry_timestamps = self.retry_request_timestamps.lock().unwrap();
            let key = (session_id, phase.clone(), round);
            if let Some(last_retry) = retry_timestamps.get(&key) {
                if last_retry.elapsed().as_secs() >= (self.retry_timeout / 2) {
                    retry_timestamps.insert(key, Instant::now());
                    true
                } else {
                    false
                }
            } else {
                retry_timestamps.insert(key, Instant::now());
                true
            }
        };

        if should_send_retry {
            log::info!(
                "[TSS] Requesting retries for session {} phase {:?} round {} from {} participants: {:?}",
                session_id,
                phase,
                round,
                missing_participants.len(),
                missing_participants
            );
            Some(TssMessage::ECDSARetryRequest(
                session_id,
                phase,
                round,
                missing_participants,
            ))
        } else {
            None
        }
    }

    /// Handle incoming retry request by resending our data if available
    pub fn handle_retry_request(
        &self,
        session_id: SessionId,
        phase: ECDSAPhase,
        round: u8,
        missing_participants: Vec<String>,
        peer_mapper: &Arc<Mutex<PeerMapper>>,
    ) -> Option<TssMessage> {
        if !self.enabled {
            return None;
        }

        let our_index = {
            let mut peer_mapper = peer_mapper.lock().unwrap();
            let peer_id = sc_network_types::PeerId::from_bytes(&self.local_peer_id).ok()?;
            peer_mapper
                .get_id_from_peer_id(&session_id, &peer_id)
                .map(|id| id.to_string())
        };

        let Some(our_index) = our_index else {
            return None; // We're not a participant in this session
        };

        if !missing_participants.contains(&our_index) {
            return None; // We're not being asked to retry
        }

        let retry_key = (session_id, phase.clone(), round, our_index.clone());
        let mut retry_attempts = self.retry_attempts.lock().unwrap();
        let count = retry_attempts.entry(retry_key).or_insert(0);

        if *count >= self.max_retry_attempts {
            log::warn!(
                "[TSS] Maximum retry attempts ({}) reached for session {} phase {:?} round {}",
                self.max_retry_attempts,
                session_id,
                phase,
                round
            );
            return None;
        }
        *count += 1;
        let retry_count = *count;
        drop(retry_attempts);

        log::info!(
            "[TSS] Handling retry request for session {} phase {:?} round {} (attempt {})",
            session_id,
            phase,
            round,
            retry_count
        );

        let message_key = (session_id, phase.clone(), round, our_index.clone());
        let stored_message = {
            let sent_messages = self.sent_messages.lock().unwrap();
            sent_messages.get(&message_key).cloned()
        };

        if let Some(message_data) = stored_message {
            log::info!(
                "[TSS] Found stored message, creating retry response for session {} phase {:?} round {}",
                session_id,
                phase,
                round
            );
            Some(TssMessage::ECDSARetryResponse(
                session_id,
                phase,
                round,
                our_index,
                message_data,
            ))
        } else {
            log::warn!(
                "[TSS] No stored message found for retry request - session {} phase {:?} round {}",
                session_id,
                phase,
                round
            );
            None
        }
    }

    /// Handle incoming retry response by processing the resent data
    pub fn handle_retry_response(
        &self,
        session_id: SessionId,
        phase: ECDSAPhase,
        round: u8,
        sender_index: String,
        message_data: Vec<u8>,
    ) -> Option<TssMessage> {
        if !self.enabled {
            return None;
        }

        log::info!(
            "[TSS] Received retry response for session {} phase {:?} round {} from participant {}",
            session_id,
            phase,
            round,
            sender_index
        );

        self.track_received_message(session_id, phase.clone(), round, sender_index.clone());

        match phase {
            ECDSAPhase::Key => Some(TssMessage::ECDSAMessageKeygen(
                session_id,
                sender_index,
                message_data,
            )),
            ECDSAPhase::Reshare => Some(TssMessage::ECDSAMessageReshare(
                session_id,
                sender_index,
                message_data,
            )),
            ECDSAPhase::Sign => Some(TssMessage::ECDSAMessageSign(
                session_id,
                sender_index,
                message_data,
            )),
            ECDSAPhase::SignOnline => Some(TssMessage::ECDSAMessageSignOnline(
                session_id,
                sender_index,
                message_data,
            )),
        }
    }

    pub fn set_retry_timeout(&mut self, retry_timeout_secs: u64) {
        self.retry_timeout = retry_timeout_secs;
        log::debug!("[TSS] Retry timeout set to {} seconds", retry_timeout_secs);
    }

    pub fn set_max_retry_attempts(&mut self, max_retry_attempts: u8) {
        self.max_retry_attempts = max_retry_attempts;
        log::debug!("[TSS] Max retry attempts set to {}", max_retry_attempts);
    }

}
