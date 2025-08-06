use crate::{
    client::ClientManager,
    ecdsa::ECDSAPhase,
    types::{SessionId},
    SessionManager,
};
use sp_runtime::traits::Block as BlockT;
use log::{info};


impl<B: BlockT, C: ClientManager<B>> SessionManager<B, C> {
    /// Configure retry mechanism parameters
    pub fn configure_retry_mechanism(&mut self, retry_timeout_secs: u64, max_retry_attempts: u8) {
        self.retry_mechanism.set_retry_timeout(retry_timeout_secs);
        self.retry_mechanism.set_max_retry_attempts(max_retry_attempts);
        info!("[TSS] Retry mechanism configured: timeout={}s, max_attempts={}", 
            retry_timeout_secs, max_retry_attempts);
    }

    /// Check all active sessions for missing messages and trigger retry requests
    pub fn check_all_sessions_for_retries(&self) {
        // Get all active sessions from session data
        let active_sessions: Vec<SessionId> = {
            let sessions_data = self.session_core.sessions_data.lock().unwrap();
            sessions_data.keys().cloned().collect()
        };
        
        for session_id in active_sessions {
            // Only check sessions that haven't timed out yet
            if !self.is_session_timed_out(&session_id) {
                // Check all ECDSA phases and assume round 0 for simplicity
                // In practice, you'd track the current round for each phase
                for phase in [ECDSAPhase::Key, ECDSAPhase::Reshare, ECDSAPhase::Sign, ECDSAPhase::SignOnline] {
                    self.retry_mechanism.check_and_request_retries(session_id, phase, 0, &self.session_core.peer_mapper);
                }
            }
        }
    }
}
