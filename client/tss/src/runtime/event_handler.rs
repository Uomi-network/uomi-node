use std::marker::PhantomData;
use std::sync::Arc;

use codec::{Compact, Decode};
use frame_system::EventRecord;
use sc_client_api::{BlockchainEvents, HeaderBackend};
use sc_utils::mpsc::TracingUnboundedSender;
use sp_api::ProvideRuntimeApi;
use sp_runtime::traits::Block as BlockT;
use futures::StreamExt;

use uomi_runtime::{
    pallet_tss::{Event as TssEvent, TssApi},
    RuntimeEvent
};

use crate::types::TSSRuntimeEvent;

/// Handles runtime events from the blockchain and forwards them to the session manager
pub struct RuntimeEventHandler<B: BlockT, C>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
{
    client: Arc<C>,
    sender: TracingUnboundedSender<TSSRuntimeEvent>,
    _phantom: PhantomData<B>,
}

impl<B: BlockT, C> RuntimeEventHandler<B, C>
where
    C: BlockchainEvents<B> + ProvideRuntimeApi<B> + Send + Sync + 'static,
    C::Api: uomi_runtime::pallet_tss::TssApi<B>,
{
    /// Create a new RuntimeEventHandler
    pub fn new(client: Arc<C>, sender: TracingUnboundedSender<TSSRuntimeEvent>) -> Self {
        Self {
            client,
            sender,
            _phantom: PhantomData,
        }
    }

    /// Start listening for runtime events and processing them
    pub async fn run(self) {
        log::info!("[TSS] Listening for messages from Runtime");
        let notification_stream = self.client.storage_changes_notification_stream(None, None);

        if let Err(error) = notification_stream {
            log::error!("[TSS] Error acquiring notification stream {:?}", error);
            return;
        }

        let mut notification_stream = notification_stream.unwrap();

        while let Some(event) = notification_stream.next().await {
            let hash = event.block;
            let events_key = sp_core::twox_128("System".as_bytes()).to_vec();
            let events_storage_key =
                [events_key, sp_core::twox_128("Events".as_bytes()).to_vec()].concat();

            for (_parent_key, key, value) in event.changes.iter() {
                if key.as_ref().starts_with(&events_storage_key[..]) {
                    if let Some(data) = value {
                        self.process_events_data(hash, &data.0).await;
                    }
                }
            }
        }
    }

    /// Process the raw events data from storage
    async fn process_events_data(&self, hash: B::Hash, raw_bytes: &[u8]) {
        let mut cursor = &raw_bytes[..];
        let num_events_compact =
            Compact::<u32>::decode(&mut cursor).unwrap_or(Compact(0));
        let num_events = num_events_compact.0;

        for _i in 0..num_events {
            match EventRecord::<RuntimeEvent, B::Hash>::decode(&mut cursor) {
                Ok(event_record) => {
                    self.handle_runtime_event(hash, event_record.event).await;
                }
                Err(e) => {
                    log::error!("[TSS] Error decoding event: {:?}", e);
                }
            }
        }
    }

    /// Handle a specific runtime event
    async fn handle_runtime_event(&self, hash: B::Hash, event: RuntimeEvent) {
        match event {
            RuntimeEvent::Tss(TssEvent::DKGSessionCreated(id)) => {
                self.handle_dkg_session_created(hash, id).await;
            }
            RuntimeEvent::Tss(TssEvent::DKGReshareSessionCreated(id)) => {
                self.handle_dkg_reshare_session_created(hash, id).await;
            }
            RuntimeEvent::Tss(TssEvent::SigningSessionCreated(signing_session_id, dkg_session_id)) => {
                self.handle_signing_session_created(hash, signing_session_id, dkg_session_id).await;
            }
            RuntimeEvent::Tss(TssEvent::ValidatorIdAssigned(account_id, id)) => {
                self.handle_validator_id_assigned(account_id, id).await;
            }
            _ => (),
        }
    }

    /// Handle DKG session creation event
    async fn handle_dkg_session_created(&self, hash: B::Hash, id: u64) {
        let n = self
            .client
            .runtime_api()
            .get_dkg_session_participants_count(hash, id)
            .unwrap();
        let t = self
            .client
            .runtime_api()
            .get_dkg_session_threshold(hash, id)
            .unwrap();

        // t is a percentage value, convert it to the actual threshold value
        let t = (t as f64 * n as f64 / 100.0) as u16;

        let participants = self
            .client
            .runtime_api()
            .get_dkg_session_participants(hash, id)
            .unwrap_or(Vec::new());

        // Notify the session manager about the new DKG Session
        if let Err(e) = self.sender.unbounded_send(
            TSSRuntimeEvent::DKGSessionInfoReady(
                id,
                u16::try_from(t).unwrap_or(u16::MAX),
                n,
                participants,
            ),
        ) {
            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
        }
    }

    /// Handle DKG reshare session creation event
    async fn handle_dkg_reshare_session_created(&self, hash: B::Hash, id: u64) {
        let n = self
            .client
            .runtime_api()
            .get_dkg_session_participants_count(hash, id)
            .unwrap();
        let t = self
            .client
            .runtime_api()
            .get_dkg_session_threshold(hash, id)
            .unwrap();

        // t is a percentage value, convert it to the actual threshold value
        let t = (t as f64 * n as f64 / 100.0) as u16;

        let participants = self
            .client
            .runtime_api()
            .get_dkg_session_participants(hash, id)
            .unwrap_or(Vec::new());

        let old_participants = self
            .client
            .runtime_api()
            .get_dkg_session_old_participants(hash, id)
            .unwrap_or(Vec::new());

        // Notify the session manager about the new DKG Reshare Session
        if let Err(e) = self.sender.unbounded_send(
            TSSRuntimeEvent::DKGReshareSessionInfoReady(
                id,
                u16::try_from(t).unwrap_or(u16::MAX),
                n,
                participants,
                old_participants,
            ),
        ) {
            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
        }
    }

    /// Handle signing session creation event
    async fn handle_signing_session_created(&self, hash: B::Hash, signing_session_id: u64, dkg_session_id: u64) {
        log::debug!("[TSS] Starting signing session {:?} using DKG session {:?}", signing_session_id, dkg_session_id);
        
        let n = self
            .client
            .runtime_api()
            .get_dkg_session_participants_count(hash, dkg_session_id)
            .unwrap();
        let t = self
            .client
            .runtime_api()
            .get_dkg_session_threshold(hash, dkg_session_id)
            .unwrap();

        // t is a percentage value, convert it to the actual threshold value
        let t = (t as f64 * n as f64 / 100.0) as u16;

        let participants = self
            .client
            .runtime_api()
            .get_dkg_session_participants(hash, dkg_session_id)
            .unwrap_or(Vec::new());

        let message = self
            .client
            .runtime_api()
            .get_signing_session_message(hash, dkg_session_id)
            .unwrap_or(Vec::new());

        // TODO: add the function in the pallet for these three:
        let coordinator = participants[0];
        let id = dkg_session_id;

        // Notify the session manager about the new Signing Session
        if let Err(e) = self.sender.unbounded_send(
            TSSRuntimeEvent::SigningSessionInfoReady(
                id,
                u16::try_from(t).unwrap_or(u16::MAX),
                n,
                participants,
                coordinator,
                message
            ),
        ) {
            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
        }
    }

    /// Handle validator ID assignment event
    async fn handle_validator_id_assigned(&self, account_id: uomi_runtime::AccountId, id: u32) {
        if let Err(e) = self.sender.unbounded_send(
            TSSRuntimeEvent::ValidatorIdAssigned(account_id.into(), id),
        ) {
            log::error!("[TSS] There was a problem communicating with the TSS Session Manager {:?}", e);
        }
    }
}
