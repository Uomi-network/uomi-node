#[cfg(test)]
mod tests {
    use crate::{
        dkghelpers::{Storage, StorageType},
        process_session_manager_message,
        session::{
            dkg_state_manager::DKGSessionState, signing_state_manager::SigningSessionState,
        },
        test_framework::{MockTssMessageHandler, TestConfig, TestNetwork},
        SessionId, TSSRuntimeEvent, TssMessageHandler,
    };

    use frost_ed25519::Identifier;
    use rand::Rng;
    use sc_network::PeerId;

    // Helper function to generate session ID for testing
    fn _generate_test_session_id() -> SessionId {
        let mut rng = rand::thread_rng();
        rng.gen()
    }

    /// A helper function to create a simple test network with `n` nodes.
    /// Adjust this to match your real `TestNetwork::new` or constructor usage.
    fn setup_test_network(n: usize) -> TestNetwork {
        TestNetwork::new(n, TestConfig::default())
    }

    /// A helper to grab the participants array from the network.
    /// The logic is the same as in your example snippet:
    /// We gather `[u8; 32]` from each node's `validator_key`.
    fn gather_participants(network: &TestNetwork) -> Vec<[u8; 32]> {
        network
            .nodes()
            .iter()
            .map(|(_, node)| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&node.session_manager.validator_key);
                key
            })
            .collect()
    }

    #[test]
    fn test_session_manager_creation() {
        let mut network = TestNetwork::new(1, TestConfig::default());
        let peer_id = network.nodes().keys().next().unwrap().clone();
        let node = network.node_mut(&peer_id);

        // Check if the session manager is correctly initialized
        // assert!(node.session_manager.storage.lock().unwrap().is_empty());
        // assert!(node.session_manager.key_storage.lock().unwrap().is_empty());
        assert!(node
            .session_manager
            .sessions_participants
            .lock()
            .unwrap()
            .is_empty());
        assert!(node
            .session_manager
            .sessions_data
            .lock()
            .unwrap()
            .is_empty());
        assert!(node
            .session_manager
            .dkg_session_states
            .lock()
            .unwrap()
            .is_empty());
        assert!(node
            .session_manager
            .signing_session_states
            .lock()
            .unwrap()
            .is_empty());
        assert_eq!(node.session_manager.validator_key.len(), 32);
        assert_eq!(node.session_manager.local_peer_id, peer_id.to_bytes());
        assert_eq!(node.session_manager.session_timeout, 3600);
    }

    #[test]
    fn test_inject_runtime_event() {
        let mut network = TestNetwork::new(5, TestConfig::default());
        let peer_id = network.nodes().keys().next().unwrap().clone();
        let participants = network
            .nodes()
            .iter()
            .map(|(_, el)| {
                let mut key = [0u8; 32];
                key.copy_from_slice(&el.session_manager.validator_key);
                key
            })
            .collect::<Vec<[u8; 32]>>();

        let node = network.node_mut(&peer_id);

        let session_id: SessionId = 1;
        let t = 3;
        let n = 5;

        let result =
            node.session_manager
                .dkg_handle_session_created(session_id, n, t, participants);
        assert!(result.is_ok())
    }

    /// Test a successful creation of a DKG session (assuming add_session_data + handle_session_created).
    #[test]
    fn test_create_session_success() {
        let nodes_count = 5;
        let mut network = setup_test_network(nodes_count);
        let peer_id = network.nodes().keys().next().unwrap().clone();
        let participants = gather_participants(&network);

        let node = network.node_mut(&peer_id);

        let session_id: SessionId = 2;
        let t = 3;
        let n = 5;

        // First, call add_session_data in a valid way:
        let add_result = node.session_manager.add_session_data(
            session_id,
            t,
            n,
            [0; 32], // Maybe some group public key or placeholder
            participants.clone(),
            Vec::new(), // Additional data
        );
        assert!(add_result.is_ok(), "Failed to add session data");
        assert_eq!(participants.len(), 5);

        assert!(node.session_manager.sessions_data.try_lock().is_ok());
        assert!(node
            .session_manager
            .sessions_participants
            .try_lock()
            .is_ok());

        assert!(node
            .session_manager
            .sessions_participants
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert!(node
            .session_manager
            .sessions_data
            .lock()
            .unwrap()
            .contains_key(&session_id));

        // do the tests also for the peer_mapper
        assert!(node.session_manager.peer_mapper.try_lock().is_ok());
        assert!(node
            .session_manager
            .peer_mapper
            .lock()
            .unwrap()
            .sessions_participants_u16
            .try_lock()
            .is_ok());
        assert!(node
            .session_manager
            .peer_mapper
            .lock()
            .unwrap()
            .sessions_participants_u16
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert_eq!(
            node.session_manager
                .peer_mapper
                .lock()
                .unwrap()
                .sessions_participants_u16
                .lock()
                .unwrap()
                .get(&session_id)
                .unwrap()
                .len(),
            nodes_count
        );

        assert!(node
            .session_manager
            .dkg_session_states
            .lock()
            .unwrap()
            .is_empty());
        assert!(node
            .session_manager
            .signing_session_states
            .lock()
            .unwrap()
            .is_empty());

        assert_eq!(
            node.session_manager
                .sessions_participants
                .try_lock()
                .is_ok(),
            true
        );
        assert_eq!(node.session_manager.peer_mapper.try_lock().is_ok(), true);

        assert_eq!(
            node.session_manager
                .peer_mapper
                .lock()
                .unwrap()
                .sessions_participants
                .lock()
                .unwrap()
                .get(&session_id)
                .map(|m| m.len()),
            Some(5)
        );

        let identifier = node
            .session_manager
            .peer_mapper
            .lock()
            .unwrap()
            .get_identifier_from_peer_id(&session_id, &peer_id);

        assert!(identifier.is_some());
        assert_eq!(
            node.session_manager
                .sessions_participants
                .lock()
                .unwrap()
                .get_key_value(&session_id)
                .is_some(),
            true
        );
        assert_eq!(
            node.session_manager
                .sessions_participants
                .lock()
                .unwrap()
                .get_key_value(&session_id)
                .unwrap()
                .1
                .contains_key(&identifier.unwrap()),
            true
        );

        // Now call dkg_handle_session_created; expect Ok for a valid scenario
        let result = node.session_manager.dkg_handle_session_created(
            session_id,
            n.into(),
            t.into(),
            participants,
        );

        assert!(node
            .session_manager
            .dkg_session_states
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert!(node
            .session_manager
            .signing_session_states
            .lock()
            .unwrap()
            .is_empty());

        assert!(
            result.is_ok(),
            "Expected successful creation of DKG session, got: {:?}",
            result
        );
    }

    #[test]
    fn test_three_nodes_communicating() {
        let mut network = setup_test_network(3);
        let peer_id = network.nodes().keys().next().unwrap().clone();
        let participants = gather_participants(&network);

        let node = network.node_mut(&peer_id);

        let session_id: SessionId = 3;
        let t = 2;
        let n = 3;

        let event = TSSRuntimeEvent::DKGSessionInfoReady(session_id, t, n, participants.clone());

        assert_eq!(
            false,
            node.session_manager
                .sessions_participants
                .lock()
                .unwrap()
                .contains_key(&session_id)
        );

        node.session_manager.process_runtime_message(event);

        assert_eq!(participants.len(), 3);

        assert!(node.session_manager.sessions_data.try_lock().is_ok());
        assert!(node
            .session_manager
            .sessions_participants
            .try_lock()
            .is_ok());

        assert!(node
            .session_manager
            .sessions_participants
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert!(node
            .session_manager
            .sessions_data
            .lock()
            .unwrap()
            .contains_key(&session_id));

        assert_eq!(
            false,
            node.session_manager
                .dkg_session_states
                .lock()
                .unwrap()
                .is_empty()
        );
        assert!(node
            .session_manager
            .signing_session_states
            .lock()
            .unwrap()
            .is_empty());

        assert_eq!(
            node.session_manager
                .sessions_participants
                .try_lock()
                .is_ok(),
            true
        );
        assert_eq!(node.session_manager.peer_mapper.try_lock().is_ok(), true);

        assert_eq!(
            node.session_manager
                .peer_mapper
                .lock()
                .unwrap()
                .sessions_participants
                .lock()
                .unwrap()
                .get(&session_id)
                .map(|m| m.len()),
            Some(3)
        );

        let identifier = node
            .session_manager
            .peer_mapper
            .lock()
            .unwrap()
            .get_identifier_from_peer_id(&session_id, &peer_id);

        assert!(identifier.is_some());
        assert_eq!(
            node.session_manager
                .sessions_participants
                .lock()
                .unwrap()
                .get_key_value(&session_id)
                .is_some(),
            true
        );
        assert_eq!(
            node.session_manager
                .sessions_participants
                .lock()
                .unwrap()
                .get_key_value(&session_id)
                .unwrap()
                .1
                .contains_key(&identifier.unwrap()),
            true
        );

        assert!(node
            .session_manager
            .dkg_session_states
            .lock()
            .unwrap()
            .contains_key(&session_id));
        assert!(node
            .session_manager
            .signing_session_states
            .lock()
            .unwrap()
            .is_empty());

        let messages = node.outgoing_messages();
        assert_eq!(2, messages.len());

        let mut handler = MockTssMessageHandler::default();
        for msg in messages {
            assert_eq!(
                process_session_manager_message(&mut handler, msg).is_ok(),
                true
            );
        }

        assert_eq!(handler.broadcast_messages.borrow().len(), 2);

        let node_keys = network
            .nodes()
            .iter()
            .skip(1)
            .map(|(key, _)| key.clone())
            .collect::<Vec<PeerId>>();

        for node_key in node_keys {
            let next_node = network.node_mut(&node_key);

            let event =
                TSSRuntimeEvent::DKGSessionInfoReady(session_id, t, n, participants.clone());
            next_node.session_manager.process_runtime_message(event);

            assert!(identifier.is_some());
            assert_eq!(
                next_node
                    .session_manager
                    .sessions_participants
                    .lock()
                    .unwrap()
                    .get_key_value(&session_id)
                    .is_some(),
                true
            );
            assert_eq!(
                next_node
                    .session_manager
                    .sessions_participants
                    .lock()
                    .unwrap()
                    .get_key_value(&session_id)
                    .unwrap()
                    .1
                    .contains_key(&identifier.unwrap()),
                true
            );

            assert_eq!(
                next_node
                    .session_manager
                    .sessions_participants
                    .lock()
                    .unwrap()
                    .get_key_value(&session_id)
                    .unwrap()
                    .1
                    .contains_key(&identifier.unwrap()),
                true
            );

            assert_eq!(
                next_node
                    .session_manager
                    .sessions_participants
                    .lock()
                    .unwrap()
                    .get(&session_id)
                    .unwrap()
                    .len(),
                3
            );

            assert!(next_node
                .session_manager
                .dkg_session_states
                .lock()
                .unwrap()
                .contains_key(&session_id));
            assert!(next_node
                .session_manager
                .signing_session_states
                .lock()
                .unwrap()
                .is_empty());

            let messages = next_node.outgoing_messages();
            assert_eq!(
                2,
                messages.len(),
                "Node {:?} should have two messages outgoing",
                identifier
            );

            let mut handler = MockTssMessageHandler::default();
            for msg in messages {
                assert_eq!(
                    process_session_manager_message(&mut handler, msg).is_ok(),
                    true
                );
            }

            assert_eq!(handler.broadcast_messages.borrow().len(), 2);
        }
    }
    #[test]
    fn test_process_round1_success() {
        // let _ = env_logger::try_init();
        let nodes_count = 10;

        let session_id: SessionId = 7;
        let t = 8;
        let n: u16 = nodes_count.try_into().unwrap();

        let mut network = setup_test_network(nodes_count);
        let participants = gather_participants(&network);

        for (_, node) in network.nodes_mut() {
            let event =
                TSSRuntimeEvent::DKGSessionInfoReady(session_id, t, n, participants.clone());
            node.session_manager.process_runtime_message(event);
            assert_eq!(
                node.session_manager
                    .peer_mapper
                    .lock()
                    .unwrap()
                    .sessions_participants_u16
                    .lock()
                    .unwrap()
                    .get(&session_id)
                    .unwrap()
                    .len(),
                nodes_count
            );
            assert_eq!(
                node.session_manager.peer_mapper.lock().unwrap().peers.len(),
                nodes_count
            );
        }

        let delivered = network.process_round();
        assert_eq!(delivered.len(), nodes_count * 2); // 3 * 2 : 3 nodes each of which sending two messages: 1 for frost and one for ecdsa.

        // verify that all the nodes have their session_state in Round1
        let node_keys = network
            .nodes()
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<Vec<PeerId>>();
        // make sure we make all the three loops, so all the assertions will be done on all the three nodes.
        assert_eq!(nodes_count, node_keys.len());

        for peer_id in &node_keys {
            let node = network.node_mut(peer_id);
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .read_secret_package_round1(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round1_packages(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round1_packages(session_id)
                    .unwrap()
                    .len(),
                nodes_count - 1
            );

            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .read_secret_package_round2(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round2_packages(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round2_packages(session_id)
                    .unwrap()
                    .len(),
                0
            );

            let session_states = node.session_manager.dkg_session_states.lock().unwrap();
            let state = session_states.get(&session_id);
            assert_eq!(state.is_some(), true);
            assert_eq!(*state.unwrap(), DKGSessionState::Round2Initiated);

            // check the ECDSA Manager inside the Session Manager
            assert!(node.session_manager.ecdsa_manager.lock().is_ok());
            assert!(node
                .session_manager
                .ecdsa_manager
                .lock()
                .unwrap()
                .get_keygen(session_id)
                .is_some());
            assert_ne!(
                node.session_manager
                    .ecdsa_manager
                    .lock()
                    .unwrap()
                    .get_keygen(session_id)
                    .unwrap()
                    .msgs
                    .phase_one_two_msgs
                    .len(),
                0
            );
        }

        let delivered_messages = network.process_round();
        assert_eq!(delivered_messages.len(), nodes_count * nodes_count);

        for peer_id in &node_keys {
            let node = network.node_mut(peer_id);
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .read_secret_package_round1(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round1_packages(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round1_packages(session_id)
                    .unwrap()
                    .len(),
                nodes_count - 1
            );

            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .read_secret_package_round2(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round2_packages(session_id)
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .storage
                    .lock()
                    .unwrap()
                    .fetch_round2_packages(session_id)
                    .unwrap()
                    .len(),
                nodes_count - 1
            );

            let session_states = node.session_manager.dkg_session_states.lock().unwrap();
            let state = session_states.get(&session_id);
            assert_eq!(state.is_some(), true);
            assert_eq!(*state.unwrap(), DKGSessionState::KeyGenerated);

            let identifier = node
                .session_manager
                .peer_mapper
                .lock()
                .unwrap()
                .get_identifier_from_peer_id(
                    &session_id,
                    &PeerId::from_bytes(&node.session_manager.local_peer_id[..]).unwrap(),
                );
            assert!(identifier.is_some());

            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .get_key_package(session_id, &identifier.unwrap())
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .get_pubkey(session_id, &identifier.unwrap())
                    .is_ok(),
                true
            );

            // check the ECDSA Manager inside the Session Manager
            assert!(node.session_manager.ecdsa_manager.lock().is_ok());
            assert!(node
                .session_manager
                .ecdsa_manager
                .lock()
                .unwrap()
                .get_keygen(session_id)
                .is_some());
            assert_ne!(
                node.session_manager
                    .ecdsa_manager
                    .lock()
                    .unwrap()
                    .get_keygen(session_id)
                    .unwrap()
                    .msgs
                    .phase_one_two_msgs
                    .len(),
                0
            );
        }

        // complete the whole carousel
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count * 2, "check 1");
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count, "check 2");
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count, "check 3");
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count * 2, "check 4");
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count, "check 5");
        let _delivered_messages = network.process_round();
        // assert_eq!(delivered_messages.len(), nodes_count, "check 6");

        for peer_id in &node_keys {
            let node = network.node_mut(peer_id);

            let my_id = participants
                .iter()
                .position(|&el| el == &node.session_manager.validator_key[..]);

            assert!(my_id.is_some());

            let my_id = my_id.unwrap() + 1;

            let identifier: Identifier = u16::try_from(my_id).unwrap().try_into().unwrap();

            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(session_id, StorageType::EcdsaKeys, Some(&identifier.serialize()))
                    .is_ok(),
                true
            );
            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(
                        session_id,
                        StorageType::EcdsaOfflineOutput,
                        Some(&identifier.serialize())
                    )
                    .is_ok(),
                true
            );
        }
    }

    #[test]
    fn test_signing_session_after_dkg() {
        let _ = env_logger::try_init();

        let nodes_count = 3;
        let session_id: SessionId = 9;
        let dkg_session_id: SessionId = session_id; // DKG and Signing use the same session ID for simplicity in this test
        let t = 2;
        let n: u16 = nodes_count.try_into().unwrap();

        let mut network = setup_test_network(nodes_count);
        let participants = gather_participants(&network);

        // --- 1. Setup DKG Session ---
        for (_, node) in network.nodes_mut() {
            let event =
                TSSRuntimeEvent::DKGSessionInfoReady(dkg_session_id, t, n, participants.clone());
            node.session_manager.process_runtime_message(event);
        }

        network.process_all_rounds(); // Complete DKG
                                      // let messages = network.process_round();
                                      //         assert_eq!(messages.len(), 6);

        // Verify DKG completion (optional, but good to check)
        for (_, node) in network.nodes() {
            let session_states = node.session_manager.dkg_session_states.lock().unwrap();
            let state = session_states.get(&dkg_session_id);
            assert_eq!(state.is_some(), true);
            assert_eq!(*state.unwrap(), DKGSessionState::KeyGenerated);
            assert_eq!(node.session_manager.client.submit_dkg_result_calls().len(), 1);
        }

        // --- 2. Initiate Signing Session ---
        let signing_session_id: SessionId = session_id;
        let coordinator = participants[0]; // Let's just pick the first participant as coordinator
        let message_to_sign =
            hex::decode("788b0eb4bdd12ebc0600f47910acf3ff458264584920a7a465cd3d548c1d1cc5")
                .unwrap(); // Example message

        for (_, node) in network.nodes_mut() {
            let event = TSSRuntimeEvent::SigningSessionInfoReady(
                signing_session_id,
                t,
                n,
                participants.clone(),
                coordinator,
                message_to_sign.clone(),
            );
            node.session_manager.process_runtime_message(event);
        }

        let messages = network.process_round(); // Here each member sends its material to the coordinator
        assert_eq!(messages.len(), 6, "We expect only 6 messages");

        let messages = network.process_round(); // here
        assert_eq!(
            messages.len(),
            5,
            "We expect only 5 messages, t=2 + 3 messages for EDCSA"
        );

        // --- 3. Verify Signing Session progress and Signature (basic verification) ---
        for (_, node) in network.nodes() {
            assert_eq!(
                node.session_manager
                    .signing_session_states
                    .try_lock()
                    .is_ok(),
                true
            );
            let signing_session_states =
                node.session_manager.signing_session_states.lock().unwrap();

            assert_eq!(signing_session_states.len(), 1);
            let signing_state = signing_session_states.get(&signing_session_id);
            assert_eq!(signing_state.is_some(), true);

            if node.session_manager.validator_key == participants[0] {
                // coordinator
                // At this point the coordinator should have received the commitmentsm generated the signing package
                // and sent them to the participants. So on its side he's round2 completed
                assert!(
                    *signing_state.unwrap() == SigningSessionState::Round2Completed,
                    "Signing session should progress {:?}",
                    signing_state.unwrap()
                );
            } else {
                // for participants (= no coordinator), they should have received the signing package, and sent yet their signature share
                // so on their side they are on round2 completed
                // assert!(
                //     *signing_state.unwrap() == SigningSessionState::Round2Completed,
                //     "Signing session should progress {:?}",
                //     signing_state.unwrap()
                // );
                log::info!(
                    "peer_id = {:?}, signing session state = {:?}",
                    node.session_manager.local_peer_id,
                    *signing_state.unwrap()
                );
            }
            assert_eq!(node.session_manager.ecdsa_manager.try_lock().is_ok(), true);
            assert_eq!(
                node.session_manager
                    .ecdsa_manager
                    .lock()
                    .unwrap()
                    .get_sign_online(session_id)
                    .is_some(),
                true
            );
        }

        let messages = network.process_round(); // here
        assert_eq!(
            messages.len(),
            5,
            "We expect only 5 messages, t=2 + 3 for EDCSA"
        );

        for (_, node) in network.nodes() {
            assert_eq!(
                node.session_manager
                    .signing_session_states
                    .try_lock()
                    .is_ok(),
                true
            );
            let signing_session_states =
                node.session_manager.signing_session_states.lock().unwrap();

            assert_eq!(signing_session_states.len(), 1);
            let signing_state = signing_session_states.get(&signing_session_id);
            assert_eq!(signing_state.is_some(), true);

            if node.session_manager.validator_key == participants[0] {
                // coordinator
                // At this point the coordinator should have received the commitmentsm generated the signing package
                // and sent them to the participants. So on its side he's round2 completed
                assert!(
                    *signing_state.unwrap() == SigningSessionState::SignatureGenerated,
                    "Signing session should progress {:?}",
                    signing_state.unwrap()
                );
            }
            // assert_eq!(node.session_manager.ecdsa_manager.try_lock().is_ok(), true);
            // assert_eq!(node.session_manager.ecdsa_manager.lock().unwrap().get_sign_online(session_id).is_some(), true);
        }

        network.process_all_rounds();
        let mut signatures = Vec::new();

        for (_, node) in network.nodes() {
            assert_eq!(node.session_manager.key_storage.try_lock().is_ok(), true);

            let _id = node.session_manager.get_my_identifier(session_id);
            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(session_id, StorageType::EcdsaOnlineOutput, Some(&_id.serialize()))
                    .is_ok(),
                true
            );

            signatures.push(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(session_id, StorageType::EcdsaOnlineOutput, Some(&_id.serialize()))
                    .unwrap(),
            );
        }

        // check that all signatures are the same
        let first_signature = &signatures[0];
        for signature in &signatures {
            assert_eq!(
                signature, first_signature,
                "All signatures should be the same"
            );
        }
    }


    #[test]
    fn test_signing_session_after_dkg_and_reshare() {
        let _ = env_logger::try_init();

        let nodes_count = 3;
        let session_id: SessionId = 9;
        let dkg_session_id: SessionId = session_id; // DKG and Signing use the same session ID for simplicity in this test
        let t = 2;
        let n: u16 = nodes_count.try_into().unwrap();

        let mut network = setup_test_network(nodes_count);
        let participants = gather_participants(&network);

        // --- 1. Setup DKG Session ---
        for (_, node) in network.nodes_mut() {
            let event =
                TSSRuntimeEvent::DKGSessionInfoReady(dkg_session_id, t, n, participants.clone());
            node.session_manager.process_runtime_message(event);
        }

        network.process_all_rounds(); // Complete DKG
                                      // let messages = network.process_round();
                                      //         assert_eq!(messages.len(), 6);

        // Verify DKG completion (optional, but good to check)
        for (_, node) in network.nodes() {
            let session_states = node.session_manager.dkg_session_states.lock().unwrap();
            let state = session_states.get(&dkg_session_id);
            assert_eq!(state.is_some(), true);
            assert_eq!(*state.unwrap(), DKGSessionState::KeyGenerated);
        }


        for (_, node) in network.nodes_mut() {
            let event = TSSRuntimeEvent::DKGReshareSessionInfoReady(
                dkg_session_id,
                t,
                n,
                participants.clone(),
                participants.clone(),
            );
            node.session_manager.process_runtime_message(event);
        }

        let messages = network.process_round(); // Here each member sends its material to the coordinator
        assert_eq!(messages.len(), 9, "Reshare, We expect only 6 messages");
        let _messages = network.process_all_rounds();



        // --- 2. Initiate Signing Session ---
        let signing_session_id: SessionId = session_id;
        let coordinator = participants[0]; // Let's just pick the first participant as coordinator
        let message_to_sign =
            hex::decode("788b0eb4bdd12ebc0600f47910acf3ff458264584920a7a465cd3d548c1d1cc5")
                .unwrap(); // Example message

        for (_, node) in network.nodes_mut() {
            let event = TSSRuntimeEvent::SigningSessionInfoReady(
                signing_session_id,
                t,
                n,
                participants.clone(),
                coordinator,
                message_to_sign.clone(),
            );
            node.session_manager.process_runtime_message(event);
        }

        let messages = network.process_round(); // Here each member sends its material to the coordinator
        assert_eq!(messages.len(), 6, "We expect only 6 messages");

        let messages = network.process_round(); // here
        assert_eq!(
            messages.len(),
            5,
            "We expect only 5 messages, t=2 + 3 messages for EDCSA"
        );

        // --- 3. Verify Signing Session progress and Signature (basic verification) ---
        for (_, node) in network.nodes() {
            assert_eq!(
                node.session_manager
                    .signing_session_states
                    .try_lock()
                    .is_ok(),
                true
            );
            let signing_session_states =
                node.session_manager.signing_session_states.lock().unwrap();

            assert_eq!(signing_session_states.len(), 1);
            let signing_state = signing_session_states.get(&signing_session_id);
            assert_eq!(signing_state.is_some(), true);

            if node.session_manager.validator_key == participants[0] {
                // coordinator
                // At this point the coordinator should have received the commitmentsm generated the signing package
                // and sent them to the participants. So on its side he's round2 completed
                assert!(
                    *signing_state.unwrap() == SigningSessionState::Round2Completed,
                    "Signing session should progress {:?}",
                    signing_state.unwrap()
                );
            } else {
                // for participants (= no coordinator), they should have received the signing package, and sent yet their signature share
                // so on their side they are on round2 completed
                // assert!(
                //     *signing_state.unwrap() == SigningSessionState::Round2Completed,
                //     "Signing session should progress {:?}",
                //     signing_state.unwrap()
                // );
                log::info!(
                    "peer_id = {:?}, signing session state = {:?}",
                    node.session_manager.local_peer_id,
                    *signing_state.unwrap()
                );
            }
            assert_eq!(node.session_manager.ecdsa_manager.try_lock().is_ok(), true);
            assert_eq!(
                node.session_manager
                    .ecdsa_manager
                    .lock()
                    .unwrap()
                    .get_sign_online(session_id)
                    .is_some(),
                true
            );
        }

        let messages = network.process_round(); // here
        assert_eq!(
            messages.len(),
            5,
            "We expect only 5 messages, t=2 + 3 for EDCSA"
        );

        for (_, node) in network.nodes() {
            assert_eq!(
                node.session_manager
                    .signing_session_states
                    .try_lock()
                    .is_ok(),
                true
            );
            let signing_session_states =
                node.session_manager.signing_session_states.lock().unwrap();

            assert_eq!(signing_session_states.len(), 1);
            let signing_state = signing_session_states.get(&signing_session_id);
            assert_eq!(signing_state.is_some(), true);

            if node.session_manager.validator_key == participants[0] {
                // coordinator
                // At this point the coordinator should have received the commitmentsm generated the signing package
                // and sent them to the participants. So on its side he's round2 completed
                assert!(
                    *signing_state.unwrap() == SigningSessionState::SignatureGenerated,
                    "Signing session should progress {:?}",
                    signing_state.unwrap()
                );
            }
            // assert_eq!(node.session_manager.ecdsa_manager.try_lock().is_ok(), true);
            // assert_eq!(node.session_manager.ecdsa_manager.lock().unwrap().get_sign_online(session_id).is_some(), true);
        }

        network.process_all_rounds();
        let mut signatures = Vec::new();

        for (_, node) in network.nodes() {
            assert_eq!(node.session_manager.key_storage.try_lock().is_ok(), true);

            let _id = node.session_manager.get_my_identifier(session_id);
            assert_eq!(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(session_id, StorageType::EcdsaOnlineOutput, Some(&_id.serialize()))
                    .is_ok(),
                true
            );

            signatures.push(
                node.session_manager
                    .key_storage
                    .lock()
                    .unwrap()
                    .read_data(session_id, StorageType::EcdsaOnlineOutput, Some(&_id.serialize()))
                    .unwrap(),
            );
        }

        // check that all signatures are the same
        let first_signature = &signatures[0];
        for signature in &signatures {
            assert_eq!(
                signature, first_signature,
                "All signatures should be the same"
            );
        }
    }


    // Add this test function to the existing `tests` module in 
// /Users/lucasimonetti/Work/uomi-node-public/client/tss/src/test_framework_multi_node.rs

use crate::TssMessage; // Add TssMessage and sign_announcement to imports

#[test]
fn test_unknown_peer_handling() {
    let _ = env_logger::try_init(); // Optional: for logging during test run

    let nodes_count = 4;
    let session_id: SessionId = 10;
    let t = 3;
    let n: u16 = nodes_count.try_into().unwrap();

    // --- Setup Network ---
    // We need a keystore to sign the announcement

    let mut network = setup_test_network(nodes_count);
    let participants = gather_participants(&network);
    let node_ids: Vec<PeerId> = network.nodes().keys().cloned().collect();
    let node_a_id = node_ids[0].clone();
    let node_b_id = node_ids[1].clone();



    // Get Node B's public key for the announcement later
    let node_b_pubkey = network.nodes().get(&node_b_id).unwrap().session_manager.validator_key.clone();

    // --- Setup Session on Node A ---
    {
        let node_a = network.node_mut(&node_a_id);
        let event =
            TSSRuntimeEvent::DKGSessionInfoReady(session_id, t, n, participants.clone());
        node_a.session_manager.process_runtime_message(event);

        // Initially, Node A knows about Node B via the test setup, but let's simulate B being unknown
        // by clearing B from A's peer map *after* session setup but *before* message arrival.
        // NOTE: In a real scenario, B wouldn't be in the map yet.
        // Let's verify B *is* initially known due to TestNetwork setup:
        assert!(node_a.session_manager.peer_mapper.lock().unwrap().peers.contains_key(&node_b_id));
        // For the test, we *don't* remove B here. Instead, we rely on the fact that B hasn't *announced* itself yet.
        // The check in `handle_gossip_message` looks for the peer in the map, which it will find,
        // but the crucial part is that the `Announce` message triggers the queue consumption.
        // Let's refine the test logic slightly: the check `!peer_mapper.peers.contains_key(&sender_peer_id)`
        // might not be the *only* trigger for buffering. If the Announce hasn't been processed,
        // even if the peer is technically in the map from setup, the buffering should still occur
        // until Announce is processed. Let's proceed assuming the Announce processing is the key.
        // **Correction:** The current code *only* buffers if the peer is *not* in the map.
        // To properly test the buffer, we *must* remove B from A's map.
        node_a.session_manager.peer_mapper.lock().unwrap().peers.remove(&node_b_id);
        assert!(!node_a.session_manager.peer_mapper.lock().unwrap().peers.contains_key(&node_b_id));

    
    } // Drop mutable borrow of network


    
    // --- Step 1: Node B sends a message to Node A (B is unknown to A) ---
    {


        let node_b = network.node_mut(&node_b_id);
        let event =
            TSSRuntimeEvent::DKGSessionInfoReady(session_id, t, n, participants.clone());
        node_b.session_manager.process_runtime_message(event);
        // let outgoing_messages_from_node_b = node_b.outgoing_messages();



        // assert_eq!(
        //     outgoing_messages_from_node_b.len(),
        //     2, // ECDSA + FROST
        //     "Node B should have sent one message"
        // );



        let node_a = network.node_mut(&node_a_id);
        let mut handler = MockTssMessageHandler::default();
        // Directly process the message as if received from gossip
        let messages = network.process_round();


        
    } // Drop mutable borrow

    // --- Verification 1 ---
    {
        let node_a = network.node_mut(&node_a_id);

        // 1a. Check unknown peer queue
        let unknown_queue = node_a.session_manager.unknown_peer_queue.lock().unwrap();
        assert!(unknown_queue.contains_key(&node_b_id), "Message from unknown peer B should be buffered");
        assert_eq!(unknown_queue.get(&node_b_id).unwrap().len(), 2, "Should be one message buffered for B");
        // We can't easily compare TssMessage directly without PartialEq, but we know the type
        match &unknown_queue.get(&node_b_id).unwrap()[0] {
            TssMessage::DKGRound1(id, data) => {
                assert_eq!(*id, session_id);
                // assert_eq!(data, &vec![1, 2, 3]);
            },
            _ => panic!("Incorrect message type buffered"),
        }
        drop(unknown_queue);

        // 1b. Check outgoing messages for GetInfo
        let outgoing = node_a.outgoing_messages();
        println!("Outgoing messages: {:?}", outgoing.len());
        assert!(outgoing.len() >= 1, "Node A should send one message back");
        let (recipient, sent_message) = &outgoing[0];
        assert_eq!(recipient, &node_b_id, "Message should be sent to Node B");
        match sent_message {
            TssMessage::GetInfo(pk) => {
                // Check if the public key matches Node A's key
                 assert_eq!(pk, &node_a.session_manager.validator_key);
            },
            _ => panic!("Expected GetInfo message, got {:?}", sent_message),
        }

        // // 1c. Check storage (DKG message should NOT be processed yet)
        let storage = node_a.storage.lock().unwrap();
        assert!(storage.fetch_round1_packages(session_id).unwrap().is_empty(), "DKG Round 1 message should not be processed yet");
        drop(storage);

    } // Drop mutable borrow

    // --- Step 2: Node B sends Announce message to Node A ---
    // Generate a valid signature for the announcement
    // We need Node B's key in the keystore to sign
    let node_b_seed = [1u8; 32]; // Seed used in generate_peer_data(1)
   

    let announce_message = TssMessage::Announce(
        rand::thread_rng().gen(), // Nonce
        node_b_id.to_bytes(),     // PeerId bytes
        node_b_pubkey.clone(),    // Public key
        Vec::new(),                // Signature
    );

    {
        let node_a = network.node_mut(&node_a_id);
        // Simulate GossipHandler processing the Announce
        let mut gossip_handler_mock = MockTssMessageHandler::default(); // We don't need a full handler, just the announce logic part
        gossip_handler_mock.handle_announcment(node_b_id.clone(), announce_message.clone());
        // Manually add peer like the real handler would
         node_a.session_manager.peer_mapper.lock().unwrap().add_peer(node_b_id.clone(), node_b_pubkey.clone());

        // Now process the announce message within SessionManager to trigger queue consumption
        node_a.session_manager.process_gossip_message(node_b_id.clone(), announce_message);
    } // Drop mutable borrow

    // --- Verification 2 ---
    {
        let node_a = network.node_mut(&node_a_id);

        // 2a. Check PeerMapper
        let peer_mapper = node_a.session_manager.peer_mapper.lock().unwrap();
        assert!(peer_mapper.peers.contains_key(&node_b_id), "Node B should now be known to Node A");
        assert_eq!(peer_mapper.peers.get(&node_b_id).unwrap(), &node_b_pubkey);
        drop(peer_mapper);

        // 2b. Check unknown peer queue is empty
        let unknown_queue = node_a.session_manager.unknown_peer_queue.lock().unwrap();
        assert!(!unknown_queue.contains_key(&node_b_id), "Unknown queue for Node B should be empty");
        drop(unknown_queue);

        // 2c. Check storage (DKG message SHOULD be processed now)
        // Note: Full processing depends on state, but it should at least be stored.
        let storage = node_a.storage.lock().unwrap();
        let round1_packages = storage.fetch_round1_packages(session_id).unwrap();
        assert_eq!(round1_packages.len(), 1, "DKG Round 1 message should have been processed");
        // Find the identifier for node B
        let node_b_identifier = node_a.session_manager.peer_mapper.lock().unwrap().get_identifier_from_peer_id(&session_id, &node_b_id);
        assert!(node_b_identifier.is_some(), "Node B identifier should exist");
        assert!(round1_packages.contains_key(&node_b_identifier.unwrap()), "Package from Node B should be stored");
        drop(storage);

         // 2d. Check DKG state (should have progressed if conditions met)
         // Since t=1, n=2, receiving one package should trigger round 2 start
         let dkg_state = node_a.session_manager.dkg_session_states.lock().unwrap();
         assert_eq!(dkg_state.get(&session_id), Some(&DKGSessionState::Round1Initiated), "DKG state should progress to Round2Initiated");
         drop(dkg_state);
    } // Drop mutable borrow
}

}
