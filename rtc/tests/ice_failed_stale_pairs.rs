/// Regression test: the ICE agent used to panic when a peer-reflexive
/// candidate was discovered after the Checking timeout had silently expired.
///
/// Historical crash path (rtc-ice/src/agent/mod.rs `handle_inbound`):
///   1. ICE agent is in Checking state; timeout has elapsed but hasn't been
///      detected yet (handle_timeout was not called)
///   2. A STUN binding request arrives from an address not in remote_candidates
///   3. handle_inbound creates a peer-reflexive candidate via add_remote_candidate
///   4. add_remote_candidate → request_connectivity_check → contact()
///   5. contact() detected the expired timeout → Failed → cleared candidate vectors
///   6. Back in handle_inbound: `self.remote_candidates.len() - 1` underflowed
///      ("subtract with overflow" in debug; stale-index access in release).
///
/// Fix: `request_connectivity_check` now only sets `pending_connectivity_check`
/// so the next `handle_timeout` tick runs `contact` outside the inbound call
/// stack. `delete_all_candidates_and_pairs` also clears `candidate_pairs` and
/// `selected_pair`, so no stale indices can survive a Failed transition.
///
/// After the fix this test verifies that the offerer transitions cleanly to
/// `RTCIceConnectionState::Failed` instead of panicking.
///
/// Trigger: the answer peer's candidate is added AFTER the SDP exchange so the
/// offer peer doesn't know the answer's address. When the answer's STUN packets
/// arrive, find_remote_candidate returns None → peer-reflexive path.
use bytes::BytesMut;
use sansio::Protocol;
use shared::{TaggedBytesMut, TransportContext, TransportProtocol};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;

use rtc::peer_connection::RTCPeerConnectionBuilder;
use rtc::peer_connection::configuration::RTCConfigurationBuilder;
use rtc::peer_connection::configuration::setting_engine::SettingEngine;
use rtc::peer_connection::event::RTCPeerConnectionEvent;
use rtc::peer_connection::state::RTCIceConnectionState;
use rtc::peer_connection::transport::RTCDtlsRole;
use rtc::peer_connection::transport::RTCIceCandidateInit;
use rtc::peer_connection::transport::{CandidateConfig, CandidateHostConfig, RTCIceCandidate};

#[tokio::test]
async fn test_ice_transitions_to_failed_when_peer_reflexive_discovered_after_checking_timeout() {
    let disconnected_timeout = Duration::from_secs(1);
    let failed_timeout = Duration::from_secs(1);
    let checking_timeout = disconnected_timeout + failed_timeout;

    // --- Offer peer ---
    let offer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let offer_addr = offer_socket.local_addr().unwrap();

    let mut offer_se = SettingEngine::default();
    offer_se
        .set_answering_dtls_role(RTCDtlsRole::Server)
        .unwrap();
    offer_se.set_ice_timeouts(Some(disconnected_timeout), Some(failed_timeout), None);

    let mut offer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(offer_se)
        .build()
        .unwrap();

    offer_pc.create_data_channel("ch", None).unwrap();
    let host = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: offer_addr.ip().to_string(),
            port: offer_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    offer_pc
        .add_local_candidate(
            RTCIceCandidate::from(&host.new_candidate_host().unwrap())
                .to_json()
                .unwrap(),
        )
        .unwrap();

    let offer = offer_pc.create_offer(None).unwrap();
    offer_pc.set_local_description(offer.clone()).unwrap();

    // --- Answer peer ---
    let answer_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let answer_addr = answer_socket.local_addr().unwrap();

    let mut answer_se = SettingEngine::default();
    answer_se
        .set_answering_dtls_role(RTCDtlsRole::Client)
        .unwrap();
    answer_se.set_ice_timeouts(Some(disconnected_timeout), Some(failed_timeout), None);

    let mut answer_pc = RTCPeerConnectionBuilder::new()
        .with_configuration(RTCConfigurationBuilder::new().build())
        .with_setting_engine(answer_se)
        .build()
        .unwrap();
    answer_pc.set_remote_description(offer).unwrap();

    // Create the answer BEFORE adding the answer's local candidate so that
    // the SDP does NOT contain the answer's address. The offer peer will not
    // know this address → STUN from it triggers the peer-reflexive path.
    let answer = answer_pc.create_answer(None).unwrap();
    answer_pc.set_local_description(answer.clone()).unwrap();
    offer_pc.set_remote_description(answer).unwrap();
    // ^^^ start_transports → start_connectivity_checks → Checking; timer starts.

    // Add candidates AFTER SDP exchange (trickle ICE style)
    let host = CandidateHostConfig {
        base_config: CandidateConfig {
            network: "udp".to_owned(),
            address: answer_addr.ip().to_string(),
            port: answer_addr.port(),
            component: 1,
            ..Default::default()
        },
        ..Default::default()
    };
    answer_pc
        .add_local_candidate(
            RTCIceCandidate::from(&host.new_candidate_host().unwrap())
                .to_json()
                .unwrap(),
        )
        .unwrap();
    answer_pc
        .add_remote_candidate(RTCIceCandidateInit {
            candidate: format!(
                "candidate:1 1 udp 2130706431 {} {} typ host",
                offer_addr.ip(),
                offer_addr.port()
            ),
            ..Default::default()
        })
        .unwrap();

    // Let the offerer tick its timer ONCE so its ICE agent records the
    // moment it entered Checking (`checking_duration`). Without this the
    // checking timer never starts, and the later "expired timeout"
    // premise of this test doesn't hold.
    offer_pc.handle_timeout(Instant::now()).ok();
    while offer_pc.poll_write().is_some() {}
    while offer_pc.poll_event().is_some() {}

    // --- Drive the answer peer until the checking timeout expires ---
    // The answer peer sends STUN binding requests to the offer socket.
    // We capture them but do NOT call handle_timeout on the offer peer
    // again, so its checking timeout expires silently.
    let mut captured = Vec::new();
    let mut buf = vec![0u8; 2000];
    let start = Instant::now();

    while start.elapsed() < checking_timeout + Duration::from_millis(500) {
        // Drive the answer peer
        while let Some(msg) = answer_pc.poll_write() {
            answer_socket
                .send_to(&msg.message, msg.transport.peer_addr)
                .await
                .ok();
        }
        while answer_pc.poll_event().is_some() {}
        while answer_pc.poll_read().is_some() {}
        answer_pc.handle_timeout(Instant::now()).ok();

        // Drain the offer peer (but NO handle_timeout!)
        while offer_pc.poll_write().is_some() {}
        while offer_pc.poll_event().is_some() {}
        while offer_pc.poll_read().is_some() {}

        // Capture STUN packets arriving at the offer socket
        while let Ok((n, addr)) = offer_socket.try_recv_from(&mut buf) {
            captured.push((BytesMut::from(&buf[..n]), addr));
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    assert!(
        !captured.is_empty(),
        "need at least one STUN packet from answer"
    );

    // Drain any events queued on the offerer before this point so we only
    // observe the state change triggered below.
    let mut last_ice_state = None;
    while let Some(evt) = offer_pc.poll_event() {
        if let RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) = evt {
            last_ice_state = Some(state);
        }
    }

    // --- Deliver a captured STUN packet to the offer peer ---
    // The offer's ICE is in Checking with an expired timeout. handle_inbound
    // discovers a peer-reflexive candidate and marks pending_connectivity_check
    // so the next handle_timeout tick runs contact outside the inbound call
    // stack. The subsequent handle_timeout then notices the expired checking
    // timeout and transitions the agent to Failed cleanly.
    let (pkt, peer) = captured.last().unwrap();
    offer_pc
        .handle_read(TaggedBytesMut {
            now: Instant::now(),
            transport: TransportContext {
                local_addr: offer_addr,
                peer_addr: *peer,
                ecn: None,
                transport_protocol: TransportProtocol::UDP,
            },
            message: pkt.clone(),
        })
        .ok();

    // Drive the offer peer so the deferred contact runs, detects the expired
    // checking timeout, transitions to Failed, and propagates the state change
    // through the rtc handler chain into peer-connection events.
    for _ in 0..10 {
        offer_pc.handle_timeout(Instant::now()).ok();
        while offer_pc.poll_write().is_some() {}
        while offer_pc.poll_read().is_some() {}
        while let Some(evt) = offer_pc.poll_event() {
            if let RTCPeerConnectionEvent::OnIceConnectionStateChangeEvent(state) = evt {
                last_ice_state = Some(state);
            }
        }
        if last_ice_state == Some(RTCIceConnectionState::Failed) {
            break;
        }
    }

    assert_eq!(
        last_ice_state,
        Some(RTCIceConnectionState::Failed),
        "offerer should transition to ICE Failed after peer-reflexive discovery on expired checking timeout",
    );
}
