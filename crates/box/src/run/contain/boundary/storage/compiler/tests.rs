use super::*;

#[test]
fn compiler_frames_preserve_authority_role_index_and_manifest_binding() {
    let (sender, receiver) = UnixStream::pair().expect("socket pair");
    send_json(
        &sender,
        &WorkerMessage::Verify {
            authority: Authority::Installation,
            descriptor: 3,
            digest: [42; 32],
        },
    )
    .expect("send request");
    match receive_json::<WorkerMessage>(&receiver).expect("receive request") {
        WorkerMessage::Verify {
            authority: Authority::Installation,
            descriptor,
            digest,
        } => {
            assert_eq!(descriptor, 3);
            assert_eq!(digest, [42; 32]);
        }
        other => panic!("unexpected message: {other:?}"),
    }
    send_json(&receiver, &OwnerReply::Verified {}).expect("send reply");
    assert!(matches!(
        receive_json::<OwnerReply>(&sender).expect("receive reply"),
        OwnerReply::Verified {}
    ));
}

#[test]
fn compiler_frames_reject_oversized_and_truncated_messages() {
    let (mut sender, receiver) = UnixStream::pair().expect("socket pair");
    sender
        .write_all(&((FRAME_LIMIT + 1) as u32).to_be_bytes())
        .expect("oversized header");
    assert!(receive_json::<WorkerMessage>(&receiver).is_err());

    let (mut sender, receiver) = UnixStream::pair().expect("socket pair");
    sender.write_all(&32_u32.to_be_bytes()).expect("header");
    sender.write_all(b"short").expect("partial body");
    drop(sender);
    assert!(receive_json::<WorkerMessage>(&receiver).is_err());
}

#[test]
fn compiler_frames_reject_unknown_fields_and_unexpected_reply_types() {
    let (sender, receiver) = UnixStream::pair().expect("socket pair");
    send_json(
        &sender,
        &serde_json::json!({"type":"verified", "ignored":"not allowed"}),
    )
    .expect("frame");
    assert!(receive_json::<OwnerReply>(&receiver).is_err());
    send_json(
        &sender,
        &serde_json::json!({"type":"refused", "message":"reason", "ignored":"not allowed"}),
    )
    .expect("refusal frame");
    assert!(receive_json::<OwnerReply>(&receiver).is_err());
    send_json(&sender, &serde_json::json!({"type":"verify", "authority":"commands", "descriptor":0, "digest":vec![0_u8;32], "ignored":"not allowed"})).expect("verification frame");
    assert!(receive_json::<WorkerMessage>(&receiver).is_err());
    send_json(&sender, &OwnerReply::Verified {}).expect("reply frame");
    assert!(receive_json::<WorkerMessage>(&receiver).is_err());
}

#[test]
fn compiler_descriptor_transfer_retains_identity_and_sets_close_on_exec() {
    let (sender, receiver) = UnixStream::pair().expect("socket pair");
    let original = tempfile::tempfile().expect("file");
    let expected = ObjectIdentity::capture(&original).expect("identity");
    send_fd(&sender, &original).expect("send original pin");
    let received =
        File::from(containment::storage::receive_fd(&receiver).expect("received descriptor"));
    expected.verify(&received).expect("same object");
    // SAFETY: inspect flags on this live test descriptor.
    assert_ne!(
        unsafe { libc::fcntl(received.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
        0
    );
    let wrong = tempfile::tempfile().expect("wrong object");
    assert!(expected.verify(&wrong).is_err());
}

#[test]
fn compiler_callback_returns_owner_rejection_and_closed_channel_errors() {
    let (worker, host) = UnixStream::pair().expect("socket pair");
    worker
        .set_read_timeout(Some(Duration::from_secs(1)))
        .expect("timeout");
    let server = std::thread::spawn(move || {
        assert!(matches!(
            receive_json::<WorkerMessage>(&host).expect("request"),
            WorkerMessage::Verify {
                authority: Authority::Commands,
                descriptor: 7,
                ..
            }
        ));
        send_json(
            &host,
            &OwnerReply::Refused {
                message: "original mode changed".into(),
            },
        )
        .expect("refusal");
    });
    let owner = RemoteOwner {
        authority: Authority::Commands,
        control: Arc::new(Mutex::new(worker)),
    };
    assert!(commands::OwnerVerifier::verify(&owner, 7, [1; 32]).is_err());
    server.join().expect("server");
    assert!(commands::OwnerVerifier::verify(&owner, 7, [1; 32]).is_err());
}

#[test]
fn compiler_child_guard_kills_and_reaps_failed_worker() {
    let child = Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .expect("test worker");
    let pid = child.id() as libc::pid_t;
    drop(ChildGuard::new(child));
    let mut status = 0;
    // SAFETY: WNOHANG observes this test's child after its guard already reaped it.
    assert_eq!(
        unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn compiler_child_guard_accepts_only_successful_exit() {
    let mut success = ChildGuard::new(
        Command::new("/bin/true")
            .spawn()
            .expect("successful worker"),
    );
    success.finish().expect("successful exit");
    assert!(success.0.is_none());
    let mut failure = ChildGuard::new(Command::new("/bin/false").spawn().expect("failed worker"));
    assert!(failure.finish().is_err());
}

#[test]
fn compiler_cancellation_interrupts_waiting_controller_channel() {
    let cancel = Arc::new(Cancellation::default());
    let (parent, _worker) = UnixStream::pair().expect("socket pair");
    cancel.track(&parent).expect("cancellation registration");
    let blocked = std::thread::spawn(move || receive_json::<WorkerMessage>(&parent));
    cancel.cancel();
    assert!(blocked.join().expect("waiting controller").is_err());
}

#[test]
fn compiler_registration_releases_completed_socket_before_box_cancellation() {
    let cancel = Cancellation::default();
    let (parent, worker) = UnixStream::pair().expect("socket pair");
    let registration = cancel.track(&parent).expect("registration");
    drop(CancellationRegistration {
        cancel: &cancel,
        registration,
    });
    cancel.cancel();
    send_json(&parent, &OwnerReply::Verified {})
        .expect("completed compiler socket is no longer cancelled");
    assert!(matches!(
        receive_json::<OwnerReply>(&worker).expect("still connected"),
        OwnerReply::Verified {}
    ));
}

#[test]
fn cancellation_classifies_only_expected_interrupted_socket_io() {
    let cancel = Cancellation::default();
    let eof = || TransportError::Io(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
    assert!(
        !owner_error(eof(), &cancel).is_storage_cancelled(),
        "unexpected worker EOF remains a real failure"
    );
    cancel.cancel();
    for kind in [
        std::io::ErrorKind::Interrupted,
        std::io::ErrorKind::UnexpectedEof,
        std::io::ErrorKind::BrokenPipe,
        std::io::ErrorKind::ConnectionReset,
        std::io::ErrorKind::ConnectionAborted,
        std::io::ErrorKind::NotConnected,
    ] {
        assert!(
            owner_error(TransportError::Io(std::io::Error::from(kind)), &cancel)
                .is_storage_cancelled()
        );
    }
    assert!(
        !owner_error(
            TransportError::Io(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
            &cancel
        )
        .is_storage_cancelled(),
        "an expired transfer timeout is not an interrupted socket"
    );
    assert!(
        !owner_error(
            TransportError::Invalid(failure("invalid captured policy")),
            &cancel
        )
        .is_storage_cancelled(),
        "validation failure survives concurrent cancellation"
    );
    let (sender, receiver) = UnixStream::pair().expect("socket pair");
    send_json(&sender, &serde_json::json!({"type":"not-a-worker-message"}))
        .expect("malformed frame");
    let malformed = receive_json::<WorkerMessage>(&receiver).expect_err("invalid message");
    assert!(
        !owner_error(malformed, &cancel).is_storage_cancelled(),
        "parse failure survives concurrent cancellation"
    );
}
