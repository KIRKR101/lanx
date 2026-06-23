//! End-to-end transfer integration tests over in-process TCP. These
//! cover the happy path, resume, and corrupt-chunk re-fetch scenarios
//! from `plan.md` §13.

use lanx_core::destinations::resolve_destinations;
use lanx_core::manifest::{build, rel_to_path, FileEntry, FileId, Manifest, DEFAULT_CHUNK_SIZE};
use lanx_core::progress::NoopProgress;
use lanx_core::resume::plan as resume_plan;
use lanx_core::transfer::receiver::run_receiver;
use lanx_core::transfer::sender::{run_sender, SenderConfig};
use lanx_core::transfer::{
    read_frame, write_frame, ControlMsg, HelloInfo, ProtocolError, DEFAULT_MAX_RETRIES,
    PROTOCOL_VERSION,
};
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

async fn pair() -> (tokio::task::JoinHandle<()>, TcpStream, TcpStream) {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let client = TcpStream::connect(addr).await.unwrap();
    let (server, _) = l.accept().await.unwrap();
    let handle = tokio::spawn(async move {
        drop(l);
    });
    (handle, server, client)
}

fn sources_from_manifest(m: &Manifest) -> HashMap<FileId, PathBuf> {
    // Reconstruct source paths from `source_root` + rel_path. The
    // forward-slash wire form needs to be converted back to a
    // platform-native PathBuf via rel_to_path so a folder name with a
    // space doesn't get re-tokenized on Windows.
    m.files
        .iter()
        .map(|f| (f.id, m.source_root.join(rel_to_path(&f.rel_path))))
        .collect()
}

fn build_manifest_for(src_dir: &std::path::Path) -> Manifest {
    build(&[src_dir.to_path_buf()], DEFAULT_CHUNK_SIZE).unwrap()
}

#[tokio::test]
async fn single_file_clean_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dst = tmp.path().join("dst");
    let dst_for_recv = dst.clone();

    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        let (mut sr, mut sw) = tokio::io::split(server);
        run_sender(
            &mut sr,
            &mut sw,
            &m_send,
            &sources_send,
            &NoopProgress,
            &SenderConfig::default(),
        )
        .await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 1);

    let dests = resolve_destinations(&m, &dst).unwrap();
    let read = std::fs::read(dests.paths[&0].clone()).unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn multi_file_transfer() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    for i in 0..3u32 {
        let p = src.join(format!("f{i}.bin"));
        let data: Vec<u8> = (0..(50_000 + i * 10_000))
            .map(|j| ((j + i) & 0xFF) as u8)
            .collect();
        std::fs::write(p, &data).unwrap();
    }
    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dst_for_recv = dst.clone();

    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            run_sender(
                &mut sr,
                &mut sw,
                &m_send,
                &sources_send,
                &NoopProgress,
                &SenderConfig::default(),
            )
            .await
        }
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 3);

    let dests = resolve_destinations(&m, &dst).unwrap();
    for f in &m.files {
        let read = std::fs::read(dests.paths[&f.id].clone()).unwrap();
        let src_data = std::fs::read(m.source_root.join(rel_to_path(&f.rel_path))).unwrap();
        assert_eq!(read, src_data);
    }
}

#[tokio::test]
async fn resume_after_corruption() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..5_000_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dest_path = resolve_destinations(&m, &dst).unwrap().paths[&0].clone();
    if let Some(p) = dest_path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    let partial = {
        let mut v = data[..(DEFAULT_CHUNK_SIZE as usize * 3)].to_vec();
        v.extend_from_slice(&vec![0u8; DEFAULT_CHUNK_SIZE as usize]);
        v
    };
    std::fs::write(&dest_path, &partial).unwrap();

    let dests = resolve_destinations(&m, &dst).unwrap();
    let plan = resume_plan(&m, &dests).unwrap();
    assert_eq!(plan.offsets[&0], (DEFAULT_CHUNK_SIZE as u64) * 3);

    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            run_sender(
                &mut sr,
                &mut sw,
                &m_send,
                &sources_send,
                &NoopProgress,
                &SenderConfig::default(),
            )
            .await
        }
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 1);
    let read = std::fs::read(dests.paths[&0].clone()).unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn already_complete_files_are_skipped() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dests = resolve_destinations(&m, &dst).unwrap();
    let dest_path = dests.paths[&0].clone();
    if let Some(p) = dest_path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(&dest_path, &data).unwrap();

    let plan = resume_plan(&m, &dests).unwrap();
    assert!(plan.complete.contains(&0));

    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            run_sender(
                &mut sr,
                &mut sw,
                &m_send,
                &sources_send,
                &NoopProgress,
                &SenderConfig::default(),
            )
            .await
        }
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.skipped, 1);
    assert_eq!(report.verified, 0);
}

#[tokio::test]
async fn directory_send_creates_folder_on_receiver() {
    // Sending a single directory should produce a folder of the same
    // name on the receiver side, not a flat dump of files.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("myrepo");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(src.join("sub")).unwrap();
    let data1: Vec<u8> = (0..50_000u32).map(|i| (i & 0xFF) as u8).collect();
    let data2: Vec<u8> = (0..30_000u32).map(|i| ((i * 3) & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data1).unwrap();
    std::fs::write(src.join("sub").join("b.bin"), &data2).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dst = tmp.path().join("dst");
    let dst_for_recv = dst.clone();

    // The manifest's rel_paths should be prefixed with the directory
    // name, in forward-slash form, regardless of platform.
    let dir_name = src.file_name().unwrap().to_str().unwrap();
    for f in &m.files {
        assert!(
            f.rel_path.starts_with(&format!("{dir_name}/")),
            "rel_path should start with {dir_name:?}, got {:?}",
            f.rel_path
        );
        assert!(
            !f.rel_path.contains('\\'),
            "rel_path must use forward slashes only, got {:?}",
            f.rel_path
        );
    }

    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            run_sender(
                &mut sr,
                &mut sw,
                &m_send,
                &sources_send,
                &NoopProgress,
                &SenderConfig::default(),
            )
            .await
        }
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let _report = receiver_task.await.unwrap().unwrap();

    // The receiver should have written files into a folder named `myrepo`
    // inside the destination.
    let dest_root = dst.join("myrepo");
    assert!(
        dest_root.is_dir(),
        "expected destination folder {dest_root:?}"
    );
    let read1 = std::fs::read(dest_root.join("a.bin")).unwrap();
    assert_eq!(read1, data1);
    let read2 = std::fs::read(dest_root.join("sub").join("b.bin")).unwrap();
    assert_eq!(read2, data2);
}

#[tokio::test]
async fn folder_name_with_space_creates_nested_folders() {
    // Regression: on Windows, a folder name containing a space used to
    // round-trip with backslashes in rel_path, which the receiver's
    // Path::join then re-tokenized as additional path components. The
    // receiver ended up with files in a flat structure or with mangled
    // paths. With forward-slash wire form + rel_to_path, the receiver
    // always creates the right nested folder tree.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("Piete de Hooch");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    let sub = src.join("figures");
    std::fs::create_dir(&sub).unwrap();
    let top_data: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    let fig_data: Vec<u8> = (0..30_000u32).map(|i| ((i * 7) & 0xFF) as u8).collect();
    std::fs::write(src.join("readme.txt"), &top_data).unwrap();
    std::fs::write(sub.join("fig5.jpg"), &fig_data).unwrap();

    let m = build(std::slice::from_ref(&src), DEFAULT_CHUNK_SIZE).unwrap();

    // rel_paths must use forward slashes only.
    for f in &m.files {
        assert!(!f.rel_path.contains('\\'), "got {:?}", f.rel_path);
        assert!(
            f.rel_path.starts_with("Piete de Hooch/"),
            "got {:?}",
            f.rel_path
        );
    }

    // Destinations resolve to a real nested folder tree. Look up paths
    // by rel_path rather than by id, since sort order in the manifest
    // is byte-wise (and `figures` < `readme.txt` lexicographically).
    let dests = resolve_destinations(&m, &dst).unwrap();
    let readme_dest = dests
        .paths
        .values()
        .find(|p| p.to_string_lossy().ends_with("readme.txt"))
        .expect("missing destination for readme.txt")
        .clone();
    let fig_dest = dests
        .paths
        .values()
        .find(|p| p.to_string_lossy().ends_with("fig5.jpg"))
        .expect("missing destination for fig5.jpg")
        .clone();
    let readme_parts: Vec<String> = readme_dest
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(String::from))
        .collect();
    let fig_parts: Vec<String> = fig_dest
        .components()
        .filter_map(|c| c.as_os_str().to_str().map(String::from))
        .collect();
    assert!(readme_parts.iter().any(|s| s == "Piete de Hooch"));
    assert_eq!(readme_parts.last().map(String::as_str), Some("readme.txt"));
    assert!(fig_parts.iter().any(|s| s == "Piete de Hooch"));
    assert!(fig_parts.iter().any(|s| s == "figures"));
    assert_eq!(fig_parts.last().map(String::as_str), Some("fig5.jpg"));

    // End-to-end: send and receive, verify the on-disk tree is the
    // expected nested folder.
    let sources = sources_from_manifest(&m);
    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        {
            let (mut sr, mut sw) = tokio::io::split(server);
            run_sender(
                &mut sr,
                &mut sw,
                &m_send,
                &sources_send,
                &NoopProgress,
                &SenderConfig::default(),
            )
            .await
        }
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 2);

    // On disk, the destination must be: <dst>/Piete de Hooch/{readme.txt, figures/fig5.jpg}
    assert!(dst.join("Piete de Hooch").is_dir());
    let read_top = std::fs::read(dst.join("Piete de Hooch").join("readme.txt")).unwrap();
    assert_eq!(read_top, top_data);
    let read_fig =
        std::fs::read(dst.join("Piete de Hooch").join("figures").join("fig5.jpg")).unwrap();
    assert_eq!(read_fig, fig_data);
}

#[tokio::test]
async fn resume_truncates_oversized_destination() {
    // If the destination file is longer than the manifest size, the
    // receiver must truncate it before resuming. Otherwise trailing bytes
    // from the old file would remain on disk even though the final hash
    // only covers the manifest size.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..100_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);
    let dest_path = resolve_destinations(&m, &dst).unwrap().paths[&0].clone();
    if let Some(p) = dest_path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    // Destination is the correct prefix plus trailing garbage.
    let mut oversized = data.clone();
    oversized.extend_from_slice(&vec![0xFFu8; 50_000]);
    std::fs::write(&dest_path, &oversized).unwrap();

    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        let (mut sr, mut sw) = tokio::io::split(server);
        run_sender(
            &mut sr,
            &mut sw,
            &m_send,
            &sources_send,
            &NoopProgress,
            &SenderConfig::default(),
        )
        .await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(
            &mut r,
            &mut w,
            &dst_for_recv,
            &NoopProgress,
            DEFAULT_MAX_RETRIES,
        )
        .await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 1);

    let read = std::fs::read(&dest_path).unwrap();
    assert_eq!(read, data);
}

#[tokio::test]
async fn sender_respects_empty_accepted_list() {
    // The receiver can decline files via `ManifestAck.accepted` even when
    // `resume_offsets` contains an entry. The sender must not transmit
    // declined files.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);

    let (local, peer) = tokio::io::duplex(4096);
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let (mut peer_r, mut peer_w) = tokio::io::split(peer);

    let sender_task = tokio::spawn(async move {
        run_sender(
            &mut local_r,
            &mut local_w,
            &m,
            &sources,
            &NoopProgress,
            &SenderConfig::default(),
        )
        .await
    });

    let fake_receiver = tokio::spawn(async move {
        let hello = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(hello, ControlMsg::Hello(_)));
        write_frame(
            &mut peer_w,
            &ControlMsg::Hello(HelloInfo {
                version: PROTOCOL_VERSION,
                chunk_size: DEFAULT_CHUNK_SIZE,
            }),
        )
        .await
        .unwrap();
        peer_w.flush().await.unwrap();

        let manifest = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(manifest, ControlMsg::Manifest(_)));

        let mut resume_offsets = HashMap::new();
        resume_offsets.insert(0, 0u64);
        write_frame(
            &mut peer_w,
            &ControlMsg::ManifestAck {
                accepted: vec![],
                resume_offsets,
            },
        )
        .await
        .unwrap();
        peer_w.flush().await.unwrap();

        // The sender must skip the declined file and go straight to Done.
        let done = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(done, ControlMsg::Done));
    });

    let (sender_result, _) = tokio::join!(sender_task, fake_receiver);
    sender_result.unwrap().unwrap();
}

#[tokio::test]
async fn receiver_gives_up_after_max_retries() {
    // A fake sender keeps sending a file whose FileEnd hash never matches.
    // The receiver must send exactly `max_retries + 1` failure verdicts,
    // then move on cleanly without hanging waiting for another retry.
    let tmp = tempfile::tempdir().unwrap();
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&dst).unwrap();

    let (local, peer) = tokio::io::duplex(4096);
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let (mut peer_r, mut peer_w) = tokio::io::split(peer);

    let receiver_task = tokio::spawn(async move {
        run_receiver(&mut local_r, &mut local_w, &dst, &NoopProgress, 2).await
    });

    let fake_sender = tokio::spawn(async move {
        write_frame(
            &mut peer_w,
            &ControlMsg::Hello(HelloInfo {
                version: PROTOCOL_VERSION,
                chunk_size: DEFAULT_CHUNK_SIZE,
            }),
        )
        .await
        .unwrap();
        peer_w.flush().await.unwrap();

        let hello = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(hello, ControlMsg::Hello(_)));

        let manifest = Manifest {
            files: vec![FileEntry {
                id: 0,
                rel_path: "a.bin".to_string(),
                size: 4,
                chunk_size: DEFAULT_CHUNK_SIZE,
                chunk_hashes: vec![],
            }],
            chunk_size: DEFAULT_CHUNK_SIZE,
            source_root: PathBuf::new(),
        };
        write_frame(&mut peer_w, &ControlMsg::Manifest(manifest))
            .await
            .unwrap();
        peer_w.flush().await.unwrap();

        let ack = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(ack, ControlMsg::ManifestAck { .. }));

        let wrong_hash = [0u8; 32];
        for _ in 0..3 {
            write_frame(&mut peer_w, &ControlMsg::FileStart { id: 0, offset: 0 })
                .await
                .unwrap();
            peer_w.flush().await.unwrap();

            write_frame(
                &mut peer_w,
                &ControlMsg::ChunkHeader {
                    id: 0,
                    offset: 0,
                    len: 4,
                },
            )
            .await
            .unwrap();
            peer_w.write_all(b"data").await.unwrap();
            peer_w.flush().await.unwrap();

            write_frame(
                &mut peer_w,
                &ControlMsg::FileEnd {
                    id: 0,
                    hash: wrong_hash,
                },
            )
            .await
            .unwrap();
            peer_w.flush().await.unwrap();

            let verdict = read_frame(&mut peer_r).await.unwrap();
            assert!(
                matches!(verdict, ControlMsg::FileVerified { id: 0, ok: false }),
                "expected FileVerified ok=false, got {verdict:?}"
            );
        }

        // Receiver should now be waiting for Done.
        write_frame(&mut peer_w, &ControlMsg::Done).await.unwrap();
        peer_w.flush().await.unwrap();
    });

    let (receiver_result, _) = tokio::join!(receiver_task, fake_sender);
    let report = receiver_result.unwrap().unwrap();
    assert_eq!(report.failed, 1);
    assert_eq!(report.verified, 0);
}

#[tokio::test]
async fn sender_gives_up_after_max_retries() {
    // A fake receiver rejects every FileEnd. The sender must retry exactly
    // `max_retries` times after the initial attempt, then return
    // `ProtocolError::MaxRetries` without sending extra FileStart messages.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path().join("src");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..10_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m);

    let (local, peer) = tokio::io::duplex(4096);
    let (mut local_r, mut local_w) = tokio::io::split(local);
    let (mut peer_r, mut peer_w) = tokio::io::split(peer);

    let sender_task = tokio::spawn(async move {
        let cfg = SenderConfig {
            max_retries: 1,
            ..SenderConfig::default()
        };
        run_sender(
            &mut local_r,
            &mut local_w,
            &m,
            &sources,
            &NoopProgress,
            &cfg,
        )
        .await
    });

    let fake_receiver = tokio::spawn(async move {
        let hello = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(hello, ControlMsg::Hello(_)));
        write_frame(
            &mut peer_w,
            &ControlMsg::Hello(HelloInfo {
                version: PROTOCOL_VERSION,
                chunk_size: DEFAULT_CHUNK_SIZE,
            }),
        )
        .await
        .unwrap();
        peer_w.flush().await.unwrap();

        let manifest = read_frame(&mut peer_r).await.unwrap();
        assert!(matches!(manifest, ControlMsg::Manifest(_)));

        let mut resume_offsets = HashMap::new();
        resume_offsets.insert(0, 0u64);
        write_frame(
            &mut peer_w,
            &ControlMsg::ManifestAck {
                accepted: vec![0],
                resume_offsets,
            },
        )
        .await
        .unwrap();
        peer_w.flush().await.unwrap();

        // Initial attempt + 1 retry = 2 FileStart messages.
        for _ in 0..2 {
            let start = read_frame(&mut peer_r).await.unwrap();
            assert!(matches!(start, ControlMsg::FileStart { id: 0, .. }));

            // Drain chunk headers and raw bytes until FileEnd.
            loop {
                let msg = read_frame(&mut peer_r).await.unwrap();
                match msg {
                    ControlMsg::ChunkHeader { len, .. } => {
                        let mut raw = vec![0u8; len as usize];
                        peer_r.read_exact(&mut raw).await.unwrap();
                    }
                    ControlMsg::FileEnd { .. } => break,
                    other => panic!("expected chunk or FileEnd, got {other:?}"),
                }
            }

            write_frame(&mut peer_w, &ControlMsg::FileVerified { id: 0, ok: false })
                .await
                .unwrap();
            peer_w.flush().await.unwrap();
        }

        // Sender should now give up and close / error; it must not send a
        // third FileStart.
        let mut extra = false;
        loop {
            match read_frame(&mut peer_r).await {
                Ok(ControlMsg::FileStart { id: 0, .. }) => {
                    extra = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(!extra, "sender sent more FileStart messages than allowed");
    });

    let (sender_result, _) = tokio::join!(sender_task, fake_receiver);
    let err = sender_result.unwrap().unwrap_err();
    assert!(
        matches!(err, ProtocolError::MaxRetries(1, 0)),
        "expected MaxRetries(1, 0), got {err:?}"
    );
}
