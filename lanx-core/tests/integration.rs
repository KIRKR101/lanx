//! End-to-end transfer integration tests over in-process TCP. These
//! cover the happy path, resume, and corrupt-chunk re-fetch scenarios
//! from `plan.md` §13.

use lanx_core::destinations::resolve_destinations;
use lanx_core::manifest::{build, rel_to_path, FileId, Manifest, DEFAULT_CHUNK_SIZE};
use lanx_core::progress::NoopProgress;
use lanx_core::resume::plan as resume_plan;
use lanx_core::transfer::receiver::run_receiver;
use lanx_core::transfer::sender::{run_sender, SenderConfig};
use std::collections::HashMap;
use std::path::PathBuf;
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

fn sources_from_manifest(m: &Manifest, _dir: &std::path::Path) -> HashMap<FileId, PathBuf> {
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
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    let data: Vec<u8> = (0..200_000u32).map(|i| (i & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m, &src);
    let dst_for_recv = dst.clone();

    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
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
        let data: Vec<u8> = (0..(50_000 + i * 10_000)).map(|j| ((j + i) & 0xFF) as u8).collect();
        std::fs::write(p, &data).unwrap();
    }
    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m, &src);
    let dst_for_recv = dst.clone();

    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
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
    let sources = sources_from_manifest(&m, &src);
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
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
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
    let sources = sources_from_manifest(&m, &src);
    let dests = resolve_destinations(&m, &dst).unwrap();
    let dest_path = dests.paths[&0].clone();
    if let Some(p) = dest_path.parent() {
        std::fs::create_dir_all(p).unwrap();
    }
    std::fs::write(&dest_path, &data).unwrap();

    let plan = resume_plan(&m, &dests).unwrap();
    assert!(plan.complete.contains_key(&0));

    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
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
    let dst = tmp.path().join("dst");
    std::fs::create_dir(&src).unwrap();
    std::fs::create_dir(src.join("sub")).unwrap();
    let data1: Vec<u8> = (0..50_000u32).map(|i| (i & 0xFF) as u8).collect();
    let data2: Vec<u8> = (0..30_000u32).map(|i| ((i * 3) & 0xFF) as u8).collect();
    std::fs::write(src.join("a.bin"), &data1).unwrap();
    std::fs::write(src.join("sub").join("b.bin"), &data2).unwrap();

    let m = build_manifest_for(&src);
    let sources = sources_from_manifest(&m, &src);
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
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
    });
    sender_task.await.unwrap().unwrap();
    let _report = receiver_task.await.unwrap().unwrap();

    // The receiver should have written files into a folder named `myrepo`
    // inside the destination.
    let dest_root = dst.join("myrepo");
    assert!(dest_root.is_dir(), "expected destination folder {dest_root:?}");
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
    let sources = sources_from_manifest(&m, &src);
    let dst_for_recv = dst.clone();
    let (_h, server, client) = pair().await;
    let m_send = m.clone();
    let sources_send = sources.clone();
    let sender_task = tokio::spawn(async move {
        run_sender(server, &m_send, &sources_send, &NoopProgress, &SenderConfig::default()).await
    });
    let receiver_task = tokio::spawn(async move {
        let (mut r, mut w) = client.into_split();
        run_receiver(&mut r, &mut w, &dst_for_recv, &NoopProgress).await
    });
    sender_task.await.unwrap().unwrap();
    let report = receiver_task.await.unwrap().unwrap();
    assert_eq!(report.verified, 2);

    // On disk, the destination must be: <dst>/Piete de Hooch/{readme.txt, figures/fig5.jpg}
    assert!(dst.join("Piete de Hooch").is_dir());
    let read_top = std::fs::read(dst.join("Piete de Hooch").join("readme.txt")).unwrap();
    assert_eq!(read_top, top_data);
    let read_fig = std::fs::read(
        dst.join("Piete de Hooch").join("figures").join("fig5.jpg"),
    )
    .unwrap();
    assert_eq!(read_fig, fig_data);
}
