//! Content-addressed artifact cache.
//!
//! # The one rule
//!
//! **The cache is disposable.** Every compiled artifact can be rebuilt from its
//! source, so a corrupt, truncated, or tampered entry must cause a clean retry
//! and a quarantine - never an incorrect verdict for a user.
//!
//! That rule is enforced structurally: [`ArtifactCache::get`] verifies the
//! BLAKE3 hash of the bytes it read **on every read**, not just on write. An
//! entry whose content no longer matches its key is removed and reported as
//! [`JudgeError::CacheIntegrity`], which maps to `IE` - retryable, and never
//! `WA`.
//!
//! # Quarantine
//!
//! Artifacts produced by a non-trusted worker enter [`Trust::Quarantined`]. A
//! quarantined artifact is stored and served for *diagnostics*, but
//! [`ArtifactCache::get_verified`] refuses to hand it to a judging path until it
//! has been independently reproduced by trusted capacity.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

use std::path::{Path, PathBuf};

use rustly_judge_common::{JudgeError, Result};
use serde::{Deserialize, Serialize};

/// CID prefix. Present so a future hash change is visible rather than silent.
pub const CID_PREFIX: &str = "b3:";

/// How much an artifact is trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Trust {
    /// Produced by a non-trusted worker. Not usable for judging yet.
    Quarantined,
    /// Reproduced by trusted capacity, or produced by it directly.
    Verified,
}

/// Compute the CID of some bytes.
pub fn cid(bytes: &[u8]) -> String {
    format!("{CID_PREFIX}{}", blake3::hash(bytes).to_hex())
}

/// Whether a string is a syntactically valid CID.
pub fn is_cid(value: &str) -> bool {
    let Some(hex) = value.strip_prefix(CID_PREFIX) else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A local on-disk artifact cache.
#[derive(Debug, Clone)]
pub struct ArtifactCache {
    root: PathBuf,
}

impl ArtifactCache {
    /// Open (creating if needed) a cache rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        std::fs::create_dir_all(&root).map_err(|e| {
            JudgeError::Infrastructure(format!("cannot create cache at {root:?}: {e}"))
        })?;
        Ok(Self { root })
    }

    /// Where an artifact with this CID lives. Exposed for diagnostics and for
    /// tests that need to simulate a bad disk.
    pub fn path_of(&self, cid: &str, trust: Trust) -> PathBuf {
        self.path_for(cid, trust)
    }

    fn path_for(&self, cid: &str, trust: Trust) -> PathBuf {
        let directory = match trust {
            Trust::Verified => "verified",
            Trust::Quarantined => "quarantine",
        };
        // Two-character fan-out keeps directory sizes reasonable.
        let hex = cid.trim_start_matches(CID_PREFIX);
        self.root.join(directory).join(&hex[..2]).join(hex)
    }

    /// Store `bytes`, returning their CID.
    ///
    /// The caller does not choose the key: it is the hash of the content, so a
    /// mislabelled entry cannot exist.
    pub fn put(&self, bytes: &[u8], trust: Trust) -> Result<String> {
        let cid = cid(bytes);
        let path = self.path_for(&cid, trust);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| JudgeError::Infrastructure(format!("cache mkdir failed: {e}")))?;
        }

        // Write to a temporary file and rename, so a crash mid-write cannot
        // leave a truncated artifact under a valid-looking key.
        let temporary = path.with_extension("partial");
        std::fs::write(&temporary, bytes)
            .map_err(|e| JudgeError::Infrastructure(format!("cache write failed: {e}")))?;
        std::fs::rename(&temporary, &path)
            .map_err(|e| JudgeError::Infrastructure(format!("cache rename failed: {e}")))?;
        Ok(cid)
    }

    /// Read an artifact, verifying its integrity.
    ///
    /// Verification happens on **every** read. A cache that only verifies on
    /// write trusts the filesystem, and a disposable cache should trust nothing.
    pub fn get(&self, cid: &str, trust: Trust) -> Result<Option<Vec<u8>>> {
        if !is_cid(cid) {
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: "not a valid BLAKE3 CID".into(),
            });
        }

        let path = self.path_for(cid, trust);
        let bytes = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(JudgeError::Infrastructure(format!(
                    "cache read failed: {e}"
                )))
            }
        };

        let actual = self::cid(&bytes);
        if actual != cid {
            // Evict, then report. Leaving a known-bad entry in place would let
            // the next read fail the same way, or worse, be trusted.
            let _ = std::fs::remove_file(&path);
            tracing::warn!(
                cid,
                actual,
                "evicted a cache entry that failed verification"
            );
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: format!("content hashes to {actual}"),
            });
        }
        Ok(Some(bytes))
    }

    /// Read an artifact that is safe to judge with.
    ///
    /// Only [`Trust::Verified`] artifacts qualify. A quarantined artifact is
    /// reported as absent, so a caller that forgets to check trust gets a cache
    /// miss and a rebuild rather than an unverified binary.
    pub fn get_verified(&self, cid: &str) -> Result<Option<Vec<u8>>> {
        self.get(cid, Trust::Verified)
    }

    /// Promote a quarantined artifact after independent reproduction.
    ///
    /// `reproduced` must be the bytes produced by trusted capacity. Promotion
    /// only happens if they hash to the same CID; otherwise the quarantined copy
    /// is destroyed and the mismatch is reported.
    pub fn promote(&self, cid: &str, reproduced: &[u8]) -> Result<()> {
        let actual = self::cid(reproduced);
        if actual != cid {
            let _ = std::fs::remove_file(self.path_for(cid, Trust::Quarantined));
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: format!("trusted rebuild produced {actual}; quarantined copy destroyed"),
            });
        }
        self.put(reproduced, Trust::Verified)?;
        let _ = std::fs::remove_file(self.path_for(cid, Trust::Quarantined));
        Ok(())
    }

    /// Store `bytes` under a **build key** as well as their content address.
    ///
    /// A compiled artifact is looked up by what produced it - source, toolchain,
    /// compiler - not by what came out, because the output is exactly what we do
    /// not know yet. The content is still stored content-addressed, and the build
    /// key is a tiny index entry pointing at it. That keeps verify-on-read intact:
    /// a corrupt index yields a CID whose content does not match, which is an
    /// integrity error and a rebuild, never a wrong artifact.
    pub fn put_build(&self, build_key: &str, bytes: &[u8], trust: Trust) -> Result<String> {
        if !is_cid(build_key) {
            return Err(JudgeError::Infrastructure(format!(
                "build key {build_key:?} is not a valid CID"
            )));
        }
        let cid = self.put(bytes, trust)?;
        let path = self.index_path(build_key, trust);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| JudgeError::Infrastructure(format!("cache mkdir failed: {e}")))?;
        }
        let temporary = path.with_extension("partial");
        std::fs::write(&temporary, cid.as_bytes())
            .map_err(|e| JudgeError::Infrastructure(format!("index write failed: {e}")))?;
        std::fs::rename(&temporary, &path)
            .map_err(|e| JudgeError::Infrastructure(format!("index rename failed: {e}")))?;
        Ok(cid)
    }

    /// Read the artifact stored under a build key, verifying its integrity.
    pub fn get_build(&self, build_key: &str, trust: Trust) -> Result<Option<Vec<u8>>> {
        if !is_cid(build_key) {
            return Err(JudgeError::Infrastructure(format!(
                "build key {build_key:?} is not a valid CID"
            )));
        }
        let path = self.index_path(build_key, trust);
        let cid = match std::fs::read_to_string(&path) {
            Ok(cid) => cid,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(JudgeError::Infrastructure(format!(
                    "index read failed: {e}"
                )))
            }
        };
        match self.get(cid.trim(), trust) {
            Ok(bytes) => Ok(bytes),
            Err(error) => {
                // The index points at something that no longer verifies. Drop
                // the pointer too, so the next lookup is a clean miss.
                let _ = std::fs::remove_file(&path);
                Err(error)
            }
        }
    }

    /// Whether a build key resolves to a verified artifact.
    pub fn contains_build(&self, build_key: &str) -> bool {
        is_cid(build_key) && self.index_path(build_key, Trust::Verified).exists()
    }

    fn index_path(&self, build_key: &str, trust: Trust) -> PathBuf {
        let directory = match trust {
            Trust::Verified => "index-verified",
            Trust::Quarantined => "index-quarantine",
        };
        let hex = build_key.trim_start_matches(CID_PREFIX);
        self.root.join(directory).join(&hex[..2]).join(hex)
    }

    /// Whether a verified artifact is present. Does not read the content, so it
    /// is not an integrity check.
    pub fn contains_verified(&self, cid: &str) -> bool {
        is_cid(cid) && self.path_for(cid, Trust::Verified).exists()
    }

    /// The cache root.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::Verdict;

    fn cache() -> (ArtifactCache, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        (ArtifactCache::open(dir.path()).unwrap(), dir)
    }

    #[test]
    fn cids_are_content_derived_and_stable() {
        assert_eq!(cid(b"hello"), cid(b"hello"));
        assert_ne!(cid(b"hello"), cid(b"hell0"));
        assert!(is_cid(&cid(b"hello")));
        assert!(cid(b"").starts_with(CID_PREFIX));
    }

    #[test]
    fn malformed_cids_are_rejected() {
        for bad in [
            "",
            "b3:",
            "b3:zz",
            "deadbeef",
            &format!("b3:{}", "A".repeat(64)),
        ] {
            assert!(!is_cid(bad), "should reject {bad:?}");
        }
    }

    #[test]
    fn a_round_trip_returns_the_same_bytes() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"artifact bytes", Trust::Verified).unwrap();
        assert_eq!(
            cache.get_verified(&cid).unwrap().unwrap(),
            b"artifact bytes"
        );
        assert!(cache.contains_verified(&cid));
    }

    #[test]
    fn a_miss_is_a_miss_not_an_error() {
        let (cache, _dir) = cache();
        assert_eq!(cache.get_verified(&cid(b"never stored")).unwrap(), None);
    }

    #[test]
    fn corruption_is_detected_on_read_evicted_and_reported_as_retryable() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"good bytes", Trust::Verified).unwrap();

        // Tamper with the stored file, exactly as a bad disk or an attacker would.
        let path = cache.path_for(&cid, Trust::Verified);
        std::fs::write(&path, b"evil bytes").unwrap();

        let error = cache.get_verified(&cid).unwrap_err();
        assert_eq!(
            error.verdict(),
            Verdict::InternalError,
            "cache corruption must never surface as a user verdict"
        );
        assert!(error.is_retryable());
        assert!(
            !path.exists(),
            "a known-bad entry must be evicted, not left to be re-read"
        );
    }

    #[test]
    fn truncation_is_detected_too() {
        let (cache, _dir) = cache();
        let cid = cache
            .put(b"a reasonably long artifact", Trust::Verified)
            .unwrap();
        std::fs::write(cache.path_for(&cid, Trust::Verified), b"a reasonably").unwrap();
        assert!(matches!(
            cache.get_verified(&cid),
            Err(JudgeError::CacheIntegrity { .. })
        ));
    }

    #[test]
    fn a_quarantined_artifact_is_never_served_to_a_judging_path() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"volunteer output", Trust::Quarantined).unwrap();

        assert_eq!(
            cache.get_verified(&cid).unwrap(),
            None,
            "a quarantined artifact must read as absent, forcing a rebuild"
        );
        assert!(!cache.contains_verified(&cid));
        // It is still retrievable for diagnostics.
        assert!(cache.get(&cid, Trust::Quarantined).unwrap().is_some());
    }

    #[test]
    fn promotion_requires_a_matching_trusted_rebuild() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"volunteer output", Trust::Quarantined).unwrap();

        cache.promote(&cid, b"volunteer output").unwrap();
        assert!(cache.contains_verified(&cid));
        assert_eq!(
            cache.get(&cid, Trust::Quarantined).unwrap(),
            None,
            "quarantine copy removed"
        );
    }

    #[test]
    fn a_mismatched_rebuild_destroys_the_quarantined_copy() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"volunteer output", Trust::Quarantined).unwrap();

        let error = cache.promote(&cid, b"different output").unwrap_err();
        assert_eq!(error.verdict(), Verdict::InternalError);
        assert_eq!(cache.get(&cid, Trust::Quarantined).unwrap(), None);
        assert!(!cache.contains_verified(&cid));
    }

    #[test]
    fn a_partial_write_never_becomes_a_readable_entry() {
        let (cache, _dir) = cache();
        let cid = cache.put(b"complete", Trust::Verified).unwrap();
        // No `.partial` file survives a successful put.
        let partial = cache
            .path_for(&cid, Trust::Verified)
            .with_extension("partial");
        assert!(!partial.exists());
    }

    #[test]
    fn storing_the_same_bytes_twice_is_idempotent() {
        let (cache, _dir) = cache();
        let first = cache.put(b"same", Trust::Verified).unwrap();
        let second = cache.put(b"same", Trust::Verified).unwrap();
        assert_eq!(first, second);
        assert_eq!(cache.get_verified(&first).unwrap().unwrap(), b"same");
    }

    #[test]
    fn a_build_key_resolves_to_the_artifact_it_produced() {
        let (cache, _dir) = cache();
        let key = cid(b"source+toolchain+compiler");

        assert_eq!(cache.get_build(&key, Trust::Verified).unwrap(), None);
        let stored = cache
            .put_build(&key, b"compiled module", Trust::Verified)
            .unwrap();
        assert_eq!(
            cache.get_build(&key, Trust::Verified).unwrap().unwrap(),
            b"compiled module"
        );
        assert_eq!(stored, cid(b"compiled module"));
        assert!(cache.contains_build(&key));
    }

    #[test]
    fn a_quarantined_build_is_not_visible_to_the_verified_lookup() {
        let (cache, _dir) = cache();
        let key = cid(b"volunteer build");
        cache
            .put_build(&key, b"volunteer module", Trust::Quarantined)
            .unwrap();

        assert_eq!(cache.get_build(&key, Trust::Verified).unwrap(), None);
        assert!(!cache.contains_build(&key));
        assert!(cache.get_build(&key, Trust::Quarantined).unwrap().is_some());
    }

    #[test]
    fn a_build_index_pointing_at_corrupt_content_becomes_a_clean_miss() {
        let (cache, _dir) = cache();
        let key = cid(b"build inputs");
        let stored = cache
            .put_build(&key, b"good module", Trust::Verified)
            .unwrap();

        std::fs::write(cache.path_of(&stored, Trust::Verified), b"bad module").unwrap();

        let error = cache.get_build(&key, Trust::Verified).unwrap_err();
        assert_eq!(error.verdict(), Verdict::InternalError);
        assert_eq!(
            cache.get_build(&key, Trust::Verified).unwrap(),
            None,
            "the dangling index entry must be dropped so the next lookup rebuilds"
        );
    }

    #[test]
    fn a_malformed_build_key_is_rejected() {
        let (cache, _dir) = cache();
        assert!(cache.get_build("not-a-cid", Trust::Verified).is_err());
        assert!(cache.put_build("not-a-cid", b"x", Trust::Verified).is_err());
    }

    #[test]
    fn a_malformed_key_is_an_integrity_error_not_a_silent_miss() {
        let (cache, _dir) = cache();
        assert!(matches!(
            cache.get_verified("not-a-cid"),
            Err(JudgeError::CacheIntegrity { .. })
        ));
    }
}
