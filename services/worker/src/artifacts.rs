//! Resolving content-addressed artifacts.
//!
//! The worker never receives bytes from the broker. It receives CIDs and
//! resolves them here, verifying the hash of everything it reads. That is what
//! makes the data plane replaceable - local disk today, a CDN, an object store,
//! or a P2P swarm tomorrow, with no change above this trait.

use std::path::{Path, PathBuf};

use rustly_judge_cache::{cid, is_cid};
use rustly_judge_common::{JudgeError, Result};

/// A source of immutable, content-addressed objects.
pub trait ArtifactSource: Send + Sync {
    /// Fetch the object named by `cid`.
    ///
    /// Implementations **must** verify that the returned bytes hash to `cid`.
    /// A source that returns unverified bytes turns a compromised mirror into a
    /// compromised verdict.
    fn fetch(&self, cid: &str) -> Result<Vec<u8>>;
}

/// A directory of files named by their CID.
///
/// Used for local development, offline operation, and the worker's own tests.
#[derive(Debug, Clone)]
pub struct LocalArtifacts {
    root: PathBuf,
}

impl LocalArtifacts {
    /// Open a directory as an artifact source.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Store `bytes` under their CID and return it. Test and seed helper.
    pub fn put(&self, bytes: &[u8]) -> Result<String> {
        std::fs::create_dir_all(&self.root).map_err(|e| {
            JudgeError::Infrastructure(format!("cannot create {:?}: {e}", self.root))
        })?;
        let cid = cid(bytes);
        std::fs::write(self.root.join(&cid), bytes)
            .map_err(|e| JudgeError::Infrastructure(format!("cannot write {cid}: {e}")))?;
        Ok(cid)
    }

    /// The directory backing this source.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl ArtifactSource for LocalArtifacts {
    fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
        if !is_cid(cid) {
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: "not a valid BLAKE3 CID".into(),
            });
        }
        let path = self.root.join(cid);
        let bytes = std::fs::read(&path).map_err(|e| {
            JudgeError::Infrastructure(format!("cannot read artifact {cid} from {path:?}: {e}"))
        })?;

        let actual = self::cid(&bytes);
        if actual != cid {
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: format!("content hashes to {actual}"),
            });
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustly_judge_common::Verdict;

    #[test]
    fn a_stored_artifact_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let source = LocalArtifacts::new(dir.path());
        let cid = source.put(b"package bytes").unwrap();
        assert_eq!(source.fetch(&cid).unwrap(), b"package bytes");
    }

    #[test]
    fn tampered_content_is_refused_as_a_retryable_infrastructure_error() {
        let dir = tempfile::tempdir().unwrap();
        let source = LocalArtifacts::new(dir.path());
        let cid = source.put(b"honest bytes").unwrap();

        std::fs::write(dir.path().join(&cid), b"tampered bytes").unwrap();
        let error = source.fetch(&cid).unwrap_err();

        assert_eq!(
            error.verdict(),
            Verdict::InternalError,
            "a poisoned mirror must never become a user verdict"
        );
        assert!(error.is_retryable());
    }

    #[test]
    fn a_missing_artifact_is_infrastructure_not_a_user_error() {
        let dir = tempfile::tempdir().unwrap();
        let source = LocalArtifacts::new(dir.path());
        let error = source
            .fetch(&rustly_judge_cache::cid(b"never stored"))
            .unwrap_err();
        assert_eq!(error.verdict(), Verdict::InternalError);
    }

    #[test]
    fn a_malformed_cid_is_rejected_before_any_filesystem_access() {
        let source = LocalArtifacts::new("/nonexistent");
        // Path traversal must not even be attempted.
        for bad in ["../../etc/passwd", "b3:", "", "not-a-cid"] {
            assert!(source.fetch(bad).is_err(), "should reject {bad:?}");
        }
    }
}
