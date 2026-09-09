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

/// Read/write access used by trusted workers for result manifests.
pub trait ArtifactStore: ArtifactSource {
    /// Store bytes by their BLAKE3 CID and return that CID.
    fn put(&self, bytes: &[u8]) -> Result<String>;
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
        <Self as ArtifactStore>::put(self, bytes)
    }

    /// The directory backing this source.
    pub fn root(&self) -> &Path {
        &self.root
    }
}

impl ArtifactStore for LocalArtifacts {
    fn put(&self, bytes: &[u8]) -> Result<String> {
        std::fs::create_dir_all(&self.root).map_err(|e| {
            JudgeError::Infrastructure(format!("cannot create {:?}: {e}", self.root))
        })?;
        let cid = cid(bytes);
        std::fs::write(self.root.join(&cid), bytes)
            .map_err(|e| JudgeError::Infrastructure(format!("cannot write {cid}: {e}")))?;
        Ok(cid)
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

/// Authenticated client for the artifact gateway used by hosted workers.
#[derive(Debug, Clone)]
pub struct HttpArtifacts {
    base_url: String,
    bearer_token: String,
    client: reqwest::blocking::Client,
}

impl HttpArtifacts {
    /// Construct a client with bounded network operations.
    pub fn new(base_url: impl Into<String>, bearer_token: impl Into<String>) -> Result<Self> {
        let bearer_token = bearer_token.into();
        if bearer_token.len() < 32 {
            return Err(JudgeError::SecurityPolicy(
                "artifact gateway credential must be at least 32 bytes".into(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(20))
            .build()
            .map_err(|error| {
                JudgeError::Infrastructure(format!("build artifact HTTP client: {error}"))
            })?;
        Ok(Self {
            base_url: base_url.into().trim_end_matches('/').to_owned(),
            bearer_token,
            client,
        })
    }

    fn url(&self, cid: &str) -> String {
        format!("{}/api/v1/artifacts/{cid}", self.base_url)
    }
}

impl ArtifactSource for HttpArtifacts {
    fn fetch(&self, cid: &str) -> Result<Vec<u8>> {
        if !is_cid(cid) {
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: "not a valid BLAKE3 CID".into(),
            });
        }
        let response = self
            .client
            .get(self.url(cid))
            .bearer_auth(&self.bearer_token)
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| {
                JudgeError::Infrastructure(format!("fetch artifact {cid}: {error}"))
            })?;
        if response
            .content_length()
            .is_some_and(|size| size > 32 * 1024 * 1024)
        {
            return Err(JudgeError::SecurityPolicy(
                "artifact response exceeds 32 MiB".into(),
            ));
        }
        let bytes = response
            .bytes()
            .map_err(|error| JudgeError::Infrastructure(format!("read artifact {cid}: {error}")))?;
        if bytes.len() > 32 * 1024 * 1024 {
            return Err(JudgeError::SecurityPolicy(
                "artifact response exceeds 32 MiB".into(),
            ));
        }
        let actual = self::cid(&bytes);
        if actual != cid {
            return Err(JudgeError::CacheIntegrity {
                cid: cid.to_owned(),
                detail: format!("content hashes to {actual}"),
            });
        }
        Ok(bytes.to_vec())
    }
}

impl ArtifactStore for HttpArtifacts {
    fn put(&self, bytes: &[u8]) -> Result<String> {
        let cid = self::cid(bytes);
        self.client
            .put(self.url(&cid))
            .bearer_auth(&self.bearer_token)
            .body(bytes.to_vec())
            .send()
            .and_then(reqwest::blocking::Response::error_for_status)
            .map_err(|error| {
                JudgeError::Infrastructure(format!("store artifact {cid}: {error}"))
            })?;
        Ok(cid)
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
