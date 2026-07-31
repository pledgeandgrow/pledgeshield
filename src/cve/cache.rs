use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::{Duration, SystemTime};

/// Cache entry for a CVE API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub data: String,
    pub cached_at: u64,
}

impl CacheEntry {
    pub fn is_expired(&self, ttl: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        now - self.cached_at > ttl.as_secs()
    }
}

/// Disk-based cache for CVE API responses.
pub struct CveCache {
    cache_dir: PathBuf,
    ttl: Duration,
}

impl CveCache {
    pub fn new() -> Self {
        let cache_dir = dirs::cache_dir()
            .unwrap_or_else(|| PathBuf::from(".cache"))
            .join("pledgeshield")
            .join("cve");

        Self {
            cache_dir,
            ttl: Duration::from_secs(24 * 60 * 60), // 24 hours
        }
    }

    pub fn with_ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Get a cached entry by key. Returns None if not cached or expired.
    pub fn get(&self, key: &str) -> Option<CacheEntry> {
        let path = self.cache_dir.join(sanitize_key(key));
        let data = std::fs::read_to_string(&path).ok()?;
        let entry: CacheEntry = serde_json::from_str(&data).ok()?;
        if entry.is_expired(self.ttl) {
            None
        } else {
            Some(entry)
        }
    }

    /// Store an entry in the cache.
    pub fn set(&self, key: &str, data: &str) -> Result<(), Box<dyn std::error::Error>> {
        std::fs::create_dir_all(&self.cache_dir)?;
        let entry = CacheEntry {
            data: data.to_string(),
            cached_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)?
                .as_secs(),
        };
        let path = self.cache_dir.join(sanitize_key(key));
        let json = serde_json::to_string(&entry)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Clear all cached entries.
    pub fn clear(&self) -> Result<(), Box<dyn std::error::Error>> {
        if self.cache_dir.exists() {
            std::fs::remove_dir_all(&self.cache_dir)?;
            std::fs::create_dir_all(&self.cache_dir)?;
        }
        Ok(())
    }
}

fn sanitize_key(key: &str) -> String {
    key.replace(['/', ':', '?', '&', '='], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_key() {
        assert_eq!(sanitize_key("nvd:chrome"), "nvd_chrome");
        assert_eq!(sanitize_key("https://example.com/path?q=1"), "https___example.com_path_q_1");
        assert_eq!(sanitize_key("clean_key"), "clean_key");
    }

    #[test]
    fn test_cache_entry_not_expired() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = CacheEntry {
            data: "test".to_string(),
            cached_at: now,
        };
        assert!(!entry.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn test_cache_entry_expired() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = CacheEntry {
            data: "test".to_string(),
            cached_at: now - 7200, // 2 hours ago
        };
        assert!(entry.is_expired(Duration::from_secs(3600))); // 1 hour TTL
    }

    #[test]
    fn test_cache_entry_edge_case() {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let entry = CacheEntry {
            data: "test".to_string(),
            cached_at: now - 3601, // 1 second past TTL
        };
        assert!(entry.is_expired(Duration::from_secs(3600)));
    }

    #[test]
    fn test_cache_set_and_get() {
        let cache = CveCache {
            cache_dir: std::env::temp_dir().join("pledgeshield_test_cache"),
            ttl: Duration::from_secs(3600),
        };

        // Clean up any previous test data
        let _ = cache.clear();

        // Set and get
        cache.set("test_key", "test_data").unwrap();
        let entry = cache.get("test_key");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().data, "test_data");

        // Clean up
        let _ = cache.clear();
    }

    #[test]
    fn test_cache_get_missing_key() {
        let cache = CveCache {
            cache_dir: std::env::temp_dir().join("pledgeshield_test_cache_missing"),
            ttl: Duration::from_secs(3600),
        };
        let _ = cache.clear();
        assert!(cache.get("nonexistent").is_none());
        let _ = cache.clear();
    }
}
