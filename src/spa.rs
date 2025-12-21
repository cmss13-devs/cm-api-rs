use rocket::fs::NamedFile;
use std::path::{Path, PathBuf};

const STATIC_DIR: &str = "/var/www/static";

#[get("/")]
pub async fn index() -> Option<NamedFile> {
    NamedFile::open(Path::new(STATIC_DIR).join("index.html"))
        .await
        .ok()
}

#[get("/<path..>", rank = 100)]
pub async fn fallback(path: PathBuf) -> Option<NamedFile> {
    let static_dir = Path::new(STATIC_DIR);

    // Try to serve the actual file first
    let file_path = static_dir.join(&path);
    if file_path.is_file() {
        return NamedFile::open(file_path).await.ok();
    }

    // Fallback to index.html for SPA routing
    NamedFile::open(static_dir.join("index.html")).await.ok()
}
