mod discover;
mod model;
mod parsers;
mod purl;

use std::path::{Component, Path};

pub use discover::{InventoryError, scan_repository};
pub use model::{
    DetectedFile, DetectedFileKind, Diagnostic, DiagnosticKind, Inventory, InventoryComponent,
};
pub use purl::{PackageEcosystem, PurlError, package_url};

pub fn is_dependency_file(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    if matches!(
        name,
        "package.json"
            | "package-lock.json"
            | "pnpm-lock.yaml"
            | "yarn.lock"
            | "bun.lock"
            | "poetry.lock"
            | "uv.lock"
            | "Pipfile.lock"
            | "Pipfile"
            | "pyproject.toml"
            | "composer.json"
            | "composer.lock"
            | "go.mod"
            | "go.sum"
            | "Cargo.toml"
            | "Cargo.lock"
    ) || (name.starts_with("requirements")
        && Path::new(name)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("txt")))
    {
        return true;
    }
    if name == "Dockerfile" || name.starts_with("Dockerfile.") {
        return true;
    }
    let components = path.components().collect::<Vec<_>>();
    components.windows(2).any(|pair| {
        pair[0] == Component::Normal(".github".as_ref())
            && pair[1] == Component::Normal("workflows".as_ref())
    }) && Path::new(name)
        .extension()
        .is_some_and(|extension| matches!(extension.to_str(), Some("yml" | "yaml")))
}
