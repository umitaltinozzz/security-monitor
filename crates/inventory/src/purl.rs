use purl::GenericPurlBuilder;
use thiserror::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PackageEcosystem {
    Npm,
    Pypi,
    Composer,
    Golang,
    Cargo,
}

impl PackageEcosystem {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::Pypi => "pypi",
            Self::Composer => "composer",
            Self::Golang => "golang",
            Self::Cargo => "cargo",
        }
    }
}

#[derive(Debug, Error)]
#[error("package URL could not be constructed")]
pub struct PurlError;

pub fn package_url(
    ecosystem: PackageEcosystem,
    name: &str,
    version: Option<&str>,
) -> Result<String, PurlError> {
    let normalized_name = if ecosystem == PackageEcosystem::Pypi {
        normalize_pypi_name(name)
    } else {
        name.to_owned()
    };
    let (namespace, package_name) = split_namespace(ecosystem, &normalized_name);
    let mut builder = GenericPurlBuilder::new(ecosystem.as_str().to_owned(), package_name);
    if let Some(namespace) = namespace {
        builder = builder.with_namespace(namespace);
    }
    if let Some(version) = version {
        builder = builder.with_version(version);
    }
    builder
        .build()
        .map(|purl| purl.to_string())
        .map_err(|_| PurlError)
}

fn normalize_pypi_name(name: &str) -> String {
    let mut normalized = String::with_capacity(name.len());
    let mut previous_separator = false;
    for character in name.chars() {
        if matches!(character, '-' | '_' | '.') {
            if !previous_separator {
                normalized.push('-');
            }
            previous_separator = true;
        } else {
            normalized.extend(character.to_lowercase());
            previous_separator = false;
        }
    }
    normalized
}

fn split_namespace(ecosystem: PackageEcosystem, name: &str) -> (Option<&str>, &str) {
    match ecosystem {
        PackageEcosystem::Npm if name.starts_with('@') => name
            .split_once('/')
            .map(|(scope, package)| (Some(scope), package))
            .unwrap_or((None, name)),
        PackageEcosystem::Composer | PackageEcosystem::Golang => name
            .rsplit_once('/')
            .map(|(namespace, package)| (Some(namespace), package))
            .unwrap_or((None, name)),
        PackageEcosystem::Npm | PackageEcosystem::Pypi | PackageEcosystem::Cargo => (None, name),
    }
}

#[cfg(test)]
mod tests {
    use super::{PackageEcosystem, package_url};

    #[test]
    fn generates_ecosystem_specific_package_urls() {
        let examples = [
            (
                PackageEcosystem::Npm,
                "@scope/name",
                Some("1.2.3"),
                "pkg:npm/%40scope/name@1.2.3",
            ),
            (
                PackageEcosystem::Pypi,
                "requests",
                Some("2.31.0"),
                "pkg:pypi/requests@2.31.0",
            ),
            (
                PackageEcosystem::Composer,
                "vendor/package",
                Some("1.2.3"),
                "pkg:composer/vendor/package@1.2.3",
            ),
            (
                PackageEcosystem::Golang,
                "github.com/example/module",
                Some("v1.2.3"),
                "pkg:golang/github.com/example/module@v1.2.3",
            ),
            (
                PackageEcosystem::Cargo,
                "serde",
                Some("1.0.200"),
                "pkg:cargo/serde@1.0.200",
            ),
        ];

        for (ecosystem, name, version, expected) in examples {
            assert_eq!(
                package_url(ecosystem, name, version).expect("valid package URL"),
                expected
            );
        }
    }

    #[test]
    fn requirements_without_an_exact_version_have_versionless_urls() {
        assert_eq!(
            package_url(PackageEcosystem::Pypi, "My_Package", None).expect("valid package URL"),
            "pkg:pypi/my-package"
        );
    }
}
