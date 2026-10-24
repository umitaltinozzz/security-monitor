pub fn canonical_ecosystem(ecosystem: &str) -> String {
    match ecosystem.to_ascii_lowercase().as_str() {
        "pypi" => "pypi".to_owned(),
        "go" | "golang" => "golang".to_owned(),
        "maven" => "maven".to_owned(),
        "crates.io" | "cargo" => "cargo".to_owned(),
        "packagist" | "composer" => "composer".to_owned(),
        "rubygems" | "gem" => "rubygems".to_owned(),
        "nuget" => "nuget".to_owned(),
        "npm" => "npm".to_owned(),
        other => other.to_owned(),
    }
}

pub fn normalize_package_name(ecosystem: &str, name: &str) -> String {
    let ecosystem = canonical_ecosystem(ecosystem);
    if matches!(
        ecosystem.as_str(),
        "npm" | "pypi" | "composer" | "rubygems" | "nuget" | "cargo"
    ) {
        name.to_ascii_lowercase()
            .chars()
            .map(|character| {
                if ecosystem == "pypi" && matches!(character, '_' | '.') {
                    '-'
                } else {
                    character
                }
            })
            .collect()
    } else {
        name.to_owned()
    }
}
