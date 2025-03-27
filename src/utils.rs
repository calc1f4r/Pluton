use std::collections::HashMap;
use std::fs;
use std::path::Path;
use serde_json::Value;

/// Load vulnerability descriptions from JSON files
pub fn load_vulnerability_descriptions() -> Result<HashMap<String, Value>, anyhow::Error> {
    let mut descriptions = HashMap::new();
    let vulnerabilities_dir = Path::new("vulnerabilities");
    
    // If the vulnerabilities directory doesn't exist, return an empty map
    if !vulnerabilities_dir.exists() {
        return Ok(descriptions);
    }

    // Read the index file to get a list of all vulnerabilities
    let index_path = vulnerabilities_dir.join("index.json");
    if index_path.exists() {
        let index_content = fs::read_to_string(&index_path)?;
        let index: Value = serde_json::from_str(&index_content)?;
        
        if let Some(vulns) = index["vulnerabilities"].as_array() {
            for vuln in vulns {
                if let Some(id) = vuln["id"].as_str() {
                    let file_path = vulnerabilities_dir.join(format!("{}.json", id));
                    if file_path.exists() {
                        let content = fs::read_to_string(file_path)?;
                        let vuln_data: Value = serde_json::from_str(&content)?;
                        descriptions.insert(id.to_string(), vuln_data);
                    }
                }
            }
        }
    } else {
        // If index.json doesn't exist, try to load all JSON files in the directory
        if let Ok(entries) = fs::read_dir(vulnerabilities_dir) {
            for entry in entries {
                let entry = entry?;
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "json") && path.file_name().unwrap() != "index.json" {
                    if let Some(file_stem) = path.file_stem() {
                        if let Some(id) = file_stem.to_str() {
                            let content = fs::read_to_string(&path)?;
                            let vuln_data: Value = serde_json::from_str(&content)?;
                            descriptions.insert(id.to_string(), vuln_data);
                        }
                    }
                }
            }
        }
    }
    
    Ok(descriptions)
}

// Add find_vulnerability_description function
pub fn find_vulnerability_description<'a>(key: &str, descriptions: &'a HashMap<String, Value>) -> Option<&'a Value> {
    for (vuln_key, desc) in descriptions {
        if vuln_key.contains(key) {
            return Some(desc);
        }
    }
    None
}
