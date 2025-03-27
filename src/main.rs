use pluton::SolanaAnalyzer;
use clap::Parser;
use colored::*;

/// Command line arguments for Pluton
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the Solana project to analyze
    #[clap(short, long, default_value = ".")]
    project_path: String,

    /// Path to output file for the report
    #[clap(short, long)]
    output_file: Option<String>,

    /// Format of the output report (markdown, json)
    #[clap(short, long, default_value = "markdown")]
    format: String,
    
    /// Print the full report instead of just the issues
    #[clap(short = 'F', long)]
    full_report: bool,
}

fn main() -> anyhow::Result<()> {
    // Initialize logger with filter to suppress INFO logs
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("error")).init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Create analyzer
    let analyzer = SolanaAnalyzer::new(args.project_path.clone());
    
    // Run the analysis
    let result = analyzer.analyze()?;

    // Check if analysis found any issues
    let has_findings = !result.vulnerabilities.is_empty() || 
                       !result.warnings.is_empty();
    
    // If output_file is specified or full_report is true, generate a full report
    if args.output_file.is_some() || args.full_report {
        match args.format.as_str() {
            "json" => {
                let report = result.to_json()?;
                if let Some(output_file) = args.output_file {
                    std::fs::write(&output_file, &report)?;
                    println!("{}", format!("JSON report written to: {}", output_file).green());
                } else {
                    // Only print colorized header when output is terminal-only
                    println!("{}", "=== Solana Static Analysis Report (JSON) ===".green().bold());
                    println!("{}", report);
                }
            }
            _ => {
                // Default to markdown
                let report = result.to_markdown();
                if let Some(output_file) = args.output_file {
                    std::fs::write(&output_file, &report)?;
                    println!("{}", format!("Markdown report written to: {}", output_file).green());
                } else {
                    // Only print colorized header when output is terminal-only
                    println!("{}", "=== Solana Static Analysis Report ===".green().bold());
                    
                    // Add colors to markdown output
                    let colored_report = add_colors_to_markdown(&report);
                    println!("{}", colored_report);
                    
                    // If no issues found, print a message
                    if !has_findings {
                        println!("{}", "No issues found.".green().bold());
                    }
                }
            }
        }
    } else if has_findings {
        // Default behavior: only print issues with line numbers to the terminal
        // Group issues by severity and type
        let mut critical_issues = Vec::new();
        let mut high_issues = Vec::new();
        let mut medium_issues = Vec::new();
        let mut low_issues = Vec::new();
        let mut warnings = Vec::new();

        // Collect issues by severity
        for vuln in &result.vulnerabilities {
            if !vuln.location.file.contains("/target/") {
                match vuln.severity {
                    pluton::Severity::Critical => critical_issues.push(vuln),
                    pluton::Severity::High => high_issues.push(vuln),
                    pluton::Severity::Medium => medium_issues.push(vuln),
                    pluton::Severity::Low => low_issues.push(vuln),
                }
            }
        }

        // Collect warnings
        for warning in &result.warnings {
            if !warning.location.file.contains("/target/") && 
               !warning.location.file.contains("/build/") &&
               !warning.location.file.contains("/out/") &&
               !warning.location.file.contains("/generated/") {
                warnings.push(warning);
            }
        }

        // Print issues grouped by severity
        if !critical_issues.is_empty() {
            println!("{}", "CRITICAL SECURITY ISSUES:".bright_red().bold());
            for issue in critical_issues {
                let line_display = if issue.location.line > 0 {
                    issue.location.line.to_string()
                } else {
                    "unknown line".to_string() 
                };
                
                println!("  • {} ({}:{})", 
                    issue.description, 
                    issue.location.file,
                    line_display);
                println!("    {}", issue.suggestion);
            }
            println!();
        }

        if !high_issues.is_empty() {
            println!("{}", "HIGH RISK ISSUES:".red().bold());
            for issue in high_issues {
                let line_display = if issue.location.line > 0 {
                    issue.location.line.to_string()
                } else {
                    "unknown line".to_string() 
                };
                
                println!("  • {} ({}:{})", 
                    issue.description, 
                    issue.location.file,
                    line_display);
                println!("    {}", issue.suggestion);
            }
            println!();
        }

        if !medium_issues.is_empty() {
            println!("{}", "MEDIUM RISK ISSUES:".yellow().bold());
            for issue in medium_issues {
                let line_display = if issue.location.line > 0 {
                    issue.location.line.to_string()
                } else {
                    "unknown line".to_string() 
                };
                
                println!("  • {} ({}:{})", 
                    issue.description, 
                    issue.location.file,
                    line_display);
                println!("    {}", issue.suggestion);
            }
            println!();
        }

        if !low_issues.is_empty() {
            println!("{}", "LOW RISK ISSUES:".blue());
            for vuln in low_issues {
                println!("  • {} ({}:{})\n    {}", 
                    vuln.description, 
                    vuln.location.file, 
                    vuln.location.line,
                    vuln.suggestion.bright_black());
            }
            println!();
        }

        if !warnings.is_empty() {
            println!("{}", "CODE QUALITY WARNINGS:".blue().bold());
            for warning in warnings {
                let line_display = if warning.location.line > 0 {
                    warning.location.line.to_string()
                } else {
                    "unknown line".to_string() 
                };
                
                println!("  • {} ({}:{})", 
                    warning.description, 
                    warning.location.file,
                    line_display);
                println!("    {}", warning.suggestion);
            }
            println!();
        }
    } else {
        // If no issues found, print a message
        println!("{}", "No issues found.".green().bold());
    }
    // If no issues found and not generating a report, stay silent
    
    Ok(())
}

/// Add colors to markdown report for better terminal display
fn add_colors_to_markdown(markdown: &str) -> String {
    let mut colored_lines = Vec::new();
    
    for line in markdown.lines() {
        if line.starts_with("# ") {
            colored_lines.push(line.green().bold().to_string());
        } else if line.starts_with("## ") {
            colored_lines.push(line.yellow().bold().to_string());
        } else if line.starts_with("### ") {
            colored_lines.push(line.bright_blue().bold().to_string());
        } else if line.starts_with("- ") {
            colored_lines.push(line.cyan().to_string());
        } else if line.starts_with("  - ") {
            colored_lines.push(line.bright_cyan().to_string());
        } else if line.contains("WARNING") || line.contains("Warning") {
            colored_lines.push(line.yellow().to_string());
        } else if line.contains("ERROR") || line.contains("Error") {
            colored_lines.push(line.red().to_string());
        } else if line.contains("CRITICAL") || line.contains("Critical") {
            colored_lines.push(line.red().bold().to_string());
        } else {
            colored_lines.push(line.to_string());
        }
    }
    
    colored_lines.join("\n")
}
