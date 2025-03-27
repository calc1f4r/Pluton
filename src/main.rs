use pluton::SolanaAnalyzer;
use clap::Parser;

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
}

fn main() -> anyhow::Result<()> {
    // Initialize logger
    env_logger::init();
    
    // Parse command line arguments
    let args = Args::parse();
    
    // Create analyzer
    let analyzer = SolanaAnalyzer::new(args.project_path.clone());
    
    // Run the analysis
    let result = analyzer.analyze()?;
    
    println!("Loaded vulnerability descriptions: {}", result.vulnerability_descriptions.len());
    if !result.vulnerability_descriptions.is_empty() {
        println!("Found descriptions: {:?}", result.vulnerability_descriptions.keys().collect::<Vec<_>>());
    }
    
    // Generate and output the report
    match args.format.as_str() {
        "json" => {
            let report = result.to_json()?;
            if let Some(output_file) = args.output_file {
                std::fs::write(&output_file, &report)?;
                println!("JSON report written to: {}", output_file);
            }
            // Always print to terminal
            println!("{}", report);
        }
        _ => {
            // Default to markdown
            let report = result.to_markdown();
            if let Some(output_file) = args.output_file {
                std::fs::write(&output_file, &report)?;
                println!("Markdown report written to: {}", output_file);
            }
            // Always print to terminal
            println!("{}", report);
        }
    }
    
    Ok(())
}
