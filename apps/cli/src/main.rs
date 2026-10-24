use clap::Parser;

#[derive(Debug, Parser)]
#[command(version, about = "Security Monitor command-line interface")]
struct Arguments {}

fn main() {
    let _arguments = Arguments::parse();
}
