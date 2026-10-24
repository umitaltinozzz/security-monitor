fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", security_monitor_agent_protocol::json_schema()?);
    Ok(())
}
