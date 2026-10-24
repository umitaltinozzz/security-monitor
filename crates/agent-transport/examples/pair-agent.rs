use std::{
    env,
    error::Error,
    io::{self, Write},
};

use chrono::Utc;
use security_monitor_agent_transport::{
    CredentialStore, InventoryCollectionApproval, OsCredentialStore, SshIdentity, SshTarget,
    collect_agent, create_pairing_instructions, inspect_host_key,
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut args = env::args().skip(1);
    let alias = args.next().ok_or("expected SSH alias")?;
    let hostname = args.next().ok_or("expected SSH hostname")?;
    let username = args.next().ok_or("expected SSH username")?;
    let port = args.next().ok_or("expected SSH port")?.parse::<u16>()?;
    if args.next().is_some() {
        return Err("too many arguments".into());
    }

    let target = SshTarget::new(alias, hostname, username, port, None)?;
    let candidate = inspect_host_key(&target).await?;
    eprintln!("Observed SSH host key: {}", candidate.fingerprint);
    eprint!(
        "Confirm this fingerprint only after checking it with the server administrator [type yes]: "
    );
    io::stderr().flush()?;
    let mut confirmation = String::new();
    io::stdin().read_line(&mut confirmation)?;
    if confirmation.trim() != "yes" {
        return Err("host key was not confirmed".into());
    }

    let store = OsCredentialStore;
    let pairing = create_pairing_instructions(&store, "local-device")?;
    eprintln!("Add this line to the remote account's ~/.ssh/authorized_keys:");
    eprintln!("{}", pairing.authorized_keys_line);
    eprintln!("Install the static secmon-agent binary before continuing.");
    eprint!("Press Enter after authorized_keys is installed: ");
    io::stderr().flush()?;
    let mut ready = String::new();
    io::stdin().read_line(&mut ready)?;

    eprint!("Approve sending server inventory to this device over SSH? [type yes]: ");
    io::stderr().flush()?;
    let mut approval = String::new();
    io::stdin().read_line(&mut approval)?;
    if approval.trim() != "yes" {
        let _ = store.delete(&pairing.private_key_ref);
        return Err("inventory collection was not approved".into());
    }
    let approval = InventoryCollectionApproval::after_explicit_user_confirmation(Utc::now());

    let inventory = match collect_agent(
        &target,
        &candidate.fingerprint,
        &SshIdentity::PrivateKeyRef(pairing.private_key_ref.clone()),
        &store,
        approval,
    )
    .await
    {
        Ok(inventory) => inventory,
        Err(error) => {
            let _ = store.delete(&pairing.private_key_ref);
            return Err(error.into());
        }
    };
    eprintln!(
        "Inventory collection approval recorded at {}.",
        inventory.approval.approved_at().to_rfc3339()
    );
    let json = serde_json::to_string_pretty(&inventory.inventory)?;
    let mut stdout = io::stdout().lock();
    stdout.write_all(json.as_bytes())?;
    stdout.write_all(b"\n")?;
    Ok(())
}
