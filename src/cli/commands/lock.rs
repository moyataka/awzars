//! `lock` command: drop the current session's unlock/consent token for a
//! profile so the next credential operation must re-prove consent.

use crate::auth::lock;
use crate::error::Result;

pub fn run(profile_name: &str) -> Result<()> {
    lock::gc_stale_unlocks();
    lock::remove_unlock(profile_name)?;
    println!("Profile '{}' locked for this session.", profile_name);
    Ok(())
}
