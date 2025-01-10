use alloc::{collections::BTreeSet, format, vec::Vec};

use rand_core::CryptoRngCore;

use super::run_sync::run_sync;
use crate::{
    combinators::misbehave::{Behavior, Misbehaving, MisbehavingEntryPoint},
    dev::ExecutionResult,
    protocol::{EntryPoint, Protocol, ProtocolError},
    session::{LocalError, SessionParameters},
    signature::Keypair,
};

/// Executes the sessions for the given entry points,
/// making one party (first in alphabetical order) the malicious one with the wrapper `M` and the given `behavior`.
#[allow(clippy::type_complexity)]
pub fn run_with_one_malicious_party<SP, M, B>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, M::EntryPoint)>,
    behavior: &B,
) -> Result<ExecutionResult<<M::EntryPoint as EntryPoint<SP::Verifier>>::Protocol, SP>, LocalError>
where
    SP: SessionParameters,
    B: Behavior + Clone,
    M: Misbehaving<SP::Verifier, B>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let misbehaving_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;
    let modified_entry_points = entry_points
        .into_iter()
        .map(|(signer, entry_point)| {
            let id = signer.verifying_key();
            let maybe_behavior = if &id == misbehaving_id {
                Some(behavior.clone())
            } else {
                None
            };
            let entry_point = MisbehavingEntryPoint::<SP::Verifier, B, M>::new(entry_point, maybe_behavior);
            (signer, entry_point)
        })
        .collect();

    run_sync::<_, SP>(rng, modified_entry_points)
}

/// Executes [`run_with_one_malicious_party`] and checks that the malicous party
/// does not generate any provable error reports, while all the others do.
///
/// Checks that these reports can be verified given `associated_data`,
/// and their description starts with `expected_description`, returning a `LocalError` otherwise.
#[allow(clippy::type_complexity)]
pub fn check_evidence_with_behavior<SP, M, B>(
    rng: &mut impl CryptoRngCore,
    entry_points: Vec<(SP::Signer, M::EntryPoint)>,
    behavior: &B,
    associated_data: &<<<M::EntryPoint as EntryPoint<SP::Verifier>>::Protocol as Protocol<SP::Verifier>>::ProtocolError as ProtocolError<SP::Verifier>>::AssociatedData,
    expected_description: &str,
) -> Result<(), LocalError>
where
    SP: SessionParameters,
    B: Behavior + Clone,
    M: Misbehaving<SP::Verifier, B>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let misbehaving_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;

    let execution_result = run_with_one_malicious_party::<SP, M, B>(rng, entry_points, behavior)?;
    let mut reports = execution_result.reports;

    let misbehaving_party_report = reports
        .remove(misbehaving_id)
        .ok_or_else(|| LocalError::new("Misbehaving node ID is not present in the reports"))?;
    assert!(misbehaving_party_report.provable_errors.is_empty());

    for (id, report) in reports {
        if report.provable_errors.len() == 0 {
            return Err(LocalError::new(format!(
                "Node {id:?} did not report any provable errors"
            )));
        }

        if report.provable_errors.len() > 1 {
            let errors = report
                .provable_errors
                .iter()
                .map(|(_id, evidence)| evidence.description())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(LocalError::new(format!(
                "Node {id:?} reported more than one provable errors: {}",
                errors
            )));
        }

        let description = report
            .provable_errors
            .get(misbehaving_id)
            .ok_or_else(|| LocalError::new("A lawful node did not generate a provable error report"))?
            .description();
        if !description.starts_with(expected_description) {
            return Err(LocalError::new(format!(
                "Got {description}, expected {expected_description}"
            )));
        }

        let verification_result = report
            .provable_errors
            .get(misbehaving_id)
            .ok_or_else(|| {
                LocalError::new(format!(
                    "The report for {id:?} does not contain an evidence for the misbehaving ID"
                ))
            })?
            .verify(associated_data);
        if verification_result.is_err() {
            return Err(LocalError::new(format!("Failed to verify: {verification_result:?}")));
        }
    }

    Ok(())
}
