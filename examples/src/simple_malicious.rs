use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::{Behavior, Misbehaving, MisbehavingEntryPoint},
    dev::{run_sync, BinaryFormat, ExecutionResult, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        Artifact, BoxedRound, Deserializer, DirectMessage, EchoBroadcast, EntryPoint, LocalError, ProtocolMessagePart,
        Serializer,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocol, SimpleProtocolEntryPoint};

type Id = TestVerifier;
type EP = SimpleProtocolEntryPoint<Id>;
type SP = TestSessionParams<BinaryFormat>;

/// Executes the sessions for the given entry points,
/// making one party (first in alphabetical order) the malicious one with the wrapper `M` and the given `behavior`.
pub fn run_with_one_malicious_party<M, B>(
    entry_points: Vec<(TestSigner, EP)>,
    behavior: &B,
) -> Result<ExecutionResult<SimpleProtocol, SP>, LocalError>
where
    B: Behavior + Clone,
    M: Misbehaving<Id, B, EntryPoint = EP>,
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
            let entry_point = MisbehavingEntryPoint::<Id, B, M>::new(entry_point, maybe_behavior);
            (signer, entry_point)
        })
        .collect();

    run_sync::<_, SP>(&mut OsRng, modified_entry_points)
}

/// Executes [`run_with_one_malicious_party`] and checks that the malicous party
/// does not generate any provable error reports, while all the others do.
///
/// Checks that these reports can be verified given `associated_data`,
/// and their description starts with `expected_description`, returning a `LocalError` otherwise.
pub fn check_evidence_with_behavior<M, B>(
    entry_points: Vec<(TestSigner, EP)>,
    behavior: &B,
    expected_description: &str,
) -> Result<(), LocalError>
where
    B: Behavior + Clone,
    M: Misbehaving<Id, B, EntryPoint = EP>,
{
    let ids = entry_points
        .iter()
        .map(|(signer, _ep)| signer.verifying_key())
        .collect::<BTreeSet<_>>();
    let misbehaving_id = ids
        .first()
        .ok_or_else(|| LocalError::new("Entry points list cannot be empty"))?;

    let execution_result = run_with_one_malicious_party::<M, B>(entry_points, behavior)?;
    let mut reports = execution_result.reports;

    let misbehaving_party_report = reports
        .remove(misbehaving_id)
        .ok_or_else(|| LocalError::new("Misbehaving node ID is not present in the reports"))?;
    assert!(misbehaving_party_report.provable_errors.is_empty());

    for (id, report) in reports {
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
            .verify(&());
        if verification_result.is_err() {
            return Err(LocalError::new(format!("Failed to verify: {verification_result:?}")));
        }
    }

    Ok(())
}

fn make_entry_points() -> Vec<(TestSigner, EP)> {
    let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    signers
        .into_iter()
        .map(|signer| (signer, SimpleProtocolEntryPoint::new(all_ids.clone())))
        .collect()
}

fn check_evidence<M>(expected_description: &str) -> Result<(), LocalError>
where
    M: Misbehaving<Id, (), EntryPoint = EP>,
{
    check_evidence_with_behavior::<M, _>(make_entry_points(), &(), expected_description)
}

#[test]
fn serialized_garbage() -> Result<(), LocalError> {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Part {
        EchoBroadcast,
        //NormalBroadcast,
        //DirectMessage,
    }

    #[derive(Debug, Clone, Copy)]
    struct Modify {
        round: u8,
        part: Part,
    }

    impl Modify {
        fn new(round: u8, part: Part) -> Self {
            Self { round, part }
        }
    }

    struct Override;

    impl Misbehaving<Id, Modify> for Override {
        type EntryPoint = EP;

        fn modify_echo_broadcast(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            modify: &Modify,
            serializer: &Serializer,
            _deserializer: &Deserializer,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() != modify.round || modify.part != Part::EchoBroadcast {
                return Ok(echo_broadcast);
            }

            EchoBroadcast::new::<[u8; 0]>(serializer, [])
        }
    }

    let entry_points = make_entry_points();

    check_evidence_with_behavior::<Override, _>(
        entry_points.clone(),
        &Modify::new(1, Part::EchoBroadcast),
        "Echo broadcast error: Deserialization error",
    )?;
    check_evidence_with_behavior::<Override, _>(
        entry_points.clone(),
        &Modify::new(2, Part::EchoBroadcast),
        "Echo broadcast error: The payload was expected to be `None`, but contains a message",
    )
}

#[test]
fn attributable_failure() -> Result<(), LocalError> {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = EP;

        fn modify_direct_message(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            if round.id() == 1 {
                let round1 = round.downcast_ref::<Round1<Id>>()?;
                let message = Round1Message {
                    my_position: round1.context.ids_to_positions[&round1.context.id],
                    your_position: round1.context.ids_to_positions[&round1.context.id],
                };
                let dm = DirectMessage::new(serializer, message)?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Invalid position in Round 1")
}

#[test]
fn attributable_failure_round2() -> Result<(), LocalError> {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = EP;

        fn modify_direct_message(
            _rng: &mut impl CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            serializer: &Serializer,
            _deserializer: &Deserializer,
            _destination: &Id,
            direct_message: DirectMessage,
            artifact: Option<Artifact>,
        ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
            if round.id() == 2 {
                let round2 = round.downcast_ref::<Round2<Id>>()?;
                let message = Round2Message {
                    my_position: round2.context.ids_to_positions[&round2.context.id],
                    your_position: round2.context.ids_to_positions[&round2.context.id],
                };
                let dm = DirectMessage::new(serializer, message)?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Invalid position in Round 2")
}
