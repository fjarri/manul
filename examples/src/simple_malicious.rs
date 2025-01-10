use alloc::collections::BTreeSet;

use manul::{
    combinators::misbehave::Misbehaving,
    dev::{check_evidence_with_behavior, BinaryFormat, TestSessionParams, TestSigner, TestVerifier},
    protocol::{
        Artifact, BoxedFormat, BoxedRound, DirectMessage, EchoBroadcast, EntryPoint, LocalError, ProtocolMessagePart,
    },
    signature::Keypair,
};
use rand_core::{CryptoRngCore, OsRng};
use test_log::test;

use crate::simple::{Round1, Round1Message, Round2, Round2Message, SimpleProtocolEntryPoint};

type Id = TestVerifier;
type EP = SimpleProtocolEntryPoint<Id>;
type SP = TestSessionParams<BinaryFormat>;

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
    check_evidence_with_behavior::<SP, M, _>(&mut OsRng, make_entry_points(), &(), &(), expected_description)
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
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            modify: &Modify,
            format: &BoxedFormat,
            echo_broadcast: EchoBroadcast,
        ) -> Result<EchoBroadcast, LocalError> {
            if round.id() != modify.round || modify.part != Part::EchoBroadcast {
                return Ok(echo_broadcast);
            }

            EchoBroadcast::new::<[u8; 0]>(format, [])
        }
    }

    let entry_points = make_entry_points();

    check_evidence_with_behavior::<SP, Override, _>(
        &mut OsRng,
        entry_points.clone(),
        &Modify::new(1, Part::EchoBroadcast),
        &(),
        "Echo broadcast error: Deserialization error",
    )?;
    check_evidence_with_behavior::<SP, Override, _>(
        &mut OsRng,
        entry_points.clone(),
        &Modify::new(2, Part::EchoBroadcast),
        &(),
        "Echo broadcast error: The payload was expected to be `None`, but contains a message",
    )
}

#[test]
fn attributable_failure() -> Result<(), LocalError> {
    struct Override;

    impl Misbehaving<Id, ()> for Override {
        type EntryPoint = EP;

        fn modify_direct_message(
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
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
                let dm = DirectMessage::new(format, message)?;
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
            _rng: &mut dyn CryptoRngCore,
            round: &BoxedRound<Id, <Self::EntryPoint as EntryPoint<Id>>::Protocol>,
            _behavior: &(),
            format: &BoxedFormat,
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
                let dm = DirectMessage::new(format, message)?;
                return Ok((dm, artifact));
            }

            Ok((direct_message, artifact))
        }
    }

    check_evidence::<Override>("Protocol error: Invalid position in Round 2")
}
