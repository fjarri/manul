extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use core::fmt::Debug;

use criterion::{criterion_group, criterion_main, Criterion};
use manul::{
    protocol::{
        Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, FirstRound, LocalError, Payload,
        Protocol, ProtocolError, ProtocolValidationError, ReceiveError, Round, RoundId,
    },
    session::{signature::Keypair, Deserializer, Format, SessionId, SessionOutcome},
    testing::{run_sync, Binary, Signer, TestingSessionParams, Verifier},
};
use rand_core::{CryptoRngCore, OsRng};
use serde::{Deserialize, Serialize};

#[derive(Debug)]
pub struct EmptyProtocol;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmptyProtocolError;

impl ProtocolError for EmptyProtocolError {
    fn verify_messages_constitute_error(
        &self,
        _deserializer: &Deserializer,
        _echo_broadcast: &Option<EchoBroadcast>,
        _direct_message: &DirectMessage,
        _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
        _direct_messages: &BTreeMap<RoundId, DirectMessage>,
        _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        unimplemented!()
    }
}

impl Protocol for EmptyProtocol {
    type Result = ();
    type ProtocolError = EmptyProtocolError;
    type CorrectnessProof = ();
}

struct EmptyRound<Id> {
    round_counter: u8,
    inputs: Inputs<Id>,
}

#[derive(Clone)]
struct Inputs<Id> {
    rounds_num: u8,
    echo: bool,
    other_ids: BTreeSet<Id>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Round1DirectMessage;

#[derive(Debug, Serialize, Deserialize)]
struct Round1EchoBroadcast;

struct Round1Payload;

struct Round1Artifact;

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> FirstRound<Id> for EmptyRound<Id> {
    type Inputs = Inputs<Id>;
    fn new(
        _rng: &mut impl CryptoRngCore,
        _session_id: &SessionId,
        _id: Id,
        inputs: Self::Inputs,
    ) -> Result<Self, LocalError> {
        Ok(Self {
            round_counter: 1,
            inputs,
        })
    }
}

impl<Id: 'static + Debug + Clone + Ord + Send + Sync> Round<Id> for EmptyRound<Id> {
    type Protocol = EmptyProtocol;

    fn id(&self) -> RoundId {
        RoundId::new(self.round_counter)
    }

    fn possible_next_rounds(&self) -> BTreeSet<RoundId> {
        if self.inputs.rounds_num == self.round_counter {
            BTreeSet::new()
        } else {
            [RoundId::new(self.round_counter + 1)].into()
        }
    }

    fn message_destinations(&self) -> &BTreeSet<Id> {
        &self.inputs.other_ids
    }

    fn make_echo_broadcast(&self, _rng: &mut impl CryptoRngCore) -> Option<Result<EchoBroadcast, LocalError>> {
        if self.inputs.echo {
            Some(Binary::serialize(Round1EchoBroadcast).map(|bytes| EchoBroadcast::from_bytes(bytes)))
        } else {
            None
        }
    }

    fn make_direct_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        _destination: &Id,
    ) -> Result<(DirectMessage, Artifact), LocalError> {
        let dm = {
            let bytes = Binary::serialize(Round1DirectMessage)?;
            DirectMessage::from_bytes(bytes)
        };
        let artifact = Artifact::new(Round1Artifact);
        Ok((dm, artifact))
    }

    fn receive_message(
        &self,
        _rng: &mut impl CryptoRngCore,
        deserializer: &Deserializer,
        _from: &Id,
        echo_broadcast: Option<EchoBroadcast>,
        direct_message: DirectMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>> {
        let _echo_broadcast = criterion::black_box(
            echo_broadcast
                .map(|echo| echo.deserialize::<Round1EchoBroadcast>(deserializer))
                .transpose()?,
        );
        let _direct_message = criterion::black_box(direct_message.deserialize::<Round1DirectMessage>(deserializer)?);
        Ok(Payload::new(Round1Payload))
    }

    fn finalize(
        self,
        _rng: &mut impl CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, FinalizeError<Self::Protocol>> {
        for payload in payloads.into_values() {
            let _payload = payload.try_to_typed::<Round1Payload>()?;
        }
        for artifact in artifacts.into_values() {
            let _artifact = artifact.try_to_typed::<Round1Artifact>()?;
        }

        if self.round_counter == self.inputs.rounds_num {
            Ok(FinalizeOutcome::Result(()))
        } else {
            let round = EmptyRound {
                round_counter: self.round_counter + 1,
                inputs: self.inputs,
            };
            Ok(FinalizeOutcome::another_round(round))
        }
    }

    fn expecting_messages_from(&self) -> &BTreeSet<Id> {
        &self.inputs.other_ids
    }
}

fn bench_empty_rounds(c: &mut Criterion) {
    // Benchmarks a full run of a protocol with rounds that do nothing but send and receive empty messages.
    // This serves as an "integration" benchmark for the whole `Session`.
    // Necessarily includes the overhead of `run_sync()` as well.

    let mut group = c.benchmark_group("Empty rounds");

    let nodes = 25;
    let rounds_num = 5;

    let signers = (0..nodes).map(Signer::new).collect::<Vec<_>>();
    let all_ids = signers
        .iter()
        .map(|signer| signer.verifying_key())
        .collect::<BTreeSet<_>>();

    let inputs_no_echo = signers
        .iter()
        .cloned()
        .map(|signer| {
            let mut other_ids = all_ids.clone();
            other_ids.remove(&signer.verifying_key());
            (
                signer,
                Inputs {
                    rounds_num,
                    other_ids,
                    echo: false,
                },
            )
        })
        .collect::<Vec<_>>();

    group.bench_function("25 nodes, 5 rounds, no echo", |b| {
        b.iter(|| {
            assert!(
                run_sync::<EmptyRound<Verifier>, TestingSessionParams<Binary>>(&mut OsRng, inputs_no_echo.clone())
                    .unwrap()
                    .values()
                    .all(|report| matches!(report.outcome, SessionOutcome::Result(_)))
            )
        })
    });

    let inputs_echo = signers
        .iter()
        .cloned()
        .map(|signer| {
            let mut other_ids = all_ids.clone();
            other_ids.remove(&signer.verifying_key());
            (
                signer,
                Inputs {
                    rounds_num,
                    other_ids,
                    echo: true,
                },
            )
        })
        .collect::<Vec<_>>();

    group.sample_size(30);

    group.bench_function("25 nodes, 5 rounds, echo each round", |b| {
        b.iter(|| {
            assert!(
                run_sync::<EmptyRound<Verifier>, TestingSessionParams<Binary>>(&mut OsRng, inputs_echo.clone())
                    .unwrap()
                    .values()
                    .all(|report| matches!(report.outcome, SessionOutcome::Result(_)))
            )
        })
    });

    group.finish()
}

criterion_group!(benches, bench_empty_rounds,);
criterion_main!(benches);
