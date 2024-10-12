use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    vec::Vec,
};
use core::fmt::Debug;

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::{
    echo::EchoRound,
    error::{LocalError, RemoteError},
    evidence::Evidence,
    message::{MessageBundle, MessageVerificationError, SignedMessage, VerifiedMessageBundle},
    object_safe::{ObjectSafeRound, ObjectSafeRoundWrapper},
    round::{
        Artifact, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, FirstRound, Payload, ReceiveError,
        ReceiveErrorType, RoundId,
    },
    serde_bytes,
    signing::{DigestVerifier, Keypair, RandomizedDigestSigner},
    transcript::{SessionOutcome, SessionReport, Transcript},
    Protocol, Round,
};

/// A session identifier shared between the parties.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SessionId(#[serde(with = "serde_bytes")] Box<[u8]>);

impl SessionId {
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        let mut buffer = [0u8; 256];
        rng.fill_bytes(&mut buffer);
        Self(buffer.into())
    }

    pub fn new(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

pub struct Session<P: Protocol, Signer, Verifier, S> {
    session_id: SessionId,
    signer: Signer,
    verifier: Verifier,
    round: Box<dyn ObjectSafeRound<Verifier, Protocol = P>>,
    message_destinations: BTreeSet<Verifier>,
    echo_message: Option<SignedMessage<S, EchoBroadcast>>,
    possible_next_rounds: BTreeSet<RoundId>,
    transcript: Transcript<P, Verifier, S>,
}

pub enum RoundOutcome<P: Protocol, Signer, Verifier, S> {
    Finished(SessionReport<P, Verifier, S>),
    AnotherRound {
        session: Session<P, Signer, Verifier, S>,
        cached_messages: Vec<VerifiedMessageBundle<Verifier, S>>,
    },
}

impl<P, Signer, Verifier, S> Session<P, Signer, Verifier, S>
where
    P: Protocol + 'static,
    Signer: RandomizedDigestSigner<P::Digest, S> + Keypair<VerifyingKey = Verifier>,
    Verifier: Debug
        + Clone
        + Eq
        + Ord
        + DigestVerifier<P::Digest, S>
        + 'static
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync,
    S: Debug + Clone + Eq + 'static + Serialize + for<'de> Deserialize<'de> + Send + Sync,
{
    pub fn new<R>(
        rng: &mut impl CryptoRngCore,
        session_id: SessionId,
        signer: Signer,
        inputs: R::Inputs,
    ) -> Result<Self, LocalError>
    where
        R: FirstRound<Verifier> + Round<Verifier, Protocol = P> + 'static,
    {
        let verifier = signer.verifying_key();
        let first_round = Box::new(ObjectSafeRoundWrapper::new(R::new(
            rng,
            &session_id,
            verifier.clone(),
            inputs,
        )?));
        Self::new_for_next_round(rng, session_id, signer, first_round, Transcript::new())
    }

    fn new_for_next_round(
        rng: &mut impl CryptoRngCore,
        session_id: SessionId,
        signer: Signer,
        round: Box<dyn ObjectSafeRound<Verifier, Protocol = P>>,
        transcript: Transcript<P, Verifier, S>,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();
        let echo_message = round
            .make_echo_broadcast(rng)
            .transpose()?
            .map(|echo| SignedMessage::new::<P, _>(rng, &signer, &session_id, round.id(), echo))
            .transpose()?;
        let message_destinations = round.message_destinations().clone();

        let possible_next_rounds = if echo_message.is_none() {
            round.possible_next_rounds()
        } else {
            BTreeSet::from([round.id().echo()])
        };

        Ok(Self {
            session_id,
            signer,
            verifier,
            round,
            echo_message,
            possible_next_rounds,
            message_destinations,
            transcript,
        })
    }

    pub fn verifier(&self) -> Verifier {
        self.verifier.clone()
    }

    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    pub fn message_destinations(&self) -> &BTreeSet<Verifier> {
        &self.message_destinations
    }

    pub fn make_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &Verifier,
    ) -> Result<(MessageBundle<S>, ProcessedArtifact<Verifier>), LocalError> {
        let (direct_message, artifact) = self.round.make_direct_message(rng, destination)?;

        let bundle = MessageBundle::new::<P, _>(
            rng,
            &self.signer,
            &self.session_id,
            self.round.id(),
            direct_message,
            self.echo_message.clone(),
        )?;

        Ok((
            bundle,
            ProcessedArtifact {
                destination: destination.clone(),
                artifact,
            },
        ))
    }

    pub fn add_artifact(
        &self,
        accum: &mut RoundAccumulator<P, Verifier, S>,
        processed: ProcessedArtifact<Verifier>,
    ) -> Result<(), LocalError> {
        accum.add_artifact(processed)
    }

    pub fn round_id(&self) -> RoundId {
        self.round.id()
    }

    pub fn preprocess_message(
        &self,
        accum: &mut RoundAccumulator<P, Verifier, S>,
        from: &Verifier,
        message: MessageBundle<S>,
    ) -> Result<Option<VerifiedMessageBundle<Verifier, S>>, LocalError> {
        // Quick preliminary checks, before we proceed with more expensive verification

        if self.transcript.is_banned(from) || accum.is_banned(from) {
            return Ok(None);
        }

        let checked_message = match message.unify_metadata() {
            Some(checked_message) => checked_message,
            None => {
                accum.register_unprovable_error(from, RemoteError::new("Mismatched metadata in bundled messages"))?;
                return Ok(None);
            }
        };
        let message_round_id = checked_message.metadata().round_id();

        if checked_message.metadata().session_id() != &self.session_id {
            accum.register_unprovable_error(
                from,
                RemoteError::new("The received message has an incorrect session ID"),
            )?;
            return Ok(None);
        }

        if message_round_id == self.round_id() {
            if accum.message_is_being_processed(from) {
                accum.register_unprovable_error(
                    from,
                    RemoteError::new("Message from this party is already being processed"),
                )?;
                return Ok(None);
            }
        } else if self.possible_next_rounds.contains(&message_round_id) {
            if accum.message_is_cached(from, message_round_id) {
                accum.register_unprovable_error(
                    from,
                    RemoteError::new(format!("Message for {:?} is already cached", message_round_id)),
                )?;
                return Ok(None);
            }
        } else {
            accum.register_unprovable_error(
                from,
                RemoteError::new(format!("Unexpected message round ID: {:?}", message_round_id)),
            )?;
            return Ok(None);
        }

        // Verify the signature now

        let verified_message = match checked_message.verify::<P, _>(from) {
            Ok(verified_message) => verified_message,
            Err(MessageVerificationError::InvalidSignature) => {
                accum.register_unprovable_error(from, RemoteError::new("Message verification failed"))?;
                return Ok(None);
            }
            Err(MessageVerificationError::Local(error)) => return Err(error),
        };
        debug!(
            "{:?}: received {:?} message from {:?}",
            self.verifier(),
            verified_message.metadata().round_id(),
            from
        );

        if message_round_id == self.round_id() {
            accum.mark_processing(&verified_message)?;
            Ok(Some(verified_message))
        } else if self.possible_next_rounds.contains(&message_round_id) {
            debug!(
                "{:?}: caching message from {:?} for {:?}",
                self.verifier(),
                verified_message.from(),
                verified_message.metadata().round_id()
            );
            accum.cache_message(verified_message)?;
            Ok(None)
        } else {
            unreachable!()
        }
    }

    pub fn process_message(
        &self,
        rng: &mut impl CryptoRngCore,
        message: VerifiedMessageBundle<Verifier, S>,
    ) -> ProcessedMessage<P, Verifier, S> {
        let processed = self.round.receive_message(
            rng,
            message.from(),
            message.echo_broadcast().cloned(),
            message.direct_message().clone(),
        );
        // We could filter out and return a possible `LocalError` at this stage,
        // but it's no harm in delaying it until `ProcessedMessage` is added to the accumulator.
        ProcessedMessage { message, processed }
    }

    pub fn add_processed_message(
        &self,
        accum: &mut RoundAccumulator<P, Verifier, S>,
        processed: ProcessedMessage<P, Verifier, S>,
    ) -> Result<(), LocalError> {
        accum.add_processed_message(&self.transcript, processed)
    }

    pub fn make_accumulator(&self) -> RoundAccumulator<P, Verifier, S> {
        RoundAccumulator::new(self.round.expecting_messages_from())
    }

    pub fn terminate(
        self,
        accum: RoundAccumulator<P, Verifier, S>,
    ) -> Result<SessionReport<P, Verifier, S>, LocalError> {
        let round_id = self.round_id();
        let transcript = self.transcript.update(
            round_id,
            accum.echo_broadcasts,
            accum.direct_messages,
            accum.provable_errors,
            accum.unprovable_errors,
            accum.still_have_not_sent_messages,
        )?;
        Ok(SessionReport::new(SessionOutcome::NotEnoughMessages, transcript))
    }

    pub fn finalize_round(
        self,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<P, Verifier, S>,
    ) -> Result<RoundOutcome<P, Signer, Verifier, S>, LocalError> {
        let verifier = self.verifier().clone();
        let round_id = self.round_id();

        let transcript = self.transcript.update(
            round_id,
            accum.echo_broadcasts,
            accum.direct_messages,
            accum.provable_errors,
            accum.unprovable_errors,
            accum.still_have_not_sent_messages,
        )?;

        if let Some(echo_message) = self.echo_message {
            let round = Box::new(ObjectSafeRoundWrapper::new(EchoRound::new(
                verifier,
                echo_message,
                transcript.echo_broadcasts(round_id)?,
                self.round,
                accum.payloads,
                accum.artifacts,
            )));
            let cached_messages = filter_messages(accum.cached, round.id());
            let session = Session::new_for_next_round(rng, self.session_id, self.signer, round, transcript)?;
            return Ok(RoundOutcome::AnotherRound {
                session,
                cached_messages,
            });
        }

        match self.round.finalize(rng, accum.payloads, accum.artifacts) {
            Ok(result) => Ok(match result {
                FinalizeOutcome::Result(result) => {
                    RoundOutcome::Finished(SessionReport::new(SessionOutcome::Result(result), transcript))
                }
                FinalizeOutcome::AnotherRound(another_round) => {
                    // These messages could have been cached before
                    // processing messages from the same node for the current round.
                    // So there might have been some new errors, and we need to check again
                    // if the sender is already banned.
                    let round = another_round.into_boxed();
                    let cached_messages = filter_messages(accum.cached, round.id())
                        .into_iter()
                        .filter(|message| !transcript.is_banned(message.from()))
                        .collect::<Vec<_>>();

                    let session = Session::new_for_next_round(rng, self.session_id, self.signer, round, transcript)?;
                    RoundOutcome::AnotherRound {
                        cached_messages,
                        session,
                    }
                }
            }),
            Err(error) => Ok(match error {
                FinalizeError::Local(error) => return Err(error),
                FinalizeError::Unattributable(correctness_proof) => RoundOutcome::Finished(SessionReport::new(
                    SessionOutcome::StalledWithProof(correctness_proof),
                    transcript,
                )),
                FinalizeError::Unprovable { party, error } => {
                    let mut transcript = transcript;
                    transcript.register_unprovable_error(&party, error)?;
                    RoundOutcome::Finished(SessionReport::new(SessionOutcome::UnprovableError, transcript))
                }
            }),
        }
    }

    pub fn can_finalize(&self, accum: &RoundAccumulator<P, Verifier, S>) -> CanFinalize {
        accum.can_finalize()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanFinalize {
    /// There are enough messages successfully processed to finalize the round.
    Yes,
    /// There are not enough successfully processed messages, but not all nodes have responded yet.
    NotYet,
    /// Too many responses were invalid, and finalizing the round is impossible at this stage.
    /// Call [`Session::terminate`] to get the final report.
    Never,
}

pub struct RoundAccumulator<P: Protocol, Verifier, S> {
    still_have_not_sent_messages: BTreeSet<Verifier>,
    expecting_messages_from: BTreeSet<Verifier>,
    processing: BTreeSet<Verifier>,
    payloads: BTreeMap<Verifier, Payload>,
    artifacts: BTreeMap<Verifier, Artifact>,
    cached: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessageBundle<Verifier, S>>>,
    echo_broadcasts: BTreeMap<Verifier, SignedMessage<S, EchoBroadcast>>,
    direct_messages: BTreeMap<Verifier, SignedMessage<S, DirectMessage>>,
    provable_errors: BTreeMap<Verifier, Evidence<P, Verifier, S>>,
    unprovable_errors: BTreeMap<Verifier, RemoteError>,
}

impl<P, Verifier, S> RoundAccumulator<P, Verifier, S>
where
    P: Protocol,
    Verifier: Debug + Clone + Ord + for<'de> Deserialize<'de> + DigestVerifier<P::Digest, S>,
    S: Debug + Clone + for<'de> Deserialize<'de>,
{
    fn new(expecting_messages_from: &BTreeSet<Verifier>) -> Self {
        Self {
            still_have_not_sent_messages: expecting_messages_from.clone(),
            expecting_messages_from: expecting_messages_from.clone(),
            processing: BTreeSet::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            cached: BTreeMap::new(),
            echo_broadcasts: BTreeMap::new(),
            direct_messages: BTreeMap::new(),
            provable_errors: BTreeMap::new(),
            unprovable_errors: BTreeMap::new(),
        }
    }

    fn can_finalize(&self) -> CanFinalize {
        if self
            .expecting_messages_from
            .iter()
            .all(|key| self.payloads.contains_key(key))
        {
            CanFinalize::Yes
        } else if !self.still_have_not_sent_messages.is_empty() {
            CanFinalize::NotYet
        } else {
            CanFinalize::Never
        }
    }

    fn is_banned(&self, from: &Verifier) -> bool {
        self.provable_errors.contains_key(from) || self.unprovable_errors.contains_key(from)
    }

    fn message_is_being_processed(&self, from: &Verifier) -> bool {
        self.processing.contains(from)
    }

    fn message_is_cached(&self, from: &Verifier, round_id: RoundId) -> bool {
        if let Some(entry) = self.cached.get(from) {
            entry.contains_key(&round_id)
        } else {
            false
        }
    }

    fn register_unprovable_error(&mut self, from: &Verifier, error: RemoteError) -> Result<(), LocalError> {
        if self.unprovable_errors.insert(from.clone(), error).is_some() {
            Err(LocalError::new(format!(
                "An unprovable error for {:?} is already registered",
                from
            )))
        } else {
            Ok(())
        }
    }

    fn register_provable_error(
        &mut self,
        from: &Verifier,
        evidence: Evidence<P, Verifier, S>,
    ) -> Result<(), LocalError> {
        if self.provable_errors.insert(from.clone(), evidence).is_some() {
            Err(LocalError::new(format!(
                "A provable error for {:?} is already registered",
                from
            )))
        } else {
            Ok(())
        }
    }

    fn mark_processing(&mut self, message: &VerifiedMessageBundle<Verifier, S>) -> Result<(), LocalError> {
        if !self.processing.insert(message.from().clone()) {
            Err(LocalError::new(format!(
                "A message from {:?} is already marked as being processed",
                message.from()
            )))
        } else {
            Ok(())
        }
    }

    fn add_artifact(&mut self, processed: ProcessedArtifact<Verifier>) -> Result<(), LocalError> {
        if self
            .artifacts
            .insert(processed.destination.clone(), processed.artifact)
            .is_some()
        {
            return Err(LocalError::new(format!(
                "Artifact for destination {:?} has already been recorded",
                processed.destination
            )));
        }
        Ok(())
    }

    fn add_processed_message(
        &mut self,
        transcript: &Transcript<P, Verifier, S>,
        processed: ProcessedMessage<P, Verifier, S>,
    ) -> Result<(), LocalError> {
        if self.payloads.contains_key(processed.message.from()) {
            return Err(LocalError::new(format!(
                "A processed message from {:?} has already been recorded",
                processed.message.from()
            )));
        }

        let from = processed.message.from().clone();

        if !self.still_have_not_sent_messages.remove(&from) {
            return Err(LocalError::new(format!(
                "Expected {:?} to not be in the list of expected messages",
                from
            )));
        }

        let error = match processed.processed {
            Ok(payload) => {
                let (echo_broadcast, direct_message) = processed.message.into_unverified();
                if let Some(echo) = echo_broadcast {
                    self.echo_broadcasts.insert(from.clone(), echo);
                }
                self.direct_messages.insert(from.clone(), direct_message);
                self.payloads.insert(from.clone(), payload);
                return Ok(());
            }
            Err(error) => error,
        };

        match error.0 {
            ReceiveErrorType::InvalidDirectMessage(error) => {
                let (_echo_broadcast, direct_message) = processed.message.into_unverified();
                let evidence = Evidence::new_invalid_direct_message(&from, direct_message, error);
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::InvalidEchoBroadcast(error) => {
                let (echo_broadcast, _direct_message) = processed.message.into_unverified();
                let echo_broadcast =
                    echo_broadcast.ok_or_else(|| LocalError::new("Expected a non-None echo broadcast"))?;
                let evidence = Evidence::new_invalid_echo_broadcast(&from, echo_broadcast, error);
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Protocol(error) => {
                let (echo_broadcast, direct_message) = processed.message.into_unverified();
                let evidence = Evidence::new_protocol_error(&from, echo_broadcast, direct_message, error, transcript)?;
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Unprovable(error) => {
                self.unprovable_errors.insert(from.clone(), error);
                Ok(())
            }
            ReceiveErrorType::Echo(error) => {
                let (_echo_broadcast, direct_message) = processed.message.into_unverified();
                let evidence = Evidence::new_echo_round_error(&from, direct_message, error, transcript)?;
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Local(error) => Err(error),
        }
    }

    fn cache_message(&mut self, message: VerifiedMessageBundle<Verifier, S>) -> Result<(), LocalError> {
        let from = message.from().clone();
        let round_id = message.metadata().round_id();
        let cached = self.cached.entry(from.clone()).or_default();
        if cached.insert(round_id, message).is_some() {
            return Err(LocalError::new(format!(
                "A message from for {:?} has already been cached",
                round_id
            )));
        }
        Ok(())
    }
}

pub struct ProcessedArtifact<Verifier> {
    destination: Verifier,
    artifact: Artifact,
}

pub struct ProcessedMessage<P: Protocol, Verifier, S> {
    message: VerifiedMessageBundle<Verifier, S>,
    processed: Result<Payload, ReceiveError<Verifier, P>>,
}

fn filter_messages<Verifier, S>(
    messages: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessageBundle<Verifier, S>>>,
    round_id: RoundId,
) -> Vec<VerifiedMessageBundle<Verifier, S>> {
    messages
        .into_values()
        .filter_map(|mut messages| messages.remove(&round_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

    use impls::impls;
    use serde::{Deserialize, Serialize};

    use super::{MessageBundle, ProcessedArtifact, ProcessedMessage, Session, VerifiedMessageBundle};
    use crate::{
        testing::{Signature, Signer, Verifier},
        DeserializationError, Digest, DirectMessage, EchoBroadcast, LocalError, Protocol, ProtocolError,
        ProtocolValidationError, RoundId,
    };

    #[test]
    fn test_concurrency_bounds() {
        // In order to support parallel message creation and processing we need that
        // certain generic types could be Send and/or Sync.
        //
        // Since they are generic, this depends on the exact type parameters supplied by the user,
        // so if the user does not want parallelism, they may not use Send/Sync generic parameters.
        // But we want to make sure that if the generic parameters are Send/Sync,
        // our types are too.

        #[derive(Debug)]
        struct DummyProtocol;

        #[derive(Debug, Clone)]
        struct DummyProtocolError;

        struct DummyDigest;

        impl Digest for DummyDigest {
            fn new_with_prefix(_data: impl AsRef<[u8]>) -> Self {
                unimplemented!()
            }
            fn chain_update(self, _data: impl AsRef<[u8]>) -> Self {
                unimplemented!()
            }
        }

        impl ProtocolError for DummyProtocolError {
            fn verify_messages_constitute_error(
                &self,
                _echo_broadcast: &Option<EchoBroadcast>,
                _direct_message: &DirectMessage,
                _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
                _direct_messages: &BTreeMap<RoundId, DirectMessage>,
                _combined_echos: &BTreeMap<RoundId, Vec<EchoBroadcast>>,
            ) -> Result<(), ProtocolValidationError> {
                unimplemented!()
            }
        }

        impl Protocol for DummyProtocol {
            type Result = ();
            type ProtocolError = DummyProtocolError;
            type CorrectnessProof = ();
            type Digest = DummyDigest;
            fn serialize<T>(_: T) -> Result<Box<[u8]>, LocalError>
            where
                T: Serialize,
            {
                unimplemented!()
            }
            fn deserialize<'de, T>(_: &[u8]) -> Result<T, DeserializationError>
            where
                T: Deserialize<'de>,
            {
                unimplemented!()
            }
        }

        // We need `Session` to be `Send` so that we send a `Session` object to a task
        // to run the loop there.
        assert!(impls!(Session<DummyProtocol, Signer, Verifier, Signature>: Send));

        // This is needed so that message processing offloaded to a task could use `&Session`.
        assert!(impls!(Session<DummyProtocol, Signer, Verifier, Signature>: Sync));

        // These objects are sent to/from message processing tasks
        assert!(impls!(MessageBundle<Signature>: Send));
        assert!(impls!(ProcessedArtifact<Verifier>: Send));
        assert!(impls!(VerifiedMessageBundle<Verifier, Signature>: Send));
        assert!(impls!(ProcessedMessage<DummyProtocol, Verifier, Signature>: Send));
    }
}
