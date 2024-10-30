use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
    vec::Vec,
};
use core::fmt::Debug;

use digest::Digest;
use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Hex, SliceLike};
use signature::{DigestVerifier, Keypair, RandomizedDigestSigner};
use tracing::{debug, trace};

use super::{
    echo::EchoRound,
    evidence::Evidence,
    message::{Message, MessageVerificationError, SignedMessagePart, VerifiedMessage},
    transcript::{SessionOutcome, SessionReport, Transcript},
    wire_format::WireFormat,
    LocalError, RemoteError,
};
use crate::protocol::{
    Artifact, Deserializer, DirectMessage, EchoBroadcast, FinalizeError, FinalizeOutcome, FirstRound, NormalBroadcast,
    ObjectSafeRound, ObjectSafeRoundWrapper, Payload, Protocol, ProtocolMessagePart, ReceiveError, ReceiveErrorType,
    Round, RoundId, Serializer,
};

/// A set of types needed to execute a session.
///
/// These will be generally determined by the user, depending on what signature type
/// is used in the network in which they are running the protocol.
pub trait SessionParameters: 'static {
    /// The signer type.
    type Signer: Debug + RandomizedDigestSigner<Self::Digest, Self::Signature> + Keypair<VerifyingKey = Self::Verifier>;

    /// The hash type that will be used to pre-hash message payloads before signing.
    type Digest: Digest;

    /// The verifier type, which will also serve as a node identifier.
    type Verifier: Debug
        + Clone
        + Ord
        + DigestVerifier<Self::Digest, Self::Signature>
        + Serialize
        + for<'de> Deserialize<'de>
        + Send
        + Sync;

    /// The signature type corresponding to [`Signer`](`Self::Signer`) and [`Verifier`](`Self::Verifier`).
    type Signature: Serialize + for<'de> Deserialize<'de>;

    /// The type used to (de)serialize messages.
    type WireFormat: WireFormat;
}

/// A session identifier shared between the parties.
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SessionId(#[serde(with = "SliceLike::<Hex>")] Box<[u8]>);

/// A session ID.
///
/// This must be the same for all nodes executing a session.
///
/// Must be created uniquely for each session execution, otherwise there is a danger of replay attacks.
impl SessionId {
    /// Creates a random session identifier.
    ///
    /// **Warning:** this should generally be used for testing; creating a random session ID in a centralized way
    /// usually defeats the purpose of having a distributed protocol.
    #[cfg(any(test, feature = "testing"))]
    pub fn random<SP: SessionParameters>(rng: &mut impl CryptoRngCore) -> Self {
        let mut buffer = digest::Output::<SP::Digest>::default();
        rng.fill_bytes(&mut buffer);
        Self(buffer.as_ref().into())
    }

    /// Creates a session identifier deterministically from the given bytestring.
    ///
    /// Every node executing a session must be given the same session ID.
    ///
    /// **Warning:** make sure the bytestring you provide will not be reused within your application,
    /// and cannot be predicted in advance.
    /// Session ID collisions will affect error attribution and evidence verification.
    ///
    /// In a blockchain setting, it may be some combination of the current block hash with the public parameters
    /// (identities of the parties, hash of the inputs).
    pub fn from_seed<SP: SessionParameters>(bytes: &[u8]) -> Self {
        Self(
            SP::Digest::new_with_prefix(b"SessionId")
                .chain_update(bytes)
                .finalize()
                .as_ref()
                .into(),
        )
    }
}

impl AsRef<[u8]> for SessionId {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// An object encapsulating the currently active round, transport protocol,
/// and the database of messages and errors from the previous rounds.
#[derive(Debug)]
pub struct Session<P: Protocol, SP: SessionParameters> {
    session_id: SessionId,
    signer: SP::Signer,
    verifier: SP::Verifier,
    serializer: Serializer,
    deserializer: Deserializer,
    round: Box<dyn ObjectSafeRound<SP::Verifier, Protocol = P>>,
    message_destinations: BTreeSet<SP::Verifier>,
    echo_broadcast: SignedMessagePart<EchoBroadcast>,
    normal_broadcast: SignedMessagePart<NormalBroadcast>,
    possible_next_rounds: BTreeSet<RoundId>,
    transcript: Transcript<P, SP>,
}

/// Possible non-erroneous results of finalizing a round.
#[derive(Debug)]
pub enum RoundOutcome<P: Protocol, SP: SessionParameters> {
    /// The execution is finished.
    Finished(SessionReport<P, SP>),
    /// Transitioned to another round.
    AnotherRound {
        /// The session object for the new round.
        session: Session<P, SP>,
        /// The messages intended for the new round cached during the previous round.
        cached_messages: Vec<VerifiedMessage<SP::Verifier>>,
    },
}

impl<P, SP> Session<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    /// Initializes a new session.
    pub fn new<R>(
        rng: &mut impl CryptoRngCore,
        session_id: SessionId,
        signer: SP::Signer,
        inputs: R::Inputs,
    ) -> Result<Self, LocalError>
    where
        R: FirstRound<SP::Verifier> + Round<SP::Verifier, Protocol = P>,
    {
        let verifier = signer.verifying_key();
        let first_round = Box::new(ObjectSafeRoundWrapper::new(R::new(
            rng,
            session_id.as_ref(),
            verifier.clone(),
            inputs,
        )?));
        let serializer = Serializer::new::<SP::WireFormat>();
        let deserializer = Deserializer::new::<SP::WireFormat>();
        Self::new_for_next_round(
            rng,
            session_id,
            signer,
            serializer,
            deserializer,
            first_round,
            Transcript::new(),
        )
    }

    fn new_for_next_round(
        rng: &mut impl CryptoRngCore,
        session_id: SessionId,
        signer: SP::Signer,
        serializer: Serializer,
        deserializer: Deserializer,
        round: Box<dyn ObjectSafeRound<SP::Verifier, Protocol = P>>,
        transcript: Transcript<P, SP>,
    ) -> Result<Self, LocalError> {
        let verifier = signer.verifying_key();

        let echo = round.make_echo_broadcast(rng, &serializer)?;
        let echo_broadcast = SignedMessagePart::new::<SP>(rng, &signer, &session_id, round.id(), echo)?;

        let normal = round.make_normal_broadcast(rng, &serializer)?;
        let normal_broadcast = SignedMessagePart::new::<SP>(rng, &signer, &session_id, round.id(), normal)?;

        let message_destinations = round.message_destinations().clone();

        let possible_next_rounds = if echo_broadcast.payload().is_none() {
            round.possible_next_rounds()
        } else {
            BTreeSet::from([round.id().echo()])
        };

        Ok(Self {
            session_id,
            signer,
            verifier,
            serializer,
            deserializer,
            round,
            echo_broadcast,
            normal_broadcast,
            possible_next_rounds,
            message_destinations,
            transcript,
        })
    }

    /// Returns the verifier corresponding to the session's signer.
    pub fn verifier(&self) -> SP::Verifier {
        self.verifier.clone()
    }

    /// Returns the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the set of message destinations for the current round.
    pub fn message_destinations(&self) -> &BTreeSet<SP::Verifier> {
        &self.message_destinations
    }

    /// Creates the message to be sent to the given destination.
    ///
    /// The destination must be one of those returned by [`message_destinations`](`Self::message_destinations`).
    pub fn make_message(
        &self,
        rng: &mut impl CryptoRngCore,
        destination: &SP::Verifier,
    ) -> Result<(Message<SP::Verifier>, ProcessedArtifact<SP>), LocalError> {
        let (direct_message, artifact) =
            self.round
                .make_direct_message_with_artifact(rng, &self.serializer, destination)?;

        let message = Message::new::<SP>(
            rng,
            &self.signer,
            &self.session_id,
            self.round.id(),
            destination,
            direct_message,
            self.echo_broadcast.clone(),
            self.normal_broadcast.clone(),
        )?;

        let processed_artifact = ProcessedArtifact {
            destination: destination.clone(),
            artifact,
        };

        Ok((message, processed_artifact))
    }

    /// Adds the artifact from [`make_message`](`Self::make_message`) to the accumulator.
    pub fn add_artifact(
        &self,
        accum: &mut RoundAccumulator<P, SP>,
        processed: ProcessedArtifact<SP>,
    ) -> Result<(), LocalError> {
        accum.add_artifact(processed)
    }

    /// Returns the ID of the current round.
    pub fn round_id(&self) -> RoundId {
        self.round.id()
    }

    /// Performs some preliminary checks on the message to verify its integrity.
    ///
    /// On the happy path, the return values are as follows:
    ///     - `Ok(Some(…))` if the message passes all checks.
    ///     - `Ok(None)` if the message passed all checks, but is not for this round. In this case
    ///     the preprocessed message is buffered in the "cached" message and applied in the next round.
    ///
    /// On the unhappy path, the return values are:
    ///     - `Ok(None)` when something goes wrong, either because there's a problem at the
    /// sending side or the message was received in the wrong context (e.g. wrong session, wrong
    /// round etc). In most cases a `RemoteError` is added to the `RoundAccumulator`.
    ///     - `Err` means an error while processing the data locally (likely bugs or
    /// deserialization issues).
    pub fn preprocess_message(
        &self,
        accum: &mut RoundAccumulator<P, SP>,
        from: &SP::Verifier,
        message: Message<SP::Verifier>,
    ) -> Result<PreprocessOutcome<SP::Verifier>, LocalError> {
        // Quick preliminary checks, before we proceed with more expensive verification
        let key = self.verifier();
        if self.transcript.is_banned(from) || accum.is_banned(from) {
            trace!("{key:?} Banned.");
            return Ok(PreprocessOutcome::remote_error("The sender is banned"));
        }

        let checked_message = match message.unify_metadata() {
            Some(checked_message) => checked_message,
            None => {
                let err = "Mismatched metadata in bundled messages.";
                accum.register_unprovable_error(from, RemoteError::new(err))?;
                trace!("{key:?} {err}");
                return Ok(PreprocessOutcome::remote_error(err));
            }
        };
        let message_round_id = checked_message.metadata().round_id();

        if checked_message.metadata().session_id() != &self.session_id {
            let err = "The received message has an incorrect session ID";
            accum.register_unprovable_error(from, RemoteError::new(err))?;
            trace!("{key:?} {err}");
            return Ok(PreprocessOutcome::remote_error(err));
        }

        enum MessageFor {
            ThisRound,
            NextRound,
        }

        let message_for = if message_round_id == self.round_id() {
            if accum.message_is_being_processed(from) {
                let err = "Message from this party is already being processed";
                accum.register_unprovable_error(from, RemoteError::new(err))?;
                trace!("{key:?} {err}");
                return Ok(PreprocessOutcome::remote_error(err));
            }
            MessageFor::ThisRound
        } else if self.possible_next_rounds.contains(&message_round_id) {
            if accum.message_is_cached(from, message_round_id) {
                let err = format!("Message for {:?} is already cached", message_round_id);
                accum.register_unprovable_error(from, RemoteError::new(&err))?;
                trace!("{key:?} {err}");
                return Ok(PreprocessOutcome::remote_error(err));
            }
            MessageFor::NextRound
        } else {
            let err = format!("Unexpected message round ID: {:?}", message_round_id);
            accum.register_unprovable_error(from, RemoteError::new(&err))?;
            trace!("{key:?} {err}");
            return Ok(PreprocessOutcome::remote_error(err));
        };

        // Verify the signature now

        let verified_message = match checked_message.verify::<SP>(from) {
            Ok(verified_message) => verified_message,
            Err(MessageVerificationError::InvalidSignature) => {
                let err = "The signature could not be deserialized.";
                accum.register_unprovable_error(from, RemoteError::new(err))?;
                trace!("{key:?} {err}");
                return Ok(PreprocessOutcome::remote_error(err));
            }
            Err(MessageVerificationError::SignatureMismatch) => {
                let err = "Message verification failed.";
                accum.register_unprovable_error(from, RemoteError::new(err))?;
                trace!("{key:?} {err}");
                return Ok(PreprocessOutcome::remote_error(err));
            }
            Err(MessageVerificationError::Local(error)) => return Err(error),
        };
        debug!("{key:?}: Received {message_round_id:?} message from {from:?}");

        match message_for {
            MessageFor::ThisRound => {
                accum.mark_processing(&verified_message)?;
                Ok(PreprocessOutcome::ToProcess(verified_message))
            }
            MessageFor::NextRound => {
                debug!("{key:?}: Caching message from {from:?} for {message_round_id:?}");
                accum.cache_message(verified_message)?;
                Ok(PreprocessOutcome::Cached)
            }
        }
    }

    /// Processes a verified message.
    ///
    /// This can be called in a spawned task if it is known to take a long time.
    pub fn process_message(
        &self,
        rng: &mut impl CryptoRngCore,
        message: VerifiedMessage<SP::Verifier>,
    ) -> ProcessedMessage<P, SP> {
        let processed = self.round.receive_message(
            rng,
            &self.deserializer,
            message.from(),
            message.echo_broadcast().clone(),
            message.normal_broadcast().clone(),
            message.direct_message().clone(),
        );
        // We could filter out and return a possible `LocalError` at this stage,
        // but it's no harm in delaying it until `ProcessedMessage` is added to the accumulator.
        ProcessedMessage { message, processed }
    }

    /// Adds a result of [`process_message`](`Self::process_message`) to the accumulator.
    pub fn add_processed_message(
        &self,
        accum: &mut RoundAccumulator<P, SP>,
        processed: ProcessedMessage<P, SP>,
    ) -> Result<(), LocalError> {
        accum.add_processed_message(&self.transcript, processed)
    }

    /// Makes an accumulator for a new round.
    pub fn make_accumulator(&self) -> RoundAccumulator<P, SP> {
        RoundAccumulator::new(self.round.expecting_messages_from())
    }

    /// Terminates the session.
    pub fn terminate(self, accum: RoundAccumulator<P, SP>) -> Result<SessionReport<P, SP>, LocalError> {
        let round_id = self.round_id();
        let transcript = self.transcript.update(
            round_id,
            accum.echo_broadcasts,
            accum.normal_broadcasts,
            accum.direct_messages,
            accum.provable_errors,
            accum.unprovable_errors,
            accum.still_have_not_sent_messages,
        )?;
        Ok(SessionReport::new(SessionOutcome::NotEnoughMessages, transcript))
    }

    /// Attempts to finalize the current round.
    pub fn finalize_round(
        self,
        rng: &mut impl CryptoRngCore,
        accum: RoundAccumulator<P, SP>,
    ) -> Result<RoundOutcome<P, SP>, LocalError> {
        let verifier = self.verifier().clone();
        let round_id = self.round_id();

        let transcript = self.transcript.update(
            round_id,
            accum.echo_broadcasts,
            accum.normal_broadcasts,
            accum.direct_messages,
            accum.provable_errors,
            accum.unprovable_errors,
            accum.still_have_not_sent_messages,
        )?;

        let echo_round_needed = !self.echo_broadcast.payload().is_none();

        if echo_round_needed {
            let round = Box::new(ObjectSafeRoundWrapper::new(EchoRound::<P, SP>::new(
                verifier,
                self.echo_broadcast,
                transcript.echo_broadcasts(round_id)?,
                self.round,
                accum.payloads,
                accum.artifacts,
            )));
            let cached_messages = filter_messages(accum.cached, round.id());
            let session = Session::new_for_next_round(
                rng,
                self.session_id,
                self.signer,
                self.serializer,
                self.deserializer,
                round,
                transcript,
            )?;
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
                    let round = another_round.into_boxed();

                    // Protecting against common bugs
                    if !self.possible_next_rounds.contains(&round.id()) {
                        return Err(LocalError::new(format!("Unexpected next round id: {:?}", round.id())));
                    }

                    // These messages could have been cached before
                    // processing messages from the same node for the current round.
                    // So there might have been some new errors, and we need to check again
                    // if the sender is already banned.
                    let cached_messages = filter_messages(accum.cached, round.id())
                        .into_iter()
                        .filter(|message| !transcript.is_banned(message.from()))
                        .collect::<Vec<_>>();

                    let session = Session::new_for_next_round(
                        rng,
                        self.session_id,
                        self.signer,
                        self.serializer,
                        self.deserializer,
                        round,
                        transcript,
                    )?;
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
            }),
        }
    }

    /// Checks if the round can be finalized.
    pub fn can_finalize(&self, accum: &RoundAccumulator<P, SP>) -> CanFinalize {
        accum.can_finalize()
    }
}

/// Possible answers to whether the round can be finalized.
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

/// A mutable accumulator for collecting the results and errors from processing messages for a single round.
#[derive_where::derive_where(Debug)]
pub struct RoundAccumulator<P: Protocol, SP: SessionParameters> {
    still_have_not_sent_messages: BTreeSet<SP::Verifier>,
    expecting_messages_from: BTreeSet<SP::Verifier>,
    processing: BTreeSet<SP::Verifier>,
    payloads: BTreeMap<SP::Verifier, Payload>,
    artifacts: BTreeMap<SP::Verifier, Artifact>,
    cached: BTreeMap<SP::Verifier, BTreeMap<RoundId, VerifiedMessage<SP::Verifier>>>,
    echo_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<EchoBroadcast>>,
    normal_broadcasts: BTreeMap<SP::Verifier, SignedMessagePart<NormalBroadcast>>,
    direct_messages: BTreeMap<SP::Verifier, SignedMessagePart<DirectMessage>>,
    provable_errors: BTreeMap<SP::Verifier, Evidence<P, SP>>,
    unprovable_errors: BTreeMap<SP::Verifier, RemoteError>,
}

impl<P, SP> RoundAccumulator<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    fn new(expecting_messages_from: &BTreeSet<SP::Verifier>) -> Self {
        Self {
            still_have_not_sent_messages: expecting_messages_from.clone(),
            expecting_messages_from: expecting_messages_from.clone(),
            processing: BTreeSet::new(),
            payloads: BTreeMap::new(),
            artifacts: BTreeMap::new(),
            cached: BTreeMap::new(),
            echo_broadcasts: BTreeMap::new(),
            normal_broadcasts: BTreeMap::new(),
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

    fn is_banned(&self, from: &SP::Verifier) -> bool {
        self.provable_errors.contains_key(from) || self.unprovable_errors.contains_key(from)
    }

    fn message_is_being_processed(&self, from: &SP::Verifier) -> bool {
        self.processing.contains(from)
    }

    fn message_is_cached(&self, from: &SP::Verifier, round_id: RoundId) -> bool {
        if let Some(entry) = self.cached.get(from) {
            entry.contains_key(&round_id)
        } else {
            false
        }
    }

    fn register_unprovable_error(&mut self, from: &SP::Verifier, error: RemoteError) -> Result<(), LocalError> {
        if self.unprovable_errors.insert(from.clone(), error).is_some() {
            Err(LocalError::new(format!(
                "An unprovable error for {:?} is already registered",
                from
            )))
        } else {
            Ok(())
        }
    }

    fn register_provable_error(&mut self, from: &SP::Verifier, evidence: Evidence<P, SP>) -> Result<(), LocalError> {
        if self.provable_errors.insert(from.clone(), evidence).is_some() {
            Err(LocalError::new(format!(
                "A provable error for {:?} is already registered",
                from
            )))
        } else {
            Ok(())
        }
    }

    fn mark_processing(&mut self, message: &VerifiedMessage<SP::Verifier>) -> Result<(), LocalError> {
        if !self.processing.insert(message.from().clone()) {
            Err(LocalError::new(format!(
                "A message from {:?} is already marked as being processed",
                message.from()
            )))
        } else {
            Ok(())
        }
    }

    fn add_artifact(&mut self, processed: ProcessedArtifact<SP>) -> Result<(), LocalError> {
        let artifact = match processed.artifact {
            Some(artifact) => artifact,
            None => return Ok(()),
        };

        if self.artifacts.insert(processed.destination.clone(), artifact).is_some() {
            return Err(LocalError::new(format!(
                "Artifact for destination {:?} has already been recorded",
                processed.destination
            )));
        }
        Ok(())
    }

    fn add_processed_message(
        &mut self,
        transcript: &Transcript<P, SP>,
        processed: ProcessedMessage<P, SP>,
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
                // Note: only inserting the messages if they actually have a payload
                let (echo_broadcast, normal_broadcast, direct_message) = processed.message.into_parts();
                if !echo_broadcast.payload().is_none() {
                    self.echo_broadcasts.insert(from.clone(), echo_broadcast);
                }
                if !normal_broadcast.payload().is_none() {
                    self.normal_broadcasts.insert(from.clone(), normal_broadcast);
                }
                if !direct_message.payload().is_none() {
                    self.direct_messages.insert(from.clone(), direct_message);
                }
                self.payloads.insert(from.clone(), payload);
                return Ok(());
            }
            Err(error) => error,
        };

        match error.0 {
            ReceiveErrorType::InvalidDirectMessage(error) => {
                let (_echo_broadcast, _normal_broadcast, direct_message) = processed.message.into_parts();
                let evidence = Evidence::new_invalid_direct_message(&from, direct_message, error);
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::InvalidEchoBroadcast(error) => {
                let (echo_broadcast, _normal_broadcast, _direct_message) = processed.message.into_parts();
                let evidence = Evidence::new_invalid_echo_broadcast(&from, echo_broadcast, error);
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::InvalidNormalBroadcast(error) => {
                let (_echo_broadcast, normal_broadcast, _direct_message) = processed.message.into_parts();
                let evidence = Evidence::new_invalid_normal_broadcast(&from, normal_broadcast, error);
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Protocol(error) => {
                let (echo_broadcast, normal_broadcast, direct_message) = processed.message.into_parts();
                let evidence = Evidence::new_protocol_error(
                    &from,
                    echo_broadcast,
                    normal_broadcast,
                    direct_message,
                    error,
                    transcript,
                )?;
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Unprovable(error) => {
                self.unprovable_errors.insert(from.clone(), error);
                Ok(())
            }
            ReceiveErrorType::Echo(error) => {
                let (_echo_broadcast, normal_broadcast, _direct_message) = processed.message.into_parts();
                let evidence = Evidence::new_echo_round_error(&from, normal_broadcast, error)?;
                self.register_provable_error(&from, evidence)
            }
            ReceiveErrorType::Local(error) => Err(error),
        }
    }

    fn cache_message(&mut self, message: VerifiedMessage<SP::Verifier>) -> Result<(), LocalError> {
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

#[derive(Debug)]
pub struct ProcessedArtifact<SP: SessionParameters> {
    destination: SP::Verifier,
    artifact: Option<Artifact>,
}

#[derive(Debug)]
pub struct ProcessedMessage<P: Protocol, SP: SessionParameters> {
    message: VerifiedMessage<SP::Verifier>,
    processed: Result<Payload, ReceiveError<SP::Verifier, P>>,
}

/// The result of preprocessing an incoming message.
#[derive(Debug, Clone)]
pub enum PreprocessOutcome<Verifier> {
    /// The message was successfully verified, pass it on to [`Session::process_message`].
    ToProcess(VerifiedMessage<Verifier>),
    /// The message was intended for the next round and was cached.
    ///
    /// No action required now, cached messages will be returned on successful [`Session::finalize_round`].
    Cached,
    /// There was an error verifying the message.
    ///
    /// The error has been recorded in the accumulator, and will be included in the [`SessionReport`].
    /// The attached value may be used for logging purposes.
    Error(RemoteError),
}

impl<Verifier> PreprocessOutcome<Verifier> {
    pub(crate) fn remote_error(message: impl Into<String>) -> Self {
        Self::Error(RemoteError::new(message))
    }

    /// Returns the verified message for further processing, if any, otherwise returns `None`.
    ///
    /// All the other variants of [`PreprocessOutcome`] are purely informative
    /// (all the required actions have already been performed internally)
    /// so the user may choose to ignore them if no logging is desired.
    pub fn ok(self) -> Option<VerifiedMessage<Verifier>> {
        match self {
            Self::ToProcess(message) => Some(message),
            _ => None,
        }
    }
}

fn filter_messages<Verifier>(
    messages: BTreeMap<Verifier, BTreeMap<RoundId, VerifiedMessage<Verifier>>>,
    round_id: RoundId,
) -> Vec<VerifiedMessage<Verifier>> {
    messages
        .into_values()
        .filter_map(|mut messages| messages.remove(&round_id))
        .collect()
}

#[cfg(test)]
mod tests {
    use alloc::{collections::BTreeMap, string::String, vec::Vec};

    use impls::impls;
    use serde::{Deserialize, Serialize};

    use super::{Message, ProcessedArtifact, ProcessedMessage, Session, VerifiedMessage};
    use crate::{
        protocol::{
            Deserializer, DirectMessage, EchoBroadcast, NormalBroadcast, Protocol, ProtocolError,
            ProtocolValidationError, RoundId,
        },
        testing::{BinaryFormat, TestSessionParams, TestVerifier},
    };

    #[test]
    fn test_concurrency_bounds() {
        // In order to support parallel message creation and processing we need that
        // certain generic types be Send and/or Sync.
        //
        // Since they are generic, this depends on the exact type parameters supplied by the user,
        // so if the user does not want parallelism, they can use generic parameters that are not
        // Send/Sync. But we want to make sure that if the generic parameters are
        // Send/Sync, our types are too.

        struct DummyProtocol;

        #[derive(Debug, Clone, Serialize, Deserialize)]
        struct DummyProtocolError;

        impl ProtocolError for DummyProtocolError {
            fn description(&self) -> String {
                unimplemented!()
            }

            fn verify_messages_constitute_error(
                &self,
                _deserializer: &Deserializer,
                _echo_broadcast: &EchoBroadcast,
                _normal_broadcast: &NormalBroadcast,
                _direct_message: &DirectMessage,
                _echo_broadcasts: &BTreeMap<RoundId, EchoBroadcast>,
                _normal_broadcasts: &BTreeMap<RoundId, NormalBroadcast>,
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
        }

        type SP = TestSessionParams<BinaryFormat>;

        // We need `Session` to be `Send` so that we send a `Session` object to a task
        // to run the loop there.
        assert!(impls!(Session<DummyProtocol, SP>: Send));

        // This is needed so that message processing offloaded to a task could use `&Session`.
        assert!(impls!(Session<DummyProtocol, SP>: Sync));

        // These objects are sent to/from message processing tasks
        assert!(impls!(Message<TestVerifier>: Send));
        assert!(impls!(ProcessedArtifact<SP>: Send));
        assert!(impls!(VerifiedMessage<TestVerifier>: Send));
        assert!(impls!(ProcessedMessage<DummyProtocol, SP>: Send));
    }
}
