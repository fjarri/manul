use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    format,
};
use core::{
    any::Any,
    fmt::{Debug, Display},
};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    boxed_format::BoxedFormat,
    boxed_round::BoxedRound,
    errors::{LocalError, MessageValidationError, ProtocolValidationError, ReceiveError},
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart},
    round_id::{RoundId, TransitionInfo},
};

// TODO: make a trait to implement custom threshold strategies
/// A set of IDs with an associated quorum condition.
#[derive(Debug, Clone)]
pub struct IdSet<Id> {
    ids: BTreeSet<Id>,
    threshold: usize,
}

impl<Id: Ord> IdSet<Id> {
    /// Creates a non-threshold ID set (that is, messages from all `ids` must be present for the quorum).
    pub fn new_non_threshold(ids: BTreeSet<Id>) -> Self {
        let threshold = ids.len();
        Self { ids, threshold }
    }

    /// Creates an empty ID set.
    pub fn empty() -> Self {
        Self {
            ids: BTreeSet::new(),
            threshold: 0,
        }
    }

    pub(crate) fn all(&self) -> &BTreeSet<Id> {
        &self.ids
    }

    pub(crate) fn is_quorum(&self, ids: &BTreeSet<Id>) -> bool {
        // TODO: assuming `ids` are a subset of `self.ids`. Can we?
        ids.len() >= self.threshold
    }

    pub(crate) fn is_quorum_possible(&self, banned_ids: &BTreeSet<Id>) -> bool {
        let ids = self.ids.intersection(banned_ids).collect::<BTreeSet<_>>();
        self.ids.len() - ids.len() >= self.threshold
    }
}

/// Encapsulates the communication info for the main round and the possible echo round.
#[derive(Debug, Clone)]
pub struct CommunicationInfo<Id> {
    /// Communication info for the main part of the round (that is, not considering the echo round).
    pub main_round: RoundCommunicationInfo<Id>,

    /// The specific way the node participates in the echo round following this round.
    ///
    /// `None` means that, if there is an echo round, the message destinations and expected messages senders
    /// are the same as in the main round.
    pub echo_round: EchoRoundCommunicationInfo<Id>,
}

/// Describes what other parties this rounds sends messages to, and what other parties it expects messages from.
#[derive(Debug, Clone)]
pub struct RoundCommunicationInfo<Id> {
    /// The destinations of the messages to be sent out by this round.
    ///
    /// The way it is interpreted by the execution layer is
    /// - An echo broadcast (if any) is sent to all of these destinations;
    /// - A direct message is sent to each of these destinations,
    ///   which means [`make_direct_message`](`Round::make_direct_message`) may be called
    ///   for each element of the returned set.
    pub message_destinations: BTreeSet<Id>,

    /// The set of node IDs from which this round expects messages.
    ///
    /// The execution layer will not call [`finalize`](`Round::finalize`) until enough nodes to constitute the quorum
    /// have responded (and the corresponding [`receive_message`](`Round::receive_message`) finished successfully).
    pub expecting_messages_from: IdSet<Id>,
}

impl<Id: PartyId> RoundCommunicationInfo<Id> {
    /// A regular round that sends messages to all `other_parties`, and expects messages back from them.
    pub fn all_to_all(other_parties: &BTreeSet<Id>) -> Self {
        Self {
            message_destinations: other_parties.clone(),
            expecting_messages_from: IdSet::new_non_threshold(other_parties.clone()),
        }
    }

    pub fn none() -> Self {
        Self {
            message_destinations: BTreeSet::new(),
            expecting_messages_from: IdSet::empty(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum EchoRoundCommunicationInfo<Id> {
    None,
    SameAsMainRound,
    Custom(RoundCommunicationInfo<Id>),
}

/// Possible successful outcomes of [`Round::finalize`].
#[derive(Debug)]
pub enum FinalizeOutcome<Id: PartyId, P: Protocol<Id>> {
    /// Transition to a new round.
    AnotherRound(BoxedRound<Id, P>),
    /// The protocol reached a result.
    Result(P::Result),
}

/// A distributed protocol.
pub trait Protocol<Id>: 'static {
    /// The successful result of an execution of this protocol.
    type Result: Debug;

    /// An object of this type will be returned when a provable error happens during [`Round::receive_message`].
    type ProtocolError: ProtocolError<Id>;

    /// Returns `Ok(())` if the given direct message cannot be deserialized
    /// assuming it is a direct message from the round `round_id`.
    ///
    /// Normally one would use [`ProtocolMessagePart::verify_is_not`] and [`ProtocolMessagePart::verify_is_some`]
    /// when implementing this.
    fn verify_direct_message_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &DirectMessage,
    ) -> Result<(), MessageValidationError>;

    /// Returns `Ok(())` if the given echo broadcast cannot be deserialized
    /// assuming it is an echo broadcast from the round `round_id`.
    ///
    /// Normally one would use [`ProtocolMessagePart::verify_is_not`] and [`ProtocolMessagePart::verify_is_some`]
    /// when implementing this.
    fn verify_echo_broadcast_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError>;

    /// Returns `Ok(())` if the given echo broadcast cannot be deserialized
    /// assuming it is an echo broadcast from the round `round_id`.
    ///
    /// Normally one would use [`ProtocolMessagePart::verify_is_not`] and [`ProtocolMessagePart::verify_is_some`]
    /// when implementing this.
    fn verify_normal_broadcast_is_invalid(
        format: &BoxedFormat,
        round_id: &RoundId,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError>;
}

/// Declares which parts of the message from a round have to be stored to serve as the evidence of malicious behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredMessageParts {
    pub(crate) echo_broadcast: bool,
    pub(crate) normal_broadcast: bool,
    pub(crate) direct_message: bool,
}

impl RequiredMessageParts {
    fn new(echo_broadcast: bool, normal_broadcast: bool, direct_message: bool) -> Self {
        // We must require at least one part, otherwise this struct doesn't need to be created.
        debug_assert!(echo_broadcast || normal_broadcast || direct_message);
        Self {
            echo_broadcast,
            normal_broadcast,
            direct_message,
        }
    }

    /// Store echo broadcast
    pub fn echo_broadcast() -> Self {
        Self::new(true, false, false)
    }

    /// Store normal broadcast
    pub fn normal_broadcast() -> Self {
        Self::new(false, true, false)
    }

    /// Store direct message
    pub fn direct_message() -> Self {
        Self::new(false, false, true)
    }

    /// Store echo broadcast in addition to what is already stored.
    pub fn and_echo_broadcast(&self) -> Self {
        Self::new(true, self.normal_broadcast, self.direct_message)
    }

    /// Store normal broadcast in addition to what is already stored.
    pub fn and_normal_broadcast(&self) -> Self {
        Self::new(self.echo_broadcast, true, self.direct_message)
    }

    /// Store direct message in addition to what is already stored.
    pub fn and_direct_message(&self) -> Self {
        Self::new(self.echo_broadcast, self.normal_broadcast, true)
    }
}

/// Declares which messages from this and previous rounds
/// have to be stored to serve as the evidence of malicious behavior.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequiredMessages {
    pub(crate) this_round: RequiredMessageParts,
    pub(crate) previous_rounds: Option<BTreeMap<RoundId, RequiredMessageParts>>,
    pub(crate) combined_echos: Option<BTreeSet<RoundId>>,
}

impl RequiredMessages {
    /// The general case constructor.
    ///
    /// `this_round` specifies the message parts to be stored from the message that triggered the error.
    ///
    /// `previous_rounds` specifies, optionally, if any message parts from the previous rounds need to be included.
    ///
    /// `combined_echos` specifies, optionally, if any echoed broadcasts need to be included.
    /// The combined echos are echo broadcasts sent by a party during the echo round,
    /// where it bundles all the received broadcasts and sends them back to everyone.
    /// That is, they will include the echo broadcasts from all other nodes signed by the guilty party.
    pub fn new(
        this_round: RequiredMessageParts,
        previous_rounds: Option<BTreeMap<RoundId, RequiredMessageParts>>,
        combined_echos: Option<BTreeSet<RoundId>>,
    ) -> Self {
        Self {
            this_round,
            previous_rounds,
            combined_echos,
        }
    }
}

/// Describes provable errors originating during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which, in combination, prove the party's malicious actions.
pub trait ProtocolError<Id>: Display + Debug + Clone + Serialize + for<'de> Deserialize<'de> {
    /// Additional data that cannot be derived from the node's messages alone
    /// and therefore has to be supplied externally during evidence verification.
    type AssociatedData: Debug;

    /// Specifies the messages of the guilty party that need to be stored as the evidence
    /// to prove its malicious behavior.
    fn required_messages(&self) -> RequiredMessages;

    /// Returns `Ok(())` if the attached messages indeed prove that a malicious action happened.
    ///
    /// The signatures and metadata of the messages will be checked by the calling code,
    /// the responsibility of this method is just to check the message contents.
    ///
    /// `message` contain the message parts that triggered the error
    /// during [`Round::receive_message`].
    ///
    /// `previous_messages` are message parts from the previous rounds, as requested by
    /// [`required_messages`](Self::required_messages).
    ///
    /// Note that if some message part was not requested by above methods, it will be set to an empty one
    /// in the [`ProtocolMessage`], even if it was present originally.
    ///
    /// `combined_echos` are bundled echos from other parties from the previous rounds,
    /// as requested by [`required_messages`](Self::required_messages).
    #[allow(clippy::too_many_arguments)]
    fn verify_messages_constitute_error(
        &self,
        format: &BoxedFormat,
        guilty_party: &Id,
        shared_randomness: &[u8],
        associated_data: &Self::AssociatedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError>;
}

#[derive(displaydoc::Display, Debug, Clone, Copy, Serialize, Deserialize)]
/// A stub type indicating that this protocol does not generate any provable errors.
pub struct NoProtocolErrors;

impl<Id> ProtocolError<Id> for NoProtocolErrors {
    type AssociatedData = ();

    fn required_messages(&self) -> RequiredMessages {
        panic!("Attempt to use an empty error type in an evidence. This is a bug in the protocol implementation.")
    }

    fn verify_messages_constitute_error(
        &self,
        _format: &BoxedFormat,
        _guilty_party: &Id,
        _shared_randomness: &[u8],
        _associated_data: &Self::AssociatedData,
        _message: ProtocolMessage,
        _previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        _combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), ProtocolValidationError> {
        panic!("Attempt to use an empty error type in an evidence. This is a bug in the protocol implementation.")
    }
}

/// Message payload created in [`Round::receive_message`].
#[derive(Debug)]
pub struct Payload(pub Box<dyn Any + Send + Sync>);

impl Payload {
    /// Creates a new payload.
    ///
    /// Would be normally called in [`Round::receive_message`].
    pub fn new<T: 'static + Send + Sync>(payload: T) -> Self {
        Self(Box::new(payload))
    }

    /// Creates an empty payload.
    ///
    /// Use it in [`Round::receive_message`] if it does not need to create payloads.
    pub fn empty() -> Self {
        Self::new(())
    }

    /// Attempts to downcast back to the concrete type.
    ///
    /// Would be normally called in [`Round::finalize`].
    pub fn downcast<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| LocalError::new(format!("Failed to downcast into {}", core::any::type_name::<T>())))?))
    }
}

/// Associated data created alongside a message in [`Round::make_direct_message`].
#[derive(Debug)]
pub struct Artifact(pub Box<dyn Any + Send + Sync>);

impl Artifact {
    /// Creates a new artifact.
    ///
    /// Would be normally called in [`Round::make_direct_message`].
    pub fn new<T: 'static + Send + Sync>(artifact: T) -> Self {
        Self(Box::new(artifact))
    }

    /// Attempts to downcast back to the concrete type.
    ///
    /// Would be normally called in [`Round::finalize`].
    pub fn downcast<T: 'static>(self) -> Result<T, LocalError> {
        Ok(*(self
            .0
            .downcast::<T>()
            .map_err(|_| LocalError::new(format!("Failed to downcast into {}", core::any::type_name::<T>())))?))
    }
}

/// A round that initiates a protocol.
///
/// This is a round that can be created directly;
/// all the others are only reachable throud [`Round::finalize`] by the execution layer.
pub trait EntryPoint<Id: PartyId> {
    /// The protocol implemented by the round this entry points returns.
    type Protocol: Protocol<Id>;

    /// Returns the ID of the round returned by [`Self::make_round`].
    fn entry_round_id() -> RoundId;

    /// Creates the round.
    ///
    /// `session_id` can be assumed to be the same for each node participating in a session.
    /// `id` is the ID of this node.
    fn make_round(
        self,
        rng: &mut dyn CryptoRngCore,
        shared_randomness: &[u8],
        id: &Id,
    ) -> Result<BoxedRound<Id, Self::Protocol>, LocalError>;
}

/// A trait alias for the combination of traits needed for a party identifier.
pub trait PartyId: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

impl<T> PartyId for T where T: 'static + Debug + Clone + Ord + Send + Sync + Serialize + for<'de> Deserialize<'de> {}

mod sealed {
    /// A dyn safe trait to get the type's ID.
    pub trait DynTypeId: 'static {
        /// Returns the type ID of the implementing type.
        fn get_type_id(&self) -> core::any::TypeId {
            core::any::TypeId::of::<Self>()
        }
    }

    impl<T: 'static> DynTypeId for T {}
}

use sealed::DynTypeId;

/**
A type representing a single round of a protocol.

The way a round will be used by an external caller:
- create messages to send out (by calling [`make_direct_message`](`Self::make_direct_message`)
  and [`make_echo_broadcast`](`Self::make_echo_broadcast`));
- process received messages from other nodes (by calling [`receive_message`](`Self::receive_message`));
- attempt to finalize (by calling [`finalize`](`Self::finalize`)) to produce the next round, or return a result.
*/
pub trait Round<Id: PartyId>: 'static + Debug + Send + Sync + DynTypeId {
    /// The protocol this round is a part of.
    type Protocol: Protocol<Id>;

    /// Returns the information about the position of this round in the state transition graph.
    ///
    /// See [`TransitionInfo`] documentation for more details.
    fn transition_info(&self) -> TransitionInfo;

    /// Returns the information about the communication this rounds engages in with other nodes.
    ///
    /// See [`CommunicationInfo`] documentation for more details.
    fn communication_info(&self) -> CommunicationInfo<Id>;

    /// Returns the direct message to the given destination and (maybe) an accompanying artifact.
    ///
    /// Return [`DirectMessage::none`] if this round does not send direct messages.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Artifact`] and will be available at the time of [`finalize`](`Self::finalize`).
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] format: &BoxedFormat,
        #[allow(unused_variables)] destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        Ok((DirectMessage::none(), None))
    }

    /// Returns the echo broadcast for this round.
    ///
    /// Return [`EchoBroadcast::none`] if this round does not send echo-broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast.
    /// This also means that a message with the broadcasts from all nodes signed by each node is available
    /// if an evidence of malicious behavior has to be constructed.
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        Ok(EchoBroadcast::none())
    }

    /// Returns the normal broadcast for this round.
    ///
    /// Return [`NormalBroadcast::none`] if this round does not send normal broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// Unlike the echo broadcasts, these will be just sent to every node defined in [`Self::communication_info`]
    /// without any confirmation required.
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        Ok(NormalBroadcast::none())
    }

    /// Processes the received message and generates the payload that will be used in [`finalize`](`Self::finalize`).
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, ReceiveError<Id, Self::Protocol>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`),
    /// and `artifacts` are the ones previously generated by
    /// [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;
}
