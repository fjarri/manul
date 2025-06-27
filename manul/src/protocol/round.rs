use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
};
use core::{any::TypeId, fmt::Debug, marker::PhantomData};

use rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use super::{
    errors::{LocalError, ReceiveError},
    evidence::ProvableError,
    round_id::{RoundId, TransitionInfo},
    round_info::RoundInfo,
};
use crate::dyn_protocol::BoxedRound;

// PhantomData is here to make it un-constructable by an external user.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct NoMessage(PhantomData<()>);

impl NoMessage {
    pub(crate) fn equals<T: 'static>() -> bool {
        TypeId::of::<T>() == TypeId::of::<NoMessage>()
    }

    pub(crate) fn new_if_equals<T: 'static>() -> Option<T> {
        if Self::equals::<T>() {
            let boxed = Box::new(NoMessage(PhantomData));
            // SAFETY: can cast since we checked that T == NoMessage
            let boxed_downcast = unsafe { Box::<T>::from_raw(Box::into_raw(boxed) as *mut T) };
            Some(*boxed_downcast)
        } else {
            None
        }
    }
}

#[derive(Debug)]
pub struct MessageParts<Id, R: Round<Id> + ?Sized> {
    pub direct_message: R::DirectMessage,
    pub echo_broadcast: R::EchoBroadcast,
    pub normal_broadcast: R::NormalBroadcast,
}

pub trait Round<Id>: 'static + Debug + Send + Sync {
    /// The protocol this round is a part of.
    type Protocol: Protocol<Id>;

    type ProvableError: ProvableError<Id, Round = Self>;

    /// Returns the information about the position of this round in the state transition graph.
    ///
    /// See [`TransitionInfo`] documentation for more details.
    fn transition_info(&self) -> TransitionInfo;

    /// Returns the information about the communication this rounds engages in with other nodes.
    ///
    /// See [`CommunicationInfo`] documentation for more details.
    fn communication_info(&self) -> CommunicationInfo<Id>;

    type DirectMessage: 'static + Serialize + for<'de> Deserialize<'de>;
    type NormalBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;
    type EchoBroadcast: 'static + Serialize + for<'de> Deserialize<'de>;

    type Payload: Send + Sync;
    type Artifact: Send + Sync;

    fn expects_direct_message(
        #[allow(unused_variables)] round_id: &RoundId,
        #[allow(unused_variables)] shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> bool {
        true
    }

    fn expects_normal_broadcast(
        #[allow(unused_variables)] round_id: &RoundId,
        #[allow(unused_variables)] shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> bool {
        true
    }

    fn expects_echo_broadcast(
        #[allow(unused_variables)] round_id: &RoundId,
        #[allow(unused_variables)] shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> bool {
        true
    }

    /// Returns the direct message to the given destination and (maybe) an accompanying artifact.
    ///
    /// Return [`DirectMessage::none`] if this round does not send direct messages.
    ///
    /// In some protocols, when a message to another node is created, there is some associated information
    /// that needs to be retained for later (randomness, proofs of knowledge, and so on).
    /// These should be put in an [`Artifact`] and will be available at the time of [`finalize`](`Self::finalize`).
    #[allow(clippy::type_complexity)]
    fn make_direct_message(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] destination: &Id,
    ) -> Result<Option<(Self::DirectMessage, Self::Artifact)>, LocalError> {
        Ok(None)
    }

    /// Returns the echo broadcast for this round.
    ///
    /// Return [`EchoBroadcast::none`] if this round does not send echo-broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast. This
    /// also means that a message containing the broadcasts from all nodes and signed by each node is available. This is
    /// used as part of the evidence of malicious behavior when producing provable offence reports.
    fn make_echo_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Self::EchoBroadcast>, LocalError> {
        Ok(None)
    }

    /// Returns the normal broadcast for this round.
    ///
    /// Return [`NormalBroadcast::none`] if this round does not send normal broadcast messages.
    /// This is also the blanket implementation.
    ///
    /// Unlike echo broadcasts, normal broadcasts are "send and forget" and delivered to every node defined in
    /// [`Self::communication_info`] without any confirmation required by the receiving node.
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
    ) -> Result<Option<Self::NormalBroadcast>, LocalError> {
        Ok(None)
    }

    /// Processes a received message and generates the payload that will be used in [`finalize`](`Self::finalize`). The
    /// message content can be arbitrarily checked and processed to build the exact payload needed to finalize the
    /// round.
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        from: &Id,
        message_parts: MessageParts<Id, Self>,
    ) -> Result<Self::Payload, ReceiveError<Id, Self>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`), and
    /// `artifacts` are the ones previously generated by [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Self::Payload>,
        artifacts: BTreeMap<Id, Self::Artifact>,
    ) -> Result<FinalizeOutcome<Id, Self::Protocol>, LocalError>;
}

/// Describes what other parties this rounds sends messages to, and what other parties it expects messages from.
#[derive(Debug, Clone)]
pub struct CommunicationInfo<Id> {
    /// The destinations of the messages to be sent out by this round.
    ///
    /// The way it is interpreted by the execution layer is
    /// - An echo broadcast (if any) is sent to all of these destinations;
    /// - A direct message is sent to each of these destinations,
    ///   which means [`make_direct_message`](`Round::make_direct_message`) may be called
    ///   for each element of the returned set.
    pub message_destinations: BTreeSet<Id>,

    /// Returns the set of node IDs from which this round expects messages.
    ///
    /// The execution layer will not call [`finalize`](`Round::finalize`) until all these nodes have responded
    /// (and the corresponding [`receive_message`](`Round::receive_message`) finished successfully).
    pub expecting_messages_from: BTreeSet<Id>,

    /// Returns the specific way the node participates in the echo round following this round.
    ///
    /// Returns [`EchoRoundParticipation::Default`] by default; this works fine when every node
    /// sends messages to every other one, or do not send or receive any echo broadcasts.
    /// Otherwise, review the options in [`EchoRoundParticipation`] and pick the appropriate one.
    pub echo_round_participation: EchoRoundParticipation<Id>,
}

impl<Id: PartyId> CommunicationInfo<Id> {
    /// A regular round that sends messages to all `other_parties`, and expects messages back from them.
    pub fn regular(other_parties: &BTreeSet<Id>) -> Self {
        Self {
            message_destinations: other_parties.clone(),
            expecting_messages_from: other_parties.clone(),
            echo_round_participation: EchoRoundParticipation::Default,
        }
    }
}

/// Possible successful outcomes of [`Round::finalize`].
#[derive(Debug)]
pub enum FinalizeOutcome<Id, P: Protocol<Id>> {
    /// Transition to a new round.
    AnotherRound(BoxedRound<Id, P>),
    /// The protocol reached a result.
    Result(P::Result),
}

/// A distributed protocol.
pub trait Protocol<Id>: 'static + Sized {
    /// The successful result of an execution of this protocol.
    type Result: Debug;

    type SharedData;

    /// Returns the wrapped round types for each round mapped to round IDs.
    fn round_info(round_id: &RoundId) -> Option<RoundInfo<Id, Self>>;
}

/// A round that initiates a protocol and defines how execution begins. It is the only round that can be created outside
/// the protocol flow.
///
/// The `EntryPoint` can carry data, e.g. configuration or external initialization data. All the
/// other rounds are only reachable by the execution layer through [`Round::finalize`].
pub trait EntryPoint<Id: PartyId> {
    /// The protocol implemented by the round this entry points returns.
    type Protocol: Protocol<Id>;

    /// Returns the ID of the round returned by [`Self::make_round`].
    fn entry_round_id() -> RoundId;

    /// Creates the starting round.
    ///
    /// `shared_randomness` can be assumed to be the same for each node participating in a session and can be thought of
    /// as a "session id" bytestring.
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

/// The specific way the node participates in the echo round (if any).
#[derive(Debug, Clone)]
pub enum EchoRoundParticipation<Id> {
    /// The default behavior: sends broadcasts and receives echoed messages, or does neither.
    ///
    /// That is, this node will be a part of the echo round if [`Round::make_echo_broadcast`] generates a message.
    Default,

    /// This node sends broadcasts that will be echoed, but does not receive any.
    Send,

    /// This node receives broadcasts that it needs to echo, but does not send any itself.
    Receive {
        /// The other participants of the echo round
        /// (that is, the nodes to which echoed messages will be sent).
        echo_targets: BTreeSet<Id>,
    },
}
