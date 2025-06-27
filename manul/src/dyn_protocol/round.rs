use alloc::{boxed::Box, collections::BTreeMap, format};
use core::{any::Any, fmt::Debug};

use rand_core::CryptoRngCore;

use super::{
    evidence::BoxedProvableError,
    format::BoxedFormat,
    message::{
        DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, NormalBroadcast, NormalBroadcastError,
        ProtocolMessage, ProtocolMessagePart,
    },
};
use crate::{
    protocol::{
        CommunicationInfo, FinalizeOutcome, LocalError, MessageParts, NoMessage, PartyId, Protocol, ReceiveError,
        RemoteError, Round, RoundId, TransitionInfo,
    },
    session::EchoRoundError,
    utils::DynTypeId,
};

/// Message payload created in [`Round::receive_message`].
///
/// [`Payload`]s are created as the output of processing an incoming message. When a [`Round`] finalizes, all the
/// `Payload`s received during the round are made available and can be used to decide what to do next (next round?
/// return a final result?). Payloads are not sent to other nodes.
#[derive(Debug)]
pub(crate) struct Payload(pub Box<dyn Any + Send + Sync>);

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
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast Payload into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

/// Associated data created alongside a message in [`Round::make_direct_message`].
///
/// [`Artifact`]s are local to the participant that created it and are usually containers for intermediary secrets
/// and/or dynamic parameters needed in subsequent stages of the protocol. Artifacts are never sent over the wire; they
/// are made available to [`Round::finalize`] for the participant, delivered in the form of a `BTreeMap` where the key
/// is the destination id of the participant to whom the direct message was sent.
#[derive(Debug)]
pub(crate) struct Artifact(pub Box<dyn Any + Send + Sync>);

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
        Ok(*(self.0.downcast::<T>().map_err(|_| {
            LocalError::new(format!(
                "Failed to downcast Artifact into {}",
                core::any::type_name::<T>()
            ))
        })?))
    }
}

/**
A type representing a single round of a protocol.

The way a round will be used by an external caller:
- create messages to send out (by calling [`make_direct_message`](`Self::make_direct_message`)
  and [`make_echo_broadcast`](`Self::make_echo_broadcast`));
- process received messages from other nodes (by calling [`receive_message`](`Self::receive_message`));
- attempt to finalize (by calling [`finalize`](`Self::finalize`)) to produce the next round, or return a result.
*/
pub(crate) trait DynRound<Id>: 'static + Debug + Send + Sync + DynTypeId {
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
    /// The execution layer will guarantee that all the destinations are sure they all received the same broadcast. This
    /// also means that a message containing the broadcasts from all nodes and signed by each node is available. This is
    /// used as part of the evidence of malicious behavior when producing provable offence reports.
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
    /// Unlike echo broadcasts, normal broadcasts are "send and forget" and delivered to every node defined in
    /// [`Self::communication_info`] without any confirmation required by the receiving node.
    fn make_normal_broadcast(
        &self,
        #[allow(unused_variables)] rng: &mut dyn CryptoRngCore,
        #[allow(unused_variables)] format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        Ok(NormalBroadcast::none())
    }

    /// Processes a received message and generates the payload that will be used in [`finalize`](`Self::finalize`). The
    /// message content can be arbitrarily checked and processed to build the exact payload needed to finalize the
    /// round.
    ///
    /// Note that there is no need to authenticate the message at this point;
    /// it has already been done by the execution layer.
    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, BoxedReceiveError<Id>>;

    /// Attempts to finalize the round, producing the next round or the result.
    ///
    /// `payloads` here are the ones previously generated by [`receive_message`](`Self::receive_message`), and
    /// `artifacts` are the ones previously generated by [`make_direct_message`](`Self::make_direct_message`).
    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<BoxedFinalizeOutcome<Id, Self::Protocol>, LocalError>;
}

pub(crate) enum BoxedFinalizeOutcome<Id, P: Protocol<Id>> {
    AnotherRound(BoxedRound<Id, P>),
    Result(P::Result),
}

pub(crate) struct RoundWrapper<R> {
    round: R,
}

impl<R> RoundWrapper<R> {
    pub fn new(round: R) -> Self {
        Self { round }
    }

    pub fn into_inner(self) -> R {
        self.round
    }
}

impl<R> Debug for RoundWrapper<R> {
    fn fmt(&self, _: &mut core::fmt::Formatter<'_>) -> Result<(), core::fmt::Error> {
        todo!()
    }
}

impl<Id, R> DynRound<Id> for RoundWrapper<R>
where
    Id: PartyId,
    R: Round<Id>,
{
    type Protocol = <R as Round<Id>>::Protocol;

    fn transition_info(&self) -> TransitionInfo {
        self.round.transition_info()
    }

    fn communication_info(&self) -> CommunicationInfo<Id> {
        self.round.communication_info()
    }

    fn make_direct_message(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
        destination: &Id,
    ) -> Result<(DirectMessage, Option<Artifact>), LocalError> {
        if let Some((direct_message, artifact)) = self.round.make_direct_message(rng, destination)? {
            Ok((
                DirectMessage::new(format, direct_message)?,
                Some(Artifact::new(artifact)),
            ))
        } else {
            Ok((DirectMessage::none(), None))
        }
    }

    fn make_echo_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<EchoBroadcast, LocalError> {
        let echo_broadcast = self.round.make_echo_broadcast(rng)?;
        if let Some(echo_broadcast) = echo_broadcast {
            EchoBroadcast::new(format, echo_broadcast)
        } else {
            Ok(EchoBroadcast::none())
        }
    }

    fn make_normal_broadcast(
        &self,
        rng: &mut dyn CryptoRngCore,
        format: &BoxedFormat,
    ) -> Result<NormalBroadcast, LocalError> {
        let normal_broadcast = self.round.make_normal_broadcast(rng)?;
        if let Some(normal_broadcast) = normal_broadcast {
            NormalBroadcast::new(format, normal_broadcast)
        } else {
            Ok(NormalBroadcast::none())
        }
    }

    fn receive_message(
        &self,
        format: &BoxedFormat,
        from: &Id,
        message: ProtocolMessage,
    ) -> Result<Payload, BoxedReceiveError<Id>> {
        let direct_message = if NoMessage::equals::<R::DirectMessage>() {
            message.direct_message.assert_is_none()?;
            // TODO: `expect()` can be eliminated here
            NoMessage::new_if_equals::<R::DirectMessage>().expect("DirectMessage is NoMessage")
        } else {
            message.direct_message.deserialize::<R::DirectMessage>(format)?
        };

        let echo_broadcast = if NoMessage::equals::<R::EchoBroadcast>() {
            message.echo_broadcast.assert_is_none()?;
            NoMessage::new_if_equals::<R::EchoBroadcast>().expect("EchoBroadcast is NoMessage")
        } else {
            message.echo_broadcast.deserialize::<R::EchoBroadcast>(format)?
        };

        let normal_broadcast = if NoMessage::equals::<R::NormalBroadcast>() {
            message.normal_broadcast.assert_is_none()?;
            // this is infallible
            NoMessage::new_if_equals::<R::NormalBroadcast>().expect("NormalBroadcast is NoMessage")
        } else {
            message.normal_broadcast.deserialize::<R::NormalBroadcast>(format)?
        };

        let payload = self
            .round
            .receive_message(
                from,
                MessageParts {
                    direct_message,
                    echo_broadcast,
                    normal_broadcast,
                },
            )
            .map_err(|error| BoxedReceiveError::new(error, &self.transition_info().id))?;

        Ok(Payload::new(payload))
    }

    fn finalize(
        self: Box<Self>,
        rng: &mut dyn CryptoRngCore,
        payloads: BTreeMap<Id, Payload>,
        artifacts: BTreeMap<Id, Artifact>,
    ) -> Result<BoxedFinalizeOutcome<Id, Self::Protocol>, LocalError> {
        let payloads = payloads
            .into_iter()
            .map(|(id, payload)| payload.downcast::<R::Payload>().map(|payload| (id, payload)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let artifacts = artifacts
            .into_iter()
            .map(|(id, artifact)| artifact.downcast::<R::Artifact>().map(|artifact| (id, artifact)))
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        self.round
            .finalize(rng, payloads, artifacts)
            .map(|outcome| match outcome {
                FinalizeOutcome::AnotherRound(round) => BoxedFinalizeOutcome::AnotherRound(round),
                FinalizeOutcome::Result(result) => BoxedFinalizeOutcome::Result(result),
            })
    }
}

/// A wrapped new round that may be returned by [`Round::finalize`]
/// or [`EntryPoint::make_round`](`crate::protocol::EntryPoint::make_round`).
#[derive_where::derive_where(Debug)]
pub struct BoxedRound<Id, P: Protocol<Id>>(Box<dyn DynRound<Id, Protocol = P>>);

impl<Id: PartyId, P: Protocol<Id>> BoxedRound<Id, P> {
    pub(crate) fn new_dynamic<R: DynRound<Id, Protocol = P>>(round: R) -> Self {
        Self(Box::new(round))
    }

    /// Wraps an object implementing the dynamic round trait ([`Round`](`crate::protocol::Round`)).
    pub fn new<R: Round<Id, Protocol = P>>(round: R) -> Self {
        Self(Box::new(RoundWrapper::new(round)))
    }

    pub(crate) fn as_ref(&self) -> &dyn DynRound<Id, Protocol = P> {
        self.0.as_ref()
    }

    pub(crate) fn into_boxed(self) -> Box<dyn DynRound<Id, Protocol = P>> {
        self.0
    }

    pub(crate) fn boxed_type_id(&self) -> core::any::TypeId {
        self.0.as_ref().get_type_id()
    }

    fn boxed_type_is<T: 'static>(&self) -> bool {
        core::any::TypeId::of::<T>() == self.boxed_type_id()
    }

    /// Attempts to extract an object of a concrete type, preserving the original on failure.
    pub(crate) fn try_downcast<T: Round<Id>>(self) -> Result<T, Self> {
        if self.boxed_type_is::<RoundWrapper<T>>() {
            // Safety: This is safe since we just checked that we are casting to the correct type.
            let boxed_downcast =
                unsafe { Box::<RoundWrapper<T>>::from_raw(Box::into_raw(self.0) as *mut RoundWrapper<T>) };
            Ok((*boxed_downcast).into_inner())
        } else {
            Err(self)
        }
    }

    /// Attempts to extract an object of a concrete type.
    ///
    /// Fails if the wrapped type is not `T`.
    pub(crate) fn downcast<T: Round<Id>>(self) -> Result<T, LocalError> {
        self.try_downcast()
            .map_err(|_| LocalError::new(format!("Failed to downcast into type {}", core::any::type_name::<T>())))
    }
}

#[derive(Debug)]
pub(crate) enum BoxedReceiveError<Id> {
    Local(LocalError),
    /// The given direct message cannot be deserialized.
    InvalidDirectMessage(DirectMessageError),
    /// The given echo broadcast cannot be deserialized.
    InvalidEchoBroadcast(EchoBroadcastError),
    /// The given normal broadcast cannot be deserialized.
    InvalidNormalBroadcast(NormalBroadcastError),
    // TODO: better name? Other errors are also provable
    Provable(BoxedProvableError<Id>),
    Unprovable(RemoteError),
    Echo(Box<EchoRoundError<Id>>),
}

impl<Id> BoxedReceiveError<Id> {
    pub(crate) fn new<R: Round<Id>>(error: ReceiveError<Id, R>, round_id: &RoundId) -> Self {
        match error {
            ReceiveError::Local(error) => Self::Local(error),
            ReceiveError::Unprovable(error) => Self::Unprovable(error),
            ReceiveError::Provable(error) => Self::Provable(BoxedProvableError::new::<R>(error, round_id)),
        }
    }

    pub(crate) fn group_under(self, group_num: u8) -> Self {
        if let Self::Provable(error) = self {
            Self::Provable(error.group_under(group_num))
        } else {
            self
        }
    }
}

impl<Id> From<LocalError> for BoxedReceiveError<Id> {
    fn from(error: LocalError) -> Self {
        BoxedReceiveError::Local(error)
    }
}

impl<Id> From<BoxedProvableError<Id>> for BoxedReceiveError<Id> {
    fn from(error: BoxedProvableError<Id>) -> Self {
        BoxedReceiveError::Provable(error)
    }
}

impl<Id> From<DirectMessageError> for BoxedReceiveError<Id> {
    fn from(error: DirectMessageError) -> Self {
        BoxedReceiveError::InvalidDirectMessage(error)
    }
}

impl<Id> From<EchoBroadcastError> for BoxedReceiveError<Id> {
    fn from(error: EchoBroadcastError) -> Self {
        BoxedReceiveError::InvalidEchoBroadcast(error)
    }
}

impl<Id> From<NormalBroadcastError> for BoxedReceiveError<Id> {
    fn from(error: NormalBroadcastError) -> Self {
        BoxedReceiveError::InvalidNormalBroadcast(error)
    }
}
