#![allow(dead_code, unused_variables, missing_docs)]

use alloc::boxed::Box;
use core::{fmt::Debug, marker::PhantomData};

use super::{
    boxed_format::BoxedFormat,
    errors::MessageValidationError,
    message::{DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessagePart},
    round::{Protocol, ProtocolError},
    round_id::RoundId,
    static_round::{NoMessage, StaticRound},
};

pub trait RoundInfo<Id>: Debug {
    type Protocol: Protocol<Id>;
    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError>;
    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError>;
    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError>;
}

#[derive_where::derive_where(Debug)]
pub(crate) struct StaticRoundInfoAdapter<R>(PhantomData<R>);

impl<Id, R> RoundInfo<Id> for StaticRoundInfoAdapter<R>
where
    R: StaticRound<Id>,
{
    type Protocol = R::Protocol;

    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        associated_data: &<<Self::Protocol as Protocol<Id>>::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::DirectMessage>() || !R::expects_direct_message(round_id, associated_data) {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::DirectMessage>(format)
        }
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::EchoBroadcast>() {
            message.verify_is_not::<R::EchoBroadcast>(format)
        } else {
            message.verify_is_some()
        }
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        if NoMessage::equals::<R::NormalBroadcast>() {
            message.verify_is_not::<R::NormalBroadcast>(format)
        } else {
            message.verify_is_some()
        }
    }
}

#[derive_where::derive_where(Debug)]
pub struct BoxedRoundInfo<Id, P: Protocol<Id>>(Box<dyn RoundInfo<Id, Protocol = P>>);

impl<Id, P> BoxedRoundInfo<Id, P>
where
    P: Protocol<Id>,
{
    pub fn new<R>() -> Self
    where
        R: StaticRound<Id, Protocol = P>,
    {
        Self(Box::new(StaticRoundInfoAdapter(PhantomData::<R>)))
    }

    pub(crate) fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        associated_data: &<P::ProtocolError as ProtocolError<Id>>::AssociatedData,
    ) -> Result<(), MessageValidationError> {
        self.0
            .verify_direct_message_is_invalid(round_id, format, message, associated_data)
    }

    pub(crate) fn verify_echo_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &EchoBroadcast,
    ) -> Result<(), MessageValidationError> {
        self.0.verify_echo_broadcast_is_invalid(format, message)
    }

    pub(crate) fn verify_normal_broadcast_is_invalid(
        &self,
        format: &BoxedFormat,
        message: &NormalBroadcast,
    ) -> Result<(), MessageValidationError> {
        self.0.verify_normal_broadcast_is_invalid(format, message)
    }
}
