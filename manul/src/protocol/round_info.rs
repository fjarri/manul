use alloc::{boxed::Box, collections::BTreeMap, format};
use core::{fmt::Debug, marker::PhantomData};

use super::{
    evidence::{EvidenceError, EvidenceMessages, ProvableError},
    round::{NoMessage, Protocol, Round},
    round_id::RoundId,
};
use crate::dyn_protocol::{
    BoxedFormat, DirectMessage, EchoBroadcast, NormalBroadcast, ProtocolMessage, ProtocolMessagePart,
    SerializedProvableError,
};

pub(crate) trait DynRoundInfo<Id>: Debug {
    type Protocol: Protocol<Id>;
    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError>;
    fn verify_echo_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &EchoBroadcast,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError>;
    fn verify_normal_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &NormalBroadcast,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError>;

    #[allow(clippy::too_many_arguments)]
    fn verify_evidence(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        error: &SerializedProvableError,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), EvidenceError>;
}

#[derive_where::derive_where(Debug)]
pub(crate) struct StaticRoundInfoAdapter<R>(PhantomData<R>);

impl<Id, R> DynRoundInfo<Id> for StaticRoundInfoAdapter<R>
where
    R: Round<Id>,
{
    type Protocol = R::Protocol;

    fn verify_direct_message_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &DirectMessage,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::DirectMessage>() || !R::expects_direct_message(round_id, shared_data) {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::DirectMessage>(format)
        }
    }

    fn verify_echo_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &EchoBroadcast,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::EchoBroadcast>() || !R::expects_echo_broadcast(round_id, shared_data) {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::EchoBroadcast>(format)
        }
    }

    fn verify_normal_broadcast_is_invalid(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        message: &NormalBroadcast,
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
    ) -> Result<(), EvidenceError> {
        if NoMessage::equals::<R::NormalBroadcast>() || !R::expects_normal_broadcast(round_id, shared_data) {
            message.verify_is_some()
        } else {
            message.verify_is_not::<R::NormalBroadcast>(format)
        }
    }

    fn verify_evidence(
        &self,
        round_id: &RoundId,
        format: &BoxedFormat,
        error: &SerializedProvableError,
        guilty_party: &Id,
        shared_randomness: &[u8],
        shared_data: &<Self::Protocol as Protocol<Id>>::SharedData,
        message: ProtocolMessage,
        previous_messages: BTreeMap<RoundId, ProtocolMessage>,
        combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    ) -> Result<(), EvidenceError> {
        let error = error.deserialize::<Id, R>(format).map_err(|err| {
            EvidenceError::InvalidEvidence(format!(
                "Cannot deserialize the error as {}: {err}",
                core::any::type_name::<R::ProvableError>()
            ))
        })?;
        let evidence_messages = EvidenceMessages {
            message,
            previous_messages,
            combined_echos,
            format,
            phantom: PhantomData,
        };
        error.verify_evidence(
            round_id,
            guilty_party,
            shared_randomness,
            shared_data,
            evidence_messages,
        )
    }
}

#[derive_where::derive_where(Debug)]
pub struct RoundInfo<Id, P: Protocol<Id>>(Box<dyn DynRoundInfo<Id, Protocol = P>>);

impl<Id, P> RoundInfo<Id, P>
where
    P: Protocol<Id>,
{
    pub fn new<R>() -> Self
    where
        R: Round<Id, Protocol = P>,
    {
        Self(Box::new(StaticRoundInfoAdapter(PhantomData::<R>)))
    }

    pub(crate) fn new_obj(round: impl DynRoundInfo<Id, Protocol = P> + 'static) -> Self {
        Self(Box::new(round))
    }

    pub(crate) fn as_ref(&self) -> &dyn DynRoundInfo<Id, Protocol = P> {
        self.0.as_ref()
    }
}
