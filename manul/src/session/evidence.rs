use alloc::{collections::BTreeMap, format, string::String, vec::Vec};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};

use super::{
    echo::{EchoRoundError, EchoRoundMessage},
    message::{MessageVerificationError, SignedMessage},
    session::SessionParameters,
    transcript::Transcript,
    LocalError,
};
use crate::{
    protocol::{
        DirectMessage, DirectMessageError, EchoBroadcast, EchoBroadcastError, MessageValidationError, Protocol,
        ProtocolError, ProtocolValidationError, RoundId,
    },
    utils::SerializableMap,
};

#[derive(Debug, Clone)]
pub enum EvidenceError {
    Local(LocalError),
    InvalidEvidence(String),
}

impl From<MessageVerificationError> for EvidenceError {
    fn from(error: MessageVerificationError) -> Self {
        match error {
            MessageVerificationError::Local(error) => Self::Local(error),
            MessageVerificationError::InvalidSignature => Self::InvalidEvidence("Invalid message signature".into()),
            MessageVerificationError::SignatureMismatch => {
                Self::InvalidEvidence("The signature does not match the payload".into())
            }
        }
    }
}

impl From<DirectMessageError> for EvidenceError {
    fn from(error: DirectMessageError) -> Self {
        Self::InvalidEvidence(format!("Failed to deserialize direct message: {:?}", error))
    }
}

impl From<MessageValidationError> for EvidenceError {
    fn from(error: MessageValidationError) -> Self {
        match error {
            MessageValidationError::Local(error) => Self::Local(error),
            MessageValidationError::InvalidEvidence(error) => Self::InvalidEvidence(error),
        }
    }
}

impl From<ProtocolValidationError> for EvidenceError {
    fn from(error: ProtocolValidationError) -> Self {
        match error {
            ProtocolValidationError::Local(error) => Self::Local(error),
            ProtocolValidationError::InvalidEvidence(error) => Self::InvalidEvidence(error),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Evidence<P: Protocol, SP: SessionParameters> {
    guilty_party: SP::Verifier,
    description: String,
    evidence: EvidenceEnum<P, SP>,
}

impl<P, SP> Evidence<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    pub(crate) fn new_protocol_error(
        verifier: &SP::Verifier,
        echo_broadcast: Option<SignedMessage<EchoBroadcast>>,
        direct_message: SignedMessage<DirectMessage>,
        error: P::ProtocolError,
        transcript: &Transcript<P, SP>,
    ) -> Result<Self, LocalError> {
        let echo_broadcasts = error
            .required_echo_broadcasts()
            .iter()
            .map(|round_id| {
                transcript
                    .get_echo_broadcast(*round_id, verifier)
                    .map(|echo| (*round_id, echo))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let direct_messages = error
            .required_direct_messages()
            .iter()
            .map(|round_id| {
                transcript
                    .get_direct_message(*round_id, verifier)
                    .map(|dm| (*round_id, dm))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let combined_echos = error
            .required_combined_echos()
            .iter()
            .map(|round_id| {
                transcript
                    .get_direct_message(round_id.echo(), verifier)
                    .map(|dm| (*round_id, dm))
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;

        let description = format!("Protocol error: {:?}", error);

        Ok(Self {
            guilty_party: verifier.clone(),
            description,
            evidence: EvidenceEnum::Protocol(ProtocolEvidence {
                error,
                direct_message,
                echo_broadcast,
                direct_messages: direct_messages.into(),
                echo_broadcasts: echo_broadcasts.into(),
                combined_echos: combined_echos.into(),
            }),
        })
    }

    pub(crate) fn new_echo_round_error(
        verifier: &SP::Verifier,
        direct_message: SignedMessage<DirectMessage>,
        error: EchoRoundError<SP::Verifier>,
        transcript: &Transcript<P, SP>,
    ) -> Result<Self, LocalError> {
        let description = format!("{:?}", error);
        match error {
            EchoRoundError::InvalidEcho(from) => Ok(Self {
                guilty_party: verifier.clone(),
                description,
                evidence: EvidenceEnum::InvalidEchoPack(InvalidEchoPackEvidence {
                    direct_message,
                    invalid_echo_sender: from,
                    phantom: core::marker::PhantomData,
                }),
            }),
            EchoRoundError::InvalidBroadcast(from) => {
                // We could avoid all this if we attached the SignedMessage objects
                // directly to the error. But then it would have to be generic over `S`,
                // which the `Round` trait knows nothing about.
                let round_id = direct_message.metadata().round_id().non_echo();
                let we_received = transcript.get_echo_broadcast(round_id, &from)?;

                let deserialized = direct_message
                    .payload()
                    .deserialize::<P, EchoRoundMessage<SP>>()
                    .map_err(|error| {
                        LocalError::new(format!("Failed to deserialize the given direct message: {:?}", error))
                    })?;
                let echoed_to_us = deserialized.echo_messages.get(&from).ok_or_else(|| {
                    LocalError::new(format!(
                        "The echo message from {from:?} is missing from the echo packet"
                    ))
                })?;

                Ok(Self {
                    guilty_party: from,
                    description,
                    evidence: EvidenceEnum::MismatchedBroadcasts(MismatchedBroadcastsEvidence {
                        we_received,
                        echoed_to_us: echoed_to_us.clone(),
                        phantom: core::marker::PhantomData,
                    }),
                })
            }
        }
    }

    pub(crate) fn new_invalid_direct_message(
        verifier: &SP::Verifier,
        direct_message: SignedMessage<DirectMessage>,
        error: DirectMessageError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: format!("{:?}", error),
            evidence: EvidenceEnum::InvalidDirectMessage(InvalidDirectMessageEvidence {
                direct_message,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    pub(crate) fn new_invalid_echo_broadcast(
        verifier: &SP::Verifier,
        echo_broadcast: SignedMessage<EchoBroadcast>,
        error: EchoBroadcastError,
    ) -> Self {
        Self {
            guilty_party: verifier.clone(),
            description: format!("{:?}", error),
            evidence: EvidenceEnum::InvalidEchoBroadcast(InvalidEchoBroadcastEvidence {
                echo_broadcast,
                phantom: core::marker::PhantomData,
            }),
        }
    }

    pub fn guilty_party(&self) -> &SP::Verifier {
        &self.guilty_party
    }

    pub fn description(&self) -> &str {
        &self.description
    }

    pub fn verify(&self, party: &SP::Verifier) -> Result<(), EvidenceError> {
        match &self.evidence {
            EvidenceEnum::Protocol(evidence) => evidence.verify::<SP>(party),
            EvidenceEnum::InvalidDirectMessage(evidence) => evidence.verify::<SP>(party),
            EvidenceEnum::InvalidEchoBroadcast(evidence) => evidence.verify::<SP>(party),
            EvidenceEnum::InvalidEchoPack(evidence) => evidence.verify(party),
            EvidenceEnum::MismatchedBroadcasts(evidence) => evidence.verify::<SP>(party),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
enum EvidenceEnum<P: Protocol, SP: SessionParameters> {
    Protocol(ProtocolEvidence<P>),
    InvalidDirectMessage(InvalidDirectMessageEvidence<P>),
    InvalidEchoBroadcast(InvalidEchoBroadcastEvidence<P>),
    InvalidEchoPack(InvalidEchoPackEvidence<P, SP>),
    MismatchedBroadcasts(MismatchedBroadcastsEvidence<P>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidEchoPackEvidence<P: Protocol, SP: SessionParameters> {
    direct_message: SignedMessage<DirectMessage>,
    invalid_echo_sender: SP::Verifier,
    phantom: core::marker::PhantomData<P>,
}

impl<P, SP> InvalidEchoPackEvidence<P, SP>
where
    P: Protocol,
    SP: SessionParameters,
{
    fn verify(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError> {
        let verified = self.direct_message.clone().verify::<P, SP>(verifier)?;
        let deserialized = verified.payload().deserialize::<P, EchoRoundMessage<SP>>()?;
        let invalid_echo = deserialized
            .echo_messages
            .get(&self.invalid_echo_sender)
            .ok_or_else(|| {
                EvidenceError::InvalidEvidence(format!(
                    "Did not find {:?} in the attached message",
                    self.invalid_echo_sender
                ))
            })?;

        let verified_echo = match invalid_echo.clone().verify::<P, SP>(&self.invalid_echo_sender) {
            Ok(echo) => echo,
            Err(MessageVerificationError::Local(error)) => return Err(EvidenceError::Local(error)),
            // The message was indeed incorrectly signed - fault proven
            Err(MessageVerificationError::InvalidSignature) => return Ok(()),
            Err(MessageVerificationError::SignatureMismatch) => return Ok(()),
        };

        // `from` sent us a correctly signed message but from another round or another session.
        // Provable fault of `from`.
        if verified_echo.metadata() != self.direct_message.metadata() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "There is nothing wrong with the echoed message".into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MismatchedBroadcastsEvidence<P: Protocol> {
    we_received: SignedMessage<EchoBroadcast>,
    echoed_to_us: SignedMessage<EchoBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> MismatchedBroadcastsEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let we_received = self.we_received.clone().verify::<P, SP>(verifier)?;
        let echoed_to_us = self.echoed_to_us.clone().verify::<P, SP>(verifier)?;

        if we_received.metadata() == echoed_to_us.metadata() && we_received.payload() != echoed_to_us.payload() {
            return Ok(());
        }

        Err(EvidenceError::InvalidEvidence(
            "The attached messages don't constitute malicious behavior".into(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidDirectMessageEvidence<P: Protocol> {
    direct_message: SignedMessage<DirectMessage>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> InvalidDirectMessageEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let verified_direct_message = self.direct_message.clone().verify::<P, SP>(verifier)?;
        Ok(P::verify_direct_message_is_invalid(
            self.direct_message.metadata().round_id(),
            verified_direct_message.payload(),
        )?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvalidEchoBroadcastEvidence<P: Protocol> {
    echo_broadcast: SignedMessage<EchoBroadcast>,
    phantom: core::marker::PhantomData<P>,
}

impl<P> InvalidEchoBroadcastEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let verified_echo_broadcast = self.echo_broadcast.clone().verify::<P, SP>(verifier)?;
        Ok(P::verify_echo_broadcast_is_invalid(
            self.echo_broadcast.metadata().round_id(),
            verified_echo_broadcast.payload(),
        )?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProtocolEvidence<P: Protocol> {
    error: P::ProtocolError,
    direct_message: SignedMessage<DirectMessage>,
    echo_broadcast: Option<SignedMessage<EchoBroadcast>>,
    direct_messages: SerializableMap<RoundId, SignedMessage<DirectMessage>>,
    echo_broadcasts: SerializableMap<RoundId, SignedMessage<EchoBroadcast>>,
    combined_echos: SerializableMap<RoundId, SignedMessage<DirectMessage>>,
}

impl<P> ProtocolEvidence<P>
where
    P: Protocol,
{
    fn verify<SP>(&self, verifier: &SP::Verifier) -> Result<(), EvidenceError>
    where
        SP: SessionParameters,
    {
        let session_id = self.direct_message.metadata().session_id();

        let verified_direct_message = self.direct_message.clone().verify::<P, SP>(verifier)?.payload().clone();

        let mut verified_direct_messages = BTreeMap::new();
        for (round_id, direct_message) in self.direct_messages.iter() {
            let verified_direct_message = direct_message.clone().verify::<P, SP>(verifier)?;
            let metadata = verified_direct_message.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_direct_messages.insert(*round_id, verified_direct_message.payload().clone());
        }

        let verified_echo_broadcast = if let Some(echo) = self.echo_broadcast.as_ref() {
            let metadata = echo.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != self.direct_message.metadata().round_id() {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            Some(echo.clone().verify::<P, SP>(verifier)?.payload().clone())
        } else {
            None
        };

        let mut verified_echo_broadcasts = BTreeMap::new();
        for (round_id, echo_broadcast) in self.echo_broadcasts.iter() {
            let verified_echo_broadcast = echo_broadcast.clone().verify::<P, SP>(verifier)?;
            let metadata = verified_echo_broadcast.metadata();
            if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            verified_echo_broadcasts.insert(*round_id, verified_echo_broadcast.payload().clone());
        }

        let mut combined_echos = BTreeMap::new();
        for (round_id, combined_echo) in self.combined_echos.iter() {
            let verified_combined_echo = combined_echo.clone().verify::<P, SP>(verifier)?;
            let metadata = verified_combined_echo.metadata();
            if metadata.session_id() != session_id || metadata.round_id().non_echo() != *round_id {
                return Err(EvidenceError::InvalidEvidence(
                    "Invalid attached message metadata".into(),
                ));
            }
            let echo_set = DirectMessage::deserialize::<P, EchoRoundMessage<SP>>(verified_combined_echo.payload())?;

            let mut verified_echo_set = Vec::new();
            for (other_verifier, echo_broadcast) in echo_set.echo_messages.iter() {
                let verified_echo_broadcast = echo_broadcast.clone().verify::<P, SP>(other_verifier)?;
                let metadata = verified_echo_broadcast.metadata();
                if metadata.session_id() != session_id || metadata.round_id() != *round_id {
                    return Err(EvidenceError::InvalidEvidence(
                        "Invalid attached message metadata".into(),
                    ));
                }
                verified_echo_set.push(verified_echo_broadcast.payload().clone());
            }
            combined_echos.insert(*round_id, verified_echo_set);
        }

        Ok(self.error.verify_messages_constitute_error(
            &verified_echo_broadcast,
            &verified_direct_message,
            &verified_echo_broadcasts,
            &verified_direct_messages,
            &combined_echos,
        )?)
    }
}
