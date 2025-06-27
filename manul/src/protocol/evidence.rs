use alloc::{
    collections::{BTreeMap, BTreeSet},
    format,
    string::String,
};
use core::{fmt::Debug, marker::PhantomData};

use serde::{Deserialize, Serialize};

use super::{
    errors::LocalError,
    round::{PartyId, Protocol, Round},
    round_id::RoundId,
};
use crate::dyn_protocol::{BoxedFormat, EchoBroadcast, ProtocolMessage, ProtocolMessagePart};

/// Describes provable errors originating during protocol execution.
///
/// Provable here means that we can create an evidence object entirely of messages signed by some party,
/// which, in combination, prove the party's malicious actions.
pub trait ProvableError<Id>: 'static + Debug + Clone + Send + Sync + Serialize + for<'de> Deserialize<'de> {
    type Round: Round<Id>;

    fn description(&self) -> String;

    /// Specifies the messages of the guilty party that need to be stored as the evidence
    /// to prove its malicious behavior.
    fn required_messages(&self, round_id: &RoundId) -> RequiredMessages;

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
    fn verify_evidence(
        &self,
        round_id: &RoundId,
        from: &Id,
        shared_randomness: &[u8],
        shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError>;
}

#[derive(Debug)]
pub struct EvidenceMessages<'a, Id, R: Round<Id>> {
    // TODO: implement a new() instead of publishing fields
    pub(crate) message: ProtocolMessage,
    pub(crate) previous_messages: BTreeMap<RoundId, ProtocolMessage>,
    pub(crate) combined_echos: BTreeMap<RoundId, BTreeMap<Id, EchoBroadcast>>,
    pub(crate) format: &'a BoxedFormat,
    pub(crate) phantom: PhantomData<R>,
}

impl<'a, Id: PartyId, R: Round<Id>> EvidenceMessages<'a, Id, R> {
    pub fn previous_echo_broadcast<PR: Round<Id>>(&self, round_num: u8) -> Result<PR::EchoBroadcast, EvidenceError> {
        // TODO: we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self
            .previous_messages
            .get(&RoundId::new(round_num))
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Messages for round {round_num} not found")))?;
        message_parts
            .echo_broadcast
            .deserialize::<PR::EchoBroadcast>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize an echo broadcast for round {round_num}: {error}",
                ))
            })
    }

    pub fn previous_normal_broadcast<PR: Round<Id>>(
        &self,
        round_num: u8,
    ) -> Result<PR::NormalBroadcast, EvidenceError> {
        // TODO: we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self
            .previous_messages
            .get(&RoundId::new(round_num))
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Messages for round {round_num} not found")))?;
        message_parts
            .normal_broadcast
            .deserialize::<PR::NormalBroadcast>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize a normal broadcast for round {round_num}: {error}",
                ))
            })
    }

    pub fn previous_direct_message<PR: Round<Id>>(&self, round_num: u8) -> Result<PR::DirectMessage, EvidenceError> {
        // TODO: we can check here that the RoundInfo corresponding to `round_num` is of a correct type.
        let message_parts = self
            .previous_messages
            .get(&RoundId::new(round_num))
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Messages for round {round_num} not found")))?;
        message_parts
            .direct_message
            .deserialize::<PR::DirectMessage>(self.format)
            .map_err(|error| {
                EvidenceError::InvalidEvidence(format!(
                    "Failed to deserialize a normal broadcast for round {round_num}: {error}",
                ))
            })
    }

    pub fn combined_echos<PR: Round<Id>>(
        &self,
        round_num: u8,
    ) -> Result<BTreeMap<Id, PR::EchoBroadcast>, EvidenceError> {
        let combined_echos = self
            .combined_echos
            .get(&RoundId::new(round_num))
            .ok_or_else(|| EvidenceError::InvalidEvidence(format!("Combined echos for round {round_num} not found")))?;
        combined_echos
            .iter()
            .map(|(id, echo_broadcast)| {
                echo_broadcast
                    .deserialize::<PR::EchoBroadcast>(self.format)
                    .map_err(|error| {
                        EvidenceError::InvalidEvidence(format!(
                            "Failed to deserialize a direct message for round {round_num}: {error}",
                        ))
                    })
                    .map(|echo_broadcast| (id.clone(), echo_broadcast))
            })
            .collect()
    }

    pub fn direct_message(&self) -> Result<R::DirectMessage, EvidenceError> {
        self.message
            .direct_message
            .deserialize::<R::DirectMessage>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing direct message: {}", err)))
    }

    pub fn echo_broadcast(&self) -> Result<R::EchoBroadcast, EvidenceError> {
        self.message
            .echo_broadcast
            .deserialize::<R::EchoBroadcast>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing echo broadcast: {}", err)))
    }

    pub fn normal_broadcast(&self) -> Result<R::NormalBroadcast, EvidenceError> {
        self.message
            .normal_broadcast
            .deserialize::<R::NormalBroadcast>(self.format)
            .map_err(|err| EvidenceError::InvalidEvidence(format!("Error deserializing normal broadcast: {}", err)))
    }

    pub(crate) fn into_round<NR>(self) -> EvidenceMessages<'a, Id, NR>
    where
        NR: Round<
            Id,
            EchoBroadcast = R::EchoBroadcast,
            NormalBroadcast = R::NormalBroadcast,
            DirectMessage = R::DirectMessage,
        >,
    {
        EvidenceMessages::<Id, NR> {
            message: self.message,
            previous_messages: self.previous_messages,
            combined_echos: self.combined_echos,
            format: self.format,
            phantom: PhantomData,
        }
    }
}

#[derive_where::derive_where(Clone)]
#[derive(Debug, Copy, Serialize, Deserialize)]
pub struct NoProvableErrors<R>(PhantomData<R>);

impl<Id: PartyId, R: Round<Id>> ProvableError<Id> for NoProvableErrors<R> {
    type Round = R;
    fn description(&self) -> String {
        panic!("Methods of `NoProvableErrors` should not be called during normal operation.")
    }
    fn required_messages(&self, _round_id: &RoundId) -> RequiredMessages {
        panic!("Methods of `NoProvableErrors` should not be called during normal operation.")
    }
    fn verify_evidence(
        &self,
        _round_id: &RoundId,
        _from: &Id,
        _shared_randomness: &[u8],
        _shared_data: &<<Self::Round as Round<Id>>::Protocol as Protocol<Id>>::SharedData,
        _messages: EvidenceMessages<'_, Id, Self::Round>,
    ) -> Result<(), EvidenceError> {
        panic!("Methods of `NoProvableErrors` should not be called during normal operation.")
    }
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

    pub(crate) fn group_under(self, group_num: u8) -> Self {
        let previous_rounds = self.previous_rounds.map(|previous_rounds| {
            previous_rounds
                .into_iter()
                .map(|(round_id, required)| (round_id.group_under(group_num), required))
                .collect()
        });

        let combined_echos = self.combined_echos.map(|combined_echos| {
            combined_echos
                .into_iter()
                .map(|round_id| round_id.group_under(group_num))
                .collect()
        });

        RequiredMessages {
            this_round: self.this_round,
            previous_rounds,
            combined_echos,
        }
    }
}

/// An error that can occur during the validation of an evidence of a protocol error.
#[derive(Debug, Clone)]
pub enum EvidenceError {
    /// Indicates a local problem, usually a bug in the library code.
    Local(LocalError),
    /// The evidence is improperly constructed
    ///
    /// This can indicate many things, such as: messages missing, invalid signatures, invalid messages,
    /// the messages not actually proving the malicious behavior.
    /// See the attached description for details.
    InvalidEvidence(String),
}

impl From<LocalError> for EvidenceError {
    fn from(error: LocalError) -> Self {
        Self::Local(error)
    }
}
