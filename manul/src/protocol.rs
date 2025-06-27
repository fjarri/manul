/*!
API for protocol implementors.

A protocol is a directed acyclic graph with the nodes being objects of types implementing [`Round`]
(to be specific, "acyclic" means that the values returned in the `id` field of [`TransitionInfo`]
should not repeat during the protocol execution; the types might).
The starting point is a type that implements [`EntryPoint`].
All the rounds must have their associated type [`Round::Protocol`] set to the same [`Protocol`] instance
to be executed by a [`Session`](`crate::session::Session`).

For more details, see the documentation of the mentioned traits.
*/

mod errors;
mod evidence;
mod round;
mod round_id;
mod round_info;

pub use errors::{LocalError, ReceiveError, RemoteError};
pub use evidence::{
    EvidenceError, EvidenceMessages, NoProvableErrors, ProvableError, RequiredMessageParts, RequiredMessages,
};
pub use round::{
    CommunicationInfo, EchoRoundParticipation, EntryPoint, FinalizeOutcome, MessageParts, NoMessage, PartyId, Protocol,
    Round,
};
pub use round_id::{RoundId, TransitionInfo};
pub use round_info::RoundInfo;

pub use crate::dyn_protocol::BoxedRound;
pub(crate) use round_info::DynRoundInfo;
