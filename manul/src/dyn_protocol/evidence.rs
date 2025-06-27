use alloc::{boxed::Box, string::String};
use core::fmt::Debug;

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};

use super::format::BoxedFormat;
use crate::{
    protocol::{LocalError, ProvableError, RequiredMessages, Round, RoundId},
    session::DeserializationError,
};

pub(crate) trait DynProvableError<Id>: Debug {
    fn description(&self) -> String;
    fn serialize(self: Box<Self>, format: &BoxedFormat) -> Result<SerializedProvableError, LocalError>;
}

impl<Id, T: ProvableError<Id>> DynProvableError<Id> for T {
    fn description(&self) -> String {
        self.description()
    }

    fn serialize(self: Box<Self>, format: &BoxedFormat) -> Result<SerializedProvableError, LocalError> {
        format.serialize(*self).map(SerializedProvableError)
    }
}

#[derive(Debug)]
pub(crate) struct BoxedProvableError<Id> {
    required_messages: RequiredMessages,
    error: Box<dyn DynProvableError<Id> + Send + Sync>,
}

impl<Id> BoxedProvableError<Id> {
    pub(crate) fn new<R: Round<Id>>(error: R::ProvableError, round_id: &RoundId) -> Self {
        let required_messages = error.required_messages(round_id);
        Self {
            required_messages,
            error: Box::new(error),
        }
    }

    pub(crate) fn as_ref(&self) -> &dyn DynProvableError<Id> {
        self.error.as_ref()
    }

    pub(crate) fn into_boxed(self) -> Box<dyn DynProvableError<Id>> {
        self.error
    }

    pub(crate) fn group_under(self, round_num: u8) -> Self {
        Self {
            required_messages: self.required_messages.group_under(round_num),
            error: self.error,
        }
    }

    pub(crate) fn required_messages(&self) -> &RequiredMessages {
        &self.required_messages
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub(crate) struct SerializedProvableError(#[serde(with = "SliceLike::<Base64>")] Box<[u8]>);

impl SerializedProvableError {
    pub(crate) fn deserialize<Id, R: Round<Id>>(
        &self,
        format: &BoxedFormat,
    ) -> Result<R::ProvableError, DeserializationError> {
        format.deserialize::<R::ProvableError>(&self.0)
    }
}
