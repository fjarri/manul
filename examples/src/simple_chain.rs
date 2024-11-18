use alloc::collections::BTreeSet;
use core::fmt::Debug;

use manul::{
    combinators::{
        chain::{Chain, ChainedJoin, ChainedProtocol, ChainedSplit},
        CombinatorEntryPoint,
    },
    protocol::{PartyId, Protocol},
};

use super::simple::{SimpleProtocol, SimpleProtocolEntryPoint};

/// A protocol that runs the [`SimpleProtocol`] twice, in sequence.
/// Illustrates the chain protocol combinator.
#[derive(Debug)]
pub struct DoubleSimpleProtocol;

impl ChainedProtocol for DoubleSimpleProtocol {
    type Protocol1 = SimpleProtocol;
    type Protocol2 = SimpleProtocol;
}

pub struct DoubleSimpleEntryPoint<Id> {
    all_ids: BTreeSet<Id>,
}

impl<Id: PartyId> DoubleSimpleEntryPoint<Id> {
    pub fn new(all_ids: BTreeSet<Id>) -> Self {
        Self { all_ids }
    }
}

impl<Id> CombinatorEntryPoint for DoubleSimpleEntryPoint<Id> {
    type Combinator = Chain;
}

impl<Id> ChainedSplit<Id> for DoubleSimpleEntryPoint<Id>
where
    Id: PartyId,
{
    type Protocol = DoubleSimpleProtocol;
    type EntryPoint = SimpleProtocolEntryPoint<Id>;
    fn make_entry_point1(self) -> (Self::EntryPoint, impl ChainedJoin<Id, Protocol = Self::Protocol>) {
        (
            SimpleProtocolEntryPoint::new(self.all_ids.clone()),
            DoubleSimpleProtocolTransition { all_ids: self.all_ids },
        )
    }
}

#[derive(Debug)]
struct DoubleSimpleProtocolTransition<Id> {
    all_ids: BTreeSet<Id>,
}

impl<Id> ChainedJoin<Id> for DoubleSimpleProtocolTransition<Id>
where
    Id: PartyId,
{
    type Protocol = DoubleSimpleProtocol;
    type EntryPoint = SimpleProtocolEntryPoint<Id>;
    fn make_entry_point2(self, _result: <SimpleProtocol as Protocol>::Result) -> Self::EntryPoint {
        SimpleProtocolEntryPoint::new(self.all_ids)
    }
}

#[cfg(test)]
mod tests {
    use alloc::collections::BTreeSet;

    use manul::{
        session::{signature::Keypair, SessionOutcome},
        testing::{run_sync, BinaryFormat, TestSessionParams, TestSigner},
    };
    use rand_core::OsRng;
    use tracing_subscriber::EnvFilter;

    use super::DoubleSimpleEntryPoint;

    #[test]
    fn round() {
        let signers = (0..3).map(TestSigner::new).collect::<Vec<_>>();
        let all_ids = signers
            .iter()
            .map(|signer| signer.verifying_key())
            .collect::<BTreeSet<_>>();
        let entry_points = signers
            .into_iter()
            .map(|signer| (signer, DoubleSimpleEntryPoint::new(all_ids.clone())))
            .collect::<Vec<_>>();

        let my_subscriber = tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .finish();
        let reports = tracing::subscriber::with_default(my_subscriber, || {
            run_sync::<_, TestSessionParams<BinaryFormat>>(&mut OsRng, entry_points).unwrap()
        });

        for (_id, report) in reports {
            if let SessionOutcome::Result(result) = report.outcome {
                assert_eq!(result, 3); // 0 + 1 + 2
            } else {
                panic!("Session did not finish successfully");
            }
        }
    }
}
