//! The [`TMinMutationalStage`] is a stage which will attempt to minimize corpus entries.

use alloc::string::{String, ToString};
use core::{
    fmt::Debug,
    hash::{Hash, Hasher},
    marker::PhantomData,
};

use ahash::AHasher;

#[cfg(feature = "introspection")]
use crate::monitors::PerfFeature;
use crate::{
    bolts::{tuples::Named, HasLen},
    corpus::{Corpus, Testcase},
    events::EventFirer,
    executors::{Executor, ExitKind, HasObservers},
    feedbacks::{Feedback, FeedbackFactory, HasObserverName},
    inputs::Input,
    mark_feature_time,
    mutators::Mutator,
    observers::{MapObserver, ObserversTuple},
    schedulers::Scheduler,
    stages::Stage,
    start_timer,
    state::{HasClientPerfMonitor, HasCorpus, HasExecutions, HasMaxSize, State},
    Error, ExecutesInput, ExecutionProcessor, HasFeedback, HasScheduler,
};

/// Mutational stage which minimizes corpus entries.
///
/// You must provide at least one mutator that actually reduces size.
pub trait TMinMutationalStage<CS, E, EM, F1, F2, I, M, OT, S, Z>:
    Stage<E, EM, S, Z> + FeedbackFactory<F2, I, S, OT>
where
    CS: Scheduler<Input = I, State = S>,
    E: Executor<EM, I, S, Z> + HasObservers<Observers = OT, Input = I, State = S>,
    EM: EventFirer<Input = I, State = S>,
    F1: Feedback<Input = I, State = S>,
    F2: Feedback<Input = I, State = S>,
    I: Input + Hash + HasLen,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<Input = I> + HasExecutions + HasMaxSize,
    Z: ExecutionProcessor<Observers = OT, Input = I, State = S, EventManager = EM>
        + ExecutesInput<E, EM, Input = I, State = S>
        + HasFeedback<F1, I, S>
        + HasScheduler<CS, I, S>
        + ExecutionProcessor<Observers = OT, Input = I, State = S, EventManager = EM>,
{
    /// The mutator registered for this stage
    fn mutator(&self) -> &M;

    /// The mutator registered for this stage (mutable)
    fn mutator_mut(&mut self) -> &mut M;

    /// Gets the number of iterations this mutator should run for.
    fn iterations(&self, state: &mut S, corpus_idx: usize) -> Result<usize, Error>;

    /// Runs this (mutational) stage for new objectives
    #[allow(clippy::cast_possible_wrap)] // more than i32 stages on 32 bit system - highly unlikely...
    fn perform_minification(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        base_corpus_idx: usize,
    ) -> Result<(), Error> {
        let orig_max_size = state.max_size();
        // basically copy-pasted from mutational.rs
        let num = self.iterations(state, base_corpus_idx)?;

        start_timer!(state);
        let mut base = state
            .corpus()
            .get(base_corpus_idx)?
            .borrow_mut()
            .load_input()?
            .clone();
        let mut hasher = AHasher::new_with_keys(0, 0);
        base.hash(&mut hasher);
        let base_hash = hasher.finish();
        mark_feature_time!(state, PerfFeature::GetInputFromCorpus);

        fuzzer.execute_input(state, executor, manager, &base)?;
        let observers = executor.observers();

        let mut feedback = self.create_feedback(observers);

        let mut i = 0;
        loop {
            if i >= num {
                break;
            }

            let mut next_i = i + 1;
            let mut input = base.clone();

            let before_len = input.len();

            state.set_max_size(before_len);

            start_timer!(state);
            self.mutator_mut().mutate(state, &mut input, i as i32)?;
            mark_feature_time!(state, PerfFeature::Mutate);

            let corpus_idx = if input.len() < before_len {
                // run the input
                let exit_kind = fuzzer.execute_input(state, executor, manager, &input)?;
                let observers = executor.observers();

                // let the fuzzer process this execution -- it's possible that we find something
                // interesting, or even a solution
                let (_, corpus_idx) = fuzzer.process_execution(
                    state,
                    manager,
                    input.clone(),
                    observers,
                    &exit_kind,
                    false,
                )?;

                if feedback.is_interesting(state, manager, &input, observers, &exit_kind)? {
                    // we found a reduced corpus entry! use the smaller base
                    base = input;

                    // do more runs! maybe we can minify further
                    next_i = 0;
                }

                corpus_idx
            } else {
                // we can't guarantee that the mutators provided will necessarily reduce size, so
                // skip any mutations that actually increase size so we don't waste eval time
                None
            };

            start_timer!(state);
            self.mutator_mut().post_exec(state, i as i32, corpus_idx)?;
            mark_feature_time!(state, PerfFeature::MutatePostExec);

            i = next_i;
        }

        let mut hasher = AHasher::new_with_keys(0, 0);
        base.hash(&mut hasher);
        let new_hash = hasher.finish();
        if base_hash != new_hash {
            let mut testcase = Testcase::with_executions(base, *state.executions());
            fuzzer
                .feedback_mut()
                .append_metadata(state, &mut testcase)?;
            let prev = state.corpus_mut().replace(base_corpus_idx, testcase)?;
            fuzzer
                .scheduler_mut()
                .on_replace(state, base_corpus_idx, &prev)?;
        }

        state.set_max_size(orig_max_size);

        Ok(())
    }
}

/// The default corpus entry minimising mutational stage
#[derive(Clone, Debug)]
pub struct StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, M, S, T, Z>
where
    I: Input + HasLen,
    M: Mutator<I, S>,
    S: State<Input = I>,
    Z: ExecutionProcessor<Input = I, State = S, EventManager = EM>,
{
    mutator: M,
    factory: FF,
    runs: usize,
    #[allow(clippy::type_complexity)]
    phantom: PhantomData<(CS, E, EM, F1, F2, I, S, T, Z)>,
}

impl<CS, E, EM, F1, F2, FF, I, M, OT, S, Z> Stage<E, EM, S, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, M, S, OT, Z>
where
    CS: Scheduler<Input = I, State = S>,
    E: Executor<EM, I, S, Z> + HasObservers<Observers = OT, Input = I, State = S>,
    EM: EventFirer<Input = I, State = S>,
    F1: Feedback<Input = I, State = S>,
    F2: Feedback<Input = I, State = S>,
    FF: FeedbackFactory<F2, I, S, OT>,
    I: Input + Hash + HasLen,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<Input = I> + HasExecutions + HasMaxSize + State<Input = I>,
    Z: ExecutionProcessor<Observers = OT, Input = I, State = S, EventManager = EM>
        + ExecutesInput<E, EM, Input = I, State = S>
        + HasFeedback<F1, I, S>
        + HasScheduler<CS, I, S>,
{
    fn perform(
        &mut self,
        fuzzer: &mut Z,
        executor: &mut E,
        state: &mut S,
        manager: &mut EM,
        corpus_idx: usize,
    ) -> Result<(), Error> {
        self.perform_minification(fuzzer, executor, state, manager, corpus_idx)?;

        #[cfg(feature = "introspection")]
        state.introspection_monitor_mut().finish_stage();

        Ok(())
    }
}

impl<CS, E, EM, F1, F2, FF, I, M, S, T, Z> FeedbackFactory<F2, I, S, T>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, M, S, T, Z>
where
    F2: Feedback<Input = I, State = S>,
    FF: FeedbackFactory<F2, I, S, T>,
    I: Input + HasLen,
    M: Mutator<I, S>,
    S: HasClientPerfMonitor + State<Input = I>,
    Z: ExecutionProcessor<Input = I, State = S, EventManager = EM>,
{
    fn create_feedback(&self, ctx: &T) -> F2 {
        self.factory.create_feedback(ctx)
    }
}

impl<CS, E, EM, F1, F2, FF, I, M, OT, S, Z> TMinMutationalStage<CS, E, EM, F1, F2, I, M, OT, S, Z>
    for StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, M, S, OT, Z>
where
    CS: Scheduler<Input = I, State = S>,
    E: HasObservers<Observers = OT, Input = I, State = S> + Executor<EM, I, S, Z>,
    EM: EventFirer<Input = I, State = S>,
    F1: Feedback<Input = I, State = S>,
    F2: Feedback<Input = I, State = S>,
    FF: FeedbackFactory<F2, I, S, OT>,
    I: Input + HasLen + Hash,
    M: Mutator<I, S>,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + HasCorpus<Input = I> + HasExecutions + HasMaxSize + State<Input = I>,
    Z: ExecutionProcessor<Observers = OT, Input = I, State = S, EventManager = EM>
        + ExecutesInput<E, EM, Input = I, State = S>
        + HasFeedback<F1, I, S>
        + HasScheduler<CS, I, S>,
{
    /// The mutator, added to this stage
    #[inline]
    fn mutator(&self) -> &M {
        &self.mutator
    }

    /// The list of mutators, added to this stage (as mutable ref)
    #[inline]
    fn mutator_mut(&mut self) -> &mut M {
        &mut self.mutator
    }

    /// Gets the number of iterations from a fixed number of runs
    fn iterations(&self, _state: &mut S, _corpus_idx: usize) -> Result<usize, Error> {
        Ok(self.runs)
    }
}

impl<CS, E, EM, F1, F2, FF, I, M, S, T, Z>
    StdTMinMutationalStage<CS, E, EM, F1, F2, FF, I, M, S, T, Z>
where
    I: Input + HasLen,
    M: Mutator<I, S>,
    S: State<Input = I>,
    Z: ExecutionProcessor<Input = I, State = S, EventManager = EM>,
{
    /// Creates a new minimising mutational stage that will minimize provided corpus entries
    pub fn new(mutator: M, factory: FF, runs: usize) -> Self {
        Self {
            mutator,
            factory,
            runs,
            phantom: PhantomData,
        }
    }
}

/// A feedback which checks if the hash of the currently observed map is equal to the original hash
/// provided
#[derive(Clone, Debug)]
pub struct MapEqualityFeedback<I, M, S> {
    name: String,
    obs_name: String,
    orig_hash: u64,
    phantom: PhantomData<(I, M, S)>,
}

impl<I, M, S> MapEqualityFeedback<I, M, S> {
    /// Create a new map equality feedback -- can be used with feedback logic
    #[must_use]
    pub fn new(name: &str, obs_name: &str, orig_hash: u64) -> Self {
        MapEqualityFeedback {
            name: name.to_string(),
            obs_name: obs_name.to_string(),
            orig_hash,
            phantom: PhantomData,
        }
    }
}

impl<I, M, S> Named for MapEqualityFeedback<I, M, S> {
    fn name(&self) -> &str {
        &self.name
    }
}

impl<I, M, S> HasObserverName for MapEqualityFeedback<I, M, S> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<I, M, S> Feedback for MapEqualityFeedback<I, M, S>
where
    I: Input,
    M: MapObserver + Debug,
    S: State<Input = I> + Debug,
{
    type Input = I;

    type State = S;

    fn is_interesting<EM, OT>(
        &mut self,
        _state: &mut Self::State,
        _manager: &mut EM,
        _input: &Self::Input,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error>
    where
        EM: EventFirer<Input = Self::Input, State = Self::State>,
        OT: ObserversTuple<Self::Input, Self::State>,
    {
        let obs = observers
            .match_name::<I, M, S>(self.observer_name())
            .expect("Should have been provided valid observer name.");
        Ok(obs.hash() == self.orig_hash)
    }
}

/// A feedback factory for ensuring that the maps for minimized inputs are the same
#[derive(Debug, Clone)]
pub struct MapEqualityFactory<I, M, S> {
    obs_name: String,
    phantom: PhantomData<(I, M, S)>,
}

impl<I, M, S> MapEqualityFactory<I, M, S>
where
    M: MapObserver,
{
    /// Creates a new map equality feedback for the given observer
    pub fn new_from_observer(obs: &M) -> Self {
        Self {
            obs_name: obs.name().to_string(),
            phantom: PhantomData,
        }
    }
}

impl<I, M, S> HasObserverName for MapEqualityFactory<I, M, S> {
    fn observer_name(&self) -> &str {
        &self.obs_name
    }
}

impl<I, M, OT, S> FeedbackFactory<MapEqualityFeedback<I, M, S>, I, S, OT>
    for MapEqualityFactory<I, M, S>
where
    I: Input,
    M: MapObserver,
    OT: ObserversTuple<I, S>,
    S: HasClientPerfMonitor + Debug + State<Input = I>,
{
    fn create_feedback(&self, observers: &OT) -> MapEqualityFeedback<I, M, S> {
        let obs = observers
            .match_name::<I, M, S>(self.observer_name())
            .expect("Should have been provided valid observer name.");
        MapEqualityFeedback {
            name: "MapEq".to_string(),
            obs_name: self.obs_name.clone(),
            orig_hash: obs.hash(),
            phantom: PhantomData,
        }
    }
}
