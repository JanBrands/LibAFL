use mimalloc::MiMalloc;
#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;
//use std::path::PathBuf;
use frida_gum::Gum;
use libafl::{
    corpus::{
        //CachedOnDiskCorpus,
        InMemoryCorpus,
        Corpus,
        OnDiskCorpus,
    },
    Error,
    events::{
        EventConfig,
        launcher::Launcher,
        llmp::LlmpRestartingEventManager,
        //simple::SimpleEventManager,
        //tcp::TcpRestartingEventManager,
    },
    executors::{
        ExitKind,
        inprocess::InProcessExecutor,
    },
    feedbacks::{
        CrashFeedback,
        ConstFeedback,  
        MaxMapFeedback,
        TimeFeedback,
        TimeoutFeedback,
    },
    feedback_and_fast,
    feedback_or,
    feedback_or_fast,
    fuzzer::{
        Fuzzer,
        StdFuzzer,
    },
    inputs::{
        BytesInput,
        HasTargetBytes,
    },
    monitors::{
        //MultiMonitor,
        tui::{
            TuiMonitor,
            ui::TuiUI,
        },
    },
    mutators::{
        scheduled::{
            havoc_mutations,
            StdScheduledMutator,
            tokens_mutations,
        },
    },
    observers::{
        HitcountsMapObserver,
        StdMapObserver,
        TimeObserver,
    },
    schedulers::{
        IndexesLenTimeMinimizerScheduler,
        powersched::PowerSchedule,
        StdWeightedScheduler,
    },
    stages::{
        calibrate::CalibrationStage,
        power::StdPowerMutationalStage,
    },
    state::{
        HasCorpus,
        StdState,
    },
};
use libafl_bolts::{
    AsSlice,
    cli::{
        FuzzerOptions,
        parse_args,
    },
    current_nanos,
    rands::StdRand,
    shmem::{
        ShMemProvider,
        StdShMemProvider,
    },
    tuples::{
        Merge,
        tuple_list,
    },
};
use libafl_frida::{
    asan::{
        errors::{
            AsanErrorsFeedback,
            AsanErrorsObserver,
            ASAN_ERRORS,
        },
    },
    coverage_rt::{
        CoverageRuntime,
        MAP_SIZE,
    },
    executor::FridaInProcessExecutor,
    helper::FridaInstrumentationHelper,
};

pub fn main() {
    let options = parse_args();

    unsafe {
        match fuzz(&options) {
            Ok(()) | Err(Error::ShuttingDown) => println!("\nFinished fuzzing. Good bye."),
            Err(e) => panic!("Error during fuzzing: {e:?}"),
        }
    }
}

#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
unsafe fn fuzz(options: &FuzzerOptions) -> Result<(), Error> {
    let ui = TuiUI::with_version(String::from("Lab Fuzzer Frida"), String::from("0.0.5"), false);
    let monitor = TuiMonitor::new(ui);
    //let monitor = MultiMonitor::new(|s| println!("{s}"));

    let shmem_provider = StdShMemProvider::new()?;

    let mut run_client = |state: Option<_>, mgr: LlmpRestartingEventManager<_, _>, core_id| {
        let lib = libloading::Library::new(options.clone().harness.unwrap()).unwrap();
        let target_func: libloading::Symbol<
            unsafe extern "C" fn(data: *const u8, size: usize) -> i32
        > = lib.get(options.harness_function.as_bytes()).unwrap();

        let mut frida_harness = |input: &BytesInput| {
            let target = input.target_bytes();
            let buf = target.as_slice();
            target_func(buf.as_ptr(), buf.len());
            ExitKind::Ok
        };

        (|state: Option<_>, mut mgr: LlmpRestartingEventManager<_, _>, _core_id| {
            let gum = Gum::obtain();

            let coverage = CoverageRuntime::new();

            let mut frida_helper = FridaInstrumentationHelper::new(&gum, options, tuple_list!(coverage));
            
            // Create an observation channel using the coverage map
            let edges_observer = HitcountsMapObserver::new(StdMapObserver::from_mut_ptr(
                "edges",
                frida_helper.map_mut_ptr().unwrap(),
                MAP_SIZE,
            ));

            // Create an observation channel to keep track of the execution time
            let time_observer = TimeObserver::new("time");

            let map_feedback = MaxMapFeedback::tracking(&edges_observer, true, false);
            let time_feedback = TimeFeedback::with_observer(&time_observer);
            
            let calibration = CalibrationStage::new(&map_feedback);

            // Feedback to rate the interestingness of an input
            // This one is composed by two Feedbacks in OR
            let mut feedback = feedback_or!(
                map_feedback,
                time_feedback
            );

            // Feedbacks to recognize an input as solution
            let mut objective = feedback_or_fast!(
                CrashFeedback::new(),
                TimeoutFeedback::new(),
                feedback_and_fast!(ConstFeedback::from(false), AsanErrorsFeedback::new())
            );

            // If not restarting, create a State from scratch
            let mut state = state.unwrap_or_else(|| {
                StdState::new(
                    StdRand::with_seed(current_nanos()),
                    //CachedOnDiskCorpus::no_meta(PathBuf::from("./corpus_discovered"), 64).unwrap(),
                    InMemoryCorpus::new(),
                    OnDiskCorpus::new(options.output.clone()).unwrap(),
                    &mut feedback,
                    &mut objective,
                ).unwrap()
            });

            println!("We're a client, let's fuzz!");

            // Setup a basic mutator with a mutational stage
            let mutator = StdScheduledMutator::new(havoc_mutations().merge(tokens_mutations()));

            let power_mutation = StdPowerMutationalStage::new(mutator);

            // A minimization+queue policy to get testcasess from the corpus
            let scheduler = IndexesLenTimeMinimizerScheduler::new(StdWeightedScheduler::with_schedule(
                &mut state,
                &edges_observer,
                Some(PowerSchedule::FAST),
            ));

            // A fuzzer with feedbacks and a corpus scheduler
            let mut fuzzer = StdFuzzer::new(scheduler, feedback, objective);

            let observers = tuple_list!(
                edges_observer,
                time_observer,
                AsanErrorsObserver::new(&ASAN_ERRORS),
            );

            // Create the executor for an in-process function with just one observer for edge coverage
            let mut executor = FridaInProcessExecutor::new(
                &gum,
                InProcessExecutor::new(
                    &mut frida_harness,
                    observers,
                    &mut fuzzer,
                    &mut state,
                    &mut mgr,
                )?,
                &mut frida_helper,
            );

            // In case the corpus is empty (on first run), reset
            if state.must_load_initial_inputs() {
                state
                    .load_initial_inputs(&mut fuzzer, &mut executor, &mut mgr, &options.input)
                    .unwrap_or_else(|_| {
                        panic!("Failed to load initial corpus at {:?}", &options.input)
                    });
                println!("We imported {} inputs from disk.", state.corpus().count());
            }

            let mut stages = tuple_list!(calibration, power_mutation);

            fuzzer.fuzz_loop(&mut stages, &mut executor, &mut state, &mut mgr)?;

            Ok(())
        })(state, mgr, core_id)
    };

    Launcher::builder()
        .configuration(EventConfig::AlwaysUnique)
        .cores(&options.cores)
        .monitor(monitor)
        .run_client(&mut run_client)
        .shmem_provider(shmem_provider)
        .stdout_file(Some(&options.stdout))
        .build()
        .launch()
}