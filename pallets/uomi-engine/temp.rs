/*
This is an offchain_worker of a substrate chain.
The offchain_worker should run a wasm file and get the output data from it.
I need to be sure that the execution of the wasm do not require more than 30 seconds.
Im using thread to run the wasm in a separate thread and kill it if it takes more than 30 seconds but it is not a good solution because i need to run the wasm on the main thread.

Can i use sp_runtime::tasks to achieve this?

Example:
use sp_runtime::tasks;

// Inside your pallet function
tasks::spawn_blocking("wasm-execution", None, Box::pin(async move {
    wasm_run.call(&mut store, ())?;
    store.into_data()
}));
*/

#[cfg(feature = "std")]
fn offchain_worker(_: BlockNumberFor<T>) {
  let wasm = include_bytes!("./agent.wasm").to_vec();
  let input_data = Data::default(); // Data used as input for the wasm
  
  type HostState = Vec<u8>;
  let input_data_as_vec = input_data.to_vec();

  let engine = wasmi::Engine::default();
  let module = wasmi::Module::new(&engine, &wasm[..])?;
  let mut store = wasmi::Store::new(&engine, HostState::new());

  let mut linker: wasmi::Linker<Vec<u8>> = wasmi::Linker::new(&engine);
  // linker.define("env", "my_func", my_func)?;

  let instance = linker.instantiate(&mut store, &module)?.start(&mut store)?;
  let wasm_run = instance.get_typed_func::<(), ()>(&store, "run")?;

  let timeout_time_ms = 30 as u64 * 1000; // 30 seconds

  // Create a channel to communicate between threads
  let (tx, rx) = std::sync::mpsc::channel();

  // Run the function in a separate thread
  std::thread::spawn(move || {
      wasm_run.call(&mut store, ()).unwrap();
      tx.send(store.into_data()).unwrap();
  });

  // Wait for timeout_time_ms or until the function completes
  let store_data = match rx.recv_timeout(std::time::Duration::from_millis(timeout_time_ms)) {
      Ok(store_data) => {
          log::info!("WASM execution completed successfully");
          store_data
      },
      Err(_) => {
          log::error!("WASM execution timeout");
          return Err(wasmi::Error::new("WASM execution timeout"));
      },
  };

  // Run the function
  wasm_run.call(&mut store, ())?;
  let store_data = store.into_data();

  // Convert the store_data to a BoundedVec. If the store_data is too big, it will be converted to an empty BoundedVec
  let store_data_bounded: Data = store_data
      .clone()
      .try_into()
      .unwrap_or_else(|_| Data::default());
  log::info!("store_data_bounded: {:?}", store_data_bounded);
}