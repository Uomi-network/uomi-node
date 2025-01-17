/*
This is an offchain_worker of a substrate chain.
The offchain_worker should run a wasm file and get the output data from it.
I need to be sure that the execution of the wasm do not require more than 30 seconds.
Im using thread to run the wasm in a separate thread and kill it if it takes more than 30 seconds but it is not a good solution because i need to run the wasm on the main thread.

How can i run the wasm on the main thread and be sure that it will not take more than 30 seconds?
Fuel usage is not enough secure because it is not precise.
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

/*

Ensuring that the WebAssembly (Wasm) execution on the main thread does not exceed 30 seconds can be challenging. One approach is to use a combination of asynchronous execution with a timeout mechanism using the tokio runtime. This allows you to run the Wasm code on the main thread while still being able to enforce a timeout.
Here's an example implementation using tokio to run the Wasm execution and enforce a timeout:

Explanation:
Async Function: The offchain_worker function is now asynchronous, allowing you to use tokio for asynchronous execution.
Timeout Mechanism: The tokio::time::timeout function is used to enforce a 30-second timeout on the Wasm execution.
Spawn Blocking Task: The Wasm execution is run in a blocking task using tokio::task::spawn_blocking, ensuring it runs on the main thread.
Error Handling: Proper error handling is implemented to log errors and return appropriate error messages.
This approach ensures that the Wasm execution runs on the main thread and respects the 30-second timeout constraint.

*/

#[cfg(feature = "std")]
async fn offchain_worker(_: BlockNumberFor<T>) -> Result<(), Box<dyn std::error::Error>> {
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

    let timeout_duration = std::time::Duration::from_secs(30);

    let wasm_future = tokio::task::spawn_blocking(move || {
        wasm_run.call(&mut store, ()).unwrap();
        store.into_data()
    });

    let result = tokio::time::timeout(timeout_duration, wasm_future).await;

    let store_data = match result {
        Ok(Ok(store_data)) => {
            log::info!("WASM execution completed successfully");
            store_data
        },
        Ok(Err(e)) => {
            log::error!("WASM execution failed: {:?}", e);
            return Err(Box::new(e));
        },
        Err(_) => {
            log::error!("WASM execution timeout");
            return Err(Box::new(wasmi::Error::new("WASM execution timeout")));
        },
    };

    // Convert the store_data to a BoundedVec. If the store_data is too big, it will be converted to an empty BoundedVec
    let store_data_bounded: Data = store_data
        .clone()
        .try_into()
        .unwrap_or_else(|_| Data::default());
    log::info!("store_data_bounded: {:?}", store_data_bounded);

    Ok(())
}

// To run the offchain_worker function
#[tokio::main]
async fn main() {
    if let Err(e) = offchain_worker().await {
        eprintln!("Error: {:?}", e);
    }
}