/*
This is an offchain_worker of a substrate chain.
The offchain_worker should run a wasm file and get the output data from it.
I need to be sure that the execution of the wasm do not require more than 30 seconds.
Im using thread to run the wasm in a separate thread and a channel to communicate between threads.

Im getting a problem to access to IpfsPallet from the wasm because the thread makes the extrinsic to be not available.
How can i solve this?
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

  fn generate_data_for_wasm(data: Vec<u8>) -> Vec<u8> {
      let data_len = data.len();
      let mut wasm_data = Vec::new();

      // write data_len on first 4 bytes of wasm_data, then write data
      wasm_data.extend(&(data_len as u32).to_le_bytes());
      wasm_data.extend(data);

      wasm_data
  }

  let get_input_data = wasmi::Func::wrap(
      &mut store,
      move |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, _len: i32| {
          let data_to_write = generate_data_for_wasm(input_data_as_vec.clone());
          log::info!("call get input data from wasm");
      
          let memory = caller
              .get_export("memory")
              .and_then(wasmi::Extern::into_memory)
              .expect("Failed to get memory export");

          memory
              .write(&mut caller, ptr as usize, &data_to_write)
              .expect("Failed to write memory");
      }
  );

  let get_cid_file = wasmi::Func::wrap(
      &mut store,
      move |mut caller: wasmi::Caller<'_, HostState>, ptr: i32, len: i32, output_ptr: i32, _: i32| {
          let memory = caller
              .get_export("memory")
              .and_then(wasmi::Extern::into_memory)
              .expect("Failed to get memory export");

          let mut buffer = vec![0u8; len as usize];

          memory
              .read(&caller, ptr as usize, &mut buffer)
              .expect("Failed to read memory");

          let cid = Cid::try_from(buffer).unwrap();
          let file = T::IpfsPallet::get_file(&cid).unwrap();
          let data_to_write = generate_data_for_wasm(file);

          let memory = caller
              .get_export("memory")
              .and_then(wasmi::Extern::into_memory)
              .expect("Failed to get memory export");

          memory
              .write(&mut caller, output_ptr as usize, &data_to_write)
              .expect("Failed to write memory");
      }
  );

  let mut linker: wasmi::Linker<Vec<u8>> = wasmi::Linker::new(&engine);
  linker.define("env", "get_input_data", get_input_data)?;
  linker.define("env", "get_cid_file", get_cid_file)?;

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