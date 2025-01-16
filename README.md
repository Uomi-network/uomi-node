![uomi](./img/uomi.jpeg)
<div align="center">

![Version](https://badgen.net/badge/version/2.1.0/blue)
[![Substrate version](https://img.shields.io/badge/Substrate-3.0.0-brightgreen?logo=Parity%20Substrate)](https://substrate.dev/)
[![License](https://badgen.net/badge/license/MIT/blue)](./LICENSE)
[![Twitter URL](https://img.shields.io/twitter/follow/UomiNetwork?style=social)](https://twitter.com/UomiNetwork)

</div>


Empowering Ai Agents to Transform the Physical World through Economic Agency

Creating new forms of digital life capable of sustaining themselves by delivering value to humans.

## Building From Source

> This section assumes that the developer is running on either macOS or Debian-variant operating system. For Windows, although there are ways to run it, we recommend using [WSL](https://docs.microsoft.com/en-us/windows/wsl/install-win10) or from a virtual machine for stability.

```bash
# install Substrate development environment via the automatic script
$ curl https://getsubstrate.io -sSf | bash -s -- --fast

# clone the Git repository
$ git clone --recurse-submodules https://github.com/Uomi-network/uomi-node.git

# change current working directory
$ cd uomi-node

# setup hooks (for conventional commits)
$ sh ./scripts/setup-hooks.sh

# download ipfs clients required for building and store them on ./client/ipfs-manager/src/
wget https://storage.uomi.ai/ipfs_linux_amd64 -O ./client/ipfs-manager/src/ipfs_linux_amd64
wget https://storage.uomi.ai/ipfs_linux_arm64 -O ./client/ipfs-manager/src/ipfs_linux_arm64
wget https://storage.uomi.ai/ipfs_macOS -O ./client/ipfs-manager/src/ipfs_macOS

# compile the node
# note: you may encounter some errors if `wasm32-unknown-unknown` is not installed, or if the toolchain channel is outdated
$ cargo build --release

# show list of available commands
$ ./target/release/uomi --help
```

## Running a node

You can run a node and connect to the Uomi network by running the following command:

```bash
./target/release/uomi \
--base-path <path to save blocks> \
--chain <chain name> \
--name <node display name>  \
--port 30333 \
--rpc-port 9944 \
--validator
```


Now, you can obtain the node's session key by sending the following RPC payload.

```bash
# send `rotate_keys` request
$ curl -H 'Content-Type: application/json' --data '{ "jsonrpc":"2.0", "method":"author_rotateKeys", "id":1 }' localhost:9944

# should return a long string of hex, which is your session key
{"jsonrpc":"2.0","result":"<session key in hex>","id":1}
```

After this step, you should have a validator node online with a session key for your node.

## Workspace Dependency Handling

All dependencies should be listed inside the workspace's root `Cargo.toml` file.
This allows us to easily change version of a crate used by the entire repo by modifying the version in a single place.

Right now, if **non_std** is required, `default-features = false` must be set in the root `Cargo.toml` file (related to this [issue](https://github.com/rust-lang/cargo/pull/11409)). Otherwise, it will have no effect, causing your compilation to fail.
Also `package` imports aren't properly propagated from root to sub-crates, so defining those should be avoided.

Defining _features_ in the root `Cargo.toml` is additive with the features defined in concrete crate's `Cargo.toml`.

**Adding Dependency**

1. Check if the dependency is already defined in the root `Cargo.toml`
    1. if **yes**, nothing to do, just take note of the enabled features
    2. if **no**, add it (make sure to use `default-features = false` if dependency is used in _no_std_ context)
2. Add `new_dependecy = { workspace = true }` to the required crate
3. In case dependency is defined with `default-features = false` but you need it in _std_ context, add `features = ["std"]` to the required crate.

## Further Reading
* [Whitepaper](https://github.com/Uomi-network/uomi-whitepaper)
* [Website](https://uomi.network)

## Development

Running node locally for development purposes is simple. After the node is compiled (see above), run the following command:

```bash
./target/release/uomi --base-path /tmp/alice --dev --alice 
```

To start multiple nodes you can use **foreman**. First, install it with `gem install foreman`. Then run the following command:

```bash
foreman start -f Procfile.dev
``` 

After the setup of nodes you need to insert keys inside the pallets using the following command:

```bash
curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["ipfs", "//Alice//stash", "0x3e59bf9d93a34c3d5e4ef59b11e4882bbde3848bff69d2ed891e32efb9722224"]}' \
http://localhost:9944 

curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["uomi", "//Alice//stash", "0xbe5ddb1579b72e84524fc29e78609e3caf42e85aa118ebfe0b0ad404b5bdd25f"]}' \
http://localhost:9944 

curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["uomi", "//Bob//stash", "0xfe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"]}' \
http://localhost:9945 

curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["ipfs", "//Bob//stash", "0xfe65717dad0447d715f660a0a58411de509b42e6efb8375f562f58a554d5860e"]}' \
http://localhost:9945 

curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["uomi", "Charlie//stash", "0x1e07379407fecc4b89eb7dbd287c2c781cfb1907a96947a3eb18e4f8e7198625"]}' \
http://localhost:9946 

curl -H "Content-Type: application/json" \
-d '{"id": 1, "jsonrpc":"2.0", "method": "author_insertKey", "params":["ipfs", "Charlie//stash", "0x1e07379407fecc4b89eb7dbd287c2c781cfb1907a96947a3eb18e4f8e7198625"]}' \
http://localhost:9946
```

