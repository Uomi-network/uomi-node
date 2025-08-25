# Uomi Node (Bahasa Indonesia)

## Ringkas
Uomi Node adalah node blockchain berbasis Substrate.

## Prasyarat Singkat
Ubuntu 22.04/24.04, 2 vCPU, 4 GB RAM, 80 GB disk.
Dependensi: clang, pkg-config, libssl-dev, protobuf-compiler, libgmp-dev.

## Instalasi Cepat
```bash
git clone --recurse-submodules https://github.com/Uomi-network/uomi-node.git
cd uomi-node
bash scripts/install-node.sh
Troubleshooting

protoc not found

sudo apt-get install protobuf-compiler libprotobuf-dev


cannot find -lgmp

sudo apt-get install libgmp-dev zlib1g-dev


Port 30333/9944 bentrok → jalankan dengan argumen port berbeda atau ubah unit systemd.

Operasional
sudo systemctl status uomi
sudo journalctl -u uomi -f

Lisensi

Apache-2.0


**B. `FAQ.md`**
```markdown
# FAQ – Uomi Node

### Build error: `protoc not found`
```bash
sudo apt-get install protobuf-compiler libprotobuf-dev

Link error: cannot find -lgmp
sudo apt-get install libgmp-dev zlib1g-dev

Toolchain Rust
rustup update
rustup target add wasm32-unknown-unknown

Port bentrok 30333/9944

Jalankan node dengan --port dan --rpc-port berbeda atau ubah unit systemd.

Melihat log
sudo journalctl -u uomi -f


**C. `docs/architecture.md`**
```markdown
# Arsitektur Uomi Node

```mermaid
flowchart TD
    subgraph Node
      Consensus[Consensus Engine]
      Runtime[Runtime (WASM)]
      Networking[P2P Networking]
      RPC[RPC API]
    end

    User[User / CLI] --> RPC
    RPC --> Runtime
    Consensus --> Runtime
    Runtime --> Storage[(Database)]
    Networking <--> Consensus


