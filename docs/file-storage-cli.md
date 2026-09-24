# Files and names through BBG

Build the CLI from the matching Radio/Cybergraph/BBG feature checkouts:

```sh
cargo build -p radio-cli --release --locked
```

The commands below assume that binary is on `PATH`. Every file/name command
selects the same BBG path and authorization namespace. `--backend ssd` uses a
Fjall directory; `--backend hdd` uses a redb file. The parent directory must exist.
Use a fresh fixture store to explore; legacy Radio stores require explicit
migration before adopting them.

```sh
file_scope=0101010101010101010101010101010101010101010101010101010101010101
file_particle=$(radio --database ./example-bbg --namespace "$file_scope" file add ./input.bin)
radio --database ./example-bbg --namespace "$file_scope" file list
radio --database ./example-bbg --namespace "$file_scope" file export "$file_particle" --out ./restored.bin
radio --database ./example-bbg --namespace "$file_scope" name set drafts/input.bin "$file_particle"
radio --database ./example-bbg --namespace "$file_scope" name rename drafts/input.bin archive/input.bin
radio --database ./example-bbg --namespace "$file_scope" name resolve drafts/input.bin --at 0
radio --database ./example-bbg --namespace "$file_scope" name history
```

The rename preserves the payload particle. Reading at history index `0` selects
the creation state even after the rename. Another `name set` on the current path
publishes a content revision; earlier states remain readable. `--expected` pins
a mutation to a checked history index, and `--request` supplies an idempotency
identity for retrying a command after an uncertain reply.

Serve public fixture content from the selected namespace:

```sh
radio --database ./example-bbg --namespace "$file_scope" node start --public
```

For a private scope, replace `--public` with `--allow-peer ENDPOINT_ID`.
The service prints its endpoint and direct addresses. `RADIO_SECRET` can supply
an existing endpoint key through the host environment; absent that key the
endpoint is ephemeral. It does not print generated secret material.

On the receiving host, substitute the endpoint/particle values printed above:

```sh
radio --database ./received-bbg --namespace "$file_scope" file get PARTICLE ENDPOINT_ID --out ./received.bin
```

For direct testing, both commands accept `--local` to disable relay/discovery;
the receiving command adds `--addr IP:PORT`. An interrupted receive keeps
acknowledged parts in BBG; rerun with the same store/scope/particle to resume.
An existing output path is preserved and causes an explicit error. Export needs
only the local store and works while Radio networking is stopped.

`blob` remains a CLI alias for `file`. `hash sum` and `hash verify` now agree with
file import on exact bytes. The BAO inspection commands retain their explicit
legacy meaning; the file service uses the Blob verifier profile pending S1.
Local naming/history is implemented; signed metadata sync, channels, replication
receipts and full legacy-store removal remain tracked in the storage milestone.
