# private_search_fhe

C++ scaffold for testing and benchmarking your FHE-Deck-based private search
protocol. Every file currently contains real function/class signatures and
detailed `// TODO` comments pointing at the specific FHE-Deck calls from your
reference `perf_test_sequential()` example — nothing is implemented yet.

## Suggested order of work

1. **`include/params.hpp` + `src/params.cpp`** — fill in
   `Params::make_test_params()` and `CryptoContext::from_params()` first.
   Everything else depends on having a working ring/gadget context.
2. **`include/client.hpp` + `src/client.cpp`** — `generate_secret_keys()`,
   `generate_eval_keys()`. Write a throwaway `main()` (or extend the test) that
   just does keygen + a raw LWE encrypt/decrypt round trip to sanity-check
   these against FHE-Deck's API before touching the rest of the protocol.
3. **`include/server_db.hpp` + `src/server_db.cpp`** — `ServerDatabase::build()`.
4. **`include/server.hpp` + `src/server.cpp`** — fill in
   `switch_embedding_to_rlwe`, `switch_unit_vector_to_rgsw`, `worker_compute`,
   `combine_worker_results`, in that order (each is testable somewhat in
   isolation by decrypting intermediate results with the client's secret key
   while debugging, same as your Python `cryptographic_protocol_steps.py`
   does with lots of `print`/`assert` statements).
5. **`tests/test_protocol_single_process.cpp`** — get this passing for both
   `FillMode::Ones` and `FillMode::Zeros`. This is your correctness gate.
6. **`include/channel.hpp` + `src/channel.cpp`** — implement
   `InProcessThreadChannel` for real. Re-run the test but routed through
   `Server::process_query`'s real dispatch path (see the TODO in the test
   about not using `nullptr` for the channel once this exists) to make sure
   the parallel path agrees with the direct-call path.
7. **`benchmarks/benchmark_latency.cpp`** — fill in the random-value
   generation TODO and tune `BenchmarkConfig`.
8. See `future/NOTES.md` for the real multi-process deployment (later).

## Build

```sh
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build . -j
./test_protocol_single_process
./benchmark_latency
```

(You'll need to fix the `find_package(fhe_deck ...)` line in `CMakeLists.txt`
to match however your local `fhe-deck-core` checkout exposes itself — TODO.)
