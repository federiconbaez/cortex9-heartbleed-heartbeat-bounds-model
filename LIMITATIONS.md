# Limitations

- **No real TLS or memory.** Bytes past the record come from a synthetic,
  labelled region. Real Heartbleed leaked whatever the heap held next to
  the record buffer, which depended on the allocator and the process.
  The model cannot and does not say what that content would be.
- **Scope.** The model covers only the heartbeat message handler. It
  leaves out the following:
  - the record layer (MAC, decryption, fragmentation);
  - heartbeat negotiation (`tlsext_heartbeat`);
  - `ssl3_write_bytes` splitting of responses over 16,384 bytes;
  - the response-side sequence check and the `msg_callback`.
- **`rrec.length` is taken as given.** In practice the record layer
  limits it to 16,384 (plus overhead). The CLI accepts larger bodies to
  show arithmetic only; `record_too_long` flags those cases.
- **Branches.** The model covers 1.0.1f versus 1.0.1g. Other branches
  (for example 1.0.2-beta) received equivalent fixes that were not read
  here.
- **Contents of the simulated region.** Its values are synthetic, and
  only their origin label is used.
- **CI.** The workflow runs the tests on Python 3.10–3.13, regenerates
  `results/` and compares it byte by byte. See the Actions page of the
  repository for run status.
