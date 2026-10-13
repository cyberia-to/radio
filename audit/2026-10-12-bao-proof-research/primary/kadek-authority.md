  information. Negative timestamps remain valid.
- Rescale from `a/b` to `c/d` as floor(`t*a*d/(b*c)`), including negative values,
  with checked widened arithmetic. Rescale interval endpoints, then subtract;
  independently rounded durations accumulate drift.
- Random access, discontinuity, corrupt input and decode-only/preroll are distinct
  flags. An intra picture alone does not establish a complete recovery point.
- Packet provenance names the file's particle and ordered byte intervals covering
  its coded bytes exactly once; preserve repeated/reordered source occurrences.
  Reassembly copies verified source bytes. Radio inputs carry `cyber-bao` slice
  proofs; verify before admission, leaving codec state unchanged on failure.
  Proofless packets require a verified complete body. Seek/partial load open
  ranges against the particle; bindings map indexes to ranges and never fetch.

A verified complete body may derive a sealed in-process BAO anchor binding its
plain particle, complete length and canonical fixed-4096 Hemera tree root.
Derivation borrows the same immutable body and yields under persistent work
limits; the completed fixed value retains no byte allocation. Only derivation
creates authority. Raw or restored mappings require independent authentication
or complete-body reverification. The anchor alone admits no range or packet.

Preserve ordered codec headers and semantic mapping fields; [audio bindings](audio-containers.md)
own Vorbis/Opus/PCM normalization. Validate transport syntax first.
