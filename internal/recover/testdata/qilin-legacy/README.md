# Legacy Qilin fixture

These files were copied from `a7f85a7` of the predecessor `rangard` repository;
they were not generated while validating `memento`.

- `ciphertext.qilin`: 3,480 bytes. Generated in the fixed-PRN mode of the legacy
  OpenSSL C simulator. SHA-256:
  `4e788c5f14132623a8abdfb4e8bc60fd62af1c92194611fb0c91d51fe622d338`
- `plaintext.bin`: 64 zero bytes. SHA-256:
  `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`

The automated tests only decrypt the Git-tracked ciphertext into a temporary
output location and confirm that both Git-tracked files are left unchanged.
