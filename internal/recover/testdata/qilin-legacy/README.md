# 旧Qilin fixture

これらのファイルは、先行する`rangard` repositoryの`a7f85a7`からコピーしたもので、
`memento`の検証中に生成したものではありません。

- `ciphertext.qilin`：3,480 bytes。旧OpenSSL C simulatorの固定PRN modeで生成。
  SHA-256：
  `4e788c5f14132623a8abdfb4e8bc60fd62af1c92194611fb0c91d51fe622d338`
- `plaintext.bin`：64 zero bytes。SHA-256：
  `f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b`

自動testでは、Git管理された暗号文を一時出力先へ復号し、Git管理された両ファイルが
変更されていないことだけを確認します。
