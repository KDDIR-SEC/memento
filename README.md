# Memento — ランサムウェア疑似乱数復元ツールキット

`memento`は、2つの境界で疑似乱数素材を記録し、その記録をランサムウェアの鍵復元研究に利用するLinux向け研究プロトタイプです。

- eBPFによるゲスト側の`read(2)`／`getrandom(2)`取得
- 改変Intel KVMモジュールによるホスト側のRDRAND／RDSEED取得
- プロセスメモリのダンプとBabuk X25519公開鍵候補の抽出
- BabukおよびQilinの非破壊復号
- 意図的に制約を設けたBabukおよびQilinのラボ用シミュレーター

## 免責事項

Mementoは、正当な権限を有するシステム管理者がランサムウェア被害後のデータ復元を行うことを目的として設計され、セキュリティ対策研究、技術検証および評価のために提供されます。
本ツールを第三者のシステムまたはデータへの無断アクセス、無断暗号化、破壊その他の違法または有害な目的に利用することを、プロジェクトの保守担当者は推奨または容認しません。

本ツールは現状有姿（AS IS）で提供され、データやシステムを復元できることを保証するものではありません。
実環境へ導入する前に、隔離された検証環境で十分なテストを行うことを推奨します。
検証用のファイル暗号化機能では、テストデータだけを使用することを推奨します。

本ツールが生成するログ、メモリダンプその他のアーティファクトには、正規プロセスが利用した疑似乱数値を含む機密情報が含まれる可能性があります。
機密情報に適した管理策を用いて保存、転送、保持および廃棄することを推奨します。

## 対応環境

- Intel x86-64 VMXを搭載したUbuntu 24.04 LTS
- Go 1.23以降
- `/sys/kernel/btf/vmlinux`でBTFを公開するカーネル
- clang／LLVM、bpftool、libelf開発ヘッダー、GCC、GNU Make

検証済みのKVM基準環境はUbuntu `6.17.0-35-generic`、ソースパッケージ`6.17.0-35.35~24.04.1`です。
その他のLinux 6.17ビルドは未検証です。
CPU取得には、[改変KVMワークフロー](#modified-kvm-workflow)で説明する改変KVMモジュールも必要です。
Mementoがこれらのモジュールを自動でロードまたはアンロードすることはありません。

runcおよびcgroup v2/systemdを使用するrootless Dockerは、推奨するファイルベースのラボ・復号手順でのみ必要です。
Mementoのビルドや診断コマンドの実行には不要です。

## ソースからのインストール

Ubuntu用ビルド依存関係、`make check`で使用するShellCheck、後述するE2E例で使用する`jq`／`procps`、およびGo 1.23以降を導入します。

```sh
sudo apt-get update
sudo apt-get install -y git make gcc clang llvm bpftool libbpf-dev libelf-dev shellcheck jq procps

git clone https://github.com/KDDIR-SEC/memento.git
cd memento
test -r /sys/kernel/btf/vmlinux
make build
sudo install -m 0755 build/memento /usr/local/bin/memento

memento version
memento --help
memento help monitor syscall
```

`make build`は`ebpf/vmlinux.h`とbpf2goオブジェクトを生成し、eBPFバイトコードを`build/memento`へ埋め込みます。
生成ファイルとバイナリは意図的にGit管理対象から除外されています。
チェックアウト内のバイナリだけを使用する場合は`install`を省略し、後述する例の`memento`を`./build/memento`へ読み替えてください。
`libbpf-dev`はbpf2goで使用する`bpf_helpers.h`、`bpf_core_read.h`、`bpf_tracing.h`などのヘッダーを提供します。

## 最初の安全な実行：システムコール監視

次の診断は読み取り専用です。
対応するUbuntu構成では、通常eBPFのロードにrootユーザー権限が必要です。

```sh
sudo memento doctor syscall
```

診断に合格したらシステムコール取得を開始し、`Ctrl-C`で停止します。

```sh
sudo memento --state-dir /var/lib/memento monitor syscall
```

既定の出力先は`/var/lib/memento/log/syscall-prn.jsonl`と`/var/lib/memento/stats/syscall.json`です。
JSONLログには正規プロセスの秘密の乱数値が含まれる可能性があるため、状態ディレクトリを非公開で管理し、ログを公開しないことを推奨します。

`memento doctor vdso`を使用すると、`__vdso_getrandom`がシステムコールトレースポイントを迂回する可能性を確認できます。
ゲストでシステムコール経路を完全に観測する必要がある場合は、Linuxの文書化されたカーネルパラメータである`vdso=0`でvDSO経路を無効化し、再起動後に結果を確認してください。
ホスト側のCPU取得には、`memento doctor cpu`や`memento monitor cpu`を使用する前に、後述する改変KVMワークフローが必要です。

## 安全境界

シミュレーターが任意のディレクトリを暗号化対象として扱うことはありません。
`memento lab create`が`<state-dir>/lab/<scenario>/work/`配下に作成したコピーだけを読み取り、シナリオの`encrypted/`配下に`O_EXCL`で新しいファイルを書き込みます。
rootユーザー、非TTY実行、シンボリックリンク、マジックリンク、マウント境界の横断、隠しパス、特殊ファイル、ハードリンク、古いマニフェスト、シナリオの許可リスト外の拡張子は拒否されます。

ファイルベースのE2Eでは、rootless Dockerラッパーが唯一の推奨エントリーポイントです。
このラッパーは、読み取り専用のコンテナルートファイルシステム、実行時ネットワークなし、Linuxケイパビリティなし、強制されるリソース制限、範囲を限定したバインドマウントを追加します。
これらはシナリオとマニフェストの検査を補強するものであり、置き換えるものではありません。

シミュレーション中はシナリオルート、`work/`、`plans/`が読み取り専用でマウントされ、`encrypted/`と実行専用ログディレクトリだけが読み書き可能です。
復号時は各暗号文と擬似乱数（PRN）ログを個別に読み取り専用でマウントし、最初は空の出力ディレクトリ1つだけを読み書き可能にします。
一時状態データは専用tmpfsに置かれます。
ラッパーはDockerソケット、ホストのルート、デバイス、リポジトリのソースツリーをマウントせず、インプレース復号も提供しません。

## 復旧データの流れ

同じ`memento`バイナリを監視対象ゲストと、CPU命令取得時のKVMホストで実行します。

```text
ゲスト                                     KVMホスト
------                                     ---------
read/getrandom -> eBPF                     RDRAND/RDSEED VM exit
       |                                          |
       +-> memento.prn/v1 JSONL                   +-> KVMリングバッファ
       |                                                  |
プロセスメモリ -> Babuk鍵候補                 memento monitor cpu
       |                                                  |
       +--------------- PRN読み込み <---------------------+
                              |
                       Babuk/Qilin復号
                              |
                       新規復号ファイル
```

Babuk復号ではX25519共有秘密を導出してSHA-512でハッシュ化し、ハッシュの先頭32バイトをSosemanuk鍵として使用します。
PRNから導出した一時公開鍵が暗号文末尾の32バイト公開鍵と一致する候補だけを復号対象として受け入れます。

Qilin復号は旧OpenSSLの配置を維持します。
ChaCha20のIVは64ビットのリトルエンディアンカウンターとそれに続く64ビットナンスで構成され、各RSAフッターは互換性のためSHA-1およびMGF1-SHA-1によるOAEPを使用します。
3つのステージはそれぞれ16バイトのIVと32バイトの鍵を`read(/dev/urandom)`で取得するため、取得された6値が復号入力になります。

### PRNログ形式

書き込み側は、`schema: "memento.prn/v1"`を持つJSONオブジェクトを1行につき1つ出力します。
全レコードに時刻、取得元、操作、小文字の16進数値、取得長、要求長、切詰め状態が含まれます。
システムコールレコードにはPID/TID、ファイルディスクリプター、パス、フラグ、返却メタデータが、CPUレコードにはシーケンス番号、VM/vCPU、命令、オペランド幅、宛先レジスター、RIP、CR3、成功状態、RFLAGS、ホストCPUメタデータが追加されます。

eBPFが1イベントにつき取得するのは最大128バイトで、切詰めとperfリングの欠落サンプル数を記録します。
CPU監視はカーネルレコードのマジック値、バージョン、サイズを検証し、部分読み込みを処理してKVMリングのドロップ数を報告します。
読み込み側が受け入れるスキーマは`memento.prn/v1`だけであり、改名前のスキーマとスキーマなしログは意図的に拒否されます。

## 監視付きエンドツーエンドラボ評価

以下の例では、暗号化、PID限定eBPF観測、非破壊復号を実行します。
Babukでは同期したメモリダンプとヒューリスティックなマスター公開鍵特定も行います。
検証ホスト上で、リポジトリルートから、埋め込みフィクスチャだけを使用して実行してください。
任意の入力パスは受け付けず、各新規シナリオに含まれる管理対象は`fixture-0000.memento` 1件だけです。

[rootless Docker](https://docs.docker.com/engine/security/rootless/)をruncおよびcgroup v2/systemdドライバーで構成します。
次の確認ではファイルを暗号化しません。

```bash
sudo memento doctor syscall
sudo memento doctor vdso
docker info --format 'driver={{.CgroupDriver}} version={{.CgroupVersion}} security={{json .SecurityOptions}}'
test -z "$(docker ps -q)"                 # 実行中のコンテナがないことを要求
make container-image
make container-smoke
cmp -- build/memento "$(command -v memento)" # ホストとイメージ用の入力が一致
```

ラッパーは読み取り専用ルートファイルシステム、`--network=none`、Linuxケイパビリティなし、強制されるリソース制限、範囲を限定したマウントを使用します。
Mementoが完全一致の`YES`または`NO`を要求する前に、完全なマニフェストと全対象を表示します。
端末2でPID限定監視が起動するまで`YES`を入力しないでください。
以下では新しい状態ディレクトリのパスを使用します。
いずれかが既に存在する場合は、別の未使用パスを選択してください。

### Babuk：暗号化、監視、ダンプ、鍵特定、復号

**端末1**で、実行専用鍵と1ファイルだけのマニフェストを作成します。
表示された暗号化計画を確認してからラッパーを起動します。
ラッパーは承認プロンプトで停止します。

```bash
cd /path/to/memento
BABUK_STATE="$PWD/var/readme-babuk-e2e"
test ! -e "$BABUK_STATE"

KEY_OUTPUT=$(memento --state-dir "$BABUK_STATE" genkey babuk \
  --output "$BABUK_STATE/keys/e2e.json")
printf '%s\n' "$KEY_OUTPUT"
PUBLIC_KEY=$(printf '%s\n' "$KEY_OUTPUT" | sed -n 's/^public key: //p')
test "${#PUBLIC_KEY}" -eq 64

memento --state-dir "$BABUK_STATE" lab init \
  --scenario babuk-e2e --allow-ext .memento
memento --state-dir "$BABUK_STATE" lab create \
  --scenario babuk-e2e --fixture sample.txt --ext .memento --count 1
PLAN_OUTPUT=$(memento --state-dir "$BABUK_STATE" lab plan-encryption \
  --scenario babuk-e2e --ext .memento)
printf '%s\n' "$PLAN_OUTPUT"
MANIFEST=$(printf '%s\n' "$PLAN_OUTPUT" | sed -n 's/^manifest: //p')
test -f "$MANIFEST"

./scripts/memento-container.sh encrypt babuk \
  --state-dir "$BABUK_STATE" \
  --scenario babuk-e2e \
  --manifest "$MANIFEST" \
  --public-key "$PUBLIC_KEY" \
  --validation-stop-after-prn
```

端末1が待機している間に、**端末2**で唯一のコンテナにあるMemento子プロセスのPIDを特定し、監視を起動します。
このコマンドを実行したままにし、監視が出力パスを表示して、その後に起動エラーが発生していないことを確認してから端末1へ戻ります。
対象が`fixture-0000.memento` 1件だけであることを確認し、`YES`を入力します。
暗号化が完了したら端末2へ戻り、`Ctrl-C`を1回押して監視に統計を書き込ませます。

```bash
cd /path/to/memento
BABUK_STATE="$PWD/var/readme-babuk-e2e"
mapfile -t CIDS < <(docker ps -q)
test "${#CIDS[@]}" -eq 1
INIT_PID=$(docker inspect --format '{{.State.Pid}}' "${CIDS[0]}")
mapfile -t TARGETS < <(pgrep -P "$INIT_PID" -x memento)
test "${#TARGETS[@]}" -eq 1
TARGET_PID=${TARGETS[0]}

MONITOR_STATE="$BABUK_STATE/monitor-state"
EVIDENCE="$BABUK_STATE/evidence"
install -d -m 0700 "$MONITOR_STATE" "$EVIDENCE"
sudo memento --state-dir "$MONITOR_STATE" monitor syscall \
  --pid "$TARGET_PID" \
  --output "$EVIDENCE/syscall-prn.jsonl" \
  --stats "$EVIDENCE/syscall-stats.json" \
  --dump-on-prn --dump-operation read \
  --dump-path /dev/urandom --dump-length 32 \
  --dump-wait-stopped 20s --resume-after-dump
```

引き続き端末2で取得統計を確認し、鍵識別処理へ期待する鍵を与えずに鍵を特定して、eBPFログから復号します。
確認用に現在のユーザーへ所有権を戻すのは監視出力2ファイルだけです。
ダンプツリー全体の所有権は変更しません。

```bash
PRN_LOG="$EVIDENCE/syscall-prn.jsonl"
STATS="$EVIDENCE/syscall-stats.json"
sudo chown -- "$(id -u):$(id -g)" "$PRN_LOG" "$STATS"
chmod 0600 "$PRN_LOG" "$STATS"
jq -e '.read_events == 1 and .getrandom_events == 0 and
       .lost_samples == 0 and .truncated_events == 0' "$STATS"

mapfile -t DUMPS < <(sudo find "$MONITOR_STATE/dump/$TARGET_PID" \
  -mindepth 1 -maxdepth 1 -type d -print)
test "${#DUMPS[@]}" -eq 1
DUMP_DIR=${DUMPS[0]}
CIPHERTEXT="$BABUK_STATE/lab/babuk-e2e/encrypted/fixture-0000.memento.babyk"
IDENTIFY_OUTPUT=$(sudo memento identify babuk \
  --dump-dir "$DUMP_DIR" --input "$CIPHERTEXT" --prn-log "$PRN_LOG" \
  --output "$BABUK_STATE/babuk-identification.json")
printf '%s\n' "$IDENTIFY_OUTPUT"
SELECTED_KEY=$(printf '%s\n' "$IDENTIFY_OUTPUT" |
  sed -n 's/^Babuk master public key: //p')
EXPECTED_KEY=$(jq -r '.public_key_hex' "$BABUK_STATE/keys/e2e.json")
test "$SELECTED_KEY" = "$EXPECTED_KEY"

RECOVERED="$BABUK_STATE/recovered-e2e"
install -d -m 0700 "$RECOVERED"
./scripts/memento-container.sh decrypt babuk \
  --input "$CIPHERTEXT" --output-dir "$RECOVERED" \
  --prn-log "$PRN_LOG" --public-key "$SELECTED_KEY"
ORIGINAL="$BABUK_STATE/lab/babuk-e2e/work/fixture-0000.memento"
cmp -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
sha256sum -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
```

旧Babuk形式には認証タグがないため、鍵特定はヒューリスティックです。
ヒューリスティックスコアではなく、独立した公開鍵の一致と最終的なバイト単位の比較を合格条件としてください。

### Qilin：暗号化、監視、PRN分類、復号

**端末1**でBabukとは異なる新規シナリオを作成し、承認プロンプトで停止させます。

```bash
cd /path/to/memento
QILIN_STATE="$PWD/var/readme-qilin-e2e"
test ! -e "$QILIN_STATE"

memento --state-dir "$QILIN_STATE" lab init \
  --scenario qilin-e2e --allow-ext .memento
memento --state-dir "$QILIN_STATE" lab create \
  --scenario qilin-e2e --fixture sample.txt --ext .memento --count 1
PLAN_OUTPUT=$(memento --state-dir "$QILIN_STATE" lab plan-encryption \
  --scenario qilin-e2e --ext .memento)
printf '%s\n' "$PLAN_OUTPUT"
MANIFEST=$(printf '%s\n' "$PLAN_OUTPUT" | sed -n 's/^manifest: //p')
test -f "$MANIFEST"

./scripts/memento-container.sh encrypt qilin \
  --state-dir "$QILIN_STATE" \
  --scenario qilin-e2e \
  --manifest "$MANIFEST"
```

端末1が待機している間に、**端末2**でPID限定監視を起動します。
出力パスが表示され、その後に起動エラーが発生していないことを確認してから、端末1で表示された対象1件を確認して`YES`を入力します。
暗号化完了後、端末2で`Ctrl-C`を1回押します。

```bash
cd /path/to/memento
QILIN_STATE="$PWD/var/readme-qilin-e2e"
mapfile -t CIDS < <(docker ps -q)
test "${#CIDS[@]}" -eq 1
INIT_PID=$(docker inspect --format '{{.State.Pid}}' "${CIDS[0]}")
mapfile -t TARGETS < <(pgrep -P "$INIT_PID" -x memento)
test "${#TARGETS[@]}" -eq 1
TARGET_PID=${TARGETS[0]}

MONITOR_STATE="$QILIN_STATE/monitor-state"
EVIDENCE="$QILIN_STATE/evidence"
install -d -m 0700 "$MONITOR_STATE" "$EVIDENCE"
sudo memento --state-dir "$MONITOR_STATE" monitor syscall \
  --pid "$TARGET_PID" \
  --output "$EVIDENCE/syscall-prn.jsonl" \
  --stats "$EVIDENCE/syscall-stats.json"
```

復号に必要な6件の`/dev/urandom` readを確認し、PID限定eBPFログを使用して復号します。
OAEP内部で使用する`crypto/rand.Reader`の呼出しは、Goツールチェーン、FIPSモード、vDSOの利用状況によってOS上の`getrandom`システムコールとして観測される件数が変わり得るため、固定件数を合格条件にしません。

```bash
PRN_LOG="$EVIDENCE/syscall-prn.jsonl"
STATS="$EVIDENCE/syscall-stats.json"
sudo chown -- "$(id -u):$(id -g)" "$PRN_LOG" "$STATS"
chmod 0600 "$PRN_LOG" "$STATS"
jq -e '.read_events == 6 and
       .lost_samples == 0 and .truncated_events == 0' "$STATS"
jq -s -e '
  [.[] | select(.source == "syscall" and .operation == "read" and
                .syscall.name == "read" and .syscall.path == "/dev/urandom") |
         .captured_length] == [16, 32, 16, 32, 16, 32]
' "$PRN_LOG"
jq -s '[.[] | select(.operation == "getrandom") |
        {captured_length, requested_length, truncated}]' "$PRN_LOG"

CIPHERTEXT="$QILIN_STATE/lab/qilin-e2e/encrypted/fixture-0000.memento.qilin"
RECOVERED="$QILIN_STATE/recovered-e2e"
install -d -m 0700 "$RECOVERED"
./scripts/memento-container.sh decrypt qilin \
  --input "$CIPHERTEXT" --output-dir "$RECOVERED" \
  --prn-log "$PRN_LOG"
ORIGINAL="$QILIN_STATE/lab/qilin-e2e/work/fixture-0000.memento"
cmp -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
sha256sum -- "$ORIGINAL" "$RECOVERED/fixture-0000.memento"
```

6件のreadは復号に使用する3組のIV／鍵です。
20バイトの`getrandom`レコードが観測された場合、それはRSA-OAEP内部の乱数として参考表示されますが、復号候補から除外されます。
16／32バイトの`getrandom`レコードが混在した場合も復号候補にはなりません。
Qilin復号も認証タグがないためヒューリスティックです。
スコアではなく、最終的な`cmp`の結果を正否判定に使用してください。

## コマンド

| コマンド | 用途 |
|---|---|
| `memento doctor [syscall\|cpu\|vdso]` | 前提条件を読み取り専用で診断 |
| `memento monitor syscall` | `/dev/random`、`/dev/urandom`、`getrandom`を取得し、単一TGIDへの限定も可能 |
| `memento monitor cpu` | 改変KVMのdebugfsリングを読み取り |
| `memento dump --pid PID` | 選択したプロセスマッピングをダンプし、件数を制限したBabuk鍵候補を表示 |
| `memento identify babuk` | 非公開ダンプからBabukマスター公開鍵候補をヒューリスティックに順位付け |
| `memento decrypt babuk\|qilin` | 暗号文を変更せず`var/recovered/`へ復号 |
| `memento lab init/create/plan-encryption/encrypt` | 管理・承認されたシミュレーション |
| `memento verify cpu` | ゲスト側バイナリレコードとホスト側JSONLを比較 |
| `memento genkey babuk` | `0600`モードの評価用鍵素材を生成 |

状態ディレクトリの優先順位は`--state-dir`、`MEMENTO_STATE_DIR`、`./var`です。
状態ディレクトリは`0700`モード、ログ、ダンプ、マニフェスト、復号ファイル、鍵素材は`0600`モードを使用します。

`identify babuk`が報告するのはヒューリスティックであり、真正性の判定ではありません。
Babuk形式には、選択したマスター公開鍵を証明できるタグがありません。
検証時は、選択結果を別に保持した正解値と比較してください。

<a id="modified-kvm-workflow"></a>

## 改変KVMワークフロー

`kvm/patches/0001-kvm-rdrand-rdseed-monitor.patch`は、Ubuntuソースパッケージ`6.17.0-35.35~24.04.1`を対象とします。
使い捨ての未改変ソースツリー内だけでビルドしてください。

ソースパッケージの署名検証とカーネルモジュールのビルドに必要なツールを導入します。
Ubuntuの`deb-src`リポジトリを有効にしている場合は、`apt-get build-dep`でUbuntuカーネルの完全なビルド依存関係も導入してください。

```sh
sudo apt-get update
sudo apt-get install -y build-essential bc bison flex cpio dwarves kmod \
  libelf-dev libssl-dev rsync wget ubuntu-keyring dpkg-dev gpgv
# Nobleのdeb-srcリポジトリを有効にしている場合に実行します。
sudo apt-get build-dep -y linux-hwe-6.17
```

リポジトリルートから、公式Launchpadに保存された正確なソースパッケージ3ファイルを、新しい非公開作業ディレクトリへ取得します。
次の例では既存ディレクトリを再利用しません。

```sh
REPO_ROOT=$PWD
KVM_WORK=/path/to/private/memento-kvm-6.17.0-35
test ! -e "$KVM_WORK"
install -d -m 0700 "$KVM_WORK/source-package"

SOURCE_URL='https://launchpad.net/ubuntu/+archive/primary/+sourcefiles/linux-hwe-6.17/6.17.0-35.35~24.04.1'
wget --https-only --directory-prefix="$KVM_WORK/source-package" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0-35.35~24.04.1.dsc" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0.orig.tar.gz" \
  "$SOURCE_URL/linux-hwe-6.17_6.17.0-35.35~24.04.1.diff.gz"

cd "$REPO_ROOT"
make prepare-kvm-source \
  DSC="$KVM_WORK/source-package/linux-hwe-6.17_6.17.0-35.35~24.04.1.dsc" \
  SIGNER_KEYRING=/usr/share/keyrings/ubuntu-archive-keyring.gpg \
  KERNEL_TREE="$KVM_WORK/pristine-6.17.0-35" \
  SOURCE_EVIDENCE_DIR="$KVM_WORK/source-evidence"
```

`prepare-kvm-source`は`.dsc`の署名フィンガープリント、同ファイルに記録されたSHA-256、パッケージバージョンを検証してから展開し、変更のない初期Gitスナップショットを作成します。
取得したファイルを署名検証前に信頼しないでください。

バージョンが一致するUbuntuカーネルパッケージから設定ファイルと`Module.symvers`を指定します。
次の2ファイルが存在し、読み取り可能であることを確認してからビルドします。

```sh
KERNEL_CONFIG=/boot/config-6.17.0-35-generic
MODULE_SYMVERS=/usr/src/linux-headers-6.17.0-35-generic/Module.symvers
test -r "$KERNEL_CONFIG"
test -r "$MODULE_SYMVERS"

make validate-kvm \
  KERNEL_TREE="$KVM_WORK/pristine-6.17.0-35" \
  KERNEL_CONFIG="$KERNEL_CONFIG" \
  MODULE_SYMVERS="$MODULE_SYMVERS" \
  KVM_ARTIFACT_DIR="$KVM_WORK/kvm-artifacts"
```

この処理はUbuntuパッケージのバージョンを検証し、一時ワークツリーへパッチを適用して、104バイトのレコードABIを確認した上で`kvm.ko`と`kvm-intel.ko`をビルドします。
KVMのアンロードは稼働中のVMを中断し、ホストカーネルの状態を変更するため、Mementoはモジュール交換を意図的に自動化しません。
すべてのVMを停止し、帯域外の復旧経路を確保し、パッケージ版モジュールのパスを記録した上で、実験用モジュールを手動でロードまたはアンロードしてください。

モジュールをロードした後、`memento doctor cpu`は`/sys/kernel/debug/kvm_rndlog/buffer`および`stats`インターフェースを確認します。
実験用モジュールを`/lib/modules`配下へ永続的にインストールしないでください。
通常の再起動でホストをパッケージ版モジュールへ戻せるようにします。

## 制約とリリース状態

- 改変KVMによる取得を正式に検証した環境は、Ubuntu 24.04、Intel x86-64 VMX、`6.17.0-35-generic`だけです。
  AMD SVMとその他のカーネルは未対応またはベストエフォートです。
- `__vdso_getrandom`だけで返される乱数はシステムコールトレースポイントへ到達しません。
  システムコール取得へ依存する前に`memento doctor vdso`を実行してください。
- 旧BabukおよびQilin形式は暗号文本体を認証しません。
  候補順位付けはヒューリスティックであるため、可能な限り独立した情報源を用いて復号データを検証してください。
- リングバッファオーバーフローは報告されますが、ドロップしたCPUレコードを復元することはできません。
- Mementoはバージョン`0.1.0-dev`の研究プロトタイプです。
  性能測定値は互換性や合否を保証するものではありません。

## 検証

```sh
make check
make validate-safe
```

どちらのターゲットもファイルシステム暗号化を実行しません。
KVMビルドと特権が必要な基準ホスト検査には、運用者による独立した承認が必要です。
検証済みの復旧経路を備えた使い捨て検証ホストだけで実行してください。

## ライセンス

プロジェクトコードはGPL-2.0-onlyでライセンスされます。
同梱するSosemanuk実装はX-CRYPTの原ライセンスに従います。
詳細は[`internal/crypto/sosemanuk/LICENSE`](internal/crypto/sosemanuk/LICENSE)を参照してください。
