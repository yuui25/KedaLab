# 技術インデックス

全ての技術・手法の横断検索用インデックス。新しい技術を追加したらここにも1行追記する。

**フォーマット:** `技術名 | カテゴリ | ファイルパス`

**並び順:** 同一ファイル由来の複数行は、そのファイルが「Basic → 高難度」順で書かれている場合、その順序を本 INDEX 内でも保つ（例: `02_Initial_Access/SSH.md` の §1 バナー観察 〜 §11 Port Forwarding）。ファイル側で順序が定義されていない場合は追記順で構わない。

---

## 調査・列挙

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| ポートスキャン（nmap） | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| DNS調査・IP特定（nslookup・dig・ゾーン転送・サブドメイン列挙） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| OS判定（TTL・ポート構成・HTTPヘッダー・SMBバナー・SSH バナー） | Reconnaissance | `00_Playbook/00_OS_Identification.md` |
| robots.txt からの隠しパス発見 | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| サービスバージョン検出 | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| IPレンジからDockerコンテナを特定（172.17.0.x） | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| Webディレクトリファジング中のレート制限・WAF throttle 対処（gobuster -t / --delay 調整） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| コンテナ環境の確認（/.dockerenv / /etc/hosts / ip addr） | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| Webディレクトリ列挙（gobuster） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| vhostファジング | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| Webアプリバージョン特定（/api/health 等） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| searchsploit による CVE 検索 | Reconnaissance | `05_Tools_Reference/Searchsploit.md` |
| SMB匿名アクセス | Reconnaissance | `01_Reconnaissance/SMB_Enumeration.md` |
| SMB ゲストアカウント有効確認（netexec smb -u 'guest' -p ''） | Reconnaissance | `01_Reconnaissance/SMB_Enumeration.md` |
| NETLOGON 共有のログオンスクリプト確認（平文パスワード埋め込み検出） | Reconnaissance | `01_Reconnaissance/SMB_Enumeration.md` |
| SYSVOL / Replication 内部ナビゲーション観点（GPO構造・フォルダ優先度） | Reconnaissance | `01_Reconnaissance/SMB_Enumeration.md` |
| SYSVOL列挙 | Reconnaissance | `01_Reconnaissance/SMB_Enumeration.md` |
| GPP 認証情報取得（Groups.xml / cpassword / gpp-decrypt） | Reconnaissance → Initial Access | `01_Reconnaissance/SMB_Enumeration.md` |
| LDAP ユーザー列挙 | Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| LDAP カスタム属性の確認（info / description） | Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| LDAP 経由の Kerberoast / AS-REP Roast 候補抽出（SPN・DONT_REQ_PREAUTH） | Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| LDAP 有効ユーザーのみ抽出（userAccountControl bit 2 ACCOUNTDISABLE 除外）| Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| LDAP userAccountControl ビット値早見表（DELEGATION・DONT_EXPIRE_PASSWORD 等）| Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| LDAP 匿名バインド / namingcontexts 確認 | Reconnaissance | `01_Reconnaissance/LDAP_Enumeration.md` |
| GetADUsers.py によるドメインユーザー高速列挙（PasswordLastSet / LastLogon）| Reconnaissance | `05_Tools_Reference/Impacket_Suite.md` |
| ファイルメタデータ解析（exiftool / docProps/core.xml）によるユーザー名・ドメイン名取得 | Reconnaissance | `01_Reconnaissance/Metadata_Analysis.md` |
| FTP §3 匿名アクセス・再帰ダウンロード（wget -m / lftp mirror / curl）| Reconnaissance | `02_Initial_Access/FTP.md` |
| OLE2 / .msg ファイル解析・変換（msgconvert / extract-msg）| Reconnaissance | `02_Initial_Access/Binary_Analysis.md` |
| TLS プロトコル/暗号スイート列挙（nmap ssl-enum-ciphers / testssl.sh / sslyze） | Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
| 証明書 CN / SAN / Issuer からの組織・製品・FQDN 推定 | Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
| openssl s_client によるプロトコル別接続・SNI 指定・mTLS 判定 | Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
| 名前付き TLS 脆弱性確認（Heartbleed / POODLE / FREAK / Logjam / ROBOT / DROWN / Sweet32 / Ticketbleed） | Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
| HSTS / セキュリティヘッダー確認（Strict-Transport-Security / CSP / X-Frame-Options） | Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
| .git / .svn / .hg ディレクトリ露出検出と git-dumper によるリポジトリ復元 | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| .env / config.php / wp-config.php 等の設定ファイル誤公開 | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| バックアップファイル列挙（.bak / .old / ~ / .swp / .tar.gz / .zip / .sql） | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| サーバー設定ファイル誤公開（.htaccess / .htpasswd / web.config / nginx.conf） | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| 動作確認用ファイル誤公開（phpinfo.php / server-status / server-info） | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| Swagger / OpenAPI 仕様ファイル誤公開からの裏 API 列挙 | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| .DS_Store / Thumbs.db / .idea / .vscode メタファイルからのファイル名抽出 | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| ディレクトリリスティング検出（Apache autoindex / Nginx autoindex / IIS / Tomcat / Python http.server のシグナル） | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| 管理コンソール誤公開（Tomcat manager / JBoss jmx / Spring Actuator env・heapdump / Jenkins script） | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| nuclei exposures テンプレートによる誤公開一括チェック | Reconnaissance | `01_Reconnaissance/Exposed_Files.md` |
| SNMP コミュニティ文字列ブルートフォース（onesixtyone）/ UDP 161 ホスト発見 | Reconnaissance | `01_Reconnaissance/SNMP_Enumeration.md` |
| snmpwalk による MIB 全取得（OID 1.3.6.1 系 / ARP・ルーティング・プロセス・ソフトウェア・Windows ユーザー） | Reconnaissance | `01_Reconnaissance/SNMP_Enumeration.md` |
| SNMPv3 認証情報確認（auth/priv プロトコル列挙・nmap snmp-brute） | Reconnaissance | `01_Reconnaissance/SNMP_Enumeration.md` |
| SNMP 書き込み可能コミュニティ文字列による設定変更（snmpset / ルーター設定改ざん） | Reconnaissance | `01_Reconnaissance/SNMP_Enumeration.md` |

---

## 初期アクセス

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| Webアプリフレームワーク・アプリ名の特定（フッター・contactページ・HTMLソース・ヘッダー） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| Cookie 名からの CMS / フレームワーク識別（CMSSESSID / wp-* / JSESSIONID 等） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| Cookie の third-party 除外と first-party テスト対象の絞り込み（cookie_classify） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| リクエスト/レスポンスの機微情報・設定不備一括スキャン（sensitive_scan / WSTG-INFO） | Reconnaissance | `01_Reconnaissance/Web_Response_Triage.md` |
| セキュリティヘッダー欠落確認（CSP / HSTS / X-Content-Type-Options / Referrer-Policy / Permissions-Policy 等） | Reconnaissance | `01_Reconnaissance/Web_Response_Triage.md` |
| Cookie 属性不備確認（HttpOnly / Secure / SameSite 欠落・超長期 Expires）（WSTG-SESS-02） | Reconnaissance | `01_Reconnaissance/Web_Response_Triage.md` |
| **Server ヘッダーからの Python WSGI 系識別（Werkzeug / gunicorn / uWSGI / Tornado / Django runserver）と非標準ポート観点** | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| HTML `<meta name="generator">` 著作権年範囲からのバージョン推定 | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| DoS 保護・自動 IP ブロック前提のディレクトリ列挙抑制（robots.txt・トップページの警告文を読む） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| 未認証ファイルアップロード RCE（二重拡張子・マジックバイト・Content-Type 偽装） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| 難読化JavaScript解析（eval/Packer形式・console.log置換・de4js） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| ROT13 / Base64 APIレスポンスのデコード | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| 多重エンコードの自動検出・再帰デコード（URL / Base64 / JWT / gzip / Hex 等、decode_layers）（WSTG-INPV-01） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JS_Obfuscation.md` |
| OSコマンドインジェクション（セミコロン・パイプ・バッククォート） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| PDFKit コマンドインジェクション（バックティック URL 注入 / CVE-2022-25765） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| HTTPサーバー経由のリバースシェル配信（python3 -m http.server + curl \| bash） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| APIパラメータ改ざんによる権限昇格（is_admin=1・Broken Function Level Authorization） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| リバースシェル（bash -c 'bash -i >& /dev/tcp/...'） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| curlシングルクォートエスケープ（'"'"'パターン） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` |
| クロスサイトスクリプティング（XSS）— 反射型・格納型・DOM型・Blind XSS | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| XSS セッショントークン窃取（Cookie スティーリング）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| XSS DOM偽装・フィッシングリダイレクト | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| 入力バイパス — エンコーディング・難読化によるフィルタ回避（HTML / URL / ダブルエンコーディング） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| **リクエストヘッダー（User-Agent / Referer / X-Forwarded-For）経由の XSS — フォーム本文がフィルタされる場合の代替注入面** | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| **Blind XSS の発火シグナル（「管理者にレポート送信」文言・問い合わせフォーム等）** | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| **Blind XSS の `new Image()` ステルス cookie exfil チャネル + base64 デコード受信** | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| **stolen cookie のブラウザ植え替え（DevTools Storage タブ・curl/Burp の Cookie ヘッダー差し替え）** | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| ソーシャルエンジニアリング（フィッシング・スピアフィッシング・BEC） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| プリテキスティング（IT サポート・監査員・ベンダーを装った認証情報詐取） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| ベイティング（感染USB放置・偽ダウンロードリンク） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| パストラバーサル（ディレクトリトラバーサル） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| Grafana パストラバーサル CVE-2021-43798 | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| IDOR（連番ID・オブジェクト直接参照） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/IDOR.md` |
| SQLインジェクション | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| タイムベースブラインドSQLi（時間遅延オラクル） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| CMS Made Simple SQLi（CVE-2019-9053）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| MD5+Salt ハッシュのクラック（mode 20） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| ハッシュ形式の特定（hashid / 形式文字列の読み方 / --example-hashes） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| Flask / Werkzeug PBKDF2 ハッシュのクラック（mode 10000 変換） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| SSRF（サーバーサイドリクエストフォージェリ） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| SSRF defense bypass：8進数・16進数・整数表記 IP リテラル（ipaddress 解析失敗パターン） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| SSRF defense bypass：IPv4-mapped IPv6 (`::ffff:127.0.0.1`)（Python 3.11.9 / 3.12.4 未満限定） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| XXE（XML外部エンティティインジェクション） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XXE.md` |
| XSLTインジェクション（プロセッサフィンガープリント・XXE-via-XSLT・PHP拡張・Java拡張） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md` |
| JWT alg:none 攻撃（署名検証スキップ） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT 弱い秘密鍵ブルートフォース（hashcat mode 16500） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT RS256→HS256 アルゴリズム切り替え攻撃（公開鍵を HMAC 秘密鍵として悪用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT kid パラメータインジェクション（SQLi / パストラバーサル） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT jku / x5u 鍵 URL 差し替え（攻撃者 JWKS への誘導） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT jwk ヘッダーインジェクション（攻撃者公開鍵の埋め込み） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| OAuth redirect_uri 検証バイパス（サブストリングマッチ / Path Traversal / Open Redirect 連鎖 / HPP / IDN）→ 被害者 code 奪取 → アカウント乗っ取り | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth state 欠落・固定による CSRF → 既存アカウントに攻撃者 IdP 連携を強制（アカウント連携乗っ取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth Implicit Flow Token Leakage（URL fragment の access_token → Referer / 履歴 / JS 経由漏洩） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OpenID Connect id_token 検証バイパス（iss / aud / azp / nonce / exp 検証ミス・JWT 攻撃と併用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth email / sub 信頼性攻撃（federated identity confusion / `email_verified` 不検証 → 既存アカウント乗っ取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth PKCE 欠落・downgrade（`code_challenge_method=plain` 許容 → モバイル app / public client の code 横取り成立） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth client_secret 漏洩悪用（モバイル app バンドル / SPA / GitHub 由来 → confidential client なりすまし） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| Open Redirect バイパス各種（プロトコル相対 `//` / userinfo `@` / バックスラッシュ・多重スラッシュ / URL エンコード / IDN・Punycode） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| Open Redirect `javascript:` スキーム経由 XSS 化（DOM ベース `location.href = userInput` 系で成立） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| Open Redirect 経由の SSRF 防御回避（攻撃者ホスト → 302 で内部 IP / メタデータ API へ転送） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| Open Redirect の OAuth `redirect_uri` バイパス連鎖（victim 内 open redirect で OAuth code を attacker へ転送 → アカウント乗っ取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| Open Redirect 経由の認証 token / OAuth code Referer 漏洩（`Referrer-Policy` 設定次第） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md` |
| PCAPからの平文認証情報抽出 | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| WebアプリDB（SQLite等）からのハッシュ取得 | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| PBKDF2-HMAC-SHA256 ハッシュのクラック（mode 10900） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| スクリプトへの平文パスワード埋め込み | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| GPP cpassword の復号（gpp-decrypt） | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| Webアプリ .env ファイルからの認証情報取得（DB_PASSWORD・パスワード使い回し） | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| Bundler 設定ファイル（.bundle/config）からの RubyGems 認証情報取得 | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| LDAPカスタム属性への平文パスワード | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| パスワードの使い回し確認 | Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| strings コマンドによる文字列抽出 | Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| .NET バイナリ逆コンパイル（ILSpy / ilspycmd / dnSpy）| Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| XOR暗号化パスワードの復号 | Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| RC4暗号化パスワードの復号（.NETバイナリ） | Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| dnSpy コード編集・再コンパイルによるパスワード取得（SecureString / 動的生成パスワードの抽出）| Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| バイナリ実行（Wine）＋ネットワークキャプチャ（tcpdump）によるクレデンシャル取得 | Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| KeePass データベース（.kdbx）のクラック（keepass2john + hashcat / john）| Initial Access | `02_Initial_Access/Credential_Discovery.md` |
| パスワード命名パターン推測（サービス名＋年号型）| Initial Access | `02_Initial_Access/Binary_Analysis.md` |
| FTP §1 バナー観察 / バージョン判定（nmap -sV / nc 21 / FEAT） | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §2 匿名ログイン試行 + 機能列挙（ftp-anon / SYST / HELP / STAT） | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §4 取得後の精査順序（file / メタデータ / テキスト grep / 認証情報探索） | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §5 書き込み可能性の確認（put / curl -T / DocumentRoot 経由 webshell 経路） | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §6 PCAP からの平文認証情報抽出（tshark / USER + PASS / ftp-data export） | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §7 パスワード認証突破（hydra / medusa / ncrack / nmap ftp-brute）| Initial Access | `02_Initial_Access/FTP.md` |
| FTP §8.1 vsftpd 2.3.4 backdoor (CVE-2011-2523) — `:)` スマイリーで TCP/6200 root シェル | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §8.2 ProFTPD 1.3.5 mod_copy (CVE-2015-3306) — SITE CPFR/CPTO 任意ファイルコピー | Initial Access | `02_Initial_Access/FTP.md` |
| FTP §9 FTP Bounce 攻撃（PORT command 経由の踏み台スキャン・古典・finding 用）| Initial Access | `02_Initial_Access/FTP.md` |
| SSH §1 バナー観察と OS / ディストリ推定（nmap -sV / nc）| Initial Access | `02_Initial_Access/SSH.md` |
| SSH §1 CVE-2024-6387 (regreSSHion) バージョン判定と注意点（OpenSSH 8.5p1〜9.7p1 on glibc Linux・race condition pre-auth RCE） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §2 対応認証方式の列挙（`ssh -v -o PreferredAuthentications=none` で `publickey,password,keyboard-interactive,gssapi-with-mic` 判定） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §3 ホスト鍵 fingerprint 捕捉（ssh-keyscan / ssh-keygen -lf）と鍵使い回し横展開検出 | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §4 アルゴリズム・暗号スイート列挙（nmap --script ssh2-enum-algos / 弱い KEX・Cipher 検出 / CVE-2023-48795 Terrapin prefix truncation 判定） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §5 agent forwarding（`ssh -A`）の逆方向リスクと侵入先ホストでの鍵乗っ取り観点 | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §6 制限シェル（rbash / lshell）の脱出（vi / ed エディタ経由・`ssh -t '/bin/bash'`・PATH 復元） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §6 SCP / SFTP のみ許可された制限アカウントからのファイル読み取り（/etc/passwd / .bash_history / .ssh/ 系） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §7 パスワード認証突破（hydra / medusa / ncrack / nmap ssh-brute による辞書攻撃・スプレー・ロックアウト前提）| Initial Access | `02_Initial_Access/SSH.md` |
| SSH §8 秘密鍵パスフレーズクラック（ssh2john + john / hashcat mode 22921） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §9 ユーザー名列挙（CVE-2018-15473・OpenSSH 7.7 未満・タイミング差ベース / GitHub `.keys` OSINT 補完） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §10 Debian PRNG 弱鍵試行（CVE-2008-0166・事前生成 32K 鍵リスト・レガシー機器対象） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §11 authorized_keys 書込による侵入・persistence（FTP/SMB 書込 / Redis unauth `CONFIG SET dir` / PostgreSQL `COPY ... TO PROGRAM` 経由・原状回復必須） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §12 Port Forwarding / SOCKS pivot（`-L` Local / `-R` Remote / `-D` Dynamic SOCKS / `-J` ProxyJump 多段チェイン） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §13 SSH Agent ハイジャック（他ユーザの `SSH_AUTH_SOCK` 流用 / `ssh-add -l` 鍵列挙 / agent 経由の横展開連鎖 / `ssh -A` 逆方向リスク） | Initial Access | `02_Initial_Access/SSH.md` |
| Mail §1 バナー観察 / 製品判定（SMTP / POP3 / IMAP 一括・Postfix / Exim / Sendmail / Dovecot / Exchange / Cyrus 判別）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §2 SMTP 機能列挙（EHLO / HELP / AUTH メカニズム / STARTTLS / nmap smtp-commands） | Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §3 SMTP ユーザー列挙（VRFY / EXPN / RCPT TO バウンス挙動・smtp-user-enum）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §4 オープンリレー判定（nmap smtp-open-relay / swaks 実送信テスト）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §5 SPF / DKIM / DMARC 設定確認（dig TXT・受信側設定の finding）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §6 SMTP Smuggling（EOD シーケンス解釈差悪用・SPF/DKIM/DMARC バイパス・Timo Longin / SEC Consult 2023 公開）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §7 SMTP / POP3 / IMAP 認証スプレー（hydra smtp / pop3 / imap・Exchange Throttling 対応）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §8 POP3 / IMAP 認証突破後のメール本文精査（imaplib / poplib・他システム cred 抽出）| Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §9.1 Exchange ProxyLogon (CVE-2021-26855) / ProxyShell (CVE-2021-34473) / ProxyNotShell (CVE-2022-41040 / 41082) | Initial Access | `02_Initial_Access/Mail_Services.md` |
| Mail §9.2 Exim CVE-2019-10149 (Return of the WIZard) — Exim 4.87〜4.91 の SMTP RCE | Initial Access | `02_Initial_Access/Mail_Services.md` |
| WinRM (evil-winrm) | Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| WinRM Pass-The-Hash | Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| Impacket exec ツール群（wmiexec / psexec / smbexec）— WinRM 閉鎖時のシェル取得 | Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| Impacket exec ツール選択（DCERPC+DCOM / SMB / 検知性比較・Event ID 7045）| Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| RPC / rpcclient ユーザー列挙 | Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| impacket-lookupsid による RID bruteforce | Initial Access | `02_Initial_Access/Protocol_Exploitation.md` |
| MSSQL 列挙・悪用（impacket-mssqlclient / DB列挙・ハッシュ取得） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL ユーザーなりすまし（enum_impersonate / EXECUTE AS LOGIN） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL xp_cmdshell による OS コマンド実行 | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL Linked Server 列挙・悪用（enum_links / EXECUTE AT / openquery による権限昇格） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL Linked Server 経由の xp_cmdshell 遠隔有効化（多段チェーン・impacket-mssqlclient / PowerUpSQL 使い分け） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL xp_dirtree による NTLM 強制認証（Linked Server 経由 → Responder / ntlmrelayx への誘導） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| Java デシリアライズ allowlist バイパス（resolveProxyClass 経由） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md` |
| Electron アプリ XSS → RCE エスカレーション（nodeIntegration:true + contextIsolation:false） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Electron_XSS_RCE.md` |
| 製品デフォルト認証情報試行（製品カテゴリ別の出荷時組合せ早見表・SecLists Default-Credentials/ 利用） | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| アプライアンス管理 UI / Tomcat manager / JBoss / Jenkins / Grafana / Kibana / DB / プリンタ / IP カメラ / VPN 管理画面のデフォルト認証 | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| hydra による多プロトコル辞書攻撃（http-get / http-post-form / ssh / ftp / telnet / snmp / ipmi） | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| medusa による辞書攻撃（hydra 非対応プロトコルの代替） | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| IPMI cipher 0 認証バイパス（CVE-2013-4786 系） | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| nuclei default-logins/ テンプレートによる製品別デフォルト認証情報一括チェック | Initial Access | `02_Initial_Access/Default_Credentials.md` |
| アカウントロックアウトポリシー事前確認（AD：nxc smb --pass-pol / impacket-samrdump / rpcclient getdompwinfo） | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| LDAP 経由のロックアウト属性取得（lockoutThreshold / lockoutDuration / lockOutObservationWindow / 100ns 単位変換） | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| Linux ロックアウト機構の確認（pam_faillock / pam_tally2 / faillock --user） | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| Web フォームのロックアウト・IP ブロック観察（HTTPレスポンス差分・Retry-After / X-RateLimit ヘッダー） | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| SSH の MaxAuthTries / fail2ban / pam_faillock の見分けと auth.log シグネチャ | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| パスワードスプレーの試行間隔設計（観察期間 + buffer の sleep 設計・継続試行検知の回避） | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| 細粒度パスワードポリシー（FGPP / msDS-PasswordSettings）の確認 | Initial Access | `02_Initial_Access/Account_Lockout_Recon.md` |
| エッジアプライアンス製品フィンガープリント（証明書 Issuer / favicon ハッシュ / URL パス / Server ヘッダー による製品特定） | Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| Citrix NetScaler ADC / Gateway 既知 CVE 照合（CVE-2023-3519 / CVE-2023-4966 Citrix Bleed / CVE-2019-19781）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| Fortinet FortiGate / FortiOS SSL-VPN 既知 CVE 照合（CVE-2024-21762 / CVE-2022-42475 / CVE-2023-27997 XORtigate）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| Ivanti Connect Secure 既知 CVE 照合（CVE-2023-46805 + CVE-2024-21887 チェーン / CVE-2024-22024 XXE / CVE-2024-29824 EPM SQLi）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| Palo Alto PAN-OS GlobalProtect 既知 CVE 照合（CVE-2024-3400 任意ファイル作成 → RCE）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| F5 BIG-IP iControl REST / TMUI 既知 CVE 照合（CVE-2022-1388 認証バイパス / CVE-2023-46747 SSRF → admin 作成）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| nuclei によるアプライアンス CVE 一括スキャン（-tags citrix / fortinet / ivanti / panos / f5）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| PoC リポジトリ選定基準（Rapid7 / Mandiant / Horizon3 / Bishop Fox 優先・バックドア入り PoC の識別）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |
| 成功シグナルの段階的確認（到達性 → 脆弱版数 → 読み取り系 PoC → RCE 承認後のみ）| Initial Access | `02_Initial_Access/Edge_Appliance_CVEs.md` |

---

## Linux 侵入後

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| 侵入後列挙チェックリスト | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| id コマンド出力のグループ解析（staff/lxd/docker/disk/shadow 等） | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| PAM 設定不備による権限昇格（update-motd.d + PATH ハイジャック） | Post Access Linux | `03_Post_Access_Linux/PAM_Misconfig.md` |
| staff グループ + PATH ハイジャック → root | Post Access Linux | `03_Post_Access_Linux/PAM_Misconfig.md` |
| pspy による短命 root プロセス観察（SSH ログイン引き金・cron 系） | Post Access Linux | `05_Tools_Reference/pspy.md` |
| Linux Capabilities（cap_setuid等）による昇格 | Post Access Linux | `03_Post_Access_Linux/Capabilities.md` |
| SUID バイナリの悪用 | Post Access Linux | `03_Post_Access_Linux/SUID_SGID.md` |
| SGID バイナリの悪用 | Post Access Linux | `03_Post_Access_Linux/SUID_SGID.md` |
| sudo 設定不備による昇格 | Post Access Linux | `03_Post_Access_Linux/Sudo_Misconfig.md` |
| sudo docker exec ワイルドカード NOPASSWD | Post Access Linux | `03_Post_Access_Linux/Sudo_Misconfig.md` |
| Ruby YAML.load Psych Gadget Chain（sudo スクリプト経由 → root RCE） | Post Access Linux | `03_Post_Access_Linux/Sudo_Misconfig.md` |
| **sudo スクリプト内の相対パス呼び出し → CWD ハイジャック（secure_path で守られない経路）** | Post Access Linux | `03_Post_Access_Linux/Sudo_Misconfig.md`（パターン6） |
| シェル安定化（TTYアップグレード・python3 pty.spawn・stty raw -echo） | Post Access Linux | `03_Post_Access_Linux/Shell_Stabilization.md` |
| /var/mail/[USERNAME] 確認（システムメール・脆弱性ヒント） | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| カーネルエクスプロイト（CVE探索・PoC転送・Cソースコンパイル・2プロセス並行実行） | Post Access Linux | `03_Post_Access_Linux/Kernel_Exploits.md` |
| CVE-2023-0386（OverlayFS + FUSE カーネル特権昇格） | Post Access Linux | `03_Post_Access_Linux/Kernel_Exploits.md` |
| python3 -m http.server によるファイル転送（攻撃側HTTP配信 + wget取得） | Post Access Linux | `03_Post_Access_Linux/Kernel_Exploits.md` |
| Docker コンテナからホストへのブレイクアウト（ブロックデバイスマウント） | Post Access Linux | `03_Post_Access_Linux/Sudo_Misconfig.md` |

---

## Windows AD 侵入後

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| AD 侵入後列挙チェックリスト | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| Windows ローカルサービス発見（netstat -ano + tasklist による内部ポート特定） | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| 既知 Buffer Overflow PoC 悪用（Exploit-DB PoC + msfvenom シェルコード差し替え） | Post Access AD/Win | `04_Post_Access_Windows_AD/Buffer_Overflow_LocalService.md` |
| 特権トークン（SeXxxPrivilege）の確認 | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| Get-ComputerInfo による OS バージョン・ビルド番号確認 | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| inetpub（IIS Webルート）のソースコード・設定ファイル確認 | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| Windows PoC 取得・転送・実行（evil-winrm upload / IWR / certutil） | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| netexec RID bruteforce によるドメインユーザー列挙 | Reconnaissance | `05_Tools_Reference/Netexec.md` |
| BloodHound による権限チェーン可視化（bloodhound-python / Linux側） | Post Access AD | `05_Tools_Reference/BloodHound.md` |
| SharpHound.exe による AD データ収集（Windowsシェル内） | Post Access AD | `05_Tools_Reference/BloodHound.md` |
| GenericAll によるパスワードリセット | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md` |
| GenericAll による Shadow Credentials | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md` |
| GenericAll によるグループメンバー追加 | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md` |
| GenericAll によるRBCD設定 | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericAll.md` |
| ForcePasswordChange（パスワードリセット専用ACE）| Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/ForcePasswordChange.md` |
| PSSession（New-PSSession / Enter-PSSession / Invoke-Command）による別ユーザーへの横断移動 | Post Access AD | `04_Post_Access_Windows_AD/Enumeration_Checklist.md` |
| LAPS 管理者パスワード取得（laps.py / nxc --laps / Get-ADComputer）| Post Access AD | `04_Post_Access_Windows_AD/LAPS_Dump.md` |
| GenericWrite による Targeted Kerberoasting（targetedKerberoast.py 自動方式） | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md` |
| GenericWrite による Targeted Kerberoasting（bloodyAD + GetUserSPNs 手動2ステップ方式） | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md` |
| GenericWrite による logon script 設定 | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/GenericWrite.md` |
| WriteDACL による GenericAll 付与 | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/WriteDACL.md` |
| WriteDACL による DCSync 権限付与 | Post Access AD | `04_Post_Access_Windows_AD/ACE_Abuse/WriteDACL.md` |
| RBCD（Impacketベース：Linux側から実行） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |
| RBCD（PowerMad + Rubeus S4U：Windowsシェル内から実行） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |
| Rubeus S4U → kirbi→ccache変換（impacket-ticketConverter）→ psexec | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/RBCD.md` |
| Unconstrained Delegation + Printer Bug（MS-RPRN coercion） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` |
| Unconstrained Delegation + PetitPotam（MS-EFSRPC coercion。Printer Bug の代替） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` |
| bloodyAD による UAC TRUSTED_FOR_DELEGATION 設定（Linux 側から Unconstrained Delegation 付与） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` |
| 平文パスワード → NT ハッシュ変換（python3 hashlib md4 / krbrelayx 事前準備） | Post Access AD | `04_Post_Access_Windows_AD/Delegation_Attacks/Unconstrained.md` |
| Kerberoasting | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md` |
| Targeted Kerberoasting（SPN付与→ハッシュ取得） | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/Kerberoasting.md` |
| ASREPRoasting（ユーザーリストなし・単一ユーザー名からの発火を含む） | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md` |
| Pass-The-Ticket（PTT） | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` |
| Golden Ticket | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` |
| Silver Ticket | Post Access AD | `04_Post_Access_Windows_AD/Kerberos_Attacks/Pass_The_Ticket.md` |
| LLMNR / NBT-NS / mDNS / WPAD ポイズニング（Responder）— ハッシュキャプチャ・SMB Signing 事前確認・Relay 専用モード | Post Access AD | `04_Post_Access_Windows_AD/NTLM_Relay/Responder.md` |
| NTLM リレー（ntlmrelayx）— SMB / LDAP / LDAPS / MSSQL / AD CS ESC8 リレー・Shadow Credentials・RBCD・socks モード・Drop the MIC | Post Access AD | `04_Post_Access_Windows_AD/NTLM_Relay/ntlmrelayx.md` |
| Coerce 系強制認証（PetitPotam / PrinterBug / DFSCoerce）— LLMNR 無効環境での代替 Relay 起点・ESC8 DC$ 認証強制 | Post Access AD | `04_Post_Access_Windows_AD/NTLM_Relay/Coerce.md` |
| mitm6（IPv6 DNS スプーフィング）— DHCPv6 / WPAD 悪用・LLMNR/NBT-NS 無効環境でも有効な Relay 起点 | Post Access AD | `04_Post_Access_Windows_AD/NTLM_Relay/mitm6.md` |
| SeImpersonate / SeAssignPrimaryToken — GodPotato / PrintSpoofer / RoguePotato による SYSTEM 昇格（環境判定フロー付き） | Post Access AD/Win | `04_Post_Access_Windows_AD/Privilege_Tokens.md` |
| SeBackup / SeRestore — `reg save` による SAM/SYSTEM/SECURITY ハイブ取得 → impacket-secretsdump でハッシュ解析 | Post Access AD/Win | `04_Post_Access_Windows_AD/Privilege_Tokens.md` |
| SeDebug — procdump / Mimikatz による LSASS ダンプ → pypykatz でハッシュ・DPAPI マスターキー取得 | Post Access AD/Win | `04_Post_Access_Windows_AD/Privilege_Tokens.md` |
| SeTakeOwnership — `takeown` + `icacls` による SAM/SYSTEM ハイブの強制取得 | Post Access AD/Win | `04_Post_Access_Windows_AD/Privilege_Tokens.md` |
| DPAPI マスターキー取得（オンライン：`sekurlsa::dpapi` / pypykatz / SharpDPAPI） | Post Access AD/Win | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| DPAPI マスターキー取得（オフライン：ドメインバックアップキー / NT ハッシュ → impacket-dpapi） | Post Access AD/Win | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| Chrome / Edge 保存パスワード取得（`Login Data` SQLite + DPAPI / AES-GCM 復号） | Post Access AD/Win | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| Firefox 保存パスワード取得（`logins.json` + `key4.db` → firepwd / firefox_decrypt） | Post Access AD/Win | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| Windows Credential Manager 取得（`cmdkey /list` + SharpDPAPI / Mimikatz `dpapi::cred`） | Post Access AD/Win | `04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md` |
| UAC レベル確認（ConsentPromptBehaviorAdmin / EnableLUA レジストリ値） | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.3） |
| UAC バイパス — fodhelper.exe / eventvwr.exe 自動昇格バイナリ悪用（HKCU レジストリ書き換え） | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.3） |
| UAC バイパス — UACME / Metasploit bypassuac モジュールの使い分けと検知性 | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 1.3） |
| AMSI 有効状態確認（AmsiUtils クラス検出）と PowerShell Downgrade Attack（v2 起動） | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 8: AMSI バイパス） |
| AMSI バイパス — AmsiScanBuffer メモリパッチ（amsiInitFailed 設定）と検知性 | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 8: AMSI バイパス） |
| AMSI バイパス — ETW 無効化との組み合わせ（本番では原則禁止） | Post Access AD/Win | `04_Post_Access_Windows_AD/Enumeration_Checklist.md`（Step 8: AMSI バイパス） |
| BYOVD（Bring Your Own Vulnerable Driver）— 脆弱ドライバーロードで EDR Kernel Callback を削除 | Post Access AD/Win | `04_Post_Access_Windows_AD/BYOVD.md` |
| BYOVD — LOLDrivers.io / Microsoft Vulnerable Driver Blocklist による脆弱ドライバー選定 | Post Access AD/Win | `04_Post_Access_Windows_AD/BYOVD.md` |
| BYOVD — sc.exe による脆弱カーネルドライバー登録・起動・原状回復（Sysmon Event ID 6 / 7045） | Post Access AD/Win | `04_Post_Access_Windows_AD/BYOVD.md` |
| DCSync（全NTLMハッシュ取得） | Post Access AD | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| Pass-The-Hash（PTH） | Post Access AD | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| SAM / SYSTEM ローカルダンプ | Post Access AD | `04_Post_Access_Windows_AD/Credential_Dumping.md` |
| AD CS 列挙（Certipy find・脆弱テンプレート特定・CA フラグ確認） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/Overview.md` |
| ESC1（ENROLLEE_SUPPLIES_SUBJECT + Client Auth → 任意ユーザー証明書取得 → PKINIT → DCSync） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC1.md` |
| ESC2（Any Purpose EKU / SubCA テンプレート → ESC1 相当または ESC3 チェーン起点） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC2.md` |
| ESC3（Enrollment Agent テンプレートチェーン → 代理申請で任意ユーザー証明書取得） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC3.md` |
| ESC4（テンプレートオブジェクト Write ACL → テンプレートを ESC1 化） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC4.md` |
| ESC5（PKI オブジェクト Write ACL → CA オブジェクト・NTAuthCertificates 改ざん） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC5.md` |
| ESC6（EDITF_ATTRIBUTESUBJECTALTNAME2 CA フラグ → 任意テンプレートで UPN 自由指定） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC6.md` |
| ESC7（ManageCA / ManageCertificates → CA フラグ変更・Pending 証明書強制発行） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC7.md` |
| ESC8（NTLM Relay to AD CS HTTP WebEnrollment → DC$ 証明書取得 → DCSync） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC8.md` |
| ESC9（No Security Extension：CT_FLAG_NO_SECURITY_EXTENSION + GenericWrite(UPN) → SAN 偽装・標的 UPN 証明書取得） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC9.md` |
| ESC10（Weak Certificate Mappings：StrongCertificateBindingEnforcement 0/1 → UPN ベースマッピング悪用） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC10.md` |
| ESC11（IF_ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME + PEND_ALL_REQUESTS → ManageCertificates で強制発行） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC11.md` |
| ESC12（CA シェルアクセス + EDITF_ATTRIBUTESUBJECTALTNAME2 設定 → ESC6 相当を手動有効化） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC12.md` |
| ESC13（DCOM / RPC / CES 経由の証明書発行：HTTP WebEnrollment が無効な環境での代替申請経路） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC13.md` |
| ESC14（Issuance Policies OID グループリンク：msDS-OIDToGroupLink で特権グループにリンクされた OID 悪用） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC14.md` |
| ESC15（Cross CA Enrollment：クロスフォレスト PKI 信頼 + 別 CA の脆弱テンプレートで別フォレストに認証） | Post Access AD | `04_Post_Access_Windows_AD/AD_CS/ESC15.md` |

---

## CVE・ペイロード詳細

汎用ファイルには書かない「特定ソフト × バージョン限定」のペイロード・バージョン対応表。

| CVE / 手法名 | ファイルパス |
|------------|------------|
| CVE メモ全般（PDFKit / Ruby YAML.load Gadget Chain 等） | `05_Tools_Reference/CVE_Notes.md` |

---

## ツールリファレンス

| ツール | ファイルパス |
|--------|------------|
| Chisel（リバーストンネル・ポートフォワーディング） | `05_Tools_Reference/Chisel.md` |
| nmap（-sC 出力の読み方・AD環境向け） | `05_Tools_Reference/Nmap.md` |
| BloodHound / bloodhound-python | `05_Tools_Reference/BloodHound.md` |
| Impacket スイート全般 | `05_Tools_Reference/Impacket_Suite.md` |
| hashcat | `05_Tools_Reference/Hashcat.md` |
| searchsploit（バージョン検索・ファイル操作・Nmap XML連携） | `05_Tools_Reference/Searchsploit.md` |
| 複数CVE候補からの絞り込み基準（バージョン一致・OS一致・パッチ前確認・前提条件） | `05_Tools_Reference/Searchsploit.md` |
| Exploit-DB Web・NVD・GitHub PoC の使い分け | `05_Tools_Reference/Searchsploit.md` |
| netexec（nxc）/ CrackMapExec — パスワードスプレー・SMB/WinRM認証確認 | `05_Tools_Reference/Netexec.md` |
| pspy（procfs ポーリング型プロセス観察ツール・短命 root プロセス検出） | `05_Tools_Reference/pspy.md` |
| Certipy（AD CS 列挙・証明書申請・PKINIT 認証・CA 管理の統合ツール。find / req / auth / ca / template / forge / relay） | `05_Tools_Reference/Certipy.md` |
| GOAD（AD攻撃練習ラボ）の構築（VMware Workstation + WSL / Vagrant + ansible。host-only vmnet 手動IP・WSL1・version選択等の注意点） | `05_Tools_Reference/GOAD_Lab_Setup.md` |

---

## プレイブック・攻撃フロー

個別技術の組み合わせ方と判断順序を示すフロー全体のガイド。技術の詳細ではなく「次に何を試すか」の迷いをなくすために開く。

| Playbookタイトル | 用途 | ファイルパス |
|---------------|------|------------|
| Linux 侵入・権限昇格フロー（OS判定 → ポートスキャン → シェル取得 → 権限昇格） | Linux全体フロー | `00_Playbook/Linux_Attack_Flow.md` |
| Windows AD 攻撃フロー（偵察 → 初期アクセス → AD列挙 → DCSync） | Windows AD全体フロー | `00_Playbook/Windows_AD_Attack_Flow.md` |
| Web脆弱性調査フロー（Webのみスコープ向け偵察 → 機能別脆弱性確認 → 認証・認可横断確認） | Webスコープ限定フロー | `00_Playbook/Web_Vuln_Flow.md` |
| 技術名が分からない状態からの調査フロー（機能観察 → 英語化 → 脆弱性クラス特定） | 未知技術マッピング | `00_Playbook/01_Unknown_Tech_Research.md` |
| 内部ネットワークペネトレテスト全体フロー（VLAN アクセス開始 → ホスト発見 → AD 列挙 → DC 陥落 → 横展開） | 内部ネットワーク全体フロー | `00_Playbook/Internal_LAN_Pentest_Flow.md` |

---

## 原理・背景（セキュリティ）

作業ファイル（01〜05）から参照される動作原理の解説ファイル群。作業中ではなく「なぜその手が効くのか」「環境が違うときどこを見るか」を確認したいときに開く。

| 原理 | 参照元の作業ファイル | ファイルパス |
|------|-----------------|------------|
| Windows AD 環境とスタンドアロンの違い（ポート・認証・攻撃軸・BloodHound 有効性・各 Step の適用可否） | `00_Playbook/Windows_AD_Attack_Flow.md` / `00_Playbook/00_OS_Identification.md` | `06_Concepts/Windows_Standalone_vs_AD.md` |
| AD 用語クイックリファレンス（TGT・SPN・ACE・DCSync 等の一言定義） | `00_Playbook/Windows_AD_Attack_Flow.md` / `04_Post_Access_Windows_AD/` 全般 | `06_Concepts/AD_Terminology.md` |
| OS フィンガープリンティング（TTL 初期値の由来・FS の大文字小文字区別の仕様差） | `00_Playbook/00_OS_Identification.md` | `06_Concepts/OS_Fingerprinting_Principles.md` |
| XSLT・XXEの動作原理（外部エンティティ解決の仕組み・libxslt の制限・パラメータエンティティ vs 一般エンティティ） | `02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md` / `02_Initial_Access/Web_Vulnerabilities/XXE.md` | `06_Concepts/XSLT_XML_Processing.md` |
| YAML.load 任意デシリアライゼーション（Psych の !ruby/object タグ・Gadget Chain 原理・Ruby バージョン差異） | `03_Post_Access_Linux/Sudo_Misconfig.md`（パターン5） | `06_Concepts/YAML_Deserialization.md` |
| GPP cpassword の暗号化・復号原理（固定鍵の公開・MS14-025後の挙動） | `01_Reconnaissance/SMB_Enumeration.md` / `02_Initial_Access/Credential_Discovery.md` | `06_Concepts/GPP_Credential.md` |
| PAM の動作原理（session スタック・pam_motd・PATH ハイジャックが成立する条件） | `03_Post_Access_Linux/PAM_Misconfig.md` / `03_Post_Access_Linux/Enumeration_Checklist.md` | `06_Concepts/PAM.md` |
| Docker の分離機構（namespace / cgroup / capability とブロックデバイス可視性） | `03_Post_Access_Linux/Sudo_Misconfig.md`（パターン4） | `06_Concepts/Docker_Isolation.md` |
| Java ObjectInputStream クラス解決の2経路（resolveClass / resolveProxyClass）と allowlist バイパス原理 | `02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md` | `06_Concepts/Java_Deserialization.md` |
| Electron の nodeIntegration / contextIsolation の仕組みと XSS → RCE エスカレーション原理 | `02_Initial_Access/Web_Vulnerabilities/Electron_XSS_RCE.md` | `06_Concepts/Electron_Security.md` |
| バリアントハンティング（既知 CVE のバグクラスから類似プロジェクトの変種を探す手法） | CVE 研究・脆弱性調査全般 | `06_Concepts/Variant_Hunting.md` |
| CVE 提出前の最終 verification ゲート（Docker で最新 base image にて PoC 再実行・前提崩壊検出） | CVE 研究 | `06_Concepts/Variant_Hunting.md` |
| Web 診断ツール使い分けの原理（スクリプト / Burp / DevTools の役割分担・Cookie Prefix 仕様） | Web 診断全般 | `06_Concepts/Web_Pentest_Tooling.md` |
| /etc/hosts へのドメイン名登録（AD 攻撃の前提・vhost 発見後の登録）| `00_Playbook/Windows_AD_Attack_Flow.md` / `01_Reconnaissance/Web_Enumeration.md` | `06_Concepts/Hosts_File_For_AD.md` |
| MITRE ATT&CK マッピング運用ガイド（ID 引きの考え方・本リポジトリでの使い方） | TECHNIQUES_INDEX_MITRE.md 全般 | `06_Concepts/MITRE_ATTCK_Guide.md` |
| OWASP WSTG マッピング運用ガイド（Web 系チェック項目の引き方） | TECHNIQUES_INDEX_WSTG.md 全般 | `06_Concepts/OWASP_WSTG_Guide.md` |
| ペネトレプロセス・ガイドライン運用ガイド（NIST SP 800-115 / PTES の章軸・使い分け） | TECHNIQUES_INDEX_GUIDELINES.md 全般 | `06_Concepts/Pentest_Guidelines_Guide.md` |
| 外部リファレンス集（HackTricks / OWASP / PortSwigger / NIST / ベンダーアドバイザリ / awesome 系 / SecLists 等の参照元目次） | 各サービス・各技術の参照元 | `06_Concepts/External_References.md` |
| メールプロトコル動作原理（SMTP 対話モデル / EHLO 拡張 / VRFY-EXPN の歴史 / STARTTLS と Implicit TLS / POP3 vs IMAP / SPF-DKIM-DMARC / メールヘッダ / MIME / SASL 認証メカニズム / Open Relay 史） | `02_Initial_Access/Mail_Services.md` | `06_Concepts/Mail_Protocols.md` |
| ペネトレ基礎（攻撃者視点の前提・思考の組み立て方） | 初学者導入 | `06_Concepts/Pentest_Fundamentals.md` |
| CVSS スコアリング（v3.1 / v4.0 構造差・Worst-case vs Likely-case・Environmental・報告書記載フォーマット） | 報告書作成・CVE 申請 | `06_Concepts/CVSS_Scoring.md` |
| CVE 研究スターター（起点 CVE 入手元・ライブラリ仕様調査・CWE 選定） | CVE 研究着手 | `06_Concepts/CVE_Research_Starter.md` |
| リバースシェルの原理（接続方向・インターフェース選択・bash/python/perl/nc のペイロード差） | `02_Initial_Access/Web_Vulnerabilities/Command_Injection.md` / `03_Post_Access_Linux/Shell_Stabilization.md` | `06_Concepts/Reverse_Shell.md` |
| Entra ID / ハイブリッド AD・クラウド ID 基盤（現スコープ外・将来拡張領域の見出し予約） | （未実装）| `08_Cloud_Identity/README.md` |

---

## AI / 機械学習

AI/ML・機械学習関連の技術インデックスは分離ファイルを参照：`TECHNIQUES_INDEX_AI_ML.md`

---

*新しい技術を追加した際は、このファイルにも1行追記してください。*
