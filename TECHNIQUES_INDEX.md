# 技術インデックス

全ての技術・手法の横断検索用インデックス。新しい技術を追加したらここにも1行追記する。

**フォーマット:** `技術名 | カテゴリ | ファイルパス`

**並び順:** 同一ファイル由来の複数行は、そのファイルが「Basic → 高難度」順で書かれている場合、その順序を本 INDEX 内でも保つ（例: `02_Initial_Access/SSH.md` の §1 バナー観察 〜 §11 Port Forwarding）。ファイル側で順序が定義されていない場合は追記順で構わない。

---

## 調査・列挙

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| ポートスキャン（nmap） | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| DNS 基本列挙（A / AAAA / MX / NS / TXT / CNAME / PTR / SRV / DNSKEY / CAA レコード解釈・内部 DNS 指定・/etc/hosts 登録）| Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ④ Zone Transfer (AXFR) 試行（dig axfr / fierce / dnsrecon / host -l / 全 NS 自動試行・partial AXFR・IXFR・成功時の悪用方向（内部 IP 抽出・RFC 1918 露出 finding））| Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑤ サブドメイン bruteforce（gobuster / ffuf / dnsenum / dnscan・SecLists subdomains-top1million・IPv6 用 dnsdict6） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑦ Banner Grabbing（version.bind CHAOS TXT / hostname.bind / authors.bind / fpdns で実装 fingerprint / nmap dns-nsid） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑧ AD SRV レコード列挙（外部から AD 推測：`_ldap._tcp` / `_kerberos._tcp` / `_kpasswd._tcp` / `_gc._tcp` / `_ldap._tcp.dc._msdcs`・nmap dns-srv-enum・外部公開自体が finding）| Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑨ 技術スタック特定（TXT / MX / 共通サブドメインから M365 / ProofPoint / Mimecast / Atlassian / DocuSign / Adobe IDP / ServiceNow / Webex / Jamf / Slack / GitHub 検出・dns-triage / DMARC `p=none` finding 化・社会工学への接続） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑩ Subdomain Takeover 検出（CNAME → GitHub Pages / Heroku / S3 / Azure / CloudFront / Bitbucket / GitBook の廃止リソース・subjack / subzy / 手動 curl 確認・PoC 取得は事前合意必須）| Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑪ DNSSEC NSEC walking（nmap dns-nsec-enum / dns-nsec3-enum・dnsrecon zonewalk・ldns-walk で signed zone 全レコード網羅・NSEC3 opt-out / ハッシュ辞書攻撃） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑫ Cache Snooping（`+norecurse` クエリで組織の解決履歴漏洩・応答時間判定・業務利用サービス推測） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑬ DDNS Update 書込攻撃（HIGH IMPACT・nsupdate / RFC 2136・TSIG・Windows AD SecureUpdate (Kerberos) / BIND `allow-update` ACL 不備・テスト識別子マーカー方式・原状回復必須） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑭ DNS Rebinding（TTL 1-3 秒の動的応答で SOP 迂回・rebinder.html / rbndr.us 利用・SSRF / クラウドメタデータ 169.254.169.254 経路・Private Network Access 緩和確認） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑮ Recursion 開放確認（`ra` flag・権威 vs 公開 resolver 区別・DDoS amplification 踏み台 finding 化のみ） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| DNS ⑯ Mail to nonexistent → NDN bounce 漏洩（Received: ヘッダー内の内部ホスト名・RFC 1918 IP・MTA バージョン情報抽出・swaks ツール） | Reconnaissance | `01_Reconnaissance/DNS_Enumeration.md` |
| OS判定（TTL・ポート構成・HTTPヘッダー・SMBバナー・SSH バナー） | Reconnaissance | `00_Playbook/00_OS_Identification.md` |
| robots.txt からの隠しパス発見 | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| サービスバージョン検出 | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| 高 latency での --min-rate 過大による取りこぼし（retransmission cap hit → サービス `?` / 誤 filtered）と再スキャン判断 | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| IPレンジからDockerコンテナを特定（172.17.0.x） | Reconnaissance | `01_Reconnaissance/Network_Scanning.md` |
| Webディレクトリファジング中のレート制限・WAF throttle 対処（gobuster -t / --delay 調整） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| コンテナ環境の確認（/.dockerenv / /etc/hosts / ip addr） | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| Webディレクトリ列挙（gobuster） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| vhostファジング | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| Webアプリバージョン特定（/api/health 等） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| アプリ名は出るがバージョンが取れないとき適用可否を直接判定（候補 PoC を `-x` で読む → 叩く endpoint の存在 200/404 ＋ 二次シグナル PHP バージョン→null byte 適用可否 で絞る）| Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| HTTP→HTTPS 全リダイレクト時の列挙 scheme 切替・`curl -s` 無出力をサービス無しと誤判断しない・拡張子を server 技術で選ぶ | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| searchsploit による CVE 検索 | Reconnaissance | `05_Tools_Reference/Searchsploit.md` |
| searchsploit --nmap の死角（http-title / ssl-cert のアプリ名は手動検索が必要）| Reconnaissance | `05_Tools_Reference/Searchsploit.md` |
| レガシー TLS（TLS1.0 / SSLv3 のみ）へツールが接続できないときの到達性確保（TLS スタックはツール毎に独立＝nikto/whatweb は通るのに curl だけ失敗・OpenSSL 側 openssl.cnf/`OPENSSL_CONF`・Firefox=NSS の `security.tls.version.min`・rustls 系の限界・socat ブリッジ）| Reconnaissance | `01_Reconnaissance/TLS_Audit.md` |
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
| CDN/WAF §1 配下判定（CNAME チェーン edgekey/edgesuite/akamaiedge・Server: AkamaiGHost・cf-ray・x-served-by・wafw00f・観測値はエッジでありオリジンでない切り分け） | Reconnaissance | `01_Reconnaissance/CDN_WAF_Edge_Recon.md` |
| CDN/WAF §2 製品の見分け（Bot 対策 Cookie `_abck`/`bm_sv`/`ak_bmsc`=Akamai・`cf_clearance`=Cloudflare・`incap_ses_*`=Imperva・whatweb 補完・ffuf/nuclei が急に 403/challenge になる原因切り分け） | Reconnaissance | `01_Reconnaissance/CDN_WAF_Edge_Recon.md` |
| CDN/WAF §3 Akamai デバッグヘッダ（`Pragma: akamai-x-get-cache-key` 等で X-Cache-Key/X-True-Cache-Key 露出・要実機検証/現代既定は無効化・キャッシュ汚染偵察に接続） | Reconnaissance | `01_Reconnaissance/CDN_WAF_Edge_Recon.md` |
| CDN/WAF §4 クライアント IP ヘッダ詐称によるアクセス制御バイパス（True-Client-IP=Akamai 既定・X-Forwarded-For/X-Real-IP・IP ベース ACL/地理制限/レート制限の回避） | Reconnaissance | `01_Reconnaissance/CDN_WAF_Edge_Recon.md` |
| CDN/WAF §5 オリジン IP 特定でエッジ迂回（apex A 直書き露出・CDN レンジ外サブドメイン・Host ヘッダ付き直叩き・証明書 SAN/履歴 DNS/SSRF 反射経路・オリジン側 エッジ IP ACL で不発判定） | Reconnaissance | `01_Reconnaissance/CDN_WAF_Edge_Recon.md` |
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
| 分散トレーシングヘッダの偵察（traceparent / tracestate / traceresponse / baggage の露出 → observability スタック特定・ベンダ判別・内部相関 ID 露出・tracestate/baggage の信頼境界違反・sampled flag DoS）（WSTG-INFO-05/08） | Reconnaissance | `01_Reconnaissance/Web_Response_Triage.md` |
| **Server ヘッダーからの Python WSGI 系識別（Werkzeug / gunicorn / uWSGI / Tornado / Django runserver）と非標準ポート観点** | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| HTML `<meta name="generator">` 著作権年範囲からのバージョン推定 | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| DoS 保護・自動 IP ブロック前提のディレクトリ列挙抑制（robots.txt・トップページの警告文を読む） | Reconnaissance | `01_Reconnaissance/Web_Enumeration.md` |
| 未認証ファイルアップロード RCE（二重拡張子・逆二重拡張子・大文字小文字・代替MIME/Content-Type重複・代替PHPタグ・マジックバイト・Content-Type 偽装） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| ファイルアップロードの型判定 3 箇所モデル（申告MIME/応答MIME/MIME sniffing・nosniff確認・検証方法別バイパス対応表・base64シグネチャ早見表） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| アップロード設定ファイル経由 RCE（.htaccess / .user.ini / web.config / uwsgi.ini @(exec) / Python .pth） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| 画像再エンコード生存 payload（EXIF コメント・PLTE/Global Color Table チャンク埋め込み） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| NTFS ADS によるアップロード拡張子バイパス（filename:stream / ::$DATA・IIS/Windows） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| 画像・動画変換ライブラリ経由 RCE/任意ファイル読取（ImageTragick CVE-2016-3714 / CVE-2022-44268 / FFmpeg HLS） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/File_Upload.md` |
| Web Shell §1 サーバ技術→言語選択（IIS=aspx / Apache+PHP=php / Tomcat=jsp/war・拡張子はランタイムが解釈できる言語に合わせる・言語不一致は平文表示/404） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Web_Shells.md` |
| Web Shell §2 入手元（ディストリ同梱 /usr/share/webshells・/usr/share/laudanum・SecLists Web-Shells・msfvenom 生成 -f aspx/php/war・LHOST/許可IP 編集・バックドア混入目視） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Web_Shells.md` |
| Web Shell §3 設置と実行確認（最小 cmd 実行 webshell で whoami 疎通 → リバース昇格・平文表示=言語不一致の切り分け） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Web_Shells.md` |
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
| **XSS §4 Cookie 以外の窃取（localStorage / sessionStorage トークン・キーロギング・保存パスワード autofill 窃取。HTTPOnly Cookie 保護外の窃取面）** | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSS.md` |
| CSRF §1 トークン検証不備の判定（欠落時不検証 / 値の非検証 / セッション非紐付けの3パターン・POST→GET 化バイパス・Cookie のみ認証かの切り分け） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CSRF.md` |
| CSRF §3 SameSite 別成立条件（None/Lax/Strict・Lax のトップレベル GET ナビゲーション貫通・GET 状態変更の設計ミス悪用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CSRF.md` |
| CSRF §4 Content-Type / JSON エンドポイント回避（enctype=text/plain で JSON 風ボディ送信・simple request 化・カスタムヘッダー必須なら不成立判定） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CSRF.md` |
| CORS §1 Origin 反射 + Allow-Credentials による認証済みレスポンス窃取（`*`+credentials はブラウザ拒否・curl 結果と実害の切り分け） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CORS.md` |
| CORS §2 null origin 許可の悪用（sandbox iframe で null origin 生成 → 認証済みレスポンス読み取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CORS.md` |
| CORS §3 部分一致 allowlist バイパス（startsWith / endsWith / contains・正規表現の未エスケープ `.`・サブドメイン無条件許可 × Takeover/XSS 連鎖） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/CORS.md` |
| ソーシャルエンジニアリング（フィッシング・スピアフィッシング・BEC） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| プリテキスティング（IT サポート・監査員・ベンダーを装った認証情報詐取） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| ベイティング（感染USB放置・偽ダウンロードリンク） | Initial Access | `02_Initial_Access/Social_Engineering.md` |
| パストラバーサル（ディレクトリトラバーサル） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| Grafana パストラバーサル CVE-2021-43798 | Initial Access | `02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md` |
| LFI §1-2 検出と read/include 切り分け（`php://filter/convert.base64-encode` でソース開示 → base64 が返れば include sink・生ソース表示なら traversal）・設定ファイル/DB 認証情報の開示（実行を伴わず痕跡なし）・LFI の射程＝Web プロセスユーザ権限まで（/root 0700 等は読めず空・root 専有ファイルは昇格/認証情報再利用後）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| LFI §3 PHP wrapper 直接 RCE（`data://` / `php://input` / `expect://`・`allow_url_include=On` 前提・現代既定 Off で不発が普通）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| LFI §4-5 log poisoning / session poisoning → RCE（access/auth/mail/proc ログへ UA・ユーザー名で PHP 注入後 include / `sess_[PHPSESSID]` へ制御値注入・痕跡残るため原状回復対象）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| LFI §6 php://filter chain → RCE（synacktiv generator・`allow_url_include`/書込権限 不要・LFI 単体から RCE 到達の現代主力・URL エンコード必須）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| LFI §7-8 RFI（外部 URL include・`allow_url_include=On`・SMB/ftp 経路・SSRF 表裏）・拡張子 append バイパス（null byte は PHP 5.3.4 未満のみ・現代は wrapper 優先）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| LFI 他言語での file inclusion（PHP=include 実行が特異／Perl require・2引数 open / Node 動的 require / JSP `c:import`=SSRF 寄り / .NET・Python=read 中心・読み取りは Path_Traversal・テンプレ実行は SSTI・アップロード設置は File_Upload/Web_Shells へ振り分け）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/LFI.md` |
| Shellshock §1-3 bash 環境変数インジェクション（CVE-2014-6271 系・CGI 経由 `() { :; };` をヘッダに注入・time-based `sleep` 検出 → 手動 RCE → MSF apache_mod_cgi_bash_env_exec・実行は Web プロセス権限止まり）| Initial Access | `02_Initial_Access/Shellshock.md` |
| IDOR（連番ID・オブジェクト直接参照） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/IDOR.md` |
| ビジネスロジック §1 データ検証不備（hidden field 価格改ざん・負数/極大数量・整数オーバーフロー・通貨混同・「応答 echo≠課金反映」の切り分け）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| ビジネスロジック §2-3 リクエスト偽造・Mass Assignment（UI 非表示の値/隠しパラメータ直送・保護属性 role/balance/email_verified 注入・確定後の status/total 書き換え・クーポン再適用）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| ビジネスロジック §4 レースコンディション/TOCTOU（並列多重送信で二重出金/在庫超過/上限突破・curl & wait vs Burp single-packet attack(HTTP/2)・一意制約/行ロックで不発）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| ビジネスロジック §5 回数制限不備（OTP/PIN 総当り・メール正規化漏れ +tag/ドットで特典無限化・クーポンの別アカウント再利用・リセットトークン無効化漏れ）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| ビジネスロジック §6 ワークフロー順序迂回（支払いステップ飛ばし・決済 callback 偽装 status=success・メール未確認で保護機能到達・forced browsing のロジック版）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| ビジネスロジック §7-8 不正利用防御欠如・前提の悪用（レート制限/在庫枯渇検知の有無・型崩し "1e3"/null/配列・末尾空白でユーザー一意衝突・暗黙仮定の崩し方一覧）| Initial Access | `02_Initial_Access/Web_Vulnerabilities/Business_Logic.md` |
| SQLi §1 検出（manual probing・single quote / numeric vs string context boolean / time-based confirm / comment-induced behavior change・URL `--+` `-- -` `--%20` 等の末尾コメントエスケープ・WAF で `'` 403 時の `%2527` 二重 URL encode / `0x27` / `CHAR(39)`） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §2 DB 横断 cheat sheet（comment 記号・文字列連結 (CONCAT / + / \|\|)・version 関数・current_user / current_database・information_schema vs sys.tables vs sqlite_master・SUBSTRING / SUBSTR 比較・ASCII / ORD / UNICODE・stacked queries 既定可否・OOB 経路（LOAD_FILE / xp_dirtree / dblink / UTL_HTTP）・error 誘発関数（EXTRACTVALUE / CONVERT / CAST / XMLType）の MySQL / MSSQL / PostgreSQL / Oracle / SQLite 比較） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §3 認証バイパス（WHERE 句注入・`admin' --` / `' OR '1'='1' --` / UNION で偽 cred 投影 / コメント記号変種でのWAF回避） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §4 コンテキスト別注入（ORDER BY 句注入で CASE WHEN blind / LIMIT 句注入 (PROCEDURE ANALYSE error-based) / INSERT VALUES 内 stacked queries / UPDATE SET で is_admin / password 上書き認可昇格 / JSON / XML body 経由の二重 escape 回避） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §5 UNION 攻撃（カラム数特定 (ORDER BY N / UNION SELECT NULL,NULL,...) → カラム型特定 → 抽出 → information_schema 列挙 (tables / columns) → GROUP_CONCAT / STRING_AGG で複数行集約） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §6 Error-based 抽出（MySQL EXTRACTVALUE / UPDATEXML で `~` 付き XPATH error / MSSQL CONVERT 型不一致 / PostgreSQL CAST as int / Oracle XMLType / EXTRACTVALUE の 32 文字制限と SUBSTRING 分割） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §7 Boolean blind 抽出（差分応答・AND 1=1 vs AND 1=2・SUBSTRING + ASCII 二分探索 1 文字 7 リクエスト・char encoding (utf8mb4 vs latin1) で ASCII 比較壊れ対策 HEX() 経由） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §8 Time-based blind 抽出（MySQL SLEEP / IF / BENCHMARK・MSSQL WAITFOR DELAY（stacked）・PostgreSQL CASE WHEN pg_sleep・抽出優先順位 (salt → username → email → password hash)・CMS Made Simple CVE-2019-9053 雛形・DoS 保護下での time.sleep(0.5) 挿入） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §9 Out-of-band (OAST) exfil（HIGH IMPACT・Burp Collaborator / interactsh-client・MySQL Windows UNC LOAD_FILE / MSSQL xp_dirtree (NTLMv2 hash steal 副作用) / PostgreSQL COPY TO PROGRAM curl + dblink / Oracle UTL_HTTP / DBMS_LDAP・DNS label 63 文字制限と SUBSTRING 分割・セルフホスト Interactsh 推奨） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §10 Second-order SQLi（保存時 escape あり / 後続クエリで unescaped 再使用で発火・パスワード変更 / プロフィール表示パターン・unique 制約 escape 差分シグナル・sqlmap --second-order 半自動化） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| SQLi §11 sqlmap 自動化（HIGH IMPACT・--technique=BEUSTQ / --dbms / --tamper / --level=5 --risk=3 / -r request.txt / --os-shell (stacked + SUPERUSER 必要)・--user-agent / --random-agent で WAF 偽装・--output-dir 保存） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SQLi.md` |
| MD5+Salt ハッシュのクラック（mode 20） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| ハッシュ形式の特定（hashid / 形式文字列の読み方 / --example-hashes） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| Flask / Werkzeug PBKDF2 ハッシュのクラック（mode 10000 変換） | Initial Access | `05_Tools_Reference/Hashcat.md` |
| SSRF（サーバーサイドリクエストフォージェリ） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| SSRF defense bypass：8進数・16進数・整数表記 IP リテラル（ipaddress 解析失敗パターン） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| SSRF defense bypass：IPv4-mapped IPv6 (`::ffff:127.0.0.1`)（Python 3.11.9 / 3.12.4 未満限定） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSRF.md` |
| XXE（XML外部エンティティインジェクション） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XXE.md` |
| XSLTインジェクション（プロセッサフィンガープリント・XXE-via-XSLT・PHP拡張・Java拡張） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md` |
| SSTI §1-2 検出・エンジン特定（数式ポリグロット `{{7*7}}` / `${7*7}` / `#{7*7}`・`{{7*'7'}}` の文字列演算差で Jinja2/Twig 判定・error polyglot で例外クラス名漏洩） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSTI.md` |
| SSTI §3-6 エンジン別 RCE（Jinja2 内省 `__class__`/`__mro__`/`cycler`/`lipsum` → os.popen / Twig `filter('system')`・`registerUndefinedFilterCallback` / Freemarker `Execute`?new() / Pug `global.process...child_process`） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSTI.md` |
| SSTI §7 ロジックレス系（Mustache は式評価不可で `{{{ }}}` 非エスケープ XSS 止まり / Handlebars の with+lookup constructor 連鎖 RCE） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSTI.md` |
| SSTI §8 サンドボックス脱出（Jinja2 SandboxedEnvironment を `\|attr` / `lipsum` / `get_flashed_messages` globals で迂回・16進エスケープ/文字列分割で `__class__` フィルタ回避・脱出不可でも変数漏洩 finding） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/SSTI.md` |
| JWT 未検証署名（Accepting Arbitrary Signatures：alg はそのまま署名部のみデタラメに書き換えても通る最 Basic な実装ミス） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT alg:none 攻撃（署名検証スキップ・大文字小文字バリエーション含む） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT 弱い秘密鍵ブルートフォース（hashcat mode 16500 / john HMAC-SHA256 / sample key リスト） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT jwk ヘッダーインジェクション（攻撃者公開鍵の埋め込み） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT jku / x5u 鍵 URL 差し替え（攻撃者 JWKS への誘導・URL parsing bug 経由の同一オリジン制約迂回） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT kid パラメータインジェクション（SQLi / パストラバーサルで `/dev/null` を秘密鍵化） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT RS256→HS256 アルゴリズム混乱攻撃（公開鍵を HMAC 秘密鍵として悪用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT RS256→HS256 公開鍵非公開時の n 導出（`portswigger/sig2n` Docker で既存トークン2つから RSA modulus を復元） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| JWT Claims 検証不備（exp / iss / aud / nbf 未検証 → トークン長期流用・別テナント token 流用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md` |
| OAuth redirect_uri 検証バイパス（サブストリングマッチ / Path Traversal / userinfo `@` / Open Redirect 連鎖 / HPP / IDN）→ 被害者 code 奪取 → アカウント乗っ取り | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth state 欠落・固定による CSRF → 既存アカウントに攻撃者 IdP 連携を強制（アカウント連携乗っ取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth Implicit Flow Token Leakage（URL fragment の access_token → Referer / 履歴 / JS / postMessage 経由漏洩） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth Scope 拡大（Scope Upgrade：token 交換時 / userinfo に追加 scope を通して user 未同意リソースに到達） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth PKCE 欠落・downgrade（`code_challenge_method=plain` 許容 → モバイル app / public client の code 横取り成立） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth email / sub 信頼性攻撃（federated identity confusion / `email_verified` 不検証 / nOAuth 型の email 改変 → 既存アカウント乗っ取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OpenID Connect id_token 検証バイパス（iss / aud / azp / nonce / exp 検証ミス・JWT 攻撃と併用） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OAuth client_secret 漏洩悪用（モバイル app バンドル / SPA / GitHub 由来 → confidential client なりすまし） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OIDC Dynamic Client Registration の悪用（`/connect/register` が認証なしで開いている → 攻撃者制御 redirect_uri を持つ client 登録 → code 横取り） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
| OIDC `request_uri` 経由の SSRF・認可リクエスト改ざん（外部 URL から request object JWT を fetch → 内部 URL で SSRF、認可パラメータ動的差し替えで scope/redirect 改変） | Initial Access | `02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md` |
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
| Samba §1 バージョン特定と CVE 照合（nmap smb-os-discovery / nxc / searchsploit samba）| Initial Access | `02_Initial_Access/Samba_Exploitation.md` |
| Samba §2 CVE-2007-2447 username map script コマンド注入（Samba 3.0.x・未認証 RCE・root 実行多）| Initial Access | `02_Initial_Access/Samba_Exploitation.md` |
| Samba §3 CVE-2017-7494 SambaCry (is_known_pipename・書込共有 + .so ロード・3.5.0〜4.6.4/4.5.10/4.4.14 未満)| Initial Access | `02_Initial_Access/Samba_Exploitation.md` |
| Samba §4 バージョン依存 CVE 探索パターン（searchsploit samba / OS・版数厳密一致）| Initial Access | `02_Initial_Access/Samba_Exploitation.md` |
| Windows SMB §1 バージョン特定と脆弱性スキャン（nmap smb-os-discovery / nxc SMBv1 判定 / nmap --script "smb-vuln-*" / searchsploit）| Initial Access | `02_Initial_Access/SMB_Windows_Exploitation.md` |
| Windows SMB §2 MS17-010 EternalBlue（CVE-2017-0143〜0148・SMBv1 前提・未認証 SYSTEM RCE・msf eternalblue/psexec・AutoBlue 手動・bitness 依存・失敗時 BSOD・**既定 eternalblue は x64 専用→x86 は `no-target: This module only supports x64...` で停止→psexec / MS08-067 へ**・成功確認は getuid / echo %USERNAME%（XP に whoami 不在））| Initial Access | `02_Initial_Access/SMB_Windows_Exploitation.md` |
| Windows SMB §3 MS08-067 NetAPI BoF（CVE-2008-4250・2000/XP/2003・未認証 SYSTEM RCE・msf ms08_067_netapi・TARGET 手動指定・OS 言語版/SP オフセット依存）| Initial Access | `02_Initial_Access/SMB_Windows_Exploitation.md` |
| Windows SMB §4 その他版数依存 CVE 探索（searchsploit OS ビルド一致・SMBGhost CVE-2020-0796 等）| Initial Access | `02_Initial_Access/SMB_Windows_Exploitation.md` |
| Windows SMB 刺さらなかったとき: smbclient -L の NT_STATUS_INVALID_PARAMETER ＝ 対象 SMBv1 のみ → --option='client min protocol=NT1' で再試行 | Initial Access | `02_Initial_Access/SMB_Windows_Exploitation.md` |
| distcc §1-2 CVE-2004-2687 distccd 未認証コマンド実行（3632/tcp・-p- で発見・非特権足場→要昇格）| Initial Access | `02_Initial_Access/distcc_Exploitation.md` |
| SSH §1 バナー観察と OS / ディストリ推定（nmap -sV / nc）| Initial Access | `02_Initial_Access/SSH.md` |
| SSH §1 CVE-2024-6387 (regreSSHion) バージョン判定と注意点（OpenSSH 8.5p1〜9.7p1 on glibc Linux・race condition pre-auth RCE） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §2 対応認証方式の列挙（`ssh -v -o PreferredAuthentications=none` で `publickey,password,keyboard-interactive,gssapi-with-mic` 判定） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §3 ホスト鍵 fingerprint 捕捉（ssh-keyscan / ssh-keygen -lf）と鍵使い回し横展開検出 | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §4 アルゴリズム・暗号スイート列挙（nmap --script ssh2-enum-algos / 弱い KEX・Cipher 検出 / CVE-2023-48795 Terrapin prefix truncation 判定） | Initial Access | `02_Initial_Access/SSH.md` |
| SSH §5 レガシー OpenSSH への接続（弱い KEX / ssh-rsa・ssh-dss 鍵 / CBC のみの相手に `-oKexAlgorithms=+...` / `-oHostKeyAlgorithms=+...` / `-c aes128-cbc` を明示・no matching key exchange method 対処）| Initial Access | `02_Initial_Access/SSH.md` |
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
| WinRM §1 バナー観察 / ポート判定（5985 HTTP / 5986 HTTPS・nmap -sV / nmap http-wsman-info / http-winrm-enum / curl /wsman 401 / Shodan dork） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §2 認証方式の確認（WWW-Authenticate: Negotiate / Kerberos / Basic / CredSSP・kinit + -k --spn Kerberos 経路） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §3 nxc / crackmapexec winrm 認証確認・(Pwn3d!) 判定（Remote Management Users / Administrators 権限差・-x / -X コマンド実行） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §4 evil-winrm 対話シェル取得（password / NTLM PTH / -S SSL 5986 / -k --spn Kerberos / 証明書 --cert-pem / -L セッションログ / -N path 補完無効 / IPv6 経由 / pypsrp / pywinrm / Docker クライアント代替） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §5 evil-winrm 接続後の制約とファイル転送（cwd Documents 罠 / upload / download / Invoke-Binary / menu / Bypass-4MSI / wsmprovhost.exe プロセス） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §6 Windows ネイティブ PSRemoting 経路（Test-WSMan / Invoke-Command / Enter-PSSession / New-PSSession 再利用 / Exit-PSSession バックグラウンド / winrs.exe / TrustedHosts エラー対処） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §7 Lateral Movement（Invoke-Command -ComputerName で AD 内他ホストへ連鎖侵入・二重ホップ問題と CredSSP / RBCD / PTT による回避） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §8 認証スプレー（nxc / crackmapexec winrm --continue-on-success・AD ロックアウト共通カウンタ前提・Event 4262 source IP 記録） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §9 WinRM 強制有効化 / Persistence（HIGH IMPACT・Enable-PSRemoting / wmic / PsExec 経由 / Remote Management Users へのユーザー追加バックドア・原状回復必須） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §10.1 CVE-2021-31166（HTTP Protocol Stack RCE）バージョン判定（Win10 / Server 2004 / 20H2 / 21H1・公開 PoC は BSOD のみ） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §10.2 CVE-2021-38647 OMIGOD（Azure OMI Unauth RCE as root・OMI < 1.6.8-1・5985 で Linux OS なら最優先確認） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §10.3 NTLM Relay to WinRM（Impacket 0.11+ ntlmrelayx wsman:// / HTTP 5985 listener 前提 / mitm6 / Responder 連携 / 緩和 EnableCompatibilityHttpListener=false + EPA） | Initial Access | `02_Initial_Access/WinRM.md` |
| WinRM §10.4 WSMan.Automation COM Abuse（PowerShell 経路回避・Constrained Language Mode 環境用・SharpWSManWinRM） | Initial Access | `02_Initial_Access/WinRM.md` |
| Impacket exec §1 SMB / DCERPC ポート判定と前提確認（nmap 135/139/445・nxc smb signing/SMBv1/Pwn3d 判定・rpcdump で DCERPC エンドポイント列挙・signing と Relay の関係） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §2 nxc smb 単一 cred 判定と (Pwn3d!)（パスワード / NTLM ハッシュ / --local-auth / Kerberos --use-kcache・LOCKED_OUT / EXPIRED の分岐） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §3 wmiexec — WMI/DCOM 経由（最初に試す・ファイルレス・wmiprvse.exe 子プロセス・DCOM 動的ポート 49152-65535・-no-output / -k -no-pass / 半対話シェル制約） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §4 psexec — SMB+SCM 経由 SYSTEM 取得（HIGH IMPACT・ADMIN$ への PE 書込・Event 7045 / 4697 確実検知・LocalAccountTokenFilterPolicy 罠・-service-name kedalab マーカー・-remote-binary-name で Defender 回避） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §5 smbexec — SMB+一時サービス代替（バイナリ書込なしだが Event 7045 がコマンドごとに大量発生・stdin 不可・cwd 引継ぎなし） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §6 atexec — タスクスケジューラ経由（135 のみで通る FW 抜け・非対話 1 コマンド・TaskScheduler Event 106/200/201/141・-task-name kedalab マーカー） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §7 dcomexec — DCOM オブジェクト経由（defense evasion・MMC20.Application / ShellWindows / ShellBrowserWindow で親プロセス mmc/explorer に偽装・wmiprvse 監視ルール回避・MMC20 は Win10 1803+ で既定無効） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §8 認証スプレー連携（HIGH IMPACT・nxc smb --continue-on-success で Pwn3d ホスト抽出 → wmiexec 連続実行・ローカル管理者 hash 使い回し検出（--local-auth）は LAPS 未導入の重大 finding・Event 4625 / 4262 source IP 記録） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| Impacket exec §9 Kerberos 経路（NTLM 無効化環境・kinit + KRB5CCNAME + -k -no-pass・SPN プレフィックス cifs/host のツール別差・Pass-The-Ticket / Pass-The-Key (AES) / Overpass-The-Hash・時刻同期必須） | Initial Access | `02_Initial_Access/Impacket_Exec.md` |
| RPC §1 エンドポイントマッピング（impacket-rpcdump で 135 / 593 経由の DCERPC インターフェース列挙・主要 RPC IFs 早見表（lsarpc / samr / atsvc / winreg / svcctl / srvsvc / epmapper の IFID と用途）・MS-SAMR は account lockout policy 無関係に列挙可能・Metasploit auxiliary/scanner/dcerpc/* 代替・IOXIDResolver ServerAlive2 で IPv6 / 内部 IP 取得） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §2 rpcclient 匿名バインド試行（null session / `-U ""` vs `-U "%"` 挙動差 / guest 認証 / 139 vs 445 強制） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §3 ドメイン情報・パスワードポリシー（querydominfo / getdompwinfo / srvinfo PDC フラグ / lsaquery でドメイン SID 取得） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §4 ユーザー・グループ列挙（rpcclient enumdomusers / enumdomgroups / enumalsgroups builtin・nxc --users --groups・enum4linux-ng -A・krbtgt 出現で DC 確定・svc_* で Kerberoast 候補抽出） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §5 詳細属性取得（queryuser RID で description 平文パスワード grep・lookupnames / lookupsids / queryusergroups / querygroupmem 0x200 で Domain Admins メンバ・Account Flags UD/NRP/DNE/TS/O 解釈） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §6 impacket-lookupsid による RID bruteforce（SAMR 拒否環境で LSAT 経由・SidTypeUser/Group/Computer 解釈・nxc --rid-brute 10000・コンピューターアカウント `$` 抽出） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §7 impacket-samrdump 包括列挙（SAMR 経由で getdompwinfo + enumdomusers + queryuser 一括・パスワード履歴長 / 最大年数 / Pwd Last Set でサービスアカウント抽出・139/SMB 経由フォールバック） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| RPC §8 認証情報取得後の再列挙（匿名→guest→認証ユーザー→管理者の権限段階で diff・rpcclient --pw-nt-hash PTH・Kerberos kinit + -k・nxc --loggedon-users / --shares / --pass-pol） | Reconnaissance | `01_Reconnaissance/RPC_Enumeration.md` |
| MSSQL 列挙・悪用（impacket-mssqlclient / DB列挙・ハッシュ取得） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL ユーザーなりすまし（enum_impersonate / EXECUTE AS LOGIN） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL xp_cmdshell による OS コマンド実行 | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL Linked Server 列挙・悪用（enum_links / EXECUTE AT / openquery による権限昇格） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL Linked Server 経由の xp_cmdshell 遠隔有効化（多段チェーン・impacket-mssqlclient / PowerUpSQL 使い分け） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MSSQL xp_dirtree による NTLM 強制認証（Linked Server 経由 → Responder / ntlmrelayx への誘導） | Initial Access | `02_Initial_Access/MSSQL_Exploitation.md` |
| MySQL §1 バナー観察 / バージョン判定（nmap mysql-info・MySQL / MariaDB / Percona 区別・version_comment 偽装注意・Auth Plugin Name 取得） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §2 匿名・空パスワードログイン試行（root / mysql / 匿名ユーザー・nmap mysql-empty-password・nxc mysql） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §3 認証情報での直接接続 + 権限確認（USER() / CURRENT_USER() / SHOW GRANTS / @@secure_file_priv / @@plugin_dir 確認・GRANT FILE 有無で攻撃面分岐） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §4 データベース・テーブル列挙とデータ抽出（SHOW DATABASES / TABLES / information_schema.columns 横断検索 / mysqldump --all-databases） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §5 認証スプレー / 辞書攻撃（HIGH IMPACT・nxc mysql / hydra / medusa / ncrack / nmap mysql-brute・max_connect_errors per-host throttle 注意） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §6 mysql.user ハッシュ取得 + クラック（mysql_native_password mode 300 / caching_sha2_password mode 7401 / sha256_password mode 7400 / mysql_old_password mode 200・auth_socket / unix_socket 判別） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §7 FILE 権限経由のファイル読み書き（LOAD_FILE / SELECT ... INTO OUTFILE / INTO DUMPFILE・secure_file_priv 制限・既存ファイル上書き不可制約・Windows MySQL 限定 OOB DNS exfil（UNC パス + CHAR(92)・53/UDP 経由でデータ流出）） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §8 UDF (User Defined Function) RCE（HIGH IMPACT・sqlmap lib_mysqludf_sys.so XOR デコード / plugin_dir 書込 / CREATE FUNCTION sys_exec・sys_eval・super 権限必須・mysql.func 永続化・原状回復必須） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §9 authorized_keys 書込（HIGH IMPACT・INTO OUTFILE 経由・mysql ユーザー所有による StrictModes 拒否罠・SSH §11 と連動・原状回復必須） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §10 CVE-2012-2122 認証バイパス（古典・MariaDB 5.1-5.5 / MySQL 5.1-5.5 限定・memcmp int 戻り値問題で約 1/256 確率認証成立・Metasploit mysql_authbypass_hashdump） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| MySQL §11 Rogue MySQL Server による LOAD DATA LOCAL INFILE クライアント側ファイル吸い出し（HIGH IMPACT・MySQL プロトコル仕様・クライアント LOCAL_INFILE 有効環境・MySQL 8.0+ クライアント default OFF・監視ツール / 接続テストツール経由誘導・攻撃方向はサーバ→クライアント） | Initial Access | `02_Initial_Access/MySQL_Exploitation.md` |
| PostgreSQL §1 バナー観察 / バージョン判定（nmap pgsql-brute・psql エラーメッセージから pg_hba.conf entry 有無 / ユーザー存在判別・SCRAM-SHA-256 デフォルト判定） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §2 trust 認証 / 空パスワード / デフォルトログイン試行（postgres/postgres・nmap pgsql-brute・プロンプト末尾 # / > で SUPERUSER 判定の小ワザ） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §3 認証情報での直接接続 + 権限確認（PGPASSWORD / .pgpass mode 600 / 接続文字列・rolsuper / rolreplication / predefined role (pg_read_server_files / pg_write_server_files / pg_execute_server_program) 確認・pg_basebackup 経路で SUPERUSER 不要の全 hash 取得） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §4 データベース・テーブル列挙とデータ抽出（\l / \dt / information_schema.columns 横断検索 / pg_dump / pg_dumpall --globals-only で pg_authid 取得・pg_stat_activity でリアルタイムクエリ漏洩確認） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §5 認証スプレー / 辞書攻撃（HIGH IMPACT・hydra postgres / medusa / nmap pgsql-brute・ユーザー存在有無でエラーメッセージ分岐するためユーザー列挙容易・auth_delay 拡張による遅延注意） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §6 pg_shadow ハッシュ取得 + クラック（md5 mode 12 / SCRAM-SHA-256 mode 28600・pg_authid 直接・rolreplication = t なら pg_basebackup 経路で SUPERUSER 不要・md5 は md5(password \|\| username) hex 化でユーザー名がソルト相当） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §7 サーバ側ファイル読み書き（pg_read_file / pg_read_binary_file / lo_import / lo_export / adminpack pg_file_write・PostgreSQL 11 で SUPERUSER 必須から pg_read_server_files / pg_write_server_files 付与可能に変更・adminpack は PostgreSQL 13 で関数削除） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §8 COPY FROM/TO PROGRAM 経由 RCE (CVE-2019-9193) （HIGH IMPACT・PostgreSQL 9.3+ で SUPERUSER または pg_execute_server_program role 必須・MITRE DISPUTED 状態・PostgreSQL 公式は意図された機能と表明・CREATE TABLE cmd_exec; COPY ... FROM PROGRAM 'id'; パターン） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §9 PL/PerlU / PL/PythonU 経由 UDF RCE（HIGH IMPACT・SUPERUSER + postgresql-plperl / postgresql-plpython3 パッケージ必須・「U」suffix が untrusted variant で sandbox 無し・CREATE FUNCTION 永続化 pg_proc・LOAD 経由 .so 読込も古典・原状回復必須） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §10 authorized_keys 書込（HIGH IMPACT・lo_export / COPY TO / COPY ... FROM PROGRAM chown 経由・postgres ユーザー所有による StrictModes 拒否罠・SSH §11 と連動・原状回復必須） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
| PostgreSQL §11 search_path schema poisoning (CVE-2018-1058) （HIGH IMPACT・PostgreSQL の設定パターン問題として公式整理・public スキーマの CREATE 権限デフォルト・組込関数同名上書きで SUPERUSER 操作時に攻撃者関数が SUPERUSER 権限で実行・PostgreSQL 14 / 15 で緩和強化） | Initial Access | `02_Initial_Access/PostgreSQL_Exploitation.md` |
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
| RDP §1 バナー観察 / バージョン判定 / 暗号化レベル（nmap rdp-enum-encryption・Native RDP / CredSSP / SSL 層判定・Native RDP 単独許容はハードニング不足 finding） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §2 NLA 有無判定 / Pre-Auth 情報漏洩（nmap rdp-ntlm-info で NetBIOS / DNS / Product_Version 取得・xfreerdp の挙動で代替判定・ロックアウトカウンタを進めない pre-auth 列挙） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §3 RDP 証明書からの組織・ホスト名取得（openssl s_client / nmap ssl-cert・AD CS Issuer 判定で ESC 候補連携） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §4 認証情報での直接接続（xfreerdp / rdesktop / remmina / mstsc・/cert:ignore のリスク・LOGON_TYPE_NOT_GRANTED / ACCOUNT_RESTRICTION 分岐） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §5 リダイレクト悪用 / クリップボード hijack（xfreerdp /drive / +clipboard / /printer / /usb 経由のファイル exfil・tsclient シグネチャ DLP 監視前提） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §6 認証スプレー / 辞書攻撃 / cred reuse 検出（nxc rdp / crowbar / hydra rdp / ncrack・AD ロックアウト共通カウンタ前提・Event 4625 Type 10 / 4771 / 4776 検知・LAPS 未導入の cred 使い回し finding） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §7 Pass-the-Hash for RDP（Restricted Admin Mode・xfreerdp /pth / mstsc /restrictedadmin・DisableRestrictedAdmin レジストリ前提・NETWORK logon session の制約） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §8 セッションハイジャック（tscon /dest:rdp-tcp#N・SYSTEM 経由無認証ハイジャック・PsExec -s / sc.exe create 経路・Event 4778 / 4779 / 7045・原状回復不可） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §9 BlueKeep バージョン判定（CVE-2019-0708・XP / 2003 / Vista / 2008 / Win7 / 2008R2・nmap rdp-vuln / Metasploit cve_2019_0708 scanner・NLA で緩和・target mismatch で BSOD 高確率） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §10 DejaBlue バージョン判定（CVE-2019-1181 / 1182 / 1222 / 1226・Win7 SP1〜Win10 1903・公開安定 PoC 限定・個人 GitHub PoC のバックドア混入リスク） | Initial Access | `02_Initial_Access/RDP.md` |
| RDP §11 RDP MitM（PyRDP・ARP / DNS poisoning 経路・NLA 強制で阻止・録画と GDPR / プライバシー法配慮） | Initial Access | `02_Initial_Access/RDP.md` |

---

## Linux 侵入後

| 技術名 | カテゴリ | ファイルパス |
|--------|---------|------------|
| 侵入後列挙チェックリスト | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
| ホスト FW の事後解明（netstat の 0.0.0.0 listen と外部 nmap filtered の突合 → iptables/nft でルール確認・刺さらなかった bind 型 exploit の原因特定） | Post Access Linux | `03_Post_Access_Linux/Enumeration_Checklist.md` |
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
| Metasploit Framework（モジュール探索 search → use → info → show options → set → run・LHOST 明示・handler vs nc・エラー読み分け） | `05_Tools_Reference/Metasploit.md` |
| Metasploit §3.1-3.2 multi/handler で自前ペイロード受信 + staged/stageless（payload 区切り `/` vs `_`・nc で staged meterpreter を受けられない理由・shell_reverse_tcp なら nc 可・`Sending stage` が受信成功の目印・handler は msfvenom と payload/LHOST/LPORT 完全一致） | `05_Tools_Reference/Metasploit.md` |
| Metasploit §5 3 プロンプトの取り違え（msfconsole プロンプトで打つ未知コマンドは手元のローカルシェルで実行＝`whoami` が自分のユーザー名・`dir` が手元ディレクトリ・`getuid` は Unknown command・ターゲットは `sessions -i` 後の meterpreter で触る） | `05_Tools_Reference/Metasploit.md` |
| Meterpreter セッション基礎（getuid / sysinfo / getsystem / hashdump / shell / background / sessions -i・`id`/`whoami` は meterpreter コマンドではない罠・古い Windows の `whoami` 不在と echo %USERNAME% 代替） | `05_Tools_Reference/Metasploit.md` |
| Metasploit §6 Meterpreter のパス指定 `\\` エスケープ（`\` はエスケープ文字で `c:\\..\\` 二重 or `c:/../` スラッシュ・`ls` で実名確認してから `cat`・手順書のパス盲信回避） | `05_Tools_Reference/Metasploit.md` |
| Metasploit §7 セッションからの権限昇格探索（post/multi/recon/local_exploit_suggester・sysinfo arch は x86 信頼/x64 低・`appears vulnerable` は候補で要総当り・exploit/windows/local は SESSION 指定・bypassuac は管理者前提・書込不可 cwd は %TEMP% へ cd） | `05_Tools_Reference/Metasploit.md` |
| searchsploit（バージョン検索・ファイル操作・Nmap XML連携） | `05_Tools_Reference/Searchsploit.md` |
| 複数CVE候補からの絞り込み基準（バージョン一致・OS一致・パッチ前確認・前提条件） | `05_Tools_Reference/Searchsploit.md` |
| Exploit-DB Web・NVD・GitHub PoC の使い分け | `05_Tools_Reference/Searchsploit.md` |
| netexec（nxc）/ CrackMapExec — パスワードスプレー・SMB/WinRM認証確認 | `05_Tools_Reference/Netexec.md` |
| pspy（procfs ポーリング型プロセス観察ツール・短命 root プロセス検出） | `05_Tools_Reference/pspy.md` |
| Certipy（AD CS 列挙・証明書申請・PKINIT 認証・CA 管理の統合ツール。find / req / auth / ca / template / forge / relay） | `05_Tools_Reference/Certipy.md` |
| GOAD（AD攻撃練習ラボ）の構築（VMware Workstation + WSL / Vagrant + ansible。host-only vmnet 手動IP・WSL1・version選択等の注意点） | `05_Tools_Reference/GOAD_Lab_Setup.md` |
| Linux ペネトレ用ワンライナー集（テキスト処理 grep/awk/sed・ファイル検索 find -perm・プロセス/ネット観察 ss/ps・文字列/バイナリ調査 strings/xxd・エンコード base64/openssl・ファイル転送 HTTP/nc//dev/tcp/base64・リスナー受信 python3/nc/socat） | `05_Tools_Reference/Linux_Pentest_OneLiners.md` |
| Windows ペネトレ用ワンライナー集（§0 基礎コマンド whoami/dir/cd/type と Linux→cmd→PowerShell 対応表・net user/localgroup・テキスト処理 Select-String/findstr・ファイル検索 Get-ChildItem/icacls/Unquoted Service Path・プロセス/ネット観察 Get-CimInstance/netstat -ano・バイナリ調査 Format-Hex/Get-AuthenticodeSignature・エンコード Base64/certutil・ファイル転送 iwr/certutil -urlcache/SMB/base64 コピペ・LOLBAS/CLM 代替） | `05_Tools_Reference/Windows_Pentest_OneLiners.md` |

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
| WinRM / WS-Management プロトコル動作原理（SOAP over HTTP / http.sys カーネル共有と CVE 波及 / wsmprovhost.exe プロセスモデル・検知シグネチャ / SPNEGO 認証 negotiation / Kerberos SPN HTTP/ プレフィックス / TrustedHosts と NTLM Mutual Auth / 二重ホップ問題と CredSSP/RBCD/PTT / SSH との対比） | `02_Initial_Access/WinRM.md` | `06_Concepts/WinRM_Protocol.md` |
| Impacket exec ツール群の動作原理（DCERPC 二段接続 135 → 動的ポート / SMB パイプ経由の DCERPC / 5 ツール × DCERPC インターフェース対応 / DCOM Activation と WMI = IWbemServices / SCM svcctl で psexec vs smbexec / atsvc が 445 のみで通る根拠 / プロセスツリー差と検知シグネチャ / Kerberos SPN cifs/ vs host/ のツール別差 / WinRM との対比） | `02_Initial_Access/Impacket_Exec.md` | `06_Concepts/Impacket_Exec_Internals.md` |
| MSRPC 列挙の動作原理（ncacn_ip_tcp/np/http バインディング / SAMR vs LSAT の役割と権限要件差 / 列挙が AD アカウントロックアウト badPwdCount をバイパスする境界 / RestrictAnonymous / RestrictAnonymousSAM の OS バージョン依存史 / RID 固定値 500/501/502 とドメイン SID 構造 / RID bruteforce が LSAT 単独で成立する根拠 / IOXIDResolver による内部 IP / IPv6 漏洩） | `01_Reconnaissance/RPC_Enumeration.md` / `01_Reconnaissance/LDAP_Enumeration.md` / `02_Initial_Access/Account_Lockout_Recon.md` | `06_Concepts/RPC_Enumeration_Internals.md` |
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
