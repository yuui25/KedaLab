## ガイドライン対応（冒頭サマリ）
- ASVS：V9（通信の保護/TLS）を「実装側が満たしている状態か」を外形から確認する前提情報として使う（Web診断に入る前の“通信境界の確定”）。
- WSTG：暗号/設定（TLS/HTTPヘッダ/プロトコル選択）観点の“前提となる観測”として使う（どのテストをどこに当てるかを確定する）。
- PTES：Intelligence Gathering → Vulnerability Analysis の橋渡し（到達性の次に“何が動いているか”を確定し、脆弱性仮説の母集団を絞る）。
- MITRE ATT&CK：Discovery（Network Service Discovery 等）の中核。到達できるサービスの種類/実装/終端点を把握し、次の横展開・認証攻撃の分岐に繋げる。

# 06_service_fingerprint（banner_tls_alpn）

## 目的（この技術で到達する状態）
- 「IP:port が開いている」から一段進めて、**そのポートの“実体”**を確定する。
  - 例：443/tcp が「Web」なのか「リバースプロキシ終端」なのか「管理API」なのか「別プロトコル（gRPC等）」なのかを、**観測で言い切れる**。
- 暗号化が絡む場合、**TLS終端の位置（どこまでがTLSで守られているか）**と、**プロトコル選択（ALPN/HTTP2/HTTP1.1/他）**を確定する。
- 結果として、次フェーズ（脆弱性分析・認証列挙・横展開）で「何を優先して、どの手で行くか」を迷わず決められる状態にする。

## 前提（対象・範囲・想定）
- 前工程（05_scanning_到達性把握）で、対象ネットワーク内の **到達可能なIPとopen port** が粗く取れている前提。
- 対象は「ネットワーク診断/内部ペンテスト」の典型構成を想定：
  - サーバ（Linux/Windows）、NW機器、LB/Proxy、VDI/RDP、AD周辺（LDAP/Kerberos/SMB）などが混在。
- ここで扱うのは **“脆弱性を突く”前の確定作業**：
  - 目的は「ソフト/プロトコル/終端点/バージョン/構成の推定精度を上げる」こと。
  - 侵襲が増える手（大量の試行が必要なTLS列挙や強いスクリプト）は、**必要になった対象にだけ**段階的に適用する。

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
観測は、常に「どの境界を確定しているか」で整理する。

### 1) 到達性境界：L4で“会話が成立する”か
- 見るもの
  - TCP：SYN→SYN/ACK（open）、RST（closed）、無応答（filtered/経路不達/ACL）
  - UDP：応答の有無・見えているICMP（ただし不確実）
- 意味
  - **open ≠ サービス確定**。ここは「会話の入口がある」だけ。
  - ただし、open/filtered の違いは「次の観測手段（NSE/手動/迂回）」に直結する。

### 2) プロトコル境界：最初の数往復で“何語を話すか”を確定する
- バナー（banner）とは「接続直後に返る文字列」だけを指さない。
  - “バナー相当”には以下が含まれる：
    - サーバ側のグリーティング（FTP/SMTP/SSH等）
    - こちらが最小コマンドを投げた際のエラー文・応答コード（HTTP/RTSP/Redis等）
    - バイナリプロトコルの初期ネゴ（SMB/LDAP/Kerberos等）
- 観測のコツ
  - **「何も返らない」場合でも、こちらの“1手”で判定できる**ことが多い。
  - 例：HTTPっぽいかを見たいなら、`HEAD / HTTP/1.0` を送ってステータス行の有無を見る。

### 3) TLS境界：暗号化の“外側から見える情報”で終端点を推定する
TLSは「中身が見えない」代わりに、ハンドシェイクに観測点が密集する。

- 見るもの（TLSハンドシェイクで外形的に取れる）
  - サーバ証明書（Subject/SAN/Issuer/有効期限/チェーン）
  - サポートプロトコル（TLS1.0〜1.3、場合によりDTLS）
  - ALPN（アプリ層プロトコル合意：h2/http1.1/他）
  - SNI（名前ベース終端：どのservernameで何が返るか）
- 境界としての意味
  - 「このIP:portの正体」が **“TLS終端（LB/Proxy）”** なのか、**“アプリ直結”** なのかを推定できる。
  - 証明書のSANから **内部FQDN/別名/クラスタ名** が漏れていることがある（次の探索に直結）。

### 4) 証跡境界：後工程で再現できる形に落とす
- “分かったつもり”を防ぐため、最低限これを残す：
  - 対象：ip, port, proto(tcp/udp), 観測日時
  - 結果：service推定、version推定、根拠（出力断片 or コマンドログ）
  - TLS：SNI、証明書サマリ、ALPN結果
- これがないと、次工程（脆弱性分析、報告、再検証）で判断が揺れる。

## 結果の意味（その出力が示す状態：何が言える/言えない）
### A) 「サービス名が出た」＝確定ではなく“仮説の強度が上がった”状態
- Nmap等のservice判定は、基本的に **プローブ→応答パターン照合**。
- 意味としては：
  - “この応答は○○っぽい” → **次の列挙/検証を当てる優先度**が上がる。
- 言えないこと（この段階で断言しない）
  - バージョンが出ても、**代理応答（LB/Proxy）**や**偽装**の可能性は残る。
  - 特にHTTPは、フロントが同じでもバックエンドが複数混在する。

### B) 「TLSハンドシェイクが通る」＝“暗号化サービス終端が存在する”状態
- 言えること
  - TLS終端がある（少なくともそのポートでTLSが喋れる）
  - 証明書・ALPN・SNIという外形情報が取れる
- 言えないこと
  - アプリの実体（HTTPか、別プロトコルか）は、ALPNや追加観測が要る
  - 同一IPでも、SNIを変えると別サービスに繋がる（名前ベース終端）

### C) ALPNが示す状態：同じ443でも“攻める対象”が変わる
- 例（意味）
  - ALPNが `h2`：HTTP/2で喋れる（Web/ API/ gRPC の可能性が上がる）
  - ALPNが `http/1.1`：典型的Web、あるいは古い/制限された終端
  - ALPNが空/失敗：TLSはあるがALPN未対応、または非HTTP用途（LDAPS等）
- ここで確定できる境界
  - 「HTTP前提のテストを当てて良いか」
  - 「h2専用の挙動（ヘッダ圧縮、ストリーム、多重化）を考慮すべきか」

### D) StartTLSが示す状態：平文→TLSへの“切替点”が存在する
- SMTP/IMAP/POP3/LDAPなどで **`STARTTLS`** が通る場合：
  - “平文で喋れる区間”と“TLS区間”が分かれる
  - その境界が、誤設定（強制されていない、弱いプロトコル、証明書検証無視運用）を生むことがある
- ただしこのファイルでは「誤設定の断定」ではなく、**切替点がどこか**を確定するのが目的。

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
サービスフィンガープリントは、攻撃者にとって「探索コストを下げる装置」。

### 1) “脆弱性母集団”を現実的なサイズに落とす
- 例：`OpenSSH` が見えた
  - 攻め筋：既知CVE探索、認証方式（鍵/パスワード）、踏み台化（後段pivot）へ
- 例：`Microsoft IIS` / `ASP.NET` が見えた
  - 攻め筋：Windows系の認証連携（NTLM/Kerberos）、IIS特有の管理面露出、アプリ層の認証/認可へ
- 例：`nginx` だが証明書SANが “internal-admin” を含む
  - 攻め筋：名前ベースで別vhostが存在→SNI/Hostを変えて探索

### 2) “終端点”を当てる（LB/Proxy/直結）＝次の観測点が変わる
- TLS証明書が企業内CA発行、SANに複数ホスト、Issuerが共通
  - 意思決定：フロントは共通終端の可能性が高い→**SNI/Host切替で面が増える**仮説
- 証明書が機器ベンダ名、管理用っぽいCN
  - 意思決定：アプライアンス管理画面の可能性→既知脆弱性/初期設定/認証強度へ

### 3) ALPNで“道具立て”が決まる（HTTP/2 vs HTTP/1.1）
- h2が有効
  - 意思決定：`curl --http2` / `nghttp` / h2前提の観測に寄せる（挙動差を利用した検証が可能）
- h2が無効
  - 意思決定：HTTP/1.1の前提で、ヘッダ・キャッシュ・プロキシ境界を観測する

## 次に試すこと（仮説A/Bの分岐と検証）
ここは「最小の試行で最大の確度」を狙い、段階を踏む。

### フロー0：入力を整える（05_scanningから受け取る）
- 入力（最低限）
  - `targets.txt`：IP一覧
  - `open_ports`：IPごとのopen port（tcp/udp）
  - （あれば）内部DNS/AD由来のホスト名候補（SNI/Hostで使う）
- 出力（このファイルで作る）
  - `fingerprint_table`：`ip:port -> service/version/tls/alpn/sni/根拠`

### フロー1：まずは低侵襲の“自動識別”で当てに行く（nmap -sV）
目的：人力を使う対象を絞る。

~~~~
# 代表例：既にopenが分かっている前提で、対象ポートに絞って -sV
nmap -sV -p <portlist> -iL targets.txt -oN 06_svc_nmap_sV.txt

# 精度を上げたい（ただし試行が増える）場合
nmap -sV --version-all -p <portlist> -iL targets.txt -oN 06_svc_nmap_sV_all.txt
~~~~

- 判断
  - `service/version` が埋まったもの：次の「プロトコル別観測」に進む
  - `unknown` / `tcpwrapped` / 判定が揺れるもの：手動で“最初の数往復”を観測して確定する

### フロー2：TLSっぽいポートは“opensslで外形を抜く”（SNI + ALPN）
目的：**TLS終端・SNI依存・ALPN合意**を確定し、HTTP前提で良いかを決める。

~~~~
# 1) まずTLSハンドシェイクが成立するか（SNI無し）
openssl s_client -connect <ip>:<port> -brief < /dev/null

# 2) SNIを付けて再試行（内部FQDN候補がある場合）
openssl s_client -connect <ip>:<port> -servername <fqdn> -brief < /dev/null

# 3) ALPNで http/1.1 と h2 を提示し、合意結果を見る
openssl s_client -connect <ip>:<port> -servername <fqdn> -alpn h2,http/1.1 -brief < /dev/null

# 4) 証明書チェーンも必要なら（SANやIssuer確認用）
openssl s_client -connect <ip>:<port> -servername <fqdn> -showcerts < /dev/null
~~~~

- 判断（典型分岐）
  - A：TLS成立 + ALPNが `h2`
    - 次：HTTP/2でHTTP層確認へ（フロー3）
  - B：TLS成立 + ALPNが `http/1.1`（またはALPN無し）
    - 次：HTTP/1.1でHTTP層確認へ（フロー3）
  - C：TLS成立するがHTTPっぽくない（証明書/ポート/応答がLDAPS等を示唆）
    - 次：該当プロトコルの“最小ネゴ”に移る（例：LDAP/SMB等）
  - D：TLS不成立
    - 次：平文バナー/最小コマンドで判定（フロー4）

### フロー3：HTTPかどうかを“最小のHTTPで確定”する（curl）
目的：HTTP前提テストを当てて良いかの確定。

~~~~
# 1) HTTP/1.1でヘッダだけ（TLSの場合は -k で観測優先）
curl -vkI https://<fqdn_or_ip>:<port>/

# 2) ALPNがh2ならHTTP/2を明示（curlが対応していれば）
curl --http2 -vkI https://<fqdn_or_ip>:<port>/

# 3) IP直打ちだとvhostが外れる場合：Host/SNIを合わせて観測
curl -vkI --resolve <fqdn>:<port>:<ip> https://<fqdn>:<port>/
~~~~

- 判断
  - ステータス行・Serverヘッダ・特有レスポンス（リダイレクト、401/403、独自ヘッダ）で“HTTPサービス”が確定。
  - `400 Bad Request` の文言や、プロキシ特有のヘッダで「フロントが何か」も推定できる。
- 次の一手（Web領域への接続）
  - HTTPが確定したら、`01_topics/02_web` 側の recon/headers/auth の観測に接続する（ここで無理にWeb診断を始めない）。

### フロー4：平文バナー/最小プロトコルで“何語か”を当てる（ncat）
目的：`unknown` を潰す。サーバが先に喋る系は特に強い。

~~~~
# 1) まずは素接続して、向こうが喋るかを見る（数秒待って切る）
ncat -nv <ip> <port>

# 2) HTTPを疑うなら最小リクエスト（平文HTTPの場合）
printf 'HEAD / HTTP/1.0\r\n\r\n' | ncat -nv <ip> <port>

# 3) SMTPを疑うならEHLO（※暗号化は別途STARTTLSへ）
printf 'EHLO x\r\nQUIT\r\n' | ncat -nv <ip> <port>
~~~~

- 判断
  - 文字列が返れば、その文言が“根拠”になる（製品名・実装・設定断片が出ることがある）
  - 文字化け/バイナリなら、SMB/LDAP/RDP等の可能性が上がる→そのプロトコル専用観測へ

### フロー5：StartTLSがあり得るポートは“切替点”を観測して確定する
目的：平文→TLSの境界を確定し、以降の観測を誤らない。

~~~~
# SMTPのStartTLS
openssl s_client -starttls smtp -connect <ip>:25 -brief < /dev/null

# IMAPのStartTLS
openssl s_client -starttls imap -connect <ip>:143 -brief < /dev/null

# POP3のStartTLS
openssl s_client -starttls pop3 -connect <ip>:110 -brief < /dev/null

# LDAPのStartTLS（389）
openssl s_client -starttls ldap -connect <ip>:389 -brief < /dev/null
~~~~

- 判断
  - `-starttls <protocol>` が通る：そのサービスはStartTLS対応。以降の証明書/SAN/ALPN（対応していれば）観測へ。
  - 通らない：即時TLS（ldaps 636 等）か、そもそも別サービス。

### フロー6：“侵襲が増える”TLS詳細列挙は、必要対象にだけ（ssl-enum-ciphers等）
目的：TLS設定を深掘りしたい時だけ。大量接続が発生するため、適用範囲を絞る。

~~~~
# 対象を限定してTLS設定を列挙（侵襲が増える）
nmap --script ssl-enum-ciphers -p <port> <ip>
~~~~

- 判断
  - ここで得た「許容TLS/暗号スイート」は、Web/管理面のリスク評価や検知観点に接続できる。
  - ただし“全部にやる”ではなく、管理面/重要系/外部連携系に絞るのが実務的。

### まとめ：このファイルの最終成果物（判断できる形）
- `ip:port` ごとに、最低でも以下が埋まっている状態がゴール：
  - `service仮説`（HTTP/SSH/SMB/LDAP/…）
  - `version/実装`（取れれば）
  - `TLS`（有無、StartTLS有無）
  - `SNI依存`（ある/なし、効いたFQDN）
  - `ALPN`（h2/http1.1/なし）
  - `根拠`（コマンドと出力断片）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - V9（Communications）：TLS終端/証明書/プロトコル合意（ALPN）という“通信境界”を外形から確定し、以降のWeb/APIテストで「暗号化が成立している前提」を誤らないための土台にする。
  - （接続の仕方）ASVS自体はアプリ要件だが、NW観測で得た「TLS終端/証明書/プロトコル」が、アプリの通信要件を満たす/破る条件の現実（構成）になる。
- WSTG
  - Cryptography/Configuration 系の前提：TLS設定・HTTP到達・HTTP/2有無を確定し、WSTGのテスト観点（暗号/設定/認証）を「どの入口に当てるか」決めるために使う。
  - （接続の仕方）WSTGの各テストは“対象がHTTPである”ことが前提になりがちなので、ALPN/SNIでHTTP境界を確定してからWeb側へ渡す。
- PTES
  - Intelligence Gathering：到達可能サービスの把握（05_scanningの次段）
  - Vulnerability Analysis：特定サービス/バージョンに絞った脆弱性仮説の形成（無駄打ち削減）
  - Exploitation/Post-Exploitation：SSH/SMB/RDP等が確定すると、横展開・踏み台の分岐が明確になる
- MITRE ATT&CK
  - Discovery：Network Service Discovery（サービス列挙/特定）、Remote Services へ繋がる前提確定
  - （接続の仕方）ここで確定したサービス種別が、Credential Access / Lateral Movement の“次の技術選択”を決める入力になる

## 参考（必要最小限）
- Nmap公式ドキュメント：Service and Version Detection（-sV / --version-intensity 等）
- Nmap NSE：ssl-enum-ciphers スクリプトドキュメント
- OpenSSL公式ドキュメント：openssl-s_client（-servername / -alpn / -starttls）
- Ncat（Nmap付属）ドキュメント：素接続/簡易送信での観測（バナー相当の取得）
