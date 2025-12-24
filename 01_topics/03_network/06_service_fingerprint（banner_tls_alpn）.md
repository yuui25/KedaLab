# 06_service_fingerprint（banner_tls_alpn）

## 目的（この技術で到達する状態）
- 「IP:port が開いている」から一段進めて、**そのポートの"実体"**を確定する
  - 例：443/tcp が「Web」なのか「リバースプロキシ終端」なのか「管理API」なのか「別プロトコル（gRPC等）」なのかを、**観測で言い切れる**
- 暗号化が絡む場合、**TLS終端の位置（どこまでがTLSで守られているか）**と、**プロトコル選択（ALPN/HTTP2/HTTP1.1/他）**を確定する
- 結果として、次フェーズ（脆弱性分析・認証列挙・横展開）で「何を優先して、どの手で行くか」を迷わず決められる状態にする

---

## 前提（対象・範囲・想定）
- 対象：前工程（05_scanning_到達性把握）で、対象ネットワーク内の **到達可能なIPとopen port** が粗く取れている前提
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - サーバ（Linux/Windows）、NW機器、LB/Proxy、VDI/RDP、AD周辺（LDAP/Kerberos/SMB）などが混在
- できること/やらないこと（安全に検証する範囲）：
  - できること：サービスフィンガープリント（バナー/TLS/ALPN）、プロトコル境界の確定、TLS終端の位置の推定、証跡の取得
  - やらないこと：侵襲が増える手（大量の試行が必要なTLS列挙や強いスクリプト）は、**必要になった対象にだけ**段階的に適用する、"脆弱性を突く"前の確定作業（目的は「ソフト/プロトコル/終端点/バージョン/構成の推定精度を上げる」こと）
- 依存する前提知識（必要最小限）：
  - `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：サービスフィンガープリント（バナー/TLS/ALPN）、プロトコル境界の確定、TLS終端の位置の推定
  - 扱わない（別ユニットへ接続）：
    - Web層の深掘り → `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
    - プロトコル別の深掘り → `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md` / `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md` 等

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 到達性境界：L4で"会話が成立する"か
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - TCP：SYN→SYN/ACK（open）、RST（closed）、無応答（filtered/経路不達/ACL）
  - UDP：応答の有無・見えているICMP（ただし不確実）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：**open ≠ サービス確定**。ここは「会話の入口がある」だけ
  - 信頼境界（外部連携・第三者・越境ポイント）：open/filtered の違いは「次の観測手段（NSE/手動/迂回）」に直結する
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 到達性境界の違いで次の観測手段が変わる

### 2) プロトコル境界：最初の数往復で"何語を話すか"を確定する
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - バナー（banner）とは「接続直後に返る文字列」だけを指さない
  - "バナー相当"には以下が含まれる：サーバ側のグリーティング（FTP/SMTP/SSH等）、こちらが最小コマンドを投げた際のエラー文・応答コード（HTTP/RTSP/Redis等）、バイナリプロトコルの初期ネゴ（SMB/LDAP/Kerberos等）
- 境界の観点：
  - 信頼境界：**「何も返らない」場合でも、こちらの"1手"で判定できる**ことが多い
  - 例：HTTPっぽいかを見たいなら、`HEAD / HTTP/1.0` を送ってステータス行の有無を見る
- 重要なフィールド/差分/状態：
  - プロトコル境界の違いで次の観測手段が変わる

### 3) TLS境界：暗号化の"外側から見える情報"で終端点を推定する
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - TLSは「中身が見えない」代わりに、ハンドシェイクに観測点が密集する
  - 見るもの（TLSハンドシェイクで外形的に取れる）：サーバ証明書（Subject/SAN/Issuer/有効期限/チェーン）、サポートプロトコル（TLS1.0〜1.3、場合によりDTLS）、ALPN（アプリ層プロトコル合意：h2/http1.1/他）、SNI（名前ベース終端：どのservernameで何が返るか）
- 境界の観点：
  - 信頼境界：「このIP:portの正体」が **"TLS終端（LB/Proxy）"** なのか、**"アプリ直結"** なのかを推定できる
  - 証明書のSANから **内部FQDN/別名/クラスタ名** が漏れていることがある（次の探索に直結）
- 重要なフィールド/差分/状態：
  - TLS境界の違いで終端点の推定が変わる

### 4) 証跡境界：後工程で再現できる形に落とす
- 取得する証跡（目的ベースで最小限）：
  - 対象：ip, port, proto(tcp/udp), 観測日時
  - 結果：service推定、version推定、根拠（出力断片 or コマンドログ）
  - TLS：SNI、証明書サマリ、ALPN結果
- 観測の取り方（どの視点で差分を見るか）：
  - プロトコル境界の違いでの差分
  - TLS境界の違いでの差分
  - SNIの違いでの差分
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/service_fingerprint 2>/dev/null
    cd ~/keda_evidence/service_fingerprint
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **前工程で到達可能と確定したIPとopen port** のみ
      - 観測は **サービスフィンガープリント** のみ
      - 侵襲が増える手は必要になった対象にだけ段階的に適用する
  - 相関キー（最低限）を作る（後で必ず効く）
    - IP、Port、Protocol、Service、Version、TLS、SNI、ALPN、RootCause、Time

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 到達性境界（L4で"会話が成立する"か）
  - プロトコル境界（最初の数往復で"何語を話すか"を確定する）
  - TLS境界（暗号化の"外側から見える情報"で終端点を推定する）
  - 証跡境界（後工程で再現できる形に落とす）
- 何が"推定"できるか（推定の根拠/前提）：
  - 「サービス名が出た」＝確定ではなく"仮説の強度が上がった"状態（Nmap等のservice判定は、基本的に **プローブ→応答パターン照合**）
  - 「TLSハンドシェイクが通る」＝"暗号化サービス終端が存在する"状態（TLS終端がある（少なくともそのポートでTLSが喋れる）、証明書・ALPN・SNIという外形情報が取れる）
  - ALPNが示す状態：同じ443でも"攻める対象"が変わる（ALPNが `h2`：HTTP/2で喋れる（Web/ API/ gRPC の可能性が上がる）、ALPNが `http/1.1`：典型的Web、あるいは古い/制限された終端、ALPNが空/失敗：TLSはあるがALPN未対応、または非HTTP用途（LDAPS等））
  - StartTLSが示す状態：平文→TLSへの"切替点"が存在する（SMTP/IMAP/POP3/LDAPなどで **`STARTTLS`** が通る場合："平文で喋れる区間"と"TLS区間"が分かれる）
- 何は"言えない"か（不足情報・観測限界）：
  - バージョンが出ても、**代理応答（LB/Proxy）**や**偽装**の可能性は残る
  - 特にHTTPは、フロントが同じでもバックエンドが複数混在する
  - アプリの実体（HTTPか、別プロトコルか）は、ALPNや追加観測が要る
  - 同一IPでも、SNIを変えると別サービスに繋がる（名前ベース終端）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：TLS成立 + ALPNが `h2` → HTTP/2でHTTP層確認へ
  - パターンB：TLS成立 + ALPNが `http/1.1`（またはALPN無し） → HTTP/1.1でHTTP層確認へ
  - パターンC：TLS成立するがHTTPっぽくない（証明書/ポート/応答がLDAPS等を示唆） → 該当プロトコルの"最小ネゴ"に移る（例：LDAP/SMB等）
  - パターンD：TLS不成立 → 平文バナー/最小コマンドで判定

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - "脆弱性母集団"を現実的なサイズに落とす（例：`OpenSSH` が見えた → 既知CVE探索、認証方式（鍵/パスワード）、踏み台化（後段pivot）へ、例：`Microsoft IIS` / `ASP.NET` が見えた → Windows系の認証連携（NTLM/Kerberos）、IIS特有の管理面露出、アプリ層の認証/認可へ、例：`nginx` だが証明書SANが "internal-admin" を含む → 名前ベースで別vhostが存在→SNI/Hostを変えて探索）
  - "終端点"を当てる（LB/Proxy/直結）＝次の観測点が変わる（TLS証明書が企業内CA発行、SANに複数ホスト、Issuerが共通 → フロントは共通終端の可能性が高い→**SNI/Host切替で面が増える**仮説、証明書が機器ベンダ名、管理用っぽいCN → アプライアンス管理画面の可能性→既知脆弱性/初期設定/認証強度へ）
  - ALPNで"道具立て"が決まる（HTTP/2 vs HTTP/1.1）（h2が有効 → `curl --http2` / `nghttp` / h2前提の観測に寄せる（挙動差を利用した検証が可能）、h2が無効 → HTTP/1.1の前提で、ヘッダ・キャッシュ・プロキシ境界を観測する）
- 優先度の付け方（時間制約がある場合の順序）：
  1) 管理系サービス（SSH/SMB/RDP/LDAP等）
  2) Web/APIサービス（HTTP/HTTPS）
  3) その他のサービス（DB/メール等）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1："脆弱性母集団"を現実的なサイズに落とす → サービス/バージョンが確定したら、既知CVE探索、認証方式、横展開の入口へ
  - 攻め筋2："終端点"を当てる（LB/Proxy/直結） → SNI/Host切替で面が増える仮説、既知脆弱性/初期設定/認証強度へ
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - TLS終端がLB/Proxyの場合、SNI/Host切替で面が増える可能性がある
  - 証明書のSANから内部FQDN/別名/クラスタ名が漏れていることがある（次の探索に直結）

---

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：まずは低侵襲の"自動識別"で当てに行く（nmap -sV）
- 次の検証：
  - `service/version` が埋まったもの：次の「プロトコル別観測」に進む
  - `unknown` / `tcpwrapped` / 判定が揺れるもの：手動で"最初の数往復"を観測して確定する
- 期待する観測（成功/失敗時に何が見えるか）：
  - 成功：サービス/バージョンが確定し、次の観測が決められる
  - 失敗：サービス/バージョンが確定せず、手動観測が必要

### 仮説B：TLSっぽいポートは"opensslで外形を抜く"（SNI + ALPN）
- 次の検証：
  - A：TLS成立 + ALPNが `h2` → HTTP/2でHTTP層確認へ（フロー3）
  - B：TLS成立 + ALPNが `http/1.1`（またはALPN無し） → HTTP/1.1でHTTP層確認へ（フロー3）
  - C：TLS成立するがHTTPっぽくない（証明書/ポート/応答がLDAPS等を示唆） → 該当プロトコルの"最小ネゴ"に移る（例：LDAP/SMB等）
  - D：TLS不成立 → 平文バナー/最小コマンドで判定（フロー4）
- 期待する観測：
  - 成功：TLS終端・SNI依存・ALPN合意が確定し、次の観測が決められる
  - 失敗：TLS終端・SNI依存・ALPN合意が確定せず、次の観測が決められない

### 仮説C：HTTPかどうかを"最小のHTTPで確定"する（curl）
- 次の検証：
  - ステータス行・Serverヘッダ・特有レスポンス（リダイレクト、401/403、独自ヘッダ）で"HTTPサービス"が確定
  - `400 Bad Request` の文言や、プロキシ特有のヘッダで「フロントが何か」も推定できる
- 期待する観測：
  - 成功：HTTPサービスが確定し、Web層の観測に進める
  - 失敗：HTTPサービスが確定せず、別プロトコルの可能性が高い

### 仮説D：平文バナー/最小プロトコルで"何語か"を当てる（ncat）
- 次の検証：
  - 文字列が返れば、その文言が"根拠"になる（製品名・実装・設定断片が出ることがある）
  - 文字化け/バイナリなら、SMB/LDAP/RDP等の可能性が上がる→そのプロトコル専用観測へ
- 期待する観測：
  - 成功：プロトコルが確定し、次の観測が決められる
  - 失敗：プロトコルが確定せず、次の観測が決められない

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 取得する証跡（目的ベースで最小限）：
  - 対象：ip, port, proto(tcp/udp), 観測日時
  - 結果：service推定、version推定、根拠（出力断片 or コマンドログ）
  - TLS：SNI、証明書サマリ、ALPN結果
- 観測の取り方（どの視点で差分を見るか）：
  - プロトコル境界の違いでの差分
  - TLS境界の違いでの差分
  - SNIの違いでの差分
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/service_fingerprint 2>/dev/null
    cd ~/keda_evidence/service_fingerprint
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **前工程で到達可能と確定したIPとopen port** のみ
      - 観測は **サービスフィンガープリント** のみ
      - 侵襲が増える手は必要になった対象にだけ段階的に適用する
  - 相関キー（最低限）を作る（後で必ず効く）
    - IP、Port、Protocol、Service、Version、TLS、SNI、ALPN、RootCause、Time

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# (1) まずは低侵襲の"自動識別"で当てに行く（nmap -sV）
nmap -sV -p <portlist> -iL targets.txt -oN 06_svc_nmap_sV.txt

# (2) TLSっぽいポートは"opensslで外形を抜く"（SNI + ALPN）
openssl s_client -connect <ip>:<port> -servername <fqdn> -alpn h2,http/1.1 -brief < /dev/null

# (3) HTTPかどうかを"最小のHTTPで確定"する（curl）
curl -vkI https://<fqdn_or_ip>:<port>/

# (4) 平文バナー/最小プロトコルで"何語か"を当てる（ncat）
ncat -nv <ip> <port>
~~~~

- この例で観測していること：サービスフィンガープリント（バナー/TLS/ALPN）、プロトコル境界の確定、TLS終端の位置の推定
- 出力のどこを見るか（注目点）：サービス名、バージョン、TLS情報（証明書/SAN/ALPN/SNI）、プロトコル境界、バナー情報
- この例が使えないケース（前提が崩れるケース）：完全に制限された環境で接続ができない場合、または前工程で到達可能と確定していない場合

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V9（通信の保護/TLS）を「実装側が満たしている状態か」を外形から確認する前提情報として使う（Web診断に入る前の"通信境界の確定"）
  - 該当要件（可能ならID）：V9.1.1、V9.1.2、V9.1.3
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：TLS終端/証明書/プロトコル合意（ALPN）という"通信境界"を外形から確定し、以降のWeb/APIテストで「暗号化が成立している前提」を誤らないための土台にする
    - 破れる：TLS終端/証明書/プロトコル合意が不明確な場合、Web/APIテストの前提が崩れる
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：暗号/設定（TLS/HTTPヘッダ/プロトコル選択）観点の"前提となる観測"として使う（どのテストをどこに当てるかを確定する）
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - Cryptography/Configuration 系の前提：TLS設定・HTTP到達・HTTP/2有無を確定し、WSTGのテスト観点（暗号/設定/認証）を「どの入口に当てるか」決めるために使う
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering、Vulnerability Analysis
  - 前後フェーズとの繋がり（1行）：Intelligence Gathering → Vulnerability Analysis の橋渡し（到達性の次に"何が動いているか"を確定し、脆弱性仮説の母集団を絞る）
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Discovery
  - 攻撃者の目的（この技術が支える意図）：Network Service Discovery（サービス列挙/特定）、Remote Services へ繋がる前提確定。ここで確定したサービス種別が、Credential Access / Lateral Movement の"次の技術選択"を決める入力になる
  - 参照：https://attack.mitre.org/tactics/TA0007/（Discovery）

---

## 参考（必要最小限）
- Nmap公式ドキュメント：Service and Version Detection（-sV / --version-intensity 等）
- Nmap NSE：ssl-enum-ciphers スクリプトドキュメント
- OpenSSL公式ドキュメント：openssl-s_client（-servername / -alpn / -starttls）
- Ncat（Nmap付属）ドキュメント：素接続/簡易送信での観測（バナー相当の取得）

---

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
  - `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
  - `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- 関連 playbooks：
  - `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`
- 関連 labs / cases：
  - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`

---

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- `01_topics/02_web/06_config_03_security_headers（CSP_HSTS_XFO等）.md`
- `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- `04_labs/01_local/03_capture_証跡取得（pcap har log）.md`
