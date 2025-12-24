# 05_scanning_到達性把握（nmap_masscan）

## 目的（この技術で到達する状態）
- 到達性を「開いている/閉じている」の二択にせず、**"どの層で何が起きているか"** を状態として説明できる
  1) 対象範囲（資産境界）に対し、観測点（送信元・経路・時刻）を固定した上でスキャンを設計できる
  2) Host discovery と Port scan を分離し、**"ホストが落ちている"のか"検知/遮断されている"のか** を切り分けできる
  3) port state（open/closed/filtered 等）を **防御・設計の状態** に翻訳できる（FW/SG/NACL/WAF/IPS などの影響を含む）
  4) 大規模（広いCIDR）と精密（単一ホスト深掘り）でツールを使い分け、masscan→nmapで確証を積み上げられる
  5) 次工程（fingerprint/SMB/LDAP/AD/横展開）へ渡すための「候補リスト」と「優先度」を作れる

---

## 前提（対象・範囲・想定）
- 対象：スコープに含まれるIPレンジ/ホスト/サブネット（例：オンプレ、クラウドVPC、拠点間VPN配下、踏み台配下）
  - スキャン観測は「どこから打ったか」で意味が変わるため、**送信元位置（観測点）** を必ず明示する
  - 例：インターネット側 / 社内LAN側 / VPN内 / 侵害後の内部セグメント / pivot後
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 到達性は層で分解する（混ぜると判断が崩れる）
    - L2（同一セグメントでARPが返る/返らない）
    - L3（IPとして到達し、ICMP等に応答が返る/返らない）
    - L4（特定ポートでSYN-ACK/RST/無応答が返る）
    - L7（プロトコルの握手・バナー・TLSなどの応答が返る）
  - 本ファイルは **L3/L4中心**（L7は次ファイル fingerprint に繋ぐ）
- できること/やらないこと（安全に検証する範囲）：
  - できること：Host discovery、Port scan、到達性の状態分解、証跡の取得、次工程への候補リスト作成
  - やらないこと：許可のある範囲以外での実施、過剰な速度（可用性影響、誤検知/通報、証跡の解釈不能）、L7の深掘り（次ファイルへ）
- 依存する前提知識（必要最小限）：
  - `01_topics/03_network/01_enum_到達性→サービス→認証→権限推定.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Host discovery、Port scan、到達性の状態分解、証跡の取得
  - 扱わない（別ユニットへ接続）：
    - L7の深掘り（fingerprint） → `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
    - フィルタの観測・根拠の取り方 → `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
    - サービス別の深掘り → `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md` / `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md` 等

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 「Host discovery」と「Port scan」を分離して観測する
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - Host discovery（生存判定）：ホストが"存在している"を示すシグナル（ARP/ICMP/TCP/UDP応答）
  - Port scan（ポート状態）：ポートごとの状態（open/closed/filtered）＝**サービス到達性の有無** を確定
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：送信元の境界（自端末→VPN→踏み台→pivot）、経路の境界（ルータ/FW/SG/NACL/プロキシ/IDS/IPS）、管理境界（管理系（RDP/WinRM/SSH/SMB/LDAP）と業務系（HTTP/APP）を区別）、テナント境界（クラウド/社内）：VPC/VNetやセグメント間の到達差がそのまま攻め筋の分岐になる
  - 信頼境界（外部連携・第三者・越境ポイント）：失敗の意味：ホスト不在ではなく **"応答が返らない設計/防御"** かもしれない
  - 権限境界（権限の切替/伝播/委任）：成功の意味：そのサービスへの入口が存在する（次工程の対象になる）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 送信元位置（観測点）で到達性が変わる
  - 経路の境界で到達性が変わる

### 2) 応答シグナルの種類（状態の根拠）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - TCP：SYN→SYN/ACK（open（待受））、SYN→RST（closed（到達はするが待受無し））、SYN→無応答（filtered / dropped（FW/SG/IPS/回線/host FW/レート制限など））
  - UDP：UDP→ICMP Port Unreachable（closed の根拠になり得る）、UDP→無応答（open|filtered が混ざりやすい（UDPは"沈黙が通常"が多い））
  - ICMP：Echo reply（L3到達の根拠）、Destination unreachable / admin prohibited（フィルタの根拠（※返す設計なら））
  - L2（同一セグメントのみ）：ARP応答（最強の生存根拠（ただし proxy ARP 等で誤ることがある））
- 境界の観点：
  - 信頼境界：応答シグナルの種類で"どの境界で止まっているか"を示す
- 重要なフィールド/差分/状態：
  - 応答シグナルの種類で状態（open/closed/filtered）が変わる

### 3) "どの境界で止まっているか"を示す観測点
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - 送信元の境界：自端末→VPN→踏み台→pivot（どこから見ているか）
  - 経路の境界：ルータ/FW/SG/NACL/プロキシ/IDS/IPS
  - 管理境界：管理系（RDP/WinRM/SSH/SMB/LDAP）と業務系（HTTP/APP）を区別
  - テナント境界（クラウド/社内）：VPC/VNetやセグメント間の到達差がそのまま攻め筋の分岐になる
- 境界の観点：
  - 資産境界：送信元の境界、経路の境界、管理境界、テナント境界
- 重要なフィールド/差分/状態：
  - 観測点の違いで到達性が変わる

### 4) 証跡（再現性）として残すべきもの
- 取得する証跡（目的ベースで最小限）：
  - nmap：テキスト出力だけでなく **XML含む** 出力（後工程でパース・比較）
  - masscan：実行時の設定（rate/ポート/IF/送信元IP）を必ず保存
  - 可能ならpcap：特に「filtered」の根拠確認（SYN送ったか、返ってきたか）
  - 実行条件：日時・送信元IP・経路（VPN接続/踏み台）・帯域制約
- 観測の取り方（どの視点で差分を見るか）：
  - 観測点の違いでの差分
  - 経路の違いでの差分
  - 時刻の違いでの差分
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/scanning 2>/dev/null
    cd ~/keda_evidence/scanning
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可のある範囲** のみ
      - 観測は **到達性の状態分解** のみ
      - 過剰な速度は避ける（可用性影響、誤検知/通報、証跡の解釈不能）
  - 相関キー（最低限）を作る（後で必ず効く）
    - SourceIP、TargetIP、Port、Protocol、State、Route、Time、Tool

---

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - Host discovery の結果（生存判定のシグナル）
  - Port scan の結果（open/closed/filtered の状態）
  - 応答シグナルの種類（状態の根拠）
  - "どの境界で止まっているか"を示す観測点
- 何が"推定"できるか（推定の根拠/前提）：
  - Host discovery で "Down" は「不在」とは限らない（ICMP遮断、FWでPing系遮断、レート制限/IPSでドロップ、経路不通）
  - open / closed / filtered の"翻訳"（open：サービス到達可能、closed：到達は可能だが待受無し、filtered：経路上で落とされている）
  - "広く浅く"と"狭く深く"で意味が変わる（masscanの結果は候補、nmapの結果は確証）
- 何は"言えない"か（不足情報・観測限界）：
  - スキャン結果は"真実"ではなく **観測点から見た状態**。判断は「状態の翻訳」で行う
  - 偽陰性/偽陽性が混ざる前提で"確証の積み上げ"にする
  - 偽陰性が起きやすい条件：低速回線・高遅延・パケットロス、レート制限/IPSの間欠的ドロップ、UDP/ICMPの抑制設計
  - 偽陽性が起きやすい条件：ルール/機器の応答（RST返却など）が特殊、NATやLBが"見せかけの応答"を返す、masscanの高速条件で取りこぼし・混線
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：Host discovery が "全滅" する → ICMPが遮断されているだけで、TCPは生きている可能性、経路がそもそも不通（VPN/ルーティング/ACL）の可能性
  - パターンB：open が散発・再現しない → レート制限/IPS/回線品質の問題、速すぎて取りこぼしている（偽陰性）、IPS/IDSが間欠的に落としている
  - パターンC："filtered" が多い → 境界装置が落としている、送信元位置が原因（そのセグメントからは届かない）、同一観測点でも特定ポートのみ落ちる（SG/NACL/host FW）

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 管理系ポートが外部から open（RDP/WinRM/SSH/SMB/LDAP）
  - ドメイン系サービスが到達可能（Kerberos/LDAP/SMB/RPC）
  - DB系が到達可能（MSSQL/PostgreSQL/MySQL等）
  - Web/管理UIが複数経路で露出（直接/別ポート/別サブドメイン）
- 優先度の付け方（時間制約がある場合の順序）：
  1) 管理系ポートが外部から open（RDP/WinRM/SSH/SMB/LDAP）
  2) ドメイン系サービスが到達可能（Kerberos/LDAP/SMB/RPC）
  3) DB系が到達可能（MSSQL/PostgreSQL/MySQL等）
  4) Web/管理UIが複数経路で露出（直接/別ポート/別サブドメイン）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1："到達性地図"は攻め筋の優先度を決める → "境界の硬さ"を推定し、分岐を決める
  - 攻め筋2："スキャンで得た情報"を後段の検証に変換する → TCP/445 open（SMB）→匿名可否/署名/SMBv1/共有列挙（`09_smb_enum...` へ）、TCP/389 or 636 open（LDAP/LDAPS）→匿名Bind/署名要件/チャネルバインディング等（`11_ldap_enum...` へ）、TCP/88 open（Kerberos）→AS-REP roast/kerberoast の成立条件（`12_kerberos...` へ）、TCP/3389 open（RDP）→NLA/証明書/認証方式（`19_rdp...` へ）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 外部→内部の境界が強い（大半filtered） → VPN/踏み台/端末内からの観測（観測点移動）や、アプリ経由の到達（SSRF/プロキシ/管理導線）を検討
  - 境界が弱い（openが多い、管理系が露出） → fingerprint→認証→権限→横展開の入口（SMB/LDAP/AD）へ直結

---

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：Host discovery が "全滅" する（仮説：生存判定が遮断されている）
- 次の検証：
  - 仮説A：ICMPが遮断されているだけで、TCPは生きている → Host discoveryを飛ばしてポートスキャン（-Pn）で"到達"を確認
  - 仮説B：経路がそもそも不通（VPN/ルーティング/ACL） → 観測点（送信元）を変える/ルート確認/ゲートウェイ到達確認（運用品質の切り分け）
- 期待する観測（成功/失敗時に何が見えるか）：
  - 成功：Host discovery の結果が明確になり、次の観測が決められる
  - 失敗：Host discovery の結果が不明確なまま、次の観測が決められない

### 仮説B：open が散発・再現しない（仮説：レート制限/IPS/回線品質）
- 次の検証：
  - 仮説A：速すぎて取りこぼしている（偽陰性） → レート/並列/リトライを抑えて再試行（"遅くして一致する"なら運用制御が原因）
  - 仮説B：IPS/IDSが間欠的に落としている → 時間をずらして再観測、送信元IP/観測点を変えて差を見る（※回避目的ではなく状態推定）
- 期待する観測：
  - 成功：open の状態が明確になり、次の観測が決められる
  - 失敗：open の状態が不明確なまま、次の観測が決められない

### 仮説C：大規模レンジ（/16等）で"候補抽出"が必要（masscan→nmap確証）
- 次の検証：
  - 仮説A：まずは"開いている可能性のあるポート"だけを拾えばよい → masscanでtop/重要ポートのみ候補抽出→nmapで確証
  - 仮説B：全ポート（-p-）が必要な状況（運用上の例外ポートが疑い） → masscanでもレート制御し、**"範囲を絞る/時間を区切る"** で安全に回す
- 期待する観測：
  - 成功：候補抽出ができ、nmapで確証が取れる
  - 失敗：候補抽出ができず、nmapで確証が取れない

### 仮説D："filtered" が多い（仮説：境界装置が落としている）
- 次の検証：
  - 仮説A：送信元位置が原因（そのセグメントからは届かない） → 観測点を移す（VPN内/踏み台/侵害後セグメント）
  - 仮説B：同一観測点でも特定ポートのみ落ちる（SG/NACL/host FW） → ポート別に「到達できるもの/できないもの」を表にして、後段の攻め筋を組み替える
- 期待する観測：
  - 成功："filtered" の原因が明確になり、次の観測が決められる
  - 失敗："filtered" の原因が不明確なまま、次の観測が決められない

---

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 取得する証跡（目的ベースで最小限）：
  - nmap：テキスト出力だけでなく **XML含む** 出力（後工程でパース・比較）
  - masscan：実行時の設定（rate/ポート/IF/送信元IP）を必ず保存
  - 可能ならpcap：特に「filtered」の根拠確認（SYN送ったか、返ってきたか）
  - 実行条件：日時・送信元IP・経路（VPN接続/踏み台）・帯域制約
- 観測の取り方（どの視点で差分を見るか）：
  - 観測点の違いでの差分
  - 経路の違いでの差分
  - 時刻の違いでの差分
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/scanning 2>/dev/null
    cd ~/keda_evidence/scanning
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可のある範囲** のみ
      - 観測は **到達性の状態分解** のみ
      - 過剰な速度は避ける（可用性影響、誤検知/通報、証跡の解釈不能）
  - 相関キー（最低限）を作る（後で必ず効く）
    - SourceIP、TargetIP、Port、Protocol、State、Route、Time、Tool

---

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# (1) まずは「生存判定だけ」を分離して、観測点を固定する
nmap -sn <CIDR> -oA scan_hostdiscovery

# (2) 生存判定が怪しいときは、-Pn で「ポート到達」を見に行く（範囲は絞る）
nmap -Pn -sS -p 22,80,443,445,3389 <CIDR or targets> -oA scan_tcp_reachability

# (3) masscan：候補抽出（速いが"確定"ではない）
# - rateは環境に合わせて慎重に下げる（まず低く）
masscan <CIDR> -p22,80,443,445,3389 --rate 1000 -oX masscan_candidates.xml

# (4) nmap：確証（候補ホスト/ポートに絞って精密化）
nmap -sS -sV -p22,80,443,445,3389 -iL candidates.txt -oA nmap_confirm
~~~~

- この例で観測していること：Host discovery（生存判定）、Port scan（ポート状態）、到達性の状態分解、証跡の取得
- 出力のどこを見るか（注目点）：Host discovery の結果、Port scan の結果（open/closed/filtered）、応答シグナルの種類、観測点の違い
- この例が使えないケース（前提が崩れるケース）：完全に制限された環境でスキャンができない場合、または許可範囲外の場合

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：到達性と露出面の把握は「攻撃面がどこにあるか」を確定する前提。アプリ側の堅牢性（認証/認可/入力）を議論しても、**"どの経路で到達できるか"** が不明だと設計・検証が崩れる
  - 該当要件（可能ならID）：該当なし（NW前提技術）
  - このファイルの内容が「満たす/破れる」ポイント：
    - 満たす：ネットワーク露出（不要ポート/管理系の公開）、環境分離（社内/管理/顧客系）、監視（スキャン検知・レート制御）、変更管理（公開範囲の逸脱検知）を「到達性＝状態」で説明できること
    - 破れる：到達性が不明確な場合、設計・検証が崩れる
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTGはWeb中心だが、実務では **WSTGのテスト対象へ到達するための前段** が必要（例：管理UI/内部API/管理ポート/踏み台経由）。到達性スキャンは「情報収集→境界確定→対象面の絞り込み」を支える
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - 情報収集（Information Gathering）/構成・デプロイ観測（Configuration & Deployment）に接続し、Webテストに進む前に **"どの入口が存在するか"** を確定する
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Intelligence Gathering、Threat Modeling、Vulnerability Analysis
  - 前後フェーズとの繋がり（1行）：Intelligence Gathering / Threat Modeling → Vulnerability Analysis の橋渡し。単なるポート一覧ではなく、**到達性（届く/届かない）とフィルタ（遮断/監視）を分解して"次に調べる順序"を決める**
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Discovery
  - 攻撃者の目的（この技術が支える意図）：T1046 Network Service Discovery（ネットワークサービス探索）。見つけたサービスを起点に、Credential Access / Lateral Movement / Persistence へ繋がる（ただし本ファイルは"成立根拠＝観測"の確立に集中）
  - 参照：https://attack.mitre.org/tactics/TA0007/（Discovery）

---

## 参考（必要最小限）
- Nmap Documentation（公式）
- Nmap Book：Host Discovery（設計とアルゴリズムの説明）
- masscan：公式ドキュメント/マニュアル（--rate, --banners, 出力形式）

---

## リポジトリ内リンク（最大3つまで）
- 関連 topics：
  - `01_topics/03_network/01_enum_到達性→サービス→認証→権限推定.md`
  - `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
  - `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- 関連 playbooks：
  - `02_playbooks/06_network_enum_to_post_列挙→侵入後の導線.md`
- 関連 labs / cases：
  - `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`

---

## 深掘りリンク（最大8）
- `01_topics/03_network/01_enum_到達性→サービス→認証→権限推定.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/19_rdp_設定と認証（NLA）.md`
- `04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
