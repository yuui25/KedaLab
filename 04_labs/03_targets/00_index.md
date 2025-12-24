<<<BEGIN>>>
# 00_index.md（検証ターゲット設計：Web/NW=5:5を“回せる教材”にする入口）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK）
- ASVS：
  - 位置づけ：ASVSの各管理策（認証/認可/API/設定/ログ）を“検証できる状態”にするための教材（ターゲット）設計
  - 支えるポイント：同条件比較（差分）を作れるターゲットを用意し、結論の再現性と説明責任を上げる
- WSTG：
  - 位置づけ：WSTG各テスト観点を「観測→改変→差分説明」まで通せるターゲットを配置する
  - 支えるポイント：テスト観点を“実通信の差分”に落とす（項目名の理解で止めない）
- PTES：
  - 該当フェーズ：Pre-engagement（環境準備）→ Intelligence Gathering（観測）→ Vulnerability Analysis（差分解釈）→ Exploitation（成立条件の切り分け）
  - 前後接続：ターゲットがあることで、観測点（Proxy/pcap/HAR）と攻め筋（仮説A/B）が実際に回る
- MITRE ATT&CK：
  - 該当戦術：Reconnaissance / Discovery / Collection（観測）＋（必要に応じて）Credential Access / Lateral Movement（NW側教材）
  - 目的：攻撃者が境界・到達性・権限を見極める“現実の動き”を、検証環境で再現する

## 目的（このフォルダで到達する状態）
- Web/NW=5:5 の練習を、**教材（ターゲット）** として再現性高く回せる。
- 「どのターゲットが、どの技術ユニット（topics）を支えるか」を明確にし、学習が散らからない。
- 観測点（Proxy/HAR/pcap/ログ）と巻き戻し（snapshot/reset）を前提に、壊して学ぶ→即復帰の反復を成立させる。

## 前提（対象・範囲・想定）
- 対象：自前検証環境（VirtualBox想定）。VMwareは現時点で不要。
- 既存の前提：
  - 作業端末（Attack Box）設計：`04_labs/01_local/01_attack-box_作業端末設計.md`
  - 計測点（Proxy）設計：`04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
  - 証跡設計：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
  - 仮想化/到達性：`04_labs/02_virtualization/01_virtualbox_基盤.md` / `03_networking_nat_hostonly_bridge.md`
  - 巻き戻し運用：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`
- やらないこと：
  - ターゲットの網羅（“教材化”が目的。最小で強いセットから始める）
  - 手順の丸写し（Labsは設計が主役。必要コマンドは最小限）

## このフォルダの設計思想（ターゲットを「教材」にする）
### 1) 1ターゲット＝1〜3個の“学べる境界”に絞る
- 例：
  - 認証境界：ログイン前後、セッション更新、失効、MFA/Step-up
  - 認可境界：ロール/テナント/オブジェクト境界（IDOR含む）
  - 設定境界：CORS/ヘッダ/キャッシュ/CDN/WAF相当の差分（簡易再現でも良い）
  - NW到達性：セグメント分離、公開面、踏み台、ログ相関

### 2) 観測点を先に固定する（ターゲットは後から差し替え可能）
- “ターゲットが変わっても”観測点はブレない：
  - Proxyログ（改変/差分）
  - HAR（ブラウザ視点）
  - pcap（NW到達性/TLSメタ/QUIC等）
  - サーバ側ログ（可能なら）
- どの観測点で何が言える/言えないかを、ターゲットごとに明記する。

### 3) 巻き戻し（snapshot/reset）を教材の一部にする
- 破壊して学べる状態でないと、検証は止まる。
- ターゲットごとに「クリーン状態」「脆弱化状態」「検証中」の基準スナップショットを決める。

## 標準アーキテクチャ（最小で強い構成）
- Attack Box（観測・実行）
  - NAT：更新/参照
  - Host-Only：検証セグメント入口
- Target VM（教材）
  - Host-Only：検証セグメント内（隔離）
  -（必要時のみ）NAT：パッケージ取得など（原則は最小に）

## ターゲット種別（Web / NW を同格に扱う）
### Webターゲット（例：アプリ/API中心）
- 目的：認証/セッション/認可/API/設定を“通信差分”で回す
- 典型の観測：
  - Cookie/Authorization/CSRF/CORS/リダイレクト
  - API（REST/GraphQL）のスコープ/権限伝播
- 典型の証跡：
  - HAR（ブラウザ）＋Proxyログ（改変）＋（必要時）アプリログ

### NWターゲット（例：到達性/サービス/認証基盤）
- 目的：到達性・列挙・境界（セグメント/権限/踏み台）を“pcapとログ”で回す
- 典型の観測：
  - ポート到達性、名前解決、認証試行の痕跡、ログ相関キー
- 典型の証跡：
  - pcap（到達性/TCPハンドシェイク）＋OS/サービスログ（可能なら）

## 次に作るファイル（このフォルダ内の推奨順）
1) `04_labs/03_targets/01_target-vm_教材ホスト設計（docker前提）.md`
   - Target VM の最小要件（OS/ネットワーク/ログ/スナップショット基準）
2) `04_labs/03_targets/02_web_targets_最小セット（認証・認可・API差分）.md`
   - Web教材を2〜3個に絞って、学べる境界と観測点を固定
3) `04_labs/03_targets/03_nw_targets_最小セット（到達性・列挙・境界）.md`
   - NW教材を2〜3個に絞って、pcapとログで差分を作る

## 手を動かす（このフォルダのDone条件）
- Webターゲット1つ、NWターゲット1つを最低限配置し、
  - 観測点（Proxy/HAR/pcap/ログ）のどれで何を見るか説明できる
  - “同条件比較”の最小差分セット（2条件）を取って説明できる
  - 巻き戻し（snapshot/reset）でクリーンに戻せる

## リポジトリ内リンク（最大3つまで）
- 関連 labs：`04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
- 関連 labs：`04_labs/02_virtualization/03_networking_nat_hostonly_bridge.md`
- 関連 labs：`04_labs/05_automation/02_snapshots_reset_検証の巻き戻し.md`

---

<<<END>>>
