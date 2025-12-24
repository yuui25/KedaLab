# 05_input_18_http_request_smuggling_02_cl_te（proxy_desync）
HTTP Request Smuggling（CL.TE）：フロントはCLで終端、バックはTE(chunked)で終端 → "フロントが見ない追加リクエスト"がバックで処理される

## 目的（この技術で到達する状態）
- CL.TE（フロント：Content-Length優先 × バック：Transfer-Encoding(chunked)優先）の成立条件を、観測に基づく根拠として説明できる。
  1) どの構成で起きるか（どの層がCL/TEを信じるか）
  2) 何が起きるか（バックで追加リクエストが処理され、フロント制御を迂回し得る）
  3) どう観測して確定するか（response対応/タイミング/ログ相関）
  4) 実害を"分岐点"として評価できる（認可・ルーティング・キャッシュ・監査）
  5) 修正を"設計要件"として提示できる（拒否・正規化・パーサ統一・コネクション管理）

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN/WAF/LB/Reverse Proxy/アプリが一般的。HTTP/1.1 のコネクション再利用（keep-alive）が使われる構成。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：いきなり高負荷・大量送信を行わない。第三者影響（キャッシュ汚染、他ユーザ混線）を伴う評価は、契約/VDP条件と安全設計（隔離環境）を満たすまで実施しない。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - HTTP/1.1 Request Smuggling の CL.TE パターン（proxy desync）
    - フロントがContent-Lengthで"ここまでがボディ"と決め、バックがTransfer-Encoding: chunkedで"ここまでがボディ"と決める不一致
    - 結果として、バック側で"追加リクエスト"が成立する（フロントが監視/検査していない）
  - 扱わない（別ユニットへ接続）：
    - TE.CL（逆方向） → `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
    - HTTP/2 フロント起因（H2→H1変換や疑似ヘッダ差） → `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
    - 観測シグナルの体系化 → `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - request↔response 対応の崩れ（Desyncの本体）
  - 時間差（タイムアウト/遅延の不連続）
  - エラーの層が変わる（400/502/504 など）
  - ログ相関（フロント（proxy）ログとバック（アプリ）ログ）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：対象スタック（CDN/WAF/LB/ReverseProxy/アプリ）を分解し、HTTP境界（H1/H2、TE/CL、connection reuse）を仮説化
  - 信頼境界（外部連携・第三者・越境ポイント）：中継点（proxy）を跨いだときの解釈差
  - 権限境界（権限の切替/伝播/委任）：認可・ルーティング・キャッシュ・監査の前提が崩れる
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - TE と CL の併記、あるいは TE の解釈差が存在
  - フロントが Content-Length を優先/固定長で読み、バックが Transfer-Encoding: chunked を優先/チャンク終端で読む

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 何がズレるのか（HTTPメッセージ境界＝request boundary）
  - どう観測して「成立根拠」を取るか（レスポンス対応関係、タイミング、ログ相関）
- 何が"推定"できるか（推定の根拠/前提）：
  - どの構成で起きやすいか（CDN/WAF/LB/Reverse Proxy/アプリ、H2→H1変換など）
  - 侵害評価を"現実の影響"で確定する（認可・ルーティング・キャッシュ・監査）
- 何は"言えない"か（不足情報・観測限界）：
  - すべての構成での成立可否（観測範囲に依存）
  - すべての実害の完全な再現（許可された検証環境でのみ実施）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：最前段で曖昧入力を拒否（健全） → TE+CL 等をフロントが一貫して拒否
  - パターンB：境界揺れの兆候（desync疑い） → 502/504、遅延の不連続、レスポンス対応の乱れが観測される
  - パターンC：バックで追加リクエスト処理が確定（重大） → "フロントが見ていないリクエスト"がバックで処理される

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - HTTP/1.1 のコネクション再利用（keep-alive）が使われる構成
  - 中継点（プロキシ）が"前段で解釈→後段に転送"する構成
  - TE と CL の併記、あるいは TE の解釈差が存在する構成
- 優先度の付け方（時間制約がある場合の順序）：
  1) フロント依存の制御（WAF/ACL/認証ゲート）迂回（最重要：統制破綻）
  2) ルーティング/Host境界の破壊（マルチサービスで影響大）
  3) キャッシュ/監査境界の破壊（検知・追跡性の破綻）
  4) 影響（DoS/劣化）としての利用（バックコネクション詰まり）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：フロントが path-based ACL を持つ（例：/admin はブロック）一方、バックは追加リクエストを処理してしまう構成
  - 攻め筋2：同一フロント配下に複数アプリ（Host/pathルーティング）がある構成では、追加リクエストが別サービスへ到達し得る
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 別経路（H2→H1変換、別ホスト、別proxy）で"どこが弾いているか"を特定し、設計として固定できているか確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：フロント依存の制御があり、追加リクエストが"高価値パス"へ届き得る
  - 次の検証：
    - 03_authz（認可）と接続し、フロントで守っていた境界（path/host/role）を特定
    - バックが処理した追加リクエストの到達先（サービス/パス/権限）をログで確定
    - 監査ログの不一致（frontとbackの処理差）を根拠として重大性を定義
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 本来到達できないパスがバックで処理される、フロントでは無害化したはずのヘッダがバックで残る
- 仮説B：追加リクエストは確定できないが、desync兆候と劣化が出る
  - 次の検証：
    - 影響を「DoS（ワーカ）」ではなく「バックコネクション詰まり（pool枯渇）」としてモデル化
    - `05_input_18_http_request_smuggling_04_observable_signals` の枠で、遅延/切断/エラー層の相関を整理し、修正（拒否/コネクション破棄/タイムアウト）へ落とす
  - 期待する観測：
    - ワーカ/コネクション枯渇の兆候が観測できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/18_http_request_smuggling_cl_te_proxy_desync/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - pcap（クライアント→フロント、フロント→バック）、フロントアクセスログ（request_id、upstream_response_time）、バックアクセスログ（リクエスト行、読み取りバイト、タイムアウト）
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：対象スタック、HTTP境界（H1/H2、TE/CL、connection reuse）、request↔response対応、ログ相関
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/http_request_smuggling_cl_te 2>/dev/null
    cd ~/keda_evidence/http_request_smuggling_cl_te
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ（いきなり高負荷・大量送信を行わない）
      - 第三者影響（キャッシュ汚染、他ユーザ混線）を伴う評価は、契約/VDP条件と安全設計（隔離環境）を満たすまで実施しない
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、対象スタック、HTTP境界、request↔response対応、ログ相関

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# CL.TE の核は「長さ決定ルールの不一致」。
# - フロント：Content-Lengthを採用（固定長）
# - バック：Transfer-Encoding: chunkedを採用（チャンク終端）
# その結果、フロントが"ボディ扱い"した後続データが、
# バックでは"次のリクエスト"として解釈され得る。

# 観測したい状態：
# - バックログに"追加のリクエスト"が出る
# - request↔response対応が崩れる
# - エラー層/遅延が不連続に変化する
~~~~

- この例で観測していること：
  - request↔response 対応の崩れ（Desyncの本体）、時間差（タイムアウト/遅延の不連続）、エラーの層が変わる（400/502/504 など）
- 出力のどこを見るか（注目点）：
  - レスポンス対応関係、遅延の不連続、エラー層、ログ相関
- この例が使えないケース（前提が崩れるケース）：
  - HTTP/1.1 のコネクション再利用（keep-alive）が使われない構成の場合、観測できない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：HTTP処理、プロキシ設定
  - 該当要件（可能ならID）：フロント/バックでHTTPパーサの前提を揃える（TE/CLの扱い統一）、不正な組合せ（TE+CL等）を早期拒否、hop-by-hopヘッダ正規化、HTTP/2→1.1変換境界の設計、コネクション再利用（keep-alive）前提の安全策、監査ログの相関（front/backで同一request_id）を担保する
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：HTTPメッセージ境界（request boundary）がフロント（CDN/WAF/LB/Reverse Proxy）とバックエンドで不一致になり、「フロントが見ていないリクエスト」がバックで処理され得る。認可・ルーティング・監査の前提が崩れ、フロント依存の制御（WAF/ACL/認証前処理）を迂回する"設計上の抜け道"になる。
    - 満たす：曖昧な長さ決定（TE+CL、異常なTE、重複CL等）を最前段で拒否し、hop-by-hopヘッダを正規化する。H1/H2変換境界を含め、フロント/バックのパーサ前提を揃える。異常時はコネクションを破棄し、プールへ戻さない。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：Request Smugglingは「入力検証」ではなく「中継点（proxy）を跨いだ解釈差」の検証。CL.TEでは、フロントがContent-Lengthで区切り、バックがTransfer-Encoding: chunkedで区切る差により、"追加リクエスト（バックだけが認識）"が成立するかを、レスポンス対応関係・タイミング・ログ相関で確定する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：HTTP Request Smuggling の特定と成立条件の詰め方
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：脆弱性分析、侵害評価
  - 前後フェーズとの繋がり（1行）：脆弱性分析で対象スタック（CDN/WAF/LB/Reverse Proxy/アプリ）を分解し、どの層がCL/TEをどう扱うかの仮説を立てる。侵害評価で成立の芯は「バックが追加リクエストを処理した」ことの観測。次に、その追加リクエストが"高価値分岐"（認可・ルーティング・キャッシュ・監査）に届くかを詰める。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access：T1190（公開アプリの脆弱性悪用）。Defense Evasion：フロント制御（WAF/ACL/認証ゲート）を"見えないリクエスト"として迂回する設計悪用。Collection / Credential Access：レスポンス混線、意図しないレスポンス取得、セッション関連の副作用が成立する構成では収集に接続。Impact：バックコネクション汚染・キュー滞留などのサービス劣化に接続（条件付き）。
  - 攻撃者の目的（この技術が支える意図）：HTTP Request Smuggling の特定と成立条件の詰め方
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- HTTP Request Smuggling の定義と解説
- CL.TE パターンの説明
- HTTP/1.1 のコネクション再利用（keep-alive）の仕組み

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- 関連 topics：`05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- 関連 labs：`04_labs/02_web/05_input/18_http_request_smuggling_cl_te_proxy_desync/`（追加候補）

---

## 深掘りリンク（最大8）
- `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`
- `05_input_19_cache_poisoning_01_keying（vary_normalization）.md`
- `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
- `05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`

---
