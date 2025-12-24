# 05_input_18_http_request_smuggling_01_te_cl（proxy_desync）
HTTP Request Smuggling（TE.CL）：Transfer-Encoding を信じるフロントと Content-Length を信じるバックで、リクエスト境界が壊れる

---

## 目的（この技術で到達する状態）
- TE.CL（Transfer-Encoding優先のフロント × Content-Length優先のバック）で起きる Proxy Desync を、次の形で説明・検証・報告できる。
  1) 何がズレるのか（HTTPメッセージ境界＝request boundary）
  2) どの構成で起きやすいか（CDN/WAF/LB/Reverse Proxy/アプリ、H2→H1変換など）
  3) どう観測して「成立根拠」を取るか（レスポンス対応関係、タイミング、ログ相関）
  4) 侵害評価を"現実の影響"で確定する（認可・ルーティング・キャッシュ・監査）
  5) 修正を「設計（統一/拒否/正規化）」として提示できる（単なるWAF推奨で終わらない）

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
    - HTTP/1.1 Request Smuggling の TE.CL パターン（proxy desync）
    - フロントが Transfer-Encoding: chunked を優先し、バックが Content-Length を優先/固定長で読むことで、1コネクション上の request boundary がズレる類型
  - 扱わない（別ユニットへ接続）：
    - CL.TE（逆方向） → `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
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
  - フロントが Transfer-Encoding: chunked を優先し、バックが Content-Length を優先/固定長で読む

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
  - パターンA：フロントが早期拒否（境界が守られている） → TE+CL のような曖昧入力をフロントが弾き、バックへ到達しない
  - パターンB：境界揺れの兆候（desync疑い） → 400/502/504、遅延の不連続、レスポンス対応の乱れなどが観測される
  - パターンC：desync確定（request↔response対応が崩れる） → 同一コネクション上で対応関係が崩れ、境界が壊れたことが観測できる

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - HTTP/1.1 のコネクション再利用（keep-alive）が使われる構成
  - 中継点（プロキシ）が"前段で解釈→後段に転送"する構成
  - TE と CL の併記、あるいは TE の解釈差が存在する構成
- 優先度の付け方（時間制約がある場合の順序）：
  1) 認可・ルーティング境界に届く（フロントで認可/制御（WAF、認証_toggle、path-based ACL）をしている場合）
  2) キャッシュ境界（CDN/Reverse Proxy）に届く（request boundary の崩れが、キャッシュキー生成やレスポンス格納の前提を壊す）
  3) 監査・検知境界に届く（フロントのログ上は "正しいリクエスト" に見えるが、バックでは別リクエストとして処理される）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：WAF/フロント制御を"すり抜けてバックが処理"している兆候がある → バックで到達してはいけないパス/操作（管理系・内部系・別Host想定）への処理痕跡をログで確認
  - 攻め筋2：desyncは起きるが、実害は "DoS/劣化" 方向に見える → 影響は「CPU」ではなく「ワーカ/コネクション枯渇」になりやすい
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - 別経路（H2→H1変換、別ホスト、別proxy）で"どこが弾いているか"を特定し、設計として固定できているか確認

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：WAF/フロント制御を"すり抜けてバックが処理"している兆候がある
  - 次の検証：
    - バックで到達してはいけないパス/操作（管理系・内部系・別Host想定）への処理痕跡をログで確認
    - 認可境界（03_authz）に接続し、「どのガードがフロント依存だったか」を特定
    - 監査ログの破綻（フロントの記録とバックの実処理の不一致）を根拠として提示する
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 本来到達できないパスがバックで処理される、フロントでは無害化したはずのヘッダがバックで残る
- 仮説B：desyncは起きるが、実害は "DoS/劣化" 方向に見える
  - 次の検証：
    - 影響は「CPU」ではなく「ワーカ/コネクション枯渇」になりやすい（少数でも詰まる構成がある）
    - 観測シグナルを `05_input_18_http_request_smuggling_04_observable_signals` の枠組みで整理し、どの層で詰まるか（front/back）、どの閾値で発生するか（安全な範囲で）を確定して、修正要件（拒否/正規化/タイムアウト/connection管理）へ落とす
  - 期待する観測：
    - ワーカ/コネクション枯渇の兆候が観測できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/18_http_request_smuggling_te_cl_proxy_desync/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - pcap（クライアント→フロント、フロント→バック）、フロントアクセスログ（request_id、upstream_response_time）、バックアクセスログ（リクエスト行、読み取りバイト、タイムアウト）
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：対象スタック、HTTP境界（H1/H2、TE/CL、connection reuse）、request↔response対応、ログ相関
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/http_request_smuggling_te_cl 2>/dev/null
    cd ~/keda_evidence/http_request_smuggling_te_cl
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
# TE.CL で見るべきポイント（形）
# - Transfer-Encoding: chunked と Content-Length が同時に存在する
# - フロントは chunked 終端で「終わり」と見る可能性
# - バックは Content-Length で「まだ続く」と見る可能性
# - 結果として、同一コネクション上の次リクエスト境界がズレる

POST /endpoint HTTP/1.1
Host: example
Content-Length: <CL_value>
Transfer-Encoding: chunked
Connection: keep-alive

<chunked-body ... 0\r\n\r\n>
<ここに次リクエスト相当が"混ざる/余る"状態を作ると desync の候補になる>

# 観測
# - 返ってきたレスポンスがどのリクエストに対応しているか
# - 片方がタイムアウト/遅延するか
# - 400/502/504 の層がどう変わるか
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
    - 破れる：HTTPリクエストの「境界（どこまでが1リクエストか）」が、フロント（CDN/WAF/LB/Reverse Proxy）とバックエンドで不一致になり、認可・ルーティング・監査の前提が崩れる。入力（ヘッダ/ボディ）が"別リクエスト"として解釈され得るため、意図しない宛先や権限で処理される。
    - 満たす：フロント/バックでHTTPパーサの前提を揃える（TE/CLの扱い統一）、不正な組合せ（TE+CL等）を早期拒否、hop-by-hopヘッダ正規化、HTTP/2→1.1変換境界の設計、コネクション再利用（keep-alive）前提の安全策、監査ログの相関（front/backで同一request_id）を担保する。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：入力検証（ヘッダ/ボディ）としてではなく、「中継点（proxy）を跨いだときの解釈差」を観測するテスト。特に TE/CL の優先順位、チャンク終端、メッセージ長の決定方法の差で "desync" が起きるかを、レスポンスの対応関係（request↔response）と時間差で確定する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：HTTP Request Smuggling の特定と成立条件の詰め方
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：脆弱性分析、侵害評価
  - 前後フェーズとの繋がり（1行）：脆弱性分析で対象スタック（CDN/WAF/LB/ReverseProxy/アプリ）を分解し、HTTP境界（H1/H2、TE/CL、connection reuse）を仮説化。侵害評価で成功条件は「RCE」ではなく、(1) フロントとバックで request boundary がズレる、(2) そのズレが"高価値の分岐"（認可・ルーティング・キャッシュ・ログ）に届く、を観測で固める。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access：T1190（公開アプリの脆弱性悪用）として入口になり得る。Defense Evasion：フロントのWAF/認可前処理を"別リクエスト"として回避し得る。Collection / Credential Access：セッション混線・意図しないレスポンス取得などに繋がる設計がある場合。Impact：Proxy/ワーカ枯渇やキャッシュ汚染等へ波及（ただし成立条件を分解して評価）。
  - 攻撃者の目的（この技術が支える意図）：HTTP Request Smuggling の特定と成立条件の詰め方
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- HTTP Request Smuggling の定義と解説
- TE.CL パターンの説明
- HTTP/1.1 のコネクション再利用（keep-alive）の仕組み

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- 関連 topics：`05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- 関連 labs：`04_labs/02_web/05_input/18_http_request_smuggling_te_cl_proxy_desync/`（追加候補）

---

## 深掘りリンク（最大8）
- `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`
- `05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `05_input_19_cache_poisoning_01_keying（vary_normalization）.md`
- `06_config_03_セキュリティヘッダ（CSP_HSTS_Frame_Referrer）.md`
- `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`

---
