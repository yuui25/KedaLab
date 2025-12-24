# 05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）
Request Smuggling 観測学：成功ペイロードではなく、タイミング・エラー層・ログ・キャッシュで"境界が壊れた"を証明する

---

## 目的（この技術で到達する状態）
- Smuggling（TE.CL / CL.TE / H2→H1）の検証で、次を"観測の型"として実行できる。
  1) 兆候（signals）を分類し、何を見ればよいか迷わない
  2) 兆候→確定（proof）に上げるための追加観測（ログ相関/pcap）を設計できる
  3) "実害"と"単なる不安定"を切り分け、報告が薄くならない
  4) 安全に実施する（少数回、キャッシュ/他者影響の抑制、再現性より証跡優先）
  5) 修正要求を「観測で見えた設計欠陥」に結び付けて書ける（拒否・正規化・破棄・相関）

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - 多段（CDN→Proxy→Origin）が一般的。フロントとバックで request boundary の解釈が異なる可能性がある。
- できること/やらないこと（安全に検証する範囲）：
  - やる：観測シグナル（timing、error layer、response mapping、cache、logging correlation）の体系化と証跡取得
  - やらない：キャッシュ汚染・混線・劣化は第三者影響を生みやすいため、反復より証跡（pcap/ログ/時系列）を優先する。検証は少数回で止める。
- 依存する前提知識（必要最小限）：
  - `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
  - `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
  - `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：Request Smuggling / Proxy Desync の観測シグナル体系
    - timing（遅延/不連続）
    - error layers（4xx/5xx/502/504、RST/FIN）
    - response mapping（対応関係の崩れ）
    - cache artifacts（stored response、キーの揺れ）
    - logging correlation（front/backの件数・順序・相関キー）
  - 扱わない（別ユニットへ接続）：
    - 個別のペイロード詳細 → `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`、`05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`、`05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - タイミング（遅延/不連続）：一部のリクエストだけ応答が極端に遅れる、入力の"微差"で応答が不連続に変わる
  - エラー層（4xx/5xx/502/504）：同じ系統の入力で、4xxと502/504が揺れる、502/504が特定条件で出る
  - レスポンス対応関係：2リクエスト送ったのに、レスポンスが1つしか返らない、順序が逆／内容が入れ替わる
  - キャッシュ異常：同じURLなのに、突然内容が変わる／古い内容が返る、キャッシュヒット率や応答速度が急変する
  - ログ相関：frontログ：1リクエストなのに backログ：2リクエスト、request_idが一致しない、順序が崩れる
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：どの層（フロント/バック）が request boundary を解釈するか
  - 信頼境界（外部連携・第三者・越境ポイント）：フロントで見た1リクエストとバックで処理した実リクエストが一致しないと、制御も監査も成立しない
  - 権限境界（権限の切替/伝播/委任）：認可・ルーティング・キャッシュ・監査の前提が崩れる
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 観測すべき状態の3段階：
    - S1：曖昧入力が最前段で拒否される（健全）
    - S2：境界揺れの兆候がある（desync疑い）
    - S3：境界崩壊が確定（request↔response対応崩れ or front/backログ不一致）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - 境界崩壊が確定（S3）：request↔response対応崩れ or front/backログ不一致が再現性あり
  - ログ相関（front/back不一致）は最強の根拠：frontログ：1リクエストなのに backログ：2リクエスト、request_idが一致しない、順序が崩れる
- 何が"推定"できるか（推定の根拠/前提）：
  - 境界揺れの兆候（S2）：502/504、遅延不連続、対応崩れ → 追加観測（ログ相関/pcap）で確定へ上げる
  - タイミング、エラー層、response対応、キャッシュの異常は兆候に過ぎないが、複数組み合わせると説得力が上がる
- 何は"言えない"か（不足情報・観測限界）：
  - 単一のシグナルだけでは断定できない（タイミングが変、エラーが出た、等は代替説明が可能）
  - キャッシュ汚染の断定は慎重に（通常のキャッシュ設定でも揺れるため、Smuggling由来と断定しない）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：S1（健全寄り） - 4xxで一貫して拒否される
  - パターンB：S2（疑い） - 502/504、遅延不連続、対応崩れ
  - パターンC：S3（確定） - front/backログ不一致、対応崩れが再現性あり

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - 認可境界（/admin、重要操作）へ追加リクエストが届く可能性
  - ルーティング境界（別Host/別サービス）へ追加リクエストが届く可能性
  - キャッシュ/監査境界が崩れる可能性
- 優先度の付け方（時間制約がある場合の順序）：
  1) ログ相関（front/back）を取る（最短で強い根拠）
  2) pcapで同一コネクション上の送受信を確定
  3) H2ならstream_idでresponseを紐づけ、並列性を排除
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：タイミング・エラー層・response対応の複数シグナルを組み合わせて、境界揺れの兆候（S2）を確定
  - 攻め筋2：ログ相関で境界崩壊（S3）を確定し、実害評価（認可/ルーティング/キャッシュ/監査）へ接続
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - ログが取れない場合：pcapで同一コネクション上の送受信を確定する
  - キャッシュが関与する場合：第三者影響が出やすいため、検証を増やさずに証跡と範囲確認へ切り替える

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：4xxで一貫して拒否される（S1：健全寄り）
  - 次の検証：
    - 他の入力パターン（ヘッダ順、長さ、改行等）で境界揺れの兆候（S2）が出ないか確認
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 成功：一貫して拒否される（健全）
    - 失敗：502/504、遅延不連続、対応崩れが出る（S2へ移行）
- 仮説B：502/504、遅延不連続、対応崩れ（S2：疑い）
  - 次の検証：
    - ログ相関（front/back）を取る（最短で強い根拠）
    - pcapで同一コネクション上の送受信を確定
    - H2ならstream_idでresponseを紐づけ、並列性を排除
  - 期待する観測：
    - 成功：front/backログ不一致、対応崩れが再現性あり（S3：確定）
    - 失敗：ログ相関が取れない、または並列性で説明できる（S2のまま）
- 仮説C：front/backログ不一致、対応崩れが再現性あり（S3：確定）
  - 次の検証：
    - 実害評価：追加リクエストが認可境界（/admin、重要操作）、ルーティング境界（別Host/別サービス）、キャッシュ/監査境界へ届くかを、最小回数で評価する（他者影響に注意）
  - 期待する観測：
    - 成功：実害が確定する（認可/ルーティング/キャッシュ/監査のどれかに接続できる）
    - 失敗：現時点では境界崩壊まで、実害分岐は未確認（推測しない）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/18_request_smuggling_observable_signals/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - pcap（ストリーム）：同一コネクション上の送受信順序、FIN/RSTのタイミング、再送
  - frontログ（upstream_*）：upstream_response_time / upstream_connect_time の急増、status + upstream_status の組み合わせ
  - backログ（request line / bytes / parse error）：timeout、read bytes、request parse error、400系のパースエラー、リクエスト行崩壊
  - キャッシュ層ログ（可能なら）：ヒット/ミス、キー、bypass理由
- 観測の取り方（どの視点で差分を見るか）：
  - 視点1：タイミング（遅延/不連続）の観測
  - 視点2：エラー層（4xx/5xx/502/504）の観測
  - 視点3：レスポンス対応関係の観測
  - 視点4：キャッシュ異常の観測（慎重に）
  - 視点5：ログ相関（front/back不一致）の観測（最優先）
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/request_smuggling_observable_signals 2>/dev/null
    cd ~/keda_evidence/request_smuggling_observable_signals
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **少数回で証跡重視**（第三者影響の抑制）
      - キャッシュ汚染・混線・劣化は第三者影響を生みやすいため、反復より証跡（pcap/ログ/時系列）を優先する
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id / traceparent（可能なら最優先）
    - timestamp（ミリ秒）
    - client tuple（IP/UA/セッション）
    - upstream connection id（可能なら）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# 観測学の要点：
# - "成功したか"ではなく、S1/S2/S3のどれかを判定できる証拠を集める
# - タイミング、エラー層、response対応、ログ相関、キャッシュの5軸で見る
# - 他者影響が出る可能性があるので、少数回で証拠重視
# 
# 例：ログ相関の取り方（環境依存）
# - frontログ：request_id、timestamp、path、upstream_status
# - backログ：request_id、timestamp、path、status、parse_error
# - 相関：同一request_idで、front=1件、back=2件 などの不一致を探す
~~~~

- この例で観測していること：
  - タイミング、エラー層、response対応、ログ相関、キャッシュの5軸で、境界揺れの兆候（S2）から境界崩壊の確定（S3）へ上げる
- 出力のどこを見るか（注目点）：
  - タイミング：遅延/不連続の有無
  - エラー層：4xx/5xx/502/504の揺れ
  - レスポンス対応：request↔response対応の崩れ
  - ログ相関：front/backログの件数・順序・相関キーの不一致
  - キャッシュ：異常な挙動（慎重に）
- この例が使えないケース（前提が崩れるケース）：
  - ログが取れない場合：pcapで同一コネクション上の送受信を確定する
  - キャッシュが関与しない場合：キャッシュ異常の観測は不要

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：HTTP処理、ログ/監視
  - 該当要件（可能ならID）：request boundary が壊れると、認可・ルーティング・キャッシュ・監査の前提が崩れる。特に"フロントで見た1リクエスト"と"バックで処理した実リクエスト"が一致しないと、制御も監査も成立しない。
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：request boundary が壊れると、認可・ルーティング・キャッシュ・監査の前提が崩れる。特に"フロントで見た1リクエスト"と"バックで処理した実リクエスト"が一致しないと、制御も監査も成立しない。
    - 満たす：曖昧リクエスト（TE+CL、重複CL、異常chunk等）を最前段で拒否し、異常時はコネクションを破棄してプール汚染を防ぐ。front/backで request_id を相関し、件数不一致・順序崩れを検知できる監視を備える。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：HTTP Request Smuggling、Proxy Desync
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：SmugglingはUI上の成功/失敗が見えにくい。よって、タイミング、エラー層（4xx/5xx/502/504）、レスポンス対応関係、ログ相関、キャッシュの異常（stored response）等を"体系化"して、成立根拠を作る。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：脆弱性分析、侵害評価
  - 前後フェーズとの繋がり（1行）：脆弱性分析：攻撃の可否ではなく「境界が揺れている兆候→確定証拠→実害分岐」の順に進める。侵害評価：他者影響（キャッシュ汚染、混線）を含む可能性があるため、安全設計（少数回、隔離、許可範囲）と証跡取得（pcap/log）を必須にする。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：T1190（公開アプリの脆弱性悪用）
  - 攻撃者の目的（この技術が支える意図）：T1190（公開アプリの脆弱性悪用）に繋がるが、観測学の目的は「成立根拠」。Defense Evasion（フロント検査迂回）や Impact（劣化）へ繋がる兆候を、観測で区別する。
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- HTTP Request Smuggling の観測シグナル体系
- ログ相関による境界崩壊の確定方法
- キャッシュ異常の観測と注意点

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- 関連 topics：`05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- 関連 topics：`05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`

---

## 深掘りリンク（最大8）
- `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- `05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）.md`
- `05_input_19_cache_poisoning_01_keying（vary_normalization）.md`
- `05_input_19_cache_poisoning_02_unkeyed（headers_params）.md`
- `05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`

---
