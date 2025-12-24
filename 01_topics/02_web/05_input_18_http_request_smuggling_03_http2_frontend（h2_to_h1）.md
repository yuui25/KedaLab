# 05_input_18_http_request_smuggling_03_http2_frontend（h2_to_h1）
HTTP/2フロントのRequest Smuggling：H2は安全そうに見えるが、H2→H1変換が"曖昧なH1"を再生成して境界が壊れる

## 目的（この技術で到達する状態）
- HTTP/2フロント（H2終端）を含む環境で、次を「観測に基づく成立根拠」として説明できる。
  1) どの構成でリスクが増えるか（H2→H1変換、複数プロキシ、多段LB）
  2) H2特有の"壊れ方"を分類できる（境界破壊／ルーティング破壊／正規化破壊）
  3) どう観測して確定するか（stream、レスポンス対応、front/backログ相関）
  4) 侵害評価を"高価値分岐"で確定できる（認可・ルーティング・キャッシュ・監査）
  5) 修正を"設計要件"として提示できる（拒否・正規化・変換規則・コネクション管理）

## 前提（対象・範囲・想定）
- 対象：許可された範囲のWebアプリ/環境のみ。
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - CDN/WAF/LB/Reverse Proxy/アプリが一般的。HTTP/2フロント（H2終端）がHTTP/1.1バックへ転送する構成。
- できること/やらないこと（安全に検証する範囲）：
  - やらないこと：いきなり高負荷・大量送信を行わない。第三者影響（キャッシュ汚染、他ユーザ混線）を伴う評価は、契約/VDP条件と安全設計（隔離環境）を満たすまで実施しない。
- 依存する前提知識（必要最小限）：
  - `01_topics/02_web/01_web_00_recon_入口・境界・攻め筋の確定.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - HTTP/2フロント（CDN/WAF/LB/Reverse Proxy）がHTTP/1.1バックへ転送する際に起きる "H2→H1変換境界" の問題
    - Request boundary（追加リクエスト/デシンク）に繋がる変換不整合
    - Routing boundary（:authority/Host、:path）に繋がる誤ルーティング
    - Hop-by-hop/ヘッダ正規化差によるWAF/ACL迂回の条件
  - 扱わない（別ユニットへ接続）：
    - H1同士のTE.CL/CL.TE → `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md` / `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
    - 観測シグナル集約 → `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`
    - キャッシュ汚染の詳細 → `05_input_19_cache_poisoning_*`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - H2側の観測（ストリーム単位）：stream_id、HEADERSとDATAの順序、END_STREAM/END_HEADERS、エラーの種類（RST_STREAM、GOAWAY、PROTOCOL_ERROR等）
  - 変換後（H1側）の観測：バックへ出たH1の生ログ/pcap、バックアクセスログで Host/path/method と request_id の件数・順序
  - 相関（front/backで一致させる）：request_id / traceparent などの伝播、timestamp + client tuple + connection/stream の相関
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：対象スタック（CDN/WAF/LB/ReverseProxy/アプリ）を分解し、H2終端位置を仮説化
  - 信頼境界（外部連携・第三者・越境ポイント）：H2→H1変換境界での解釈差
  - 権限境界（権限の切替/伝播/委任）：認可・ルーティング・キャッシュ・監査の前提が崩れる
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - H2で受けたヘッダが、H1側で"危険な組合せ"になる（重複Content-Length、曖昧な長さ決定、hop-by-hopの混在）
  - :authority と Host の不一致（または正規化差）で誤ルーティング
  - :path / クエリの正規化差（デコード順序差）で境界が割れる
  - HTTP/2終端の例外処理でコネクション管理が破綻（汚染/混線）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの構成でリスクが増えるか（H2→H1変換、複数プロキシ、多段LB）
  - どう観測して確定するか（stream、レスポンス対応、front/backログ相関）
- 何が"推定"できるか（推定の根拠/前提）：
  - H2特有の"壊れ方"を分類できる（境界破壊／ルーティング破壊／正規化破壊）
  - 侵害評価を"高価値分岐"で確定できる（認可・ルーティング・キャッシュ・監査）
- 何は"言えない"か（不足情報・観測限界）：
  - すべての構成での成立可否（観測範囲に依存）
  - すべての実害の完全な再現（許可された検証環境でのみ実施）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：request boundary が崩れた（desync兆候/確定）
  - パターンB：routing boundary が崩れた（誤ルーティング/揺れ）
  - パターンC：正規化差によりフロント判定とバック処理が不一致

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - HTTP/2フロント（H2終端）がHTTP/1.1バックへ転送する構成
  - 複数プロキシ、多段LBの構成
  - マルチテナント/マルチサービス環境
- 優先度の付け方（時間制約がある場合の順序）：
  1) ルーティング境界（別Host/別テナント）に届くか（最優先：マルチテナント/マルチサービス環境で影響大）
  2) 認可境界（03_authz）に届くか（フロント依存制御の迂回可能性）
  3) 監査・検知が破綻しているか（組織影響が大きい）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：:authority と Host の不一致（または正規化差）で誤ルーティング → マルチテナント/マルチサービス環境で、意図しないバックへ到達し得る
  - 攻め筋2：:path / クエリの正規化差（デコード順序差）で境界が割れる → フロント検査を通ったのにバックで別物になる
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - H2終端位置が不明な場合、エラーメッセージやヘッダから推定する
  - バックH1の生ログが取れない場合、観測シグナルを複数積み上げて"状態"として所見化する

## 次に試すこと（仮説A/Bの分岐と検証）
- 仮説A：マルチサービス/マルチテナントでルーティング境界が揺れる
  - 次の検証：
    - :authority/Hostとupstream（どのバックへ行ったか）をログで突合
    - 同一入力で揺れるなら、正規化差の"どの表現"で揺れるかを特定し、拒否/正規化要件に落とす
    - 誤ルーティングが認可境界（03_authz）へ波及するか評価する（別テナント到達は最優先）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - フロントログ上のルーティング先（upstream）が、バックログのHost/サービスと一致しない
- 仮説B：desync兆候はあるが、バックH1の生ログが取れない
  - 次の検証：
    - `05_input_18_http_request_smuggling_04_observable_signals` の枠で、タイミング/エラー層/件数不一致を積み上げて"状態"として所見化
    - 追加で、運用に「最小限の相関ログ（request_id伝播）」を依頼できるなら、最短で根拠を強化する
  - 期待する観測：
    - 観測シグナルを複数積み上げて"状態"として所見化できる

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：
    - `04_labs/02_web/05_input/18_http2_frontend_h2_to_h1_boundary/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - H2側：stream_id、HEADERS/DATA、エラー種別
  - H1側：受信したリクエスト行・ヘッダ（可能ならpcap）
  - 相関：request_id（フロントで付与→バックへ付与）
- 観測の取り方（どの視点で差分を見るか）：
  - メモに必ず残す項目：対象スタック、H2終端位置、H2→H1変換差、request↔response対応、ログ相関
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/http2_frontend_h2_to_h1 2>/dev/null
    cd ~/keda_evidence/http2_frontend_h2_to_h1
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **最小限の差分セット** のみ（いきなり高負荷・大量送信を行わない）
      - 第三者影響（キャッシュ汚染、他ユーザ混線）を伴う評価は、契約/VDP条件と安全設計（隔離環境）を満たすまで実施しない
  - 相関キー（最低限）を作る（後で必ず効く）
    - Host、User、Time、対象スタック、H2終端位置、H2→H1変換差、request↔response対応、ログ相関

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# H2→H1境界で重要なのは「H2入力」と「H1へ変換された結果」の差分。
# - H2はstream単位で観測する（response対応崩れの切り分けに必須）
# - 可能ならバックに届いたH1をログ/pcapで取得する（成立根拠が最強）
# - 取れない場合でも、front/backログの件数・順序・Host/pathの不一致で"状態"を確定する
~~~~

- この例で観測していること：
  - H2側の観測（ストリーム単位）、変換後（H1側）の観測、相関（front/backで一致させる）
- 出力のどこを見るか（注目点）：
  - stream_id、HEADERS/DATA、エラー種別、バックへ出たH1の生ログ/pcap、request_id相関
- この例が使えないケース（前提が崩れるケース）：
  - HTTP/2フロント（H2終端）がHTTP/1.1バックへ転送しない構成の場合、観測できない

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：HTTP処理、プロキシ設定
  - 該当要件（可能ならID）：H2を終端する層で厳格に正規化・拒否（曖昧さ排除）、H2→H1変換で危険な表現を生成しない（TE/CL、重複CL、改行、疑似ヘッダ順序違反など）。異常時はコネクションを破棄しプールへ戻さない。フロント/バックのrequest_id相関を必須にする。
  - このファイルの内容が「満たす/破れる」ポイント：
    - 破れる：HTTP/2（H2）のフロント（CDN/WAF/LB/Reverse Proxy）が、バックエンドにHTTP/1.1（H1）で転送する"変換境界（H2→H1）"で、(1) リクエスト境界（request boundary）、(2) ルーティング境界（Host/:authority、path）、(3) hop-by-hop正規化、(4) ログ/監査の相関が崩れる。結果として、フロントの検査/制御（WAF/ACL/認証前処理）を迂回する"見えないリクエスト"や誤ルーティングが成立し得る。
    - 満たす：H2を終端する層で厳格に正規化・拒否（曖昧さ排除）、H2→H1変換で危険な表現を生成しない（TE/CL、重複CL、改行、疑似ヘッダ順序違反など）。異常時はコネクションを破棄しプールへ戻さない。フロント/バックのrequest_id相関を必須にする。
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：H2特有の観点：H2はフレーム化されるため「H1の"チャンク終端/CL解釈"そのもの」は直接は起きないが、H2→H1変換で"再びH1の曖昧さ"が発生する。よってテストは「H2で受け付ける入力のうち、H1へ変換した際に曖昧/不正/異常なH1表現が生まれないか」を観測で確定する。
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：HTTP/2フロントのRequest Smuggling の特定と成立条件の詰め方
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：脆弱性分析、侵害評価
  - 前後フェーズとの繋がり（1行）：脆弱性分析：スタック分解（クライアント↔フロントはH2、フロント↔バックはH1 など）を行い、"境界がどこにあるか"を確定してから検証する。侵害評価：成立の芯は(1) 変換境界での解釈差（boundary/routingの破壊）を観測で確定し、(2) 高価値分岐（認可・ルーティング・キャッシュ・監査）への到達性で実害を評価する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access：T1190（公開アプリの脆弱性悪用）。Defense Evasion：フロント検査を"別リクエスト"化/誤ルーティング化して回避し得る（条件付き）。Impact：バックコネクション汚染・キュー滞留等のサービス劣化へ波及（条件付き）。
  - 攻撃者の目的（この技術が支える意図）：HTTP/2フロントのRequest Smuggling の特定と成立条件の詰め方
  - 参照：https://attack.mitre.org/tactics/TA0001/（Initial Access）

## 参考（必要最小限）
- HTTP/2 の仕様とフレーム化の仕組み
- H2→H1変換境界の問題点
- 疑似ヘッダ（:method/:path/:authority/:scheme）の扱い

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- 関連 topics：`05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- 関連 labs：`04_labs/02_web/05_input/18_http2_frontend_h2_to_h1_boundary/`（追加候補）

---

## 深掘りリンク（最大8）
- `05_input_18_http_request_smuggling_01_te_cl（proxy_desync）.md`
- `05_input_18_http_request_smuggling_02_cl_te（proxy_desync）.md`
- `05_input_18_http_request_smuggling_04_observable_signals（timing_error_cache）.md`
- `05_input_11_path_traversal_01_normalization（dotdot_encoding）.md`
- `05_input_19_cache_poisoning_01_keying（vary_normalization）.md`
- `05_input_20_crlf_injection_02_downstream（proxy_log_cache）.md`
- `04_labs/01_local/03_capture_証跡取得（pcap_harl_log）.md`
- `02_playbooks/02_web_recon_入口→境界→検証方針.md`

---
