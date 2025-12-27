# 05_input_09_ssrf_04_saas_features（webhook_preview_pdf）

## このファイルで扱う概念
- SaaS機能（webhook/preview/pdf等）のSSRF化。

## 危険性を一言で
- 信頼機能が内部到達経路として悪用される。

## 最小限の成立判断（目安）
- 機能経由で宛先差分が再現する。

## 観測例（差分のイメージ）
- A: 外部宛のみ、B: 内部宛が到達する。

## 観測が取れない場合の代替
- 実行基盤の送信制約とURL検証の実装を確認する。

## 時間制約下の最小観測点
- 機能ごとの送信制限有無。

## 対策の優先順位
1) URLのallowlist
2) 実行環境の隔離
3) 通信ログの監視

SaaS機能SSRF（Webhook / Link Preview / PDF生成）：入力URLが"第三者の到達性"を借りる瞬間

## 目的（この技術で到達する状態）
- Webhook / Link Preview / PDF生成 を、単なる「外部HTTPアクセス」ではなく **SaaS実行基盤の信頼境界（Confused Deputy）** として評価できる。
- "SSRFの成立"を、レスポンス反映の有無に依存せず、**成立根拠（観測点）** で確定できる。
- 実務で次を即断できる：
  - どの機能がURL入力を持ち、どの実行系（同期/非同期、worker/headless browser）で走るか
  - その実行系が「内部/metadata/プライベート接続」へ到達し得るか（SaaS側ネットワーク・顧客専用接続）
  - Webhook/Preview/PDFごとに「影響の質」がどう変わるか（副作用・情報漏えい・探索）
  - 修正の要点（allowlist・解決後IP・redirect再検証・egress・監視）を機能要件と結びつけて言語化できる

## 前提（対象・範囲・想定）
- 対象：SaaS機能として実装される「サーバが外部/内部へリクエストする」機能（Webhook、Link Preview、PDF生成等）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - クラウドSaaS、オンプレミスSaaS、ハイブリッド構成
  - 実行系が分離されている（worker/headless browser/pdf renderer）
  - ネットワーク境界が複数ある（egress/PrivateLink/VPC接続）
- できること/やらないこと（安全に検証する範囲）：
  - できること：機能カタログ化、実行系の特定、到達性の確定、成立根拠の観測設計
  - やらないこと：破壊的な処理の実行、本番環境での過度な試行、顧客内部への到達実証（許可範囲外）
- 依存する前提知識（必要最小限）：
  - `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
  - `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
  - `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - SaaS機能としてのSSRF（Webhook/Preview/PDF）
    - 実行系の分離（worker/headless/pdf renderer）
    - 信頼境界（Confused Deputy）のモデル化
    - 成立根拠の観測設計
  - 扱わない（別ユニットへ接続）：
    - 一般的なSSRFの基礎 → `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
    - URLトリック・パーサ差分 → `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md` / `05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
    - DNS Rebinding → `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - アプリ/ジョブログ（tenant_id / user_id / role / feature / request_id / job_id / raw_url / normalized_url / parsed / dns / redirect_chain / outbound / cache）
  - ネットワーク観測（egress proxy / FW / VPC Flow Logs / DNSログ / metadataアクセス検知）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - 実行環境の到達性（内部ネットワーク、管理面、metadata、サービスメッシュ）
    - 認証ヘッダやサービスアカウント（連携API、内部認証、クラウドIAM）
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - SaaS機能は、ユーザ入力からは見えない次の"資産"を持ち得る：実行環境の到達性、認証ヘッダやサービスアカウント、非同期処理やキャッシュ
    - プライベート接続（PrivateLink/VPN/専用線）がある場合、SaaSが顧客VPC/社内へ到達できる構成
  - 権限境界（権限の切替/伝播/委任）：
    - 誰が・どの権限でURLを差し込めるか（低権限ユーザが設定可能なら、SSRFは"想定外の権限伝播"になる）
    - 署名/ヘッダ付与がある（"権限も借用"し得る）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態W0：Webhook機能が存在し、URLが設定できる
  - 状態W1：外向きリクエストが発生する（到達性の借用が成立）
  - 状態W2：redirect追従・再解決がある（境界が伸びる）
  - 状態W3：署名/ヘッダ付与がある（"権限も借用"し得る）
  - 状態W4：プライベート接続（PrivateLink/VPN/専用線）がある
  - 状態P1：投稿/コメント等の"本文"にURLを含めると取得が発生する
  - 状態P2：Headless browser / レンダラで動作する
  - 状態P3：キャッシュがある（時間差・再検証問題）
  - 状態D1：PDF生成が"外部リソースを取りに行く"設計
  - 状態D2：生成物（PDF）に取得結果が反映される
  - 状態D3：生成は非同期ジョブ（queue/worker）で動く

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの機能がURL入力を持ち、どの実行系（同期/非同期、worker/headless browser）で走るか
  - その実行系が「内部/metadata/プライベート接続」へ到達し得るか（SaaS側ネットワーク・顧客専用接続）
  - Webhook/Preview/PDFごとに「影響の質」がどう変わるか（副作用・情報漏えい・探索）
  - 成立根拠（接続ログ/OOB/差分）の確定
- 何が"推定"できるか（推定の根拠/前提）：
  - 実行系の特定（ログの痕跡、処理遅延のパターン、エラーメッセージの指紋）
  - 外部到達性の兆候（SVGや画像内参照が外部URLへのアクセスを誘発していないか）
  - 配信方式の確定（同一オリジン配信 / CDN / 別ドメイン）
- 何は"言えない"か（不足情報・観測限界）：
  - レスポンスが見えないケースが多い（blind SSRF）
  - 実行系の内部実装詳細（policy設定、リソース制限の具体的値）
  - 顧客内部への到達実証（許可範囲外）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：SaaS機能はHTTP/HTTPSのみ、かつ private/metadata へは到達不可（比較的安全）
  - パターンB：いずれかの機能で private/metadata/社内到達が成立する（高リスク）
  - パターンC：実行系が分離されており、本体APIとネットワークが違う（「本体では防げているのにPDFだけ穴」が起きやすい）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - Webhook：設定権限があるユーザ（管理者/運用者）を狙う、または権限昇格と組み合わせる
  - Preview：一般ユーザでも発火できるなら、まずここが入口（T1190）になりやすい
  - PDF：レポート/請求書など"生成物が戻る"機能は、影響が直接可視化しやすい（調査・証拠化が容易）
- 優先度の付け方（時間制約がある場合の順序）：
  1) 入口の広さで狙いを変える（Webhook/Preview/PDFの機能カタログ化）
  2) "到達性の質"でゴールを変える（ただの外部アクセス / internal/metadata / PrivateLink等）
  3) blindでも"副作用"で前に進める（接続ログ / DNS/HTTP OOB / タイム差分 / 内部側ログ）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：機能カタログ化（Webhook/Preview/PDFの入口特定）
  - 攻め筋2：実行系の特定（worker/headless/pdf rendererの切り分け）
  - 攻め筋3：到達性の確定（internal/metadata/PrivateLinkへの到達可能性）
  - 攻め筋4：成立根拠の観測設計（ログ/OOB/差分での証拠化）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - SaaS機能SSRFは、レスポンスが見えないケースが多い。最初から"証拠の取り方"を設計しないと結論が弱くなる。
  - 成立根拠はレスポンス反映ではなく、(A) 接続ログ、(B) DNS/HTTP OOB、(C) タイム差分、(D) 内部側ログ、で固める。

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：SaaS機能はHTTP/HTTPSのみ、かつ private/metadata へは到達不可
  - 次の検証：
    - redirect追従の有無（最終宛先の再検証があるか）
    - URL正規化の一貫性（parser differential の余地）
    - キャッシュ/非同期の差（実行系が変わる入口が無いか）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 境界が守られている根拠（ログ設計・ガード条件）を示し、残余リスク（運用上の監視）を明確化
- 仮説B：いずれかの機能で private/metadata/社内到達が成立する
  - 次の検証：
    - "どの機能・どの実行系"で成立するかを切り分ける（webhook worker / preview cluster / pdf renderer）
    - allowlistの実装（hostだけか、解決後IP・redirect・再解決まで見ているか）を根拠付きで評価
    - 監視/検知の観点（metadataアクセス検知、内部宛ての異常リクエスト頻度）を具体化
  - 期待する観測：
    - 攻撃の方法ではなく「境界が破れている条件（成立根拠）」と「防御の因果（どの制御で閉じるか）」

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/02_web/05_input/09_ssrf_saas_webhook_preview_pdf/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - アプリログ（job_id, normalized_url, resolved_ip, redirect_chain）
  - egressログ（宛先IP/port、実行系タグ）
  - DNSログ（再解決の有無）
- 観測の取り方（どの視点で差分を見るか）：
  - 同一URL入力を「webhook worker / preview worker / pdf renderer」で動かし、どの実行系がどこへ到達できるかを観測
  - redirect/DNS/キャッシュで挙動がどう変わるかを観測
  - 観測点（ログ/egress/DNS/OOB）をどう相関するかを設計
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/ssrf_saas_features 2>/dev/null
    cd ~/keda_evidence/ssrf_saas_features
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 顧客内部への到達実証は許可範囲外
  - 相関キー（最低限）を作る（後で必ず効く）
    - tenant_id, user_id, feature, request_id, job_id, raw_url, normalized_url, resolved_ip

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# SaaS機能SSRFの検証は「出力（PDF/preview）が見えない」ケースが多い。

# したがって、最初に "成立根拠" を残すログ設計を固める。

#
# 例：outbound_request_log（推奨フィールド）

# - tenant_id, user_id, feature, request_id, job_id

# - raw_url, normalized_url, scheme, host, port

# - resolved_ips, selected_ip, resolver, dns_ttl

# - redirect_chain[{url, resolved_ip, status}]

# - method, status, bytes, duration, error_class

# - cache_hit, cache_key

~~~~

- この例で観測していること：
  - SaaS機能SSRFの成立根拠をログで確定する設計
  - 実行系ごとの到達性の違いを観測するための相関キー
- 出力のどこを見るか（注目点）：
  - アプリログ（job_id, normalized_url, resolved_ip, redirect_chain）
  - egressログ（宛先IP/port、実行系タグ）
  - DNSログ（再解決の有無）
- この例が使えないケース（前提が崩れるケース）：
  - ログが取得できない環境、またはログ設計が不十分な場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - URL入力を起点に「サーバが外部/内部へリクエストする」系の機能は、入力検証だけでなく **実接続先（解決後IP・redirect最終到達先）** の検証、許可schemeの制限、レスポンスの扱い（反映/保存/後続処理）を含めた境界設計が必要。SSRFは"URL妥当性"ではなく **信頼境界（SaaS実行基盤の到達性）** の問題として扱う。
    - 満たす：機能要件からallowlistを作る、解決後IPの検証、redirectを最小化、egress制御と監視を"実行系ごと"に適用する
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-08 Testing for SSRF
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - SSRFは「到達性（internal/metadata）」「レスポンス反映の有無（blind/非blind）」「redirect/DNS/URLパース差」を状態として確定し、検証の観測点（アプリログ・プロキシ・OOB）を設計する。URL入力点が"機能"として散在するため、機能カタログ化（webhook/preview/pdf/import等）が重要。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Vulnerability Analysis：SaaS機能（Webhook/Preview/PDF）が **どの実行系（worker/headless browser）** で動くか、どのネットワーク境界（egress/PrivateLink/VPC接続）を持つかを棚卸しして、到達性マップを作る。Exploitation：本質はペイロードではなく「成立根拠（接続ログ/OOB/差分）」「影響の境界（何が読める・何が起こる）」を確定すること。Reporting：修正は"SSRF対策"の一言ではなく、(A) 機能要件の再定義、(B) allowlist+解決後IP検証、(C) redirect/DNS一貫性、(D) egress制御と監視、で因果を示す。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Discovery、Credential Access
  - 攻撃者の目的（この技術が支える意図）：
    - 入口：T1190（公開アプリの悪用）
    - 到達性の利用：T1046（内部サービス探索）
    - クラウド資格情報：T1552.005（Cloud Instance Metadata API）
    - 本ファイルは「SaaS機能としての"外向き通信"が、攻撃者の Discovery / Credential Access を代行し得る」点を境界モデル化する。
  - 参照：https://attack.mitre.org/tactics/TA0001/

## 参考（必要最小限）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet
- OWASP Top 10 2021 A10 SSRF（対策観点：allowlist/redirect/DNS一貫性）
- PortSwigger: URL validation bypass cheat sheet（parser差・曖昧URLの重要性）
- PortSwigger Research: PDF生成まわりの攻撃研究（生成物に情報が乗る"性質"の理解）
- Intigriti: PDF generator におけるSSRF調査観点（機能としての入口整理）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- 関連 topics：`05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- 関連 topics：`05_input_09_ssrf_03_protocol（http_gopher_file）.md`

---

## 深掘りリンク（最大8）
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- `05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
- `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
