# 05_input_09_ssrf_06_parser_differential（url_parse_smuggling）

Parser Differential（URL Parse Smuggling）：検証系と実行系の"URL解釈のズレ"でSSRF境界が崩れる

## 目的（この技術で到達する状態）
- URL parse smuggling（= parser differential）を「曖昧URLの小技」ではなく、**検証（validator）と実行（fetcher）の境界不整合**として説明できる。
- 実務で次を即断できる：
  - どの設計が"ズレ"を生むか（典型構造）
  - どの観測（ログ/相関キー/ネットワーク）で成立根拠を固めるか
  - 修正を「単一パーサ化＋実体ベースallowlist＋egress」に落とせる
- 次ファイル（SSRF各論やSaaS機能）で、同じ"ズレ"が worker/headless/pdf で増幅する理由を接続できる。

## 前提（対象・範囲・想定）
- 対象：SSRF注入点、URL入力、URL検証（Validator）とHTTPクライアント（Fetcher）の差分、Parser Differential（URL Parse Smuggling）
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - クラウド/オンプレミス、実行系が分離されている（api/worker/pdf/headless）
  - プロキシ経由・HTTPクライアント実装・リダイレクト追従で、最終的な解釈系が変わる
  - 同じ言語でも、URL APIが複数存在し解釈が異なることがある（例：Node.jsのURL APIはレガシーとWHATWGの2系統）
- できること/やらないこと（安全に検証する範囲）：
  - できること：validatorとfetcherの差分観測、成立根拠の確定、修正提案の作成
  - やらないこと：破壊的な処理の実行、本番環境での過度な試行、内部/metadataへの到達実証（許可範囲外）
- 依存する前提知識（必要最小限）：
  - `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
  - `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
  - `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - Parser Differential（URL Parse Smuggling）：**同一のURL入力**に対し、(A) 検証側のパーサと (B) 実行側のパーサ/接続スタック が **異なる解釈**を行い、検証は通るが実行は禁則宛先へ到達する状態
    - validator≠fetcher が生む"3つのズレ"（構文確定の差、正規化の差、実行環境の差）
    - "ズレ"を生みやすい設計パターン
  - 扱わない（別ユニットへ接続）：
    - 一般的なSSRFの基礎 → `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
    - URLトリック・DNS Rebinding → `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md` / `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
    - SaaS機能としてのSSRF → `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - validatorログ（raw_url / normalized_url / parsed / allowlist判定 / dns結果 / request_id）
  - fetcherログ（destination_ip:port / SNI/Host header / redirect_chain / request_id / job_id）
  - ネットワーク観測（egressログ / DNSログ）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - validatorが見ているhostと、fetcherが接続するhostが一致しない場合、資産境界が崩れる
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - URLはRFC 3986の構文要素（scheme / authority / userinfo / host / port / path / query / fragment）で解釈される。authorityの定義（userinfo@host:port）が存在する以上、「@」「:」「[]」「%」などは"意味を持つ文字"であり、雑な文字列検査は破綻しやすい
    - parser differentialは"URL一貫性"の別形態（構文解釈の一貫性崩壊）として扱う
  - 権限境界（権限の切替/伝播/委任）：
    - validatorが文字列/別パーサで判定している場合、権限境界が崩れる可能性がある
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態PD0：URL入力点があり、サーバ側取得が走る
  - 状態PD1：validatorがURLを"文字列として"検査している
  - 状態PD2：fetcherが別パーサで解釈し、host/port/scheme がvalidatorと不一致
  - 状態PD3：不一致の結果として、禁則宛先（internal/localhost/metadata等）へ到達

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの設計が"ズレ"を生むか（典型構造）
  - validatorとfetcherで解釈がズレること（parser differentialが成立すること）
  - 成立根拠（validatorログとfetcherログの不一致）
- 何が"推定"できるか（推定の根拠/前提）：
  - validatorとfetcherが同一パーサで、正規化後実体ベースのallowlistをしているか
  - ズレの発生箇所（validatorの構文確定か、fetcherの再パースか、プロキシ/redirectか）
  - 実行系（api/worker/pdf/headless）ごとにズレが出るか
- 何は"言えない"か（不足情報・観測限界）：
  - parser differential は「何を検証したか」と「何へ接続したか」が分離しているため、ログ設計が勝負
  - 内部/metadataへの到達実証（許可範囲外）
  - 実行系の内部実装詳細（パーサの具体的な実装、ライブラリのバージョン）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：validatorとfetcherが同一パーサで、正規化後実体ベースのallowlistをしている（比較的安全）
  - パターンB：validatorとfetcherで解釈がズレる（parser differentialが成立する）（高リスク）
  - パターンC："ズレ"を生みやすい設計パターン（正規表現でURL妥当性＋ドメイン許可を同時にやる、host allowlistを"入力文字列上のhost"に当てている、validatorはURLライブラリA、fetcherはURLライブラリB、redirect追従で"検証対象"が途中で変わる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - validatorが文字列/別パーサで判定している
  - fetcherが別の解釈系で接続している
  - その実行系がinternal/metadataへ到達し得る
- 優先度の付け方（時間制約がある場合の順序）：
  1) 入口の発見（SaaS機能（preview/pdf/webhook）のように「実行系が分かれる」機能ほど現実的）
  2) 成立確認（レスポンス反映より「validatorログとfetcherログの不一致」を最優先にする）
  3) 禁則宛先到達の確認（internal/metadata等へ到達し得るか）
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：validatorとfetcherの差分観測（構文確定の差、正規化の差、実行環境の差）
  - 攻め筋2："ズレ"を生みやすい設計パターンの特定
  - 攻め筋3：成立根拠の確定（validatorログとfetcherログの不一致）
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - parser differential は「何を検証したか」と「何へ接続したか」が分離しているため、ログ設計が勝負
  - 目的は"奇妙なURLを投げる"ことではなく、次を満たす入口を見つけること：validatorが文字列/別パーサで判定している、fetcherが別の解釈系で接続している、その実行系がinternal/metadataへ到達し得る

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：validatorとfetcherが同一パーサで、正規化後実体ベースのallowlistをしている
  - 次の検証：
    - DNS rebinding/TOCTOU（前ファイル）で"時間差ズレ"が起きないか
    - worker/headless/pdf 等の実行系差でDNS/egressが分かれていないか（SaaS機能で再確認）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - validatorが確定した (scheme/host/port) と fetcherの実接続先（destination_ip）が整合
    - redirectは無効、またはホップごとに再検証されている
- 仮説B：validatorとfetcherで解釈がズレる（parser differentialが成立する）
  - 次の検証：
    - ズレの発生箇所を特定：validatorの構文確定か、fetcherの再パースか、プロキシ/redirectか
    - 実行系（api/worker/pdf/headless）ごとにズレが出るかを切り分け
    - 禁則宛先到達（internal/metadata）に繋がるかは"到達性ファイル群（01/02/05）"の枠組みで評価する
  - 期待する観測：
    - validatorログのhostと、fetcherログのHost/SNIまたはdestinationが不一致
    - 特定の入力表現でのみ不一致が再現（再現性がある）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/02_web/05_input/09_ssrf_parser_differential/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - validator_log（parsed components / decision）
  - fetcher_log（destination_ip / Host / SNI / redirect_chain）
  - egress_log（可能なら）
- 観測の取り方（どの視点で差分を見るか）：
  - "validatorパーサ"と"fetcherパーサ"を意図的に分けたミニアプリを用意し、validatorが確定した host/scheme/port と fetcherが実際に接続した destination_ip/Host/SNI の不一致をログで再現できるようにする
  - さらに、worker/headless/pdf の実行系差（ネットワーク・DNS・プロキシ）を差し替え可能にし、SaaS機能の現実に寄せる
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/ssrf_parser_differential 2>/dev/null
    cd ~/keda_evidence/ssrf_parser_differential
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 内部/metadataへの到達実証は許可範囲外
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id, job_id, raw_url, normalized_url, parsed_scheme, parsed_host, parsed_port, destination_ip, destination_port, host_header, sni

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# ログ相関の型（フィールドのみ）
# validator:
# - request_id, raw_url, normalized_url
# - parsed_scheme, parsed_host, parsed_port, parsed_userinfo_present
# - allowlist_rule_id, decision
# - resolved_ips, selected_ip, dns_ttl
#
# fetcher:
# - request_id/job_id, destination_ip, destination_port
# - host_header, sni
# - redirect_chain[{url, destination_ip, status}]
#
# 目的：validatorが許可した"host"と、fetcherが接続した"実体"の不一致を1行で証明できる形
~~~~

- この例で観測していること：
  - validatorとfetcherの差分観測（構文確定の差、正規化の差、実行環境の差）
  - parser differentialの成立根拠の確定
- 出力のどこを見るか（注目点）：
  - validator_logとfetcher_logの相関（同一URLでhost/destinationが一致するか）
  - redirect_chainでの各ホップのURLとdestination_ip
  - egress_logでの実際の接続先IP
- この例が使えないケース（前提が崩れるケース）：
  - ログが取得できない環境、またはログ設計が不十分な場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - SSRF対策の中核は「許可する宛先を"正規化後の実体"で固定する」こと。URL文字列の部分一致やブラックリストではなく、(1) 同一パーサで構文確定、(2) 正規化、(3) allowlist（scheme/port/host/解決後IP）、(4) redirectホップごとの再検証、(5) egress制御、までを一連の境界として設計する。
    - 満たす：単一パーサ化、正規化後の実体で判定、解決後IP検証＋固定化、redirectを抑制しホップごとに再検証、egress deny-by-default + 監視
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-08 Testing for SSRF
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - SSRFテストは「入口（URL入力点）」「到達性（internal/metadata）」「blind/非blind」「回避経路（URL検証の抜け・パース差・redirect・DNS）」を状態として確定し、観測（アプリログ/ネットワーク/OOB）で成立根拠を残す。URL parse smuggling（parser differential）は"検証しているつもり"を破る代表要因。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Vulnerability Analysis：検証ロジック（validator）と実接続スタック（fetcher）が同一のURL解釈をしているかを重点的に確認する（言語標準ライブラリ差、プロキシ差、非同期worker差）。Exploitation：ここで重要なのはペイロードではなく「どの段で解釈がズレ、禁止宛先へ接続されるか」を証拠化すること。Reporting：修正は"URLを厳しくチェック"ではなく「単一パーサ化＋正規化＋実体ベースのallowlist＋egress」を因果で提示する。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Discovery、Credential Access
  - 攻撃者の目的（この技術が支える意図）：
    - 入口：T1190（公開アプリの脆弱性悪用）
    - 目的：内部探索 T1046 / メタデータ到達（クラウド資格情報）T1552.005
    - 本ファイルは「SSRFの防御を回避して"到達性"を得る」ための成立根拠（差分要因）として位置づける。
  - 参照：https://attack.mitre.org/tactics/TA0001/

## 参考（必要最小限）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet（allowlist、scheme制限、実体ベース検証の考え方）
- OWASP Top 10 2021 A10 SSRF（redirect無効化、URL一貫性、DNS rebinding/TOCTOU）
- PortSwigger：URL validation bypass cheat sheet（曖昧URLがSSRF等の根因になる整理）
- RFC 3986（URI構文：authority / userinfo / host / port）
- Node.js URL docs / deprecations（URLパーサの系統差と厳格性）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- 関連 topics：`05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- 関連 topics：`05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`

---

## 深掘りリンク（最大8）
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- `05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
- `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
