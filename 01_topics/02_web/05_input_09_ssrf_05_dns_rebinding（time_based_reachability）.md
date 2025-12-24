# 05_input_09_ssrf_05_dns_rebinding（time_based_reachability）

DNS Rebinding（時間差到達性）：検証と実行の"URL一貫性"が崩れると、allowlistは簡単に破れる

## 目的（この技術で到達する状態）
- DNS Rebinding を「DNSの小技」ではなく、**SSRF防御の設計不備（検証と実行の不一致＝TOCTOU）**として説明できる。
- 次を実務で即断できる：
  - どの実装が Rebinding に弱いか（典型パターン）
  - どんなログ/観測があれば "成立根拠" を確定できるか
  - 修正が「入力検証」だけでは不十分な理由と、具体の設計落とし所（URL一貫性・egress・監視）

## 前提（対象・範囲・想定）
- 対象：URL入力を起点にサーバ側が外部/内部へアクセスする機能、特に検証（チェック）と実行（アクセス）でDNS解決が分離される実装
- 想定する環境（例：クラウド/オンプレ、CDN/WAF有無、SSO/MFA有無）：
  - クラウド/オンプレミス、非同期ジョブ（queue/worker）、SaaS機能（webhook/preview/pdf）
  - 実行系が分離されている（api/worker/pdf/headless）
- できること/やらないこと（安全に検証する範囲）：
  - できること：検証フェーズと実行フェーズのDNS解決結果の差分観測、URL一貫性の確認、成立根拠の確定
  - やらないこと：破壊的な処理の実行、本番環境での過度な試行、内部/metadataへの到達実証（許可範囲外）
- 依存する前提知識（必要最小限）：
  - `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
  - `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
  - `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- 扱う範囲（本ファイルの守備範囲）
  - 扱う：
    - DNS Rebinding / TOCTOU によるSSRF防御回避
    - 検証と実行のDNS解決結果の不一致
    - URL一貫性の設計と検証
  - 扱わない（別ユニットへ接続）：
    - 一般的なSSRFの基礎 → `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
    - URLトリック・パーサ差分 → `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md` / `05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
    - SaaS機能としてのSSRF → `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象（プロトコル/データ構造/やり取りの単位）：
  - 検証フェーズの記録（raw_url / normalized_url / parsed_host / parsed_port / scheme / dns_result / check_decision / timestamp）
  - 実行フェーズの記録（request_id / job_id / outbound_destination_ip / outbound_sni / host_header / redirect_chain / timestamp）
  - DNS側の観測（同一ホスト名に対する複数回解決、TTL、解決結果の変化）
  - ネットワーク観測（egress、内部/metadataへのアクセス検知）
- 境界の観点：
  - 資産境界（管理主体・委託先・対象範囲の線引き）：
    - 検証と実行でDNS結果が一致しない場合、資産境界が崩れる
  - 信頼境界（外部連携・第三者・越境ポイント）：
    - DNS Rebinding は、同一ホスト名が時間差で別IPに解決されることで、**最初の検証（安全）**と**後の実行（危険）**の到達先がズレる現象
    - 非同期ジョブで実行系が分離されている場合、時間差が構造的に大きくなる
  - 権限境界（権限の切替/伝播/委任）：
    - host allowlist / denylist を"壊せる"条件（検証と実行でDNS結果が一致しない）
- 重要なフィールド/差分/状態（「ここが変わると意味が変わる」点）：
  - 状態R0：URL入力点があり、外向き通信が発生する
  - 状態R1：検証フェーズで hostname を解決し、IPをチェックしている
  - 状態R2：実行フェーズで再度 hostname を解決している（または別スタックが解決している）
  - 状態R3：検証時は"外部IP"だったが、実行時に"内部/禁則IP"へ到達した
  - 状態R4：DNS Rebindingが "SaaS機能" で増幅する

## 結果の意味（その出力が示す状態：何が言える/言えない）
- 何が"確定"できるか：
  - どの実装が Rebinding に弱いか（典型パターン）
  - 検証と実行でDNS結果が一致しないこと（URL一貫性が壊れている）
  - 成立根拠（検証時IPと実行時IPの不一致）
- 何が"推定"できるか（推定の根拠/前提）：
  - 検証と実行でDNS結果が"固定"されているか（URL一貫性が保たれているか）
  - どの段階で再解決が起きるか（アプリ/HTTPクライアント/プロキシ/OS）
  - 実行系の差（api/worker/pdf/headless）でDNS/egressが分かれていないか
- 何は"言えない"か（不足情報・観測限界）：
  - DNS Rebinding は"画面の出力"に出ないことが多い
  - 内部/metadataへの到達実証（許可範囲外）
  - 実行系の内部実装詳細（DNSキャッシュ戦略、resolver設定）
- よくある状態パターン（正常/異常/境界がズレている等）：
  - パターンA：検証と実行でDNS結果が"固定"されている（URL一貫性が保たれている）→ 比較的安全
  - パターンB：検証と実行でDNS結果がズレる（TOCTOUが成立している）→ 高リスク
  - パターンC：DNS Rebindingが "SaaS機能" で増幅する（Webhook/Preview/PDFなどは **チェックと実行の時間差が構造的に大きい**）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- この状態が示す"狙い目"：
  - host allowlist / denylist を"壊せる"条件を見つける
  - blind SSRFでも"成立根拠"をOOBで固められる
  - 到達性が内部/metadataに伸びると、目的が変わる（内部探索 T1046、メタデータ到達 T1552.005）
- 優先度の付け方（時間制約がある場合の順序）：
  1) 入口が URL 入力点で、かつ検証と実行でDNS結果が一致しない条件を探す
  2) 非同期ジョブで実行系が分離されている場合を優先
  3) redirect追従で最終到達先の再検証が甘い場合を確認
- 代表的な攻め筋（この観測から自然に繋がるもの）：
  - 攻め筋1：検証と実行でDNS結果が一致しない条件の特定
  - 攻め筋2：非同期ジョブでの時間差を利用したRebinding
  - 攻め筋3：SaaS機能（webhook/preview/pdf）での構造的な時間差の利用
- 「見える/見えない」による戦略変更（例：CDN配下、SSO前提、外部委託先など）：
  - DNS Rebinding は"画面の出力"に出ないことが多い。最初から観測設計を入れないと、結論が弱くなる。
  - レスポンスが返らない場合でも、DNS/HTTPの外部観測（OAST）で「実行された」「DNS解決が発生した」を切り分けられる。

## 次に試すこと（仮説A/Bの分岐と検証）
> ここが最重要。条件が違うと次の手が変わる形で書く。

- 仮説A：検証と実行でDNS結果が"固定"されている（URL一貫性が保たれている）
  - 次の検証：
    - redirect追従の有無と、ホップごとの再検証（redirectを入口に一貫性が崩れていないか）
    - 実行系の差（api/worker/pdf/headless）でDNS/egressが分かれていないか（SaaS機能はここが多い）
  - 期待する観測（成功/失敗時に何が見えるか）：
    - 検証フェーズで解決したIPが、実行フェーズでも同一
    - 実行フェーズで hostname 再解決が起きていない（または再解決しても結果が固定）
    - それでも内部IPへは到達しない（egress制御が効いている）
    - 「Rebindingができなかった」ではなく、「URL一貫性が保たれている根拠（ログ/設計）」を示す
- 仮説B：検証と実行でDNS結果がズレる（TOCTOUが成立している）
  - 次の検証：
    - "どの実行系"でズレるかを切り分ける（workerだけ、pdfだけ等）
    - どの段階で再解決が起きるか（アプリ/HTTPクライアント/プロキシ/OS）
    - egressで内部IPが遮断されているか（遮断されていれば影響は限定されるが、検知対象にはなる）
  - 期待する観測：
    - 同一hostnameに対し、検証時IPと実行時IPが異なる
    - 特に非同期ジョブ/リトライ/キャッシュ更新でズレが再現する
    - 実行時に内部/禁則IPへ到達し得る
    - 根因＝「URL一貫性が壊れている（検証と実行の分離）」であること
    - 影響＝内部探索/metadata等へ到達可能性があること（到達性が確認できた範囲で）

## 手を動かす検証（Labs連動：観測点を明確に）
- 検証環境（関連する `04_labs/`）
  - 参照ファイル：`04_labs/02_web/05_input/09_ssrf_dns_rebinding/`（追加候補）
- 取得する証跡（目的ベースで最小限）：
  - check_log：normalized_url, resolved_ips, ttl, decision, timestamp
  - use_log：job_id, destination_ip, redirect_chain, timestamp
  - dns_log：hostname, answer, ttl, query_time
  - egress_log：src_component, dst_ip, dst_port
- 観測の取り方（どの視点で差分を見るか）：
  - 「検証（check）→時間差→実行（use）」を意図的に作り、同一hostnameで destination_ip が変わる現象を観測する
  - 実行系を分ける（api と worker を分ける、PDF生成系を分ける等）ことで、DNS/キャッシュ差を再現する
- 実施方法（最高に具体的）：観測の準備と相関キー
  - 証跡ディレクトリ（必須）
    ~~~~
    mkdir -p ~/keda_evidence/ssrf_dns_rebinding 2>/dev/null
    cd ~/keda_evidence/ssrf_dns_rebinding
    ~~~~
  - 検証の前提を固定（スコープ事故を防ぐ）
    - 必須で決める（レポート先頭に書く）
      - 対象は **許可されたスコープ** のみ
      - 観測は **代表点の抽出** のみ
      - 内部/metadataへの到達実証は許可範囲外
  - 相関キー（最低限）を作る（後で必ず効く）
    - request_id, job_id, normalized_url, parsed_host, resolved_ips, selected_ip, destination_ip, timestamp

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
> 例示は"手段"であり"結論"ではない。必ず「何を観測している例か」を添える。

~~~~
# ログ相関の型（例：フィールドだけ）
# - check_phase: request_id, normalized_url, parsed_host, resolved_ips, selected_ip, ttl, decision, ts_check
# - use_phase  : request_id/job_id, normalized_url, destination_ip, dst_port, redirect_chain, ts_use
# - dns        : parsed_host, answer_ip, ttl, resolver, ts_dns
# "同一hostでcheckとuseのIPが一致しない" を1行で証明できる形にする
~~~~

- この例で観測していること：
  - 検証フェーズと実行フェーズのDNS解決結果の差分
  - URL一貫性が保たれているか、または壊れているかの確定
- 出力のどこを見るか（注目点）：
  - check_logとuse_logの相関（同一hostnameでIPが一致するか）
  - dns_logでの再解決の有無
  - egress_logでの実際の接続先IP
- この例が使えないケース（前提が崩れるケース）：
  - ログが取得できない環境、またはログ設計が不十分な場合

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：
  - 該当領域/章：V5 Validation, Sanitization and Encoding
  - 該当要件（可能ならID）：V5.1.1、V5.1.2、V5.2.1
  - このファイルの内容が「満たす/破れる」ポイント：
    - URL入力を起点にサーバ側が外部/内部へアクセスする機能では、**検証（チェック）と実行（アクセス）で同一のURL実体に到達していること**（URL一貫性）が要件になる。DNS Rebinding / TOCTOU を前提に、解決後IP・redirect最終到達先・再解決の有無を含めた防御を設計する。
    - 満たす：URL一貫性の定義、解決後IPの固定化と再検証、egress制御、監視
  - 参照：https://github.com/OWASP/ASVS
- WSTG：
  - 該当カテゴリ/テスト観点：WSTG-INPV-08 Testing for SSRF
  - 該当が薄い場合：この技術が支える前提（情報収集/境界特定/到達性推定 等）：
    - SSRFのテストは「入口（URL入力点）」「到達性（internal/metadata）」「blind/非blind」「防御の回避（filter/allowlist/redirect/DNS）」を状態として確定し、観測（アプリログ/ネットワーク/OOB）で根拠を残す。DNS Rebinding は"allowlist/denylistがあるのに成立する"代表的な差分要因。
  - 参照：https://owasp.org/www-project-web-security-testing-guide/
- PTES：
  - 該当フェーズ：Vulnerability Analysis、Exploitation、Reporting
  - 前後フェーズとの繋がり（1行）：
    - Vulnerability Analysis：URL検証ロジック（検証フェーズ）とHTTPクライアント（実行フェーズ）が **同じDNS結果を使う保証があるか** を重点観測する（ライブラリ差、キャッシュ差、非同期ジョブ差）。Exploitation：重要なのは手口ではなく「時間差で到達性が変化する構造」を証拠化し、影響（内部探索/メタデータアクセス等）に接続する。Reporting：修正は"DNS rebinding対策"の一言ではなく、(A) URL一貫性の定義、(B) 解決後IPの固定化と再検証、(C) egress制御、(D) 監視、の因果で書く。
  - 参照：https://pentest-standard.readthedocs.io/
- MITRE ATT&CK：
  - 該当戦術（必要なら技術）：Initial Access、Discovery、Credential Access
  - 攻撃者の目的（この技術が支える意図）：
    - 入口：T1190（公開アプリの悪用）
    - 内部探索：T1046（Network Service Discovery）
    - メタデータ/資格情報：T1552.005（Cloud Instance Metadata API）
    - DNS Rebinding 自体はATT&CKの"技術"というより、SSRF防御を回避して上記目的（Discovery/Credential Access）に到達するための「成立根拠（差分）」として位置づける。
  - 参照：https://attack.mitre.org/tactics/TA0001/

## 参考（必要最小限）
- OWASP Top10 2021 A10 SSRF（URL consistency / DNS rebinding / TOCTOUに言及）
- OWASP SSRF Prevention Cheat Sheet（SSRF入口としてWebhook等を明示、対策の考え方）
- OWASP WSTG SSRF（テスト観点：blind SSRFやPDF等の"後段で見える"ケース）
- PortSwigger：Blind SSRF と OAST観測（DNSだけ見えるケースの切り分け）
- MITRE ATT&CK：Cloud Instance Metadata API（SSRF到達先として典型）

## リポジトリ内リンク（最大3つまで）
- 関連 topics：`05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- 関連 topics：`05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- 関連 topics：`05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`

---

## 深掘りリンク（最大8）
- `05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `05_input_09_ssrf_03_protocol（http_gopher_file）.md`
- `05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- `05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
- `05_input_00_入力→実行境界（テンプレ デシリアライズ等）.md`
- `04_labs/01_local/02_proxy_計測・改変ポイント設計.md`
- `04_labs/01_local/03_capture_証跡取得（pcap/har/log）.md`
