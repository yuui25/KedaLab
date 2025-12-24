## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - URL入力を起点に「サーバが外部/内部へリクエストする」系の機能は、入力検証だけでなく **実接続先（解決後IP・redirect最終到達先）** の検証、許可schemeの制限、レスポンスの扱い（反映/保存/後続処理）を含めた境界設計が必要。SSRFは“URL妥当性”ではなく **信頼境界（SaaS実行基盤の到達性）** の問題として扱う。 :contentReference[oaicite:0]{index=0}
- WSTG
  - SSRFは「到達性（internal/metadata）」「レスポンス反映の有無（blind/非blind）」「redirect/DNS/URLパース差」を状態として確定し、検証の観測点（アプリログ・プロキシ・OOB）を設計する。URL入力点が“機能”として散在するため、機能カタログ化（webhook/preview/pdf/import等）が重要。 :contentReference[oaicite:1]{index=1}
- PTES
  - Vulnerability Analysis：SaaS機能（Webhook/Preview/PDF）が **どの実行系（worker/headless browser）** で動くか、どのネットワーク境界（egress/PrivateLink/VPC接続）を持つかを棚卸しして、到達性マップを作る。 :contentReference[oaicite:2]{index=2}
  - Exploitation：本質はペイロードではなく「成立根拠（接続ログ/OOB/差分）」「影響の境界（何が読める・何が起こる）」を確定すること。
  - Reporting：修正は“SSRF対策”の一言ではなく、(A) 機能要件の再定義、(B) allowlist+解決後IP検証、(C) redirect/DNS一貫性、(D) egress制御と監視、で因果を示す。 :contentReference[oaicite:3]{index=3}
- MITRE ATT&CK
  - 入口：T1190（公開アプリの悪用） :contentReference[oaicite:4]{index=4}
  - 到達性の利用：T1046（内部サービス探索） :contentReference[oaicite:5]{index=5}
  - クラウド資格情報：T1552.005（Cloud Instance Metadata API） :contentReference[oaicite:6]{index=6}
  - 本ファイルは「SaaS機能としての“外向き通信”が、攻撃者の Discovery / Credential Access を代行し得る」点を境界モデル化する。

---

## タイトル
SaaS機能SSRF（Webhook / Link Preview / PDF生成）：入力URLが“第三者の到達性”を借りる瞬間

---

## 目的（このファイルで到達する状態）
- Webhook / Link Preview / PDF生成 を、単なる「外部HTTPアクセス」ではなく **SaaS実行基盤の信頼境界（Confused Deputy）** として評価できる。
- “SSRFの成立”を、レスポンス反映の有無に依存せず、**成立根拠（観測点）** で確定できる。
- 実務で次を即断できる：
  - どの機能がURL入力を持ち、どの実行系（同期/非同期、worker/headless browser）で走るか
  - その実行系が「内部/metadata/プライベート接続」へ到達し得るか（SaaS側ネットワーク・顧客専用接続）
  - Webhook/Preview/PDFごとに「影響の質」がどう変わるか（副作用・情報漏えい・探索）
  - 修正の要点（allowlist・解決後IP・redirect再検証・egress・監視）を機能要件と結びつけて言語化できる

---

## 前提整理：SaaS機能SSRFの本質は「Confused Deputy」
- SSRFは「サーバが代理でリクエストする」だけでなく、**代理人（SaaS）が持つ到達性・権限・ネットワーク立地** を借りる攻撃。
- SaaS機能は、ユーザ入力からは見えない次の“資産”を持ち得る：
  - 実行環境の到達性（内部ネットワーク、管理面、metadata、サービスメッシュ）
  - 認証ヘッダやサービスアカウント（連携API、内部認証、クラウドIAM）
  - 非同期処理やキャッシュ（検証時と実行時がズレる、監査が追いにくい）
- したがって、SaaS機能のSSRF評価は「URL文字列の検証」ではなく **境界（どこへ到達できるか／どんな副作用があるか）** の確定が主目的。

---

## 機能カタログ：SaaSに埋め込まれやすい“URL入力点”
> 「SSRFの入口は検索すると大量に出る」では意味がない。実務では、機能単位に棚卸しして“見落としを無くす”のが価値。

### A. Webhook（外向きコールバック：Push）
- 例：イベント通知、CI/CD通知、チケット更新通知、支払/配送イベント通知
- 特徴
  - URLが「設定画面に存在」し、権限の低いユーザが変更できると入口が広い
  - 実行は非同期ワーカー（queue/worker）で、実行基盤が本体APIと異なることが多い
  - “リトライ”や“署名付与”などで、攻撃者視点の観測点が増える

### B. Link Preview（URLプレビュー：Unfurl / OGP / oEmbed）
- 例：チャット/コメント欄、チケット、Wiki、CMSでURLを貼るとカードが出る
- 特徴
  - 「貼り付けただけ」で発火し得るため、入口が非常に広い（権限モデルと直結）
  - Headless browser が使われると、HTTPクライアントよりも“ブラウザに近い取得挙動”になる
  - 1URLに見えても、実際は複数リソース（HTML→OGP→画像→リダイレクト）を辿るため、到達性が増える

### C. PDF生成（HTML→PDF / URL→PDF / レポート出力）
- 例：請求書、台帳、レポート、画面印刷、URLを指定してPDF化
- 特徴
  - HTMLレンダリングに伴い **外部リソース取得（画像/CSS/フォント）** が発生しやすい
  - “PDFに埋め込まれた内容”としてレスポンスが返る場合、SSRFが情報漏えいに直結し得る
  - PDF生成は攻撃研究が厚く、見落としがそのまま高インパクト化しやすい :contentReference[oaicite:7]{index=7}

---

## 境界モデル（共通）：SaaS機能SSRFを4層で捉える
### 1) 入力境界（URLがどこから来るか）
- 設定画面（webhook URL）
- 投稿/コメント（preview）
- テンプレ/レポート定義（pdf）

ここでの焦点は「誰が・どの権限でURLを差し込めるか」。
- 低権限ユーザが設定可能なら、SSRFは“想定外の権限伝播”になる（AuthZの話に接続）。

### 2) パース境界（URL構造がどう確定するか）
- 文字列チェック（禁止文字/禁止prefix）ではなく、
  - パーサが確定した scheme/host/port
  - 正規化後のURL
  を基準に検証しないと破綻する（Parser Differential）。 :contentReference[oaicite:8]{index=8}

### 3) 解決境界（DNS→IP、そして一貫性）
- host allowlistをしても、解決後IPが内部/metadataに落ちると境界が壊れる。
- redirectや非同期実行でTOCTOUが発生しやすい（検証時と実接続時がズレる）。 :contentReference[oaicite:9]{index=9}

### 4) 実行境界（Fetcherがどこから出ていくか）
- 本体APIサーバではなく、以下のどれが実行するかで到達性が変わる
  - webhook worker（キュー）
  - preview worker（キャッシュ）
  - headless browser cluster（レンダリング）
  - pdf renderer（wkhtmltopdf / headless chrome 等）
- ここが“SaaS機能SSRF”の肝：**同じ会社の同じプロダクトでも、実行系が違えば到達性が違う**。

---

## 成立根拠（差分＝成立根拠）：Webhook
### 状態W0：Webhook機能が存在し、URLが設定できる
- 意味：URL入力点（設定由来）が確定。AuthZと直結（誰が変更できるか）。
- 観測：設定変更の監査ログ（user_id/role/tenant、変更前後URL、時刻）

### 状態W1：外向きリクエストが発生する（到達性の借用が成立）
- 意味：SSRFクラス（“SaaSが代理で外に出る”）が成立。
- 観測：送信ログ（request_id / job_id / tenant_id / url / resolved_ip / status / duration）

### 状態W2：redirect追従・再解決がある（境界が伸びる）
- 意味：allowlistをしても最終宛先が変わると破綻する。OWASPが「redirect無効化」や「最終宛先の再検証」を推奨する理由。 :contentReference[oaicite:10]{index=10}

### 状態W3：署名/ヘッダ付与がある（“権限も借用”し得る）
- 意味：単なる到達性だけでなく、SaaSが持つコンテキスト（署名、APIキー、相関ID）が外部へ出る。
- 現実的な論点
  - Webhook署名は防御策だが、同時に「送信の真正性が高い証拠」でもある（ログ相関がやりやすい）
  - 重要なのは“どのヘッダが自動付与されるか”の把握（秘密情報の意図しない露出が無いか）

### 状態W4：プライベート接続（PrivateLink/VPN/専用線）がある
- 意味：SaaSが顧客VPC/社内へ到達できる構成だと、Webhookが「顧客内部への到達性」を借用し得る。
- 結果：SSRFが“ベンダ内”に留まらず、顧客内部の探索・到達性へ接続する（T1046に直結）。 :contentReference[oaicite:11]{index=11}
- 実務の重要点：この構成は「クラウド接続設計（04_cloud）」とも結びつくため、検証範囲・許可が必須。

---

## 成立根拠（差分＝成立根拠）：Link Preview
### 状態P1：投稿/コメント等の“本文”にURLを含めると取得が発生する
- 意味：入口が極端に広い。権限の低いユーザでも発火し得る（AuthZ境界の話）。
- 観測：preview生成ログ（message_id / user_id / url / fetch_result / cache_hit）

### 状態P2：Headless browser / レンダラで動作する
- 意味：HTTPクライアントより挙動が豊かで、取得連鎖（HTML→OGP→画像等）が増える。
- 結果の意味：1URLに見えても、裏で複数ホストへアクセスし得る（到達性が増える）。

### 状態P3：キャッシュがある（時間差・再検証問題）
- 意味：初回と再表示で取得が変わる（検証の再現性が落ちる）。
- 実務の焦点：キャッシュキーがURLのみだと、テナント境界やユーザ境界に影響（別ユーザの操作でfetchが走る等）を与え得る。

---

## 成立根拠（差分＝成立根拠）：PDF生成（URL→PDF / HTML→PDF）
### 状態D1：PDF生成が“外部リソースを取りに行く”設計
- 意味：SSRF入口が「ユーザのURL入力」だけでなく、「HTMLテンプレ内の参照」まで広がる。
- 現実に多い：画像/CSS/フォント/リンク解決がサーバ側で走る。

### 状態D2：生成物（PDF）に取得結果が反映される
- 意味：SSRFが“情報漏えい”へ直結しやすい（blindでなくなる）。
- PDF生成周りは研究・事例が多く、単なるSSRFより複合的に悪用される余地がある点は押さえる。 :contentReference[oaicite:12]{index=12}

### 状態D3：生成は非同期ジョブ（queue/worker）で動く
- 意味：本体APIとネットワークが違うことが多く、「本体では防げているのにPDFだけ穴」が起きやすい。

---

## 観測ポイント（実務で“薄くならない”最小セット）
> SaaS機能SSRFは、レスポンスが見えないケースが多い。最初から“証拠の取り方”を設計しないと結論が弱くなる。

### アプリ/ジョブログ（必須フィールド）
- tenant_id / user_id / role
- feature（webhook|preview|pdf）
- request_id / job_id（相関キー）
- raw_url / normalized_url
- parsed（scheme/host/port）
- dns（resolved_ip, resolved_ips, resolver, ttl）
- redirect_chain（各ホップのURLとresolved_ip）
- outbound（method, headersの有無の要約, status, bytes, duration, error_class）
- cache（hit/miss, key）

### ネットワーク観測（可能なら）
- egress proxy / FW / VPC Flow Logs（どの実行系から出たかの切り分けに効く）
- DNSログ（再解決の有無が分かる）
- 可能なら “metadata宛てアクセス検知” を別シグナルとして監視（DET0001）。 :contentReference[oaicite:13]{index=13}

---

## 攻撃者視点での利用（現実寄りの意思決定）
### 1) 入口の広さで狙いを変える
- Webhook：設定権限があるユーザ（管理者/運用者）を狙う、または権限昇格と組み合わせる
- Preview：一般ユーザでも発火できるなら、まずここが入口（T1190）になりやすい :contentReference[oaicite:14]{index=14}
- PDF：レポート/請求書など“生成物が戻る”機能は、影響が直接可視化しやすい（調査・証拠化が容易）

### 2) “到達性の質”でゴールを変える
- ただの外部アクセス：観測（OOB）を作るだけでも成立根拠になる
- internal/metadataに届く：探索（T1046）や資格情報取得（T1552.005）へ接続し得る :contentReference[oaicite:15]{index=15}
- PrivateLink等がある：SaaSが顧客内部へ到達できる構造は、影響が“顧客側”に飛ぶためリスクが跳ね上がる

### 3) blindでも“副作用”で前に進める
- 成立根拠はレスポンス反映ではなく、(A) 接続ログ、(B) DNS/HTTP OOB、(C) タイム差分、(D) 内部側ログ、で固める。
- ここを最初に設計できると、SaaS系の評価が薄くならない。

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：SaaS機能はHTTP/HTTPSのみ、かつ private/metadata へは到達不可
- 次の一手
  - redirect追従の有無（最終宛先の再検証があるか） :contentReference[oaicite:16]{index=16}
  - URL正規化の一貫性（parser differential の余地） :contentReference[oaicite:17]{index=17}
  - キャッシュ/非同期の差（実行系が変わる入口が無いか）
- 報告の焦点：境界が守られている根拠（ログ設計・ガード条件）を示し、残余リスク（運用上の監視）を明確化。

### 仮説B：いずれかの機能で private/metadata/社内到達が成立する
- 次の一手
  - “どの機能・どの実行系”で成立するかを切り分ける（webhook worker / preview cluster / pdf renderer）
  - allowlistの実装（hostだけか、解決後IP・redirect・再解決まで見ているか）を根拠付きで評価 :contentReference[oaicite:18]{index=18}
  - 監視/検知の観点（metadataアクセス検知、内部宛ての異常リクエスト頻度）を具体化 :contentReference[oaicite:19]{index=19}
- 報告の焦点：攻撃の方法ではなく「境界が破れている条件（成立根拠）」と「防御の因果（どの制御で閉じるか）」。

---

## 防御設計（SaaS機能として“成立しない”状態に落とす）
> OWASPのSSRF対策は“URL検証”より広い。SaaS機能は特に「実行系が分かれる」ため、設計を分解して適用する。 :contentReference[oaicite:20]{index=20}

### 1) 機能要件からallowlistを作る（原則：HTTP/HTTPSのみ）
- そもそも「なぜ外部URLが必要か」を機能ごとに言語化し、許可ドメインを限定する。
- 許可schemeは必要最小限（未使用schemeは拒否）。 :contentReference[oaicite:21]{index=21}

### 2) 解決後IPの検証（DNS rebinding/TOCTOUを前提に）
- host allowlistだけではなく、解決後IPが内部/loopback/link-local/metadata等に落ちないことを検証する。
- redirectホップごとに「再解決→再検証」を行う（最終宛先だけ見ても破綻する）。 :contentReference[oaicite:22]{index=22}

### 3) redirectを最小化し、ヘッダ付与を制御する
- redirect追従を無効化、またはホップ制限＋最終到達先の再検証。
- Webhook署名等は必要だが、秘密情報（トークン・内部ID）を不用意に外へ出さない設計にする。

### 4) egress制御と監視を“実行系ごと”に適用する
- 本体APIだけでなく、worker/headless/pdf renderer に同等のegrss制御を適用する（ここが実務で抜けやすい）。
- metadataアクセス検知など、SSRF特有の検知戦略を持つ。 :contentReference[oaicite:23]{index=23}

---

## 手を動かす検証（Labs設計：手順書ではなく設計）
- 追加候補Lab
  - `04_labs/02_web/05_input/09_ssrf_saas_webhook_preview_pdf/`
- 設計ゴール
  - 同一URL入力を「webhook worker / preview worker / pdf renderer」で動かし、
    - どの実行系がどこへ到達できるか
    - redirect/DNS/キャッシュで挙動がどう変わるか
    - 観測点（ログ/egress/DNS/OOB）をどう相関するか
    を再現できるようにする。
- 最低限の観測
  - アプリログ（job_id, normalized_url, resolved_ip, redirect_chain）
  - egressログ（宛先IP/port、実行系タグ）
  - DNSログ（再解決の有無）

---

## 例（最小限：ログ設計の型だけ）
~~~~
# SaaS機能SSRFの検証は「出力（PDF/preview）が見えない」ケースが多い。
# したがって、最初に “成立根拠” を残すログ設計を固める。
#
# 例：outbound_request_log（推奨フィールド）
# - tenant_id, user_id, feature, request_id, job_id
# - raw_url, normalized_url, scheme, host, port
# - resolved_ips, selected_ip, resolver, dns_ttl
# - redirect_chain[{url, resolved_ip, status}]
# - method, status, bytes, duration, error_class
# - cache_hit, cache_key
~~~~

---

## 参考（一次情報）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet :contentReference[oaicite:24]{index=24}
- OWASP Top 10 2021 A10 SSRF（対策観点：allowlist/redirect/DNS一貫性） :contentReference[oaicite:25]{index=25}
- PortSwigger: URL validation bypass cheat sheet（parser差・曖昧URLの重要性） :contentReference[oaicite:26]{index=26}
- PortSwigger Research: PDF生成まわりの攻撃研究（生成物に情報が乗る“性質”の理解） :contentReference[oaicite:27]{index=27}
- Intigriti: PDF generator におけるSSRF調査観点（機能としての入口整理） :contentReference[oaicite:28]{index=28}

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_03_protocol（http_gopher_file）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`
