## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - SSRF対策の中核は「許可する宛先を“正規化後の実体”で固定する」こと。URL文字列の部分一致やブラックリストではなく、(1) 同一パーサで構文確定、(2) 正規化、(3) allowlist（scheme/port/host/解決後IP）、(4) redirectホップごとの再検証、(5) egress制御、までを一連の境界として設計する。:contentReference[oaicite:0]{index=0}
- WSTG
  - SSRFテストは「入口（URL入力点）」「到達性（internal/metadata）」「blind/非blind」「回避経路（URL検証の抜け・パース差・redirect・DNS）」を状態として確定し、観測（アプリログ/ネットワーク/OOB）で成立根拠を残す。URL parse smuggling（parser differential）は“検証しているつもり”を破る代表要因。:contentReference[oaicite:1]{index=1}
- PTES
  - Vulnerability Analysis：検証ロジック（validator）と実接続スタック（fetcher）が同一のURL解釈をしているかを重点的に確認する（言語標準ライブラリ差、プロキシ差、非同期worker差）。
  - Exploitation：ここで重要なのはペイロードではなく「どの段で解釈がズレ、禁止宛先へ接続されるか」を証拠化すること。
  - Reporting：修正は“URLを厳しくチェック”ではなく「単一パーサ化＋正規化＋実体ベースのallowlist＋egress」を因果で提示する。:contentReference[oaicite:2]{index=2}
- MITRE ATT&CK
  - 入口：T1190（公開アプリの脆弱性悪用）
  - 目的：内部探索 T1046 / メタデータ到達（クラウド資格情報）T1552.005
  - 本ファイルは「SSRFの防御を回避して“到達性”を得る」ための成立根拠（差分要因）として位置づける。:contentReference[oaicite:3]{index=3}

---

## タイトル
Parser Differential（URL Parse Smuggling）：検証系と実行系の“URL解釈のズレ”でSSRF境界が崩れる

---

## 目的（このファイルで到達する状態）
- URL parse smuggling（= parser differential）を「曖昧URLの小技」ではなく、**検証（validator）と実行（fetcher）の境界不整合**として説明できる。
- 実務で次を即断できる：
  - どの設計が“ズレ”を生むか（典型構造）
  - どの観測（ログ/相関キー/ネットワーク）で成立根拠を固めるか
  - 修正を「単一パーサ化＋実体ベースallowlist＋egress」に落とせる
- 次ファイル（SSRF各論やSaaS機能）で、同じ“ズレ”が worker/headless/pdf で増幅する理由を接続できる。

---

## 用語の固定（このリポジトリでの定義）
- Parser Differential（URL Parse Smuggling）
  - **同一のURL入力**に対し、(A) 検証側のパーサと (B) 実行側のパーサ/接続スタック が **異なる解釈**を行い、検証は通るが実行は禁則宛先へ到達する状態。
  - “Smuggling”はHTTP request smugglingと違い、ここでは「URL構造の解釈差の持ち込み」を指す（validator→fetcherの境界越え）。

---

## 位置づけ：SSRFは「URL文字列」ではなく「実接続先（実体）」の問題
- URLはRFC 3986の構文要素（scheme / authority / userinfo / host / port / path / query / fragment）で解釈される。authorityの定義（userinfo@host:port）が存在する以上、「@」「:」「[]」「%」などは“意味を持つ文字”であり、雑な文字列検査は破綻しやすい。:contentReference[oaicite:4]{index=4}
- OWASPはSSRF対策として、scheme/port/destinationのallowlist、redirect無効化、URL一貫性（DNS rebinding/TOCTOU）への注意を明示している。parser differentialはこの“URL一貫性”の別形態（構文解釈の一貫性崩壊）として扱うのが筋。:contentReference[oaicite:5]{index=5}
- PortSwiggerがURL validation bypass（SSRF/CORS/redirect向け）として体系化している通り、現代のSSRF事故の多くは「URL検証の設計」そのものが根因になりやすい。:contentReference[oaicite:6]{index=6}

---

## 境界モデル：validator≠fetcher が生む“3つのズレ”
### ズレ1：構文確定の差（どこまでがhostか）
- validator：文字列処理（split、正規表現、prefix判定）で host を“つもり”で抜く
- fetcher：正式なURLパーサで authority を解釈して host を確定する（または逆）
- 結果：validatorが見ているhostと、fetcherが接続するhostが一致しない。

### ズレ2：正規化の差（同じ意味でも表現が違う）
- validator：表層表現のdenylist/allowlist
- fetcher：デコード・正規化後の実体へ接続
- 結果：禁止対象（localhost / 内部IP / metadata）が、別表現で“合法”に見える。

### ズレ3：実行環境の差（ライブラリ・プロキシ・ランタイム）
- 同じ言語でも、URL APIが複数存在し解釈が異なることがある。
  - 例：Node.jsのURL APIはレガシーとWHATWGの2系統があり、取り扱いの差が明記されている。:contentReference[oaicite:7]{index=7}
- さらに、プロキシ経由・HTTPクライアント実装・リダイレクト追従で、最終的な解釈系が変わる。

---

## 成立根拠（差分＝成立根拠）：状態として“何が起きたら負けか”
> ここを状態化すると、ペイロードに依存せず「設計の穴」を説明できる。

### 状態PD0：URL入力点があり、サーバ側取得が走る
- 意味：SSRF入口が成立（機能単位で棚卸し対象）。

### 状態PD1：validatorがURLを“文字列として”検査している
- 典型：`startsWith("https://trusted/")`、`contains("trusted")`、`split("/")` など
- 意味：validatorがRFC準拠の構文確定をしていない時点で、解釈差の土台ができる。:contentReference[oaicite:8]{index=8}

### 状態PD2：fetcherが別パーサで解釈し、host/port/scheme がvalidatorと不一致
- 意味：parser differential が成立（中核）。

### 状態PD3：不一致の結果として、禁則宛先（internal/localhost/metadata等）へ到達
- 意味：SSRF防御の境界崩壊（最終的な負け条件）。
- 以降は到達性の問題（internal探索、metadataアクセス等）に接続。:contentReference[oaicite:9]{index=9}

---

## “ズレ”を生みやすい設計パターン（攻撃手順ではなく、設計レビュー観点）
### パターンA：正規表現でURL妥当性＋ドメイン許可を同時にやる
- 問題：URL構文は複雑で、正規表現で“完全一致の構文解釈”を再現しづらい。
- 結果：妥当性は通るが、パーサが解釈するhostが想定とズレる、という事故が起きやすい。:contentReference[oaicite:10]{index=10}

### パターンB：host allowlistを“入力文字列上のhost”に当てている
- 問題：authorityには userinfo@host:port があり、見えているhostと接続先hostがズレる設計を生みやすい。:contentReference[oaicite:11]{index=11}
- 結果：allowlistが“見かけ”に適用され、実接続先が別になる。

### パターンC：validatorはURLライブラリA、fetcherはURLライブラリB
- 例（概念）：アプリは標準ライブラリでparse → HTTPクライアントは内部で別parse
- NodeのようにAPI体系が複数あり、厳格性が変わる環境は特に注意が必要。:contentReference[oaicite:12]{index=12}

### パターンD：redirect追従で“検証対象”が途中で変わる
- 問題：最初のURLは許可されていても、redirect先でhost/schemeが変わる。
- 結果：parser differentialというより“検証対象のすり替え”だが、実務上は同じ事故として混ざるため、ここで同時に切り分ける。:contentReference[oaicite:13]{index=13}

---

## 観測ポイント（薄くしないための最小セット）
> parser differential は「何を検証したか」と「何へ接続したか」が分離しているため、ログ設計が勝負。

### 1) validatorログ（チェック時）
- raw_url / normalized_url
- parsed(scheme, host, port, userinfo有無)
- allowlist判定（どのルールに合致したか）
- dns結果（解決後IP一覧、選択IP、TTL）※IP許可/拒否をするなら必須
- request_id（相関キー）

### 2) fetcherログ（実行時）
- destination_ip:port（実接続先）
- SNI/Host header（HTTPS/HTTPで差が出るため）
- redirect_chain（ホップごとのURLとdestination_ip）
- request_id / job_id（非同期ならjob_id必須）

### 3) ネットワーク観測（可能なら）
- egressログ（src_component、dst_ip、dst_port）
- DNSログ（同一ホストの再解決・短TTLなど）

---

## 攻撃者視点での利用（意思決定：現実に寄せる）
- 目的は“奇妙なURLを投げる”ことではなく、次を満たす入口を見つけること：
  - validatorが文字列/別パーサで判定している
  - fetcherが別の解釈系で接続している
  - その実行系がinternal/metadataへ到達し得る
- 入口の発見は、SaaS機能（preview/pdf/webhook）のように「実行系が分かれる」機能ほど現実的。
- 成立確認は、レスポンス反映より「validatorログとfetcherログの不一致」を最優先にする（攻撃面の深掘りが“証拠”として強くなる）。

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：validatorとfetcherが同一パーサで、正規化後実体ベースのallowlistをしている
- 期待観測
  - validatorが確定した (scheme/host/port) と fetcherの実接続先（destination_ip）が整合
  - redirectは無効、またはホップごとに再検証されている
- 次の一手
  - DNS rebinding/TOCTOU（前ファイル）で“時間差ズレ”が起きないか
  - worker/headless/pdf 等の実行系差でDNS/egressが分かれていないか（SaaS機能で再確認）

### 仮説B：validatorとfetcherで解釈がズレる（parser differentialが成立する）
- 期待観測
  - validatorログのhostと、fetcherログのHost/SNIまたはdestinationが不一致
  - 特定の入力表現でのみ不一致が再現（再現性がある）
- 次の一手
  - ズレの発生箇所を特定：validatorの構文確定か、fetcherの再パースか、プロキシ/redirectか
  - 実行系（api/worker/pdf/headless）ごとにズレが出るかを切り分け
  - 禁則宛先到達（internal/metadata）に繋がるかは“到達性ファイル群（01/02/05）”の枠組みで評価する

---

## 防御設計（“URLを厳しく”ではなく、境界を壊れない形に固定する）
- 原則1：**単一パーサ化**（validatorとfetcherで同じURL解釈を使う）
  - 特にランタイム/ライブラリ差がある環境では「どのAPIが厳格か」を明示し、統一する。:contentReference[oaicite:14]{index=14}
- 原則2：**正規化後の実体で判定**（文字列ではなく、parse→normalize→reconstruct）
  - scheme/host/port をパーサで確定し、許可セットに照合する。:contentReference[oaicite:15]{index=15}
- 原則3：**解決後IP検証＋固定化**（rebinding/TOCTOU含む）
  - host allowlistだけでなく、解決後IPが禁則レンジでないことを確認し、実行時に同じ実体へ接続させる。:contentReference[oaicite:16]{index=16}
- 原則4：**redirectを抑制し、ホップごとに再検証**
  - “最終到達先”が変わると判定対象がすり替わるため、設計で縛る。:contentReference[oaicite:17]{index=17}
- 原則5：**egress deny-by-default + 監視**
  - アプリ層の一貫性が崩れても、ネットワーク層でinternal/metadata宛てを遮断する。

---

## 手を動かす検証（Labs設計：手順書ではなく設計）
- 追加候補Lab
  - `04_labs/02_web/05_input/09_ssrf_parser_differential/`
- 設計ゴール
  - “validatorパーサ”と“fetcherパーサ”を意図的に分けたミニアプリを用意し、
    - validatorが確定した host/scheme/port
    - fetcherが実際に接続した destination_ip/Host/SNI
    の不一致をログで再現できるようにする。
  - さらに、worker/headless/pdf の実行系差（ネットワーク・DNS・プロキシ）を差し替え可能にし、SaaS機能の現実に寄せる。
- 最低限の観測（必須）
  - validator_log（parsed components / decision）
  - fetcher_log（destination_ip / Host / SNI / redirect_chain）
  - egress_log（可能なら）

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
# 目的：validatorが許可した“host”と、fetcherが接続した“実体”の不一致を1行で証明できる形
~~~~

---

## 参考（一次情報）
- OWASP Server-Side Request Forgery Prevention Cheat Sheet（allowlist、scheme制限、実体ベース検証の考え方）:contentReference[oaicite:18]{index=18}
- OWASP Top 10 2021 A10 SSRF（redirect無効化、URL一貫性、DNS rebinding/TOCTOU）:contentReference[oaicite:19]{index=19}
- PortSwigger：URL validation bypass cheat sheet（曖昧URLがSSRF等の根因になる整理）:contentReference[oaicite:20]{index=20}
- RFC 3986（URI構文：authority / userinfo / host / port）:contentReference[oaicite:21]{index=21}
- Node.js URL docs / deprecations（URLパーサの系統差と厳格性）:contentReference[oaicite:22]{index=22}

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_02_url_tricks（redirect_dns_idn_ip）.md`
- `01_topics/02_web/05_input_09_ssrf_05_dns_rebinding（time_based_reachability）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_10_open_redirect（遷移先信頼境界）.md`
