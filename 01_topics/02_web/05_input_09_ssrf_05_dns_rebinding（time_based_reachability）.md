## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - URL入力を起点にサーバ側が外部/内部へアクセスする機能では、**検証（チェック）と実行（アクセス）で同一のURL実体に到達していること**（URL一貫性）が要件になる。DNS Rebinding / TOCTOU を前提に、解決後IP・redirect最終到達先・再解決の有無を含めた防御を設計する。 :contentReference[oaicite:0]{index=0}
- WSTG
  - SSRFのテストは「入口（URL入力点）」「到達性（internal/metadata）」「blind/非blind」「防御の回避（filter/allowlist/redirect/DNS）」を状態として確定し、観測（アプリログ/ネットワーク/OOB）で根拠を残す。DNS Rebinding は“allowlist/denylistがあるのに成立する”代表的な差分要因。 :contentReference[oaicite:1]{index=1}
- PTES
  - Vulnerability Analysis：URL検証ロジック（検証フェーズ）とHTTPクライアント（実行フェーズ）が **同じDNS結果を使う保証があるか** を重点観測する（ライブラリ差、キャッシュ差、非同期ジョブ差）。
  - Exploitation：重要なのは手口ではなく「時間差で到達性が変化する構造」を証拠化し、影響（内部探索/メタデータアクセス等）に接続する。
  - Reporting：修正は“DNS rebinding対策”の一言ではなく、(A) URL一貫性の定義、(B) 解決後IPの固定化と再検証、(C) egress制御、(D) 監視、の因果で書く。 :contentReference[oaicite:2]{index=2}
- MITRE ATT&CK
  - 入口：T1190（公開アプリの悪用） :contentReference[oaicite:3]{index=3}
  - 内部探索：T1046（Network Service Discovery） :contentReference[oaicite:4]{index=4}
  - メタデータ/資格情報：T1552.005（Cloud Instance Metadata API） :contentReference[oaicite:5]{index=5}
  - DNS Rebinding 自体はATT&CKの“技術”というより、SSRF防御を回避して上記目的（Discovery/Credential Access）に到達するための「成立根拠（差分）」として位置づける。

---

## タイトル
DNS Rebinding（時間差到達性）：検証と実行の“URL一貫性”が崩れると、allowlistは簡単に破れる

---

## 目的（このファイルで到達する状態）
- DNS Rebinding を「DNSの小技」ではなく、**SSRF防御の設計不備（検証と実行の不一致＝TOCTOU）**として説明できる。
- 次を実務で即断できる：
  - どの実装が Rebinding に弱いか（典型パターン）
  - どんなログ/観測があれば “成立根拠” を確定できるか
  - 修正が「入力検証」だけでは不十分な理由と、具体の設計落とし所（URL一貫性・egress・監視）

---

## 前提整理：DNS Rebindingは「時間差で到達性が変わる」問題
- DNS Rebinding は、同一ホスト名が時間差で別IPに解決される（または複数IPのうち選択が変わる）ことで、**最初の検証（安全）**と**後の実行（危険）**の到達先がズレる現象。
- SSRF対策で頻出の誤解：
  - 「host allowlistしているから安全」→ hostは同じでも **解決後IPが変わる**。
  - 「private IPを弾いているから安全」→ 弾くのは“検証時の解決結果”であり、実行時に再解決されると破綻する。
- OWASP Top10は、SSRF対策として **DNS rebinding と TOCTOU を避けるための“URL一貫性”に注意**することを明示している。 :contentReference[oaicite:6]{index=6}

---

## 観測ポイント（何を見れば「時間差で壊れる」ことを証明できるか）
> DNS Rebinding は“画面の出力”に出ないことが多い。最初から観測設計を入れないと、結論が弱くなる。

### 観測ポイント1：検証フェーズの記録（チェック時）
- raw_url / normalized_url（正規化後）
- parsed_host / parsed_port / scheme
- dns_result（解決したIP一覧、選択IP、TTL、resolver）
- check_decision（許可/拒否、拒否理由）
- timestamp（チェック時刻）

### 観測ポイント2：実行フェーズの記録（実アクセス時）
- request_id / job_id（非同期なら必須）
- outbound_destination_ip（実際の接続先IP）
- outbound_sni / host_header（HTTPSやHost依存がある場合）
- redirect_chain（ホップごとにURLと解決IP）
- timestamp（実行時刻）

### 観測ポイント3：DNS側の観測（可能なら）
- 同一ホスト名に対する複数回解決
- TTLが極端に短い、または解決結果が短時間で変化
- 失敗→成功、成功→別IP、の遷移

### 観測ポイント4：ネットワーク観測（可能なら）
- egress（宛先IP/port、実行系タグ：api/worker/pdf/headless等）
- 内部/metadata（169.254.169.254 など）へのアクセス検知 :contentReference[oaicite:7]{index=7}

---

## 結果の意味（状態として説明：DNS Rebindingが“成立した”とは何か）
> “Rebindingができる/できない”ではなく、どの防御がどの条件で壊れるかを状態で言う。

### 状態R0：URL入力点があり、外向き通信が発生する
- 意味：SSRFの入口が存在（WSTGの「注入点特定」）。 :contentReference[oaicite:8]{index=8}

### 状態R1：検証フェーズで hostname を解決し、IPをチェックしている
- 意味：一見まともな防御。しかし “検証と実行で同じ結果を使う保証” がなければ脆い。

### 状態R2：実行フェーズで再度 hostname を解決している（または別スタックが解決している）
- 意味：ここが Rebinding の成立根拠（差分）。
- 典型：
  - 検証：アプリ側（言語標準resolver）
  - 実行：HTTPクライアント側（別resolver/OSキャッシュ/プロキシDNS）
  - 非同期：ワーカーが別ネットワーク/別DNSを使う

### 状態R3：検証時は“外部IP”だったが、実行時に“内部/禁則IP”へ到達した
- 意味：URL一貫性が壊れており、allowlist/denylistが機能していないことの証明。
- 影響：内部探索（T1046）、メタデータ到達（T1552.005）へ繋がる可能性が現実化。 :contentReference[oaicite:9]{index=9}

### 状態R4：DNS Rebindingが “SaaS機能” で増幅する
- 意味：Webhook/Preview/PDFなどは **チェックと実行の時間差が構造的に大きい**。
  - UI保存時に検証 → 数秒〜数分後にジョブ実行
  - キャッシュ更新やリトライで“後から再実行”が起きる
- 結果：Rebindingの成立確率が上がり、再現性も上がる（攻撃者に有利）。

---

## 攻撃者視点での利用（意思決定に効く形で：過度に手順化しない）
> ここは「攻撃の手順」ではなく「成立根拠がどこにあると、何ができるか」を決める章。

### 利用1：host allowlist / denylist を“壊せる”条件を見つける
- 入口が URL 入力点で、かつ
  - 検証と実行でDNS結果が一致しない
  - 非同期ジョブで実行系が分離されている
  - redirect追従で最終到達先の再検証が甘い
  のいずれかがあると、allowlistの安全性は急落する。 :contentReference[oaicite:10]{index=10}

### 利用2：blind SSRFでも“成立根拠”をOOBで固められる
- レスポンスが返らない場合でも、DNS/HTTPの外部観測（OAST）で「実行された」「DNS解決が発生した」を切り分けられる。 :contentReference[oaicite:11]{index=11}

### 利用3：到達性が内部/metadataに伸びると、目的が変わる
- 内部到達：内部サービス探索（T1046）
- metadata到達：クラウド資格情報等（T1552.005）
- したがって、Rebindingの評価は「成功/失敗」ではなく「到達性がどこまで伸びたか」で価値が決まる。 :contentReference[oaicite:12]{index=12}

---

## 次に試すこと（仮説A/B：条件が違うと次の手が変わる）
### 仮説A：検証と実行でDNS結果が“固定”されている（URL一貫性が保たれている）
観測上、以下が満たされる：
- 検証フェーズで解決したIPが、実行フェーズでも同一
- 実行フェーズで hostname 再解決が起きていない（または再解決しても結果が固定）
- それでも内部IPへは到達しない（egress制御が効いている）

次の一手：
- redirect追従の有無と、ホップごとの再検証（redirectを入口に一貫性が崩れていないか） :contentReference[oaicite:13]{index=13}
- 実行系の差（api/worker/pdf/headless）でDNS/egressが分かれていないか（SaaS機能はここが多い）

結論の書き方：
- 「Rebindingができなかった」ではなく、「URL一貫性が保たれている根拠（ログ/設計）」を示す。

### 仮説B：検証と実行でDNS結果がズレる（TOCTOUが成立している）
観測上、以下が出る：
- 同一hostnameに対し、検証時IPと実行時IPが異なる
- 特に非同期ジョブ/リトライ/キャッシュ更新でズレが再現する
- 実行時に内部/禁則IPへ到達し得る

次の一手：
- “どの実行系”でズレるかを切り分ける（workerだけ、pdfだけ等）
- どの段階で再解決が起きるか（アプリ/HTTPクライアント/プロキシ/OS）
- egressで内部IPが遮断されているか（遮断されていれば影響は限定されるが、検知対象にはなる）

報告の焦点：
- 根因＝「URL一貫性が壊れている（検証と実行の分離）」であること
- 影響＝内部探索/metadata等へ到達可能性があること（到達性が確認できた範囲で） :contentReference[oaicite:14]{index=14}

---

## 防御設計（“DNS Rebindingを禁止する”ではなく、壊れない設計にする）
> OWASP Top10が言う “URL consistency / TOCTOU” を、実装設計に落とす。 :contentReference[oaicite:15]{index=15}

### 1) URL一貫性の定義（検証と実行で同一実体に到達する）
- 原則：検証時に解決した **IP（または接続先）を“固定”して実行**し、実行時に hostname 再解決しない。
- ただし、固定しても redirect があると別ホストへ飛ぶため、redirectは無効化、またはホップごとに同じ検証を強制する。 :contentReference[oaicite:16]{index=16}

### 2) 解決後IPの検証（private/link-local/loopback/metadata等）
- host allowlistだけでなく、解決後IPで禁則レンジを判定する（実装は“判定をどこでやるか”が重要）。
- 判定のタイミングは「検証時だけ」ではなく、「実行に使う接続先を確定する瞬間」に置く。

### 3) 実行系を分離している場合は“全系に同等の制御”を入れる
- webhook worker / preview cluster / pdf renderer が別ネットワークなら、
  - DNSポリシー（同一resolver/同一キャッシュ戦略）
  - egress制御（内部宛て遮断）
  - ログ（resolved_ipとdestination_ip）
  を全て揃える。揃っていないと、Rebindingの成立点が“穴として残る”。

### 4) 最後の砦：egress（deny by default）と監視
- アプリ層の一貫性が崩れても、ネットワーク層で内部/metadata宛てを遮断すれば影響を止められる。 :contentReference[oaicite:17]{index=17}
- metadata宛てアクセスの検知は、SSRF/リバインディング双方の有効なシグナルになり得る。 :contentReference[oaicite:18]{index=18}

---

## 手を動かす検証（Labs設計：手順書ではなく“設計”）
- 追加候補Lab（例）
  - `04_labs/02_web/05_input/09_ssrf_dns_rebinding/`
- 設計ゴール
  - 「検証（check）→時間差→実行（use）」を意図的に作り、同一hostnameで destination_ip が変わる現象を観測する
  - 実行系を分ける（api と worker を分ける、PDF生成系を分ける等）ことで、DNS/キャッシュ差を再現する
- 最低限の観測（ログ設計）
  - check_log：normalized_url, resolved_ips, ttl, decision, timestamp
  - use_log：job_id, destination_ip, redirect_chain, timestamp
  - dns_log：hostname, answer, ttl, query_time
  - egress_log：src_component, dst_ip, dst_port

~~~~
# ログ相関の型（例：フィールドだけ）
# - check_phase: request_id, normalized_url, parsed_host, resolved_ips, selected_ip, ttl, decision, ts_check
# - use_phase  : request_id/job_id, normalized_url, destination_ip, dst_port, redirect_chain, ts_use
# - dns        : parsed_host, answer_ip, ttl, resolver, ts_dns
# “同一hostでcheckとuseのIPが一致しない” を1行で証明できる形にする
~~~~

---

## 参考（一次情報）
- OWASP Top10 2021 A10 SSRF（URL consistency / DNS rebinding / TOCTOUに言及） :contentReference[oaicite:19]{index=19}
- OWASP SSRF Prevention Cheat Sheet（SSRF入口としてWebhook等を明示、対策の考え方） :contentReference[oaicite:20]{index=20}
- OWASP WSTG SSRF（テスト観点：blind SSRFやPDF等の“後段で見える”ケース） :contentReference[oaicite:21]{index=21}
- PortSwigger：Blind SSRF と OAST観測（DNSだけ見えるケースの切り分け） :contentReference[oaicite:22]{index=22}
- MITRE ATT&CK：Cloud Instance Metadata API（SSRF到達先として典型） :contentReference[oaicite:23]{index=23}

---

## リポジトリ内リンク（最大3つまで）
- `01_topics/02_web/05_input_09_ssrf_01_reachability（internal_localhost_metadata）.md`
- `01_topics/02_web/05_input_09_ssrf_04_saas_features（webhook_preview_pdf）.md`
- `01_topics/02_web/05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`

---

## 次（作成候補順）
- `01_topics/02_web/05_input_09_ssrf_06_parser_differential（url_parse_smuggling）.md`
