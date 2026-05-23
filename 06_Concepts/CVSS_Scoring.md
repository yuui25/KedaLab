# CVSS スコアリング（v3.1 / v4.0）

## このファイルの位置づけ

報告書での severity 算定に CVSS（Common Vulnerability Scoring System）を使うとき、
「どのメトリックに何を入れるか」「v3.1 / v4.0 のどちらを使うか」「Worst-case と Likely-case のどちらで算定するか」の
判断ロジックを集約したファイル。計算機の使い方ではなく **判断軸** を残す。

参照元：

- [`Pentest_Fundamentals.md`](./Pentest_Fundamentals.md)（レポート構造：CVSS スコア / リスクレーティング項目）
- [`../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md`](../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md)（単独 4.3 / チェーン 8.0+ の具体例）
- 各脆弱性ファイルで severity を併記する際の共通参照先

権威ソース：

- **FIRST CVSS v3.1 Specification Document**（FIRST.org 公開、文書名は確信あり）
- **FIRST CVSS v4.0 Specification Document**（同上。2023 年 11 月公開）
- 本ファイル内の v4.0 記述は FIRST 公式 specification-document ページの記述で裏取り済み

---

## CVSS の全体構造

CVSS は 4 種類のメトリックグループから成る。v3.1 と v4.0 で構成が変わっている。

| グループ | v3.1 | v4.0 |
|---------|------|------|
| Base | あり（必須） | あり（必須） |
| Temporal / Threat | Temporal Metrics（E / RL / RC） | Threat Metrics（Exploit Maturity のみ） |
| Environmental | CR/IR/AR + Modified Base | CR/IR/AR + Modified Base（MSI/MSA に Safety 値追加）|
| Supplemental | なし | あり（Safety / Automatable / Recovery / Value Density / Response Effort / Provider Urgency）|

**Supplemental Metrics は最終スコアに影響しない**（情報伝達用）。v4.0 公式仕様に
"No metric will ... have any impact on the final CVSS score" と明記されている。

---

## v3.1 の Base Metrics

| 略号 | 名前 | 値 |
|------|------|-----|
| AV | Attack Vector | Network / Adjacent / Local / Physical |
| AC | Attack Complexity | Low / High |
| PR | Privileges Required | None / Low / High |
| UI | User Interaction | None / Required |
| S | Scope | Unchanged / Changed |
| C | Confidentiality | None / Low / High |
| I | Integrity | None / Low / High |
| A | Availability | None / Low / High |

**Scope の意味：** 脆弱性のあるコンポーネントの権限境界を越えて影響が及ぶ場合に `Changed`。
例：ハイパーバイザの脆弱性で別 VM に影響、Web アプリの XSS で別オリジンに影響、コンテナエスケープ等。

---

## v4.0 の主要変更点

v3.1 を使い慣れている場合に「どこが違うか」を引くためのセクション。

### Base Metrics の変更

- **Attack Requirements (AT) 追加**：None / Present。
  「脆弱なシステム側の前提条件（特定の設定・タイミング・状態）」を表現。
  従来 AC に押し込めていた「環境依存性」を分離した。
- **User Interaction (UI) が 3 段階化**：None / Passive / Active。
  Passive は被害者が意図せず触れるだけで発火（リンク踏むだけ等）、
  Active は明示的な操作（フォーム入力・ファイル開く等）が必要。
- **Scope 廃止 → 影響を 2 セットに分離**：
  - **Vulnerable System impact (VC / VI / VS)**：脆弱なコンポーネント自身への影響
  - **Subsequent System impact (SC / SI / SA)**：その先（他システム・他テナント）への影響
  - v3.1 で `Scope=Changed` だった攻撃は v4.0 では SC/SI/SA に非ゼロ値を入れて表現する

> v4.0 公式仕様の表記揺れ注意：Vulnerable System 側の Availability は仕様文書内で `VA` と書かれる箇所と `VS` と書かれる箇所がある（私の裏取り範囲では `VA` が主流）。実装時は公式 calculator のラベルに合わせる。

### Temporal → Threat（簡素化）

v3.1 の Temporal Metrics は 3 つ（E / RL / RC）あったが、v4.0 では **Exploit Maturity (E) のみ** に集約。

- v4.0 の E の値：Not Defined (X) / Attacked (A) / Proof-of-Concept (P) / Unreported (U)
- Remediation Level (RL) と Report Confidence (RC) は廃止
  - 理由：実運用で値が安定せず、スコアのブレ要因になっていた（FIRST 公式の説明に基づく）

### Supplemental Metrics の新設

スコアには影響しないが、受け手が独自に重み付けするための情報として記載できる：

| 略号 | 名前 | 値の例 |
|------|------|--------|
| S | Safety | Negligible / Present / Not Defined |
| AU | Automatable | No / Yes / Not Defined |
| R | Recovery | Automatic / User / Irrecoverable / Not Defined |
| V | Value Density | Diffuse / Concentrated / Not Defined |
| RE | Vulnerability Response Effort | Low / Moderate / High / Not Defined |
| U | Provider Urgency | Clear / Green / Amber / Red / Not Defined |

Safety は IEC 61508 ベースで「人の生命・健康・物理環境への影響」を表す。OT / 医療機器 / 自動車向けの拡張。

### スコア命名規則（v4.0）

v3.1 では「Base Score」「Temporal Score」「Environmental Score」と呼んでいたが、
v4.0 では伝達するスコアがどのメトリックを含むかを命名で明示する：

| 表記 | 含まれるメトリック |
|------|----------------|
| CVSS-B | Base のみ |
| CVSS-BT | Base + Threat |
| CVSS-BE | Base + Environmental |
| CVSS-BTE | Base + Threat + Environmental |

報告書に「CVSS 4.0: 8.6」とだけ書くと、どの組み合わせか不明になる。
**`CVSS-BT 4.0: 8.6` のように Tag を付ける** のが v4.0 公式推奨。

### 計算式の根本変更

v3.1 は線形式（Impact Sub-Score × Exploitability Sub-Score の加算的な合成）だったが、
v4.0 は **MacroVector / Equivalence Class ベース** の参照テーブル方式：

- 6 つの Equivalence Group (EQ1〜EQ6) でメトリック値を量子化
- 量子化結果の組（MacroVector）から参照テーブルでスコアを引く
- 同 MacroVector 内では追加の補間で微調整

実用上は **公式 calculator を使う**。手計算は v3.1 でも煩雑だが、v4.0 はテーブル依存なので手計算は実質不可能。

---

## Severity 帯（v3.1 / v4.0 共通）

| 評価 | スコア帯 |
|------|---------|
| None | 0.0 |
| Low | 0.1 – 3.9 |
| Medium | 4.0 – 6.9 |
| High | 7.0 – 8.9 |
| Critical | 9.0 – 10.0 |

帯の閾値は v3.1 / v4.0 で同一。

---

## どちらのバージョンを使うか（流派）

どれが正解という業界合意は無い。本番のペネトレ・CVE 申請では以下を確認した上で決める：

| 選択肢 | 採用される文脈 | 注意点 |
|--------|-------------|-------|
| **v3.1 のみ** | 対象組織の既存リスク管理プロセス（脆弱性管理台帳・SIEM ダッシュボード）が v3.1 前提 | v4.0 で新たに表現できる項目（AT、Subsequent System、Supplemental）が落ちる |
| **v3.1 + v4.0 併記** | 移行期。社内ダッシュボードと外部公表で見せ方が違う場合 | 報告書が冗長になる。同じ脆弱性で score が乖離すると「どちらを信じるか」の議論が生じる |
| **v4.0 のみ** | 新規 CVE 申請・OT / 医療系（Safety 必要）・後続システム影響が支配的な攻撃 | 受け手のツールが v4.0 未対応のことがある（NVD は段階的対応中） |

**実務での迷い方の傾向（経験則・未検証）：**

- 既存の脆弱性管理プロセスがあるなら、まずそれに合わせる
- 新規 CVE 申請なら CNA の指定に従う（GHSA は v3.1 と v4.0 両対応、選択可能）
- 「どちらが本来のリスクを表すか」で迷うなら、v4.0 の Subsequent System / Automatable / Recovery が必要かを軸に判断する

---

## Worst-case vs Likely-case（算定の保守度）

同じ脆弱性でも、どの前提で算定するかで 2 〜 3 点ブレる領域で、業界合意は無い。

| 流派 | 立場 | 例：認証後 SQL インジェクション |
|------|------|---------------------------------|
| **Worst-case** | 「攻撃が成立し得る最悪の条件」で算定。PR=None 寄り、UI=None 寄り、AC=Low 寄り | 「認証バイパスと連鎖すれば未認証 RCE 相当」→ Critical |
| **Likely-case** | 「実際に攻撃が成立する現実的条件」で算定。観測された前提を素直に反映 | 「認証必須・特権ロールのみ」→ Medium |

**判断軸の例：**

- 報告書の用途が「ベンダー報告（修正促進）」なら Worst-case 寄りで書いて緊急度を伝える
- 報告書の用途が「対象組織の SIEM 連携・優先度付け」なら Likely-case で書いて他のテストと比較可能にする
- CVE 申請（NVD published）には Likely-case 寄りが多い（NVD の Analyst も保守的に振る傾向）

**両方書くのが安全：** 単独スコア（Likely-case）と、現実的なチェーン込みスコア（Worst-case）を併記する。
`Open_Redirect.md` がこの形式を採用済み。

---

## Environmental Metrics の使いどころ

Base スコアは「製品の脆弱性そのもの」を表す。実環境での「対象組織にとってのリスク」は Environmental で補正する。

| メトリック | 意味 | 実例 |
|-----------|------|------|
| CR / IR / AR | C / I / A の重要度補正 | 認証 DB は CR=High、ログ収集サーバは IR=Medium・CR=Low |
| Modified Base Metrics | 環境特有の緩和を反映 | 内部ネットワーク限定なら MAV=Adjacent / Local |

**典型的な使い方：**

- 対象組織の資産分類に応じて CR/IR/AR を設定
- 緩和策（WAF・ネットワーク分離・MFA）が効いていれば Modified Base で反映
- Environmental は **対象組織ごとに違う**。ベンダー側公表値（Base のみ）と乖離するのは正常

---

## 報告書への書き方（推奨フォーマット）

レポートで CVSS を載せるとき、最低限以下を併記する。スコア値だけでは再現性がない。

```
CVSS 3.1 Base Score: 8.1 (High)
Vector: CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H

CVSS 4.0 Base Score (CVSS-B): 8.6 (High)
Vector: CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N
```

**書く順序：**

1. Score（数値）
2. Severity 帯（Low/Medium/High/Critical）
3. Vector string（必須。これがないと第三者が再現できない）
4. 算定根拠（特に AC / AT / PR を High/Present にした理由・Worst-case か Likely-case か）

Vector string を載せないと「なぜそのスコアになったか」を受け手が検証できず、
レビュー時に「スコアの妥当性」を議論できない。

---

## 各メトリックの選び方（自分でつけるときの観点）

自分で CVSS をつけるときに迷うのは「メトリックの定義」より「**この脆弱性は具体的にどの値か**」の判断。
ここでは各メトリックについて、判断軸とよく迷うパターンをまとめる。攻撃者視点で「もっとも保守的（=スコアが高くなる側）」に倒すのが基本だが、Likely-case で書くなら現実的条件で素直に評価する。

### AV — Attack Vector（攻撃経路）

「攻撃者はどこから攻撃するか」。最遠方から到達可能な経路で評価する。

| 値 | 選ぶ条件 | 例 |
|----|---------|----|
| Network (N) | インターネット越しに直接到達できる | 公開 Web アプリの XSS / SQLi、公開 API、Exchange の RCE |
| Adjacent (A) | 同 L2・隣接 VLAN・VPN セグメント・Bluetooth・Wi-Fi 範囲内が必要 | ARP spoofing、LLMNR/NBT-NS ポイズニング、Wi-Fi 攻撃、隣接 IPv6 ND |
| Local (L) | ローカルログイン or リモートシェル経由で攻撃用コードを実行できる必要 | Linux 権限昇格、SUID 悪用、ローカル DLL ハイジャック |
| Physical (P) | 物理タッチが必要 | コールドブート、USB 経由 DMA、JTAG |

**迷いどころ：**

- ファイルアップロードで侵入したシェルから内部 RCE → 単独の脆弱性としては AV=Network（攻撃者は最初からインターネット側）
- 認証必須 Web アプリ → AV=Network のまま（PR で「認証要」を表現する。AV を Local に下げない）
- VPN 経由のみ到達可能な内部サービス → AV=Network が多数派（VPN は経路の一種）、ただし「物理的に隔離された MGMT VLAN」は Adjacent

### AC — Attack Complexity（攻撃の複雑さ・v3.1 と v4.0 で意味が違う）

「攻撃者が制御できない条件」が必要かどうか。

| 値 | 選ぶ条件 |
|----|---------|
| Low (L) | 特殊条件なしで毎回成立する |
| High (H) | 攻撃者制御外の前提が必要（タイミング・レース・MITM 成立・対象設定が必要） |

**v3.1 と v4.0 の重要な違い：**

- v3.1：AC は「攻撃手法の複雑さ + 対象側の設定前提」を両方含んでいた
- v4.0：AC は「攻撃手法そのものの困難度」だけになり、「対象側の設定前提」は新メトリック **AT** に分離された

| 状況 | v3.1 | v4.0 |
|------|------|------|
| メモリレースの成立が必要 | AC=High | AC=High, AT=N |
| 「対象が特定の設定値のとき限定」で成立 | AC=High | AC=Low, AT=Present |
| MITM 確立が必要 | AC=High | AC=High, AT=N |

v3.1 では両者が同じ AC=High に押し込まれて区別できなかった。v4.0 で別メトリック化された。

### AT — Attack Requirements（v4.0 新規・対象側の前提条件）

「対象システム側に特定の条件が揃っていないと攻撃が成立しない」場合に Present。

| 値 | 選ぶ条件 |
|----|---------|
| None (N) | 対象側に特殊な条件は不要。デフォルト状態で成立 |
| Present (P) | 特定の設定・特定の機能有効化・特定バージョン・特定のデータ状態などが必要 |

**例：**

- 「特定の registry 値が 1 のときのみ脆弱」→ AT=Present
- 「機能 X を有効化しているときのみ」→ AT=Present
- 「デフォルト設定で常に成立」→ AT=None

### PR — Privileges Required（認証要否）

| 値 | 選ぶ条件 |
|----|---------|
| None (N) | 認証不要・ゲストアクセス可 |
| Low (L) | 一般ユーザー権限が必要（自己登録 OK のサービスを含む） |
| High (H) | 管理者・特権ロールが必要 |

**迷いどころ：**

- 「サインアップが自由にできる SaaS の一般ユーザー権限」→ PR=Low（攻撃者が自前で取得できるため）
- 「SaaS のテナント管理者権限」→ PR=High
- 「テナント A の管理者が テナント B に影響を与える」→ PR=High かつ Scope=Changed (v3.1) / SC≠N (v4.0)

### UI — User Interaction（被害者の関与）

| v3.1 | v4.0 | 選ぶ条件 |
|------|------|---------|
| None (N) | None (N) | 攻撃者単独で成立。被害者の操作不要 |
| Required (R) | Passive (P) | 被害者がページを開く・メールをプレビューするなど **能動的意図を伴わない** 動作で発火 |
| Required (R) | Active (A) | 被害者が明示的操作（フォーム送信・ファイル実行・ボタンクリック）が必要 |

v3.1 は 2 段階だが v4.0 で 3 段階に分かれた。v3.1 で UI=Required としていた多くの XSS は v4.0 では Passive 寄り、CSRF やソーシャル工学を要するものは Active 寄り。

**例：**

- 反射型 XSS（リンクを踏ませる）→ v3.1: Required / v4.0: Active
- 格納型 XSS（管理画面を開くだけで発火）→ v3.1: Required / v4.0: Passive
- メールプレビューで自動発火する RCE → v3.1: Required / v4.0: Passive

### S — Scope（v3.1 のみ）/ Subsequent System Impact（v4.0）

v3.1 の Scope=Changed は「脆弱コンポーネントの権限境界を越えて影響が及ぶ」場合。
v4.0 では Scope は廃止され、別系統の SC/SI/SA で「波及先システムへの影響」を表現する。

**v3.1 Scope：**

| 値 | 選ぶ条件 |
|----|---------|
| Unchanged (U) | 影響が脆弱コンポーネントの権限境界（同一セキュリティ管理権限）内に収まる |
| Changed (C) | 脆弱コンポーネントの権限境界を越えて、別の管理権限下のリソースに影響が及ぶ |

**v4.0 SC / SI / SA（Subsequent System Impact）：**

| 値 | 選ぶ条件 |
|----|---------|
| None (N) | 波及先システム（脆弱コンポーネント外）への影響なし |
| Low (L) | 波及先で部分的な漏洩・改ざん・可用性低下。攻撃者がコントロールできる範囲が限定的 |
| High (H) | 波及先で全データ漏洩・完全な改ざん権・完全停止・任意コード実行による全制御 |

v3.1 の `Scope=Changed` は v4.0 では「SC / SI / SA のいずれかに非ゼロ値を入れる」形で表現する。
v3.1 では波及の有無（2 値）しか表せなかったが、v4.0 は波及先の C/I/A 影響度を 3 段階で個別に評価できる。

**Scope=Changed / SC≠N にすべき典型例：**

- コンテナエスケープ → ホスト OS に影響
- ハイパーバイザの脆弱性 → 別ゲスト VM に影響
- XSS で別オリジンに到達できる（postMessage 経由など）
- SSRF でクラウドメタデータサーバ（169.254.169.254）に到達
- AD CS ESC8 で別ユーザー（DC$）の認証情報を取得

迷ったときの判断軸：「脆弱なソフトウェア自身が許可している権限境界を、攻撃が越えているか」。

### C / I / A（v3.1）と VC/VI/VA + SC/SI/SA（v4.0）

CVSS の影響メトリックは情報セキュリティの 3 要素（CIA）を個別に評価する。

| 略号 | 名前 | 何への影響か |
|------|------|-------------|
| C | Confidentiality（機密性） | データの**漏洩・読取**。本来読めない情報を攻撃者が取得できる |
| I | Integrity（完全性） | データの**改ざん・偽造・書込**。本来書けない情報を攻撃者が変更できる |
| A | Availability（可用性） | サービスの**停止・遅延・利用不能化**。正規利用者が使えなくなる |

v4.0 では各要素を **VC/VI/VA（脆弱コンポーネント自身への影響）** と **SC/SI/SA（波及先システムへの影響）** に分割して評価する（接頭辞 V = Vulnerable, S = Subsequent）。v3.1 の Scope=Changed は v4.0 では SC/SI/SA に非ゼロ値を入れる形で表現される。

各要素について None/Low/High を以下で判断する：

| 値 | 選ぶ条件 |
|----|---------|
| None (N) | 影響なし |
| Low (L) | 部分的な漏洩・改ざん・可用性低下。攻撃者がコントロールできる範囲が限定的 |
| High (H) | 全データ漏洩・完全な改ざん権・完全停止・任意コード実行による全制御 |

**判断のコツ：**

- RCE は基本的に C=H, I=H, A=H（任意コード実行 = すべてを失う）
- SQLi で全テーブル読める → C=H、書込権限なし → I=N、DROP TABLE 可 → I=H, A=H
- パストラバーサル（読取のみ） → C=H, I=N, A=N
- DoS のみ → C=N, I=N, A=H
- 情報漏洩でメアドだけ → C=L

**v4.0 では「脆弱コンポーネント自身（VC/VI/VA）」と「波及先（SC/SI/SA）」を別個に評価する：**

- 認証されてないユーザーが Web アプリで RCE → VC/VI/VA=H、SC/SI/SA は OS 側に何ができるかで決まる（root 取得まで行けば SC/SI/SA=H）
- XSS（同オリジン内で完結） → VC=L〜H、SC=N
- XSS で iframe を通じて別オリジンの情報を読む → SC=L〜H

### v3.1 Vector の最小チェック項目

vector string を書く前に必ず通る順序：

1. AV：インターネットから直接到達できるか
2. AC：攻撃者制御外の前提があるか
3. PR：認証は必要か。必要ならどのレベルか
4. UI：被害者の操作が要るか
5. S：別の権限境界に影響が及ぶか
6. C/I/A：それぞれ単独で None/Low/High を決める

迷ったら **公式 Calculator にメトリックを 1 つずつ入れて、選択した瞬間にスコアがどう動くか** を確認する。
極端な値（全 High）から始めて条件で削っていく書き方もある（Worst-case 起点）。

### よくある誤算定パターン

| 誤算定 | 訂正 |
|--------|------|
| 「認証必須だから AV=Local」 | AV はネットワーク到達性。認証は PR で表現する |
| 「自分が VPN で繋いでいるから AV=Adjacent」 | VPN は経路の一種。インターネット越しの経路があるなら AV=Network |
| 「攻撃者が誘導してユーザーが踏むから UI=None」 | リンクを踏ませる = UI=Required (v3.1) / Active (v4.0) |
| 「他システムに影響しないから Scope=Unchanged」 | Web アプリ XSS で別オリジン読取は Scope=Changed |
| 「DoS だから A=Low」 | サービス完全停止なら A=High。Low は「部分的劣化」 |
| 「RCE だが管理者権限が要るから C=Low」 | 影響範囲は管理者として何を読めるかで決まる。通常は C=High |
| 「PoC があるから AC=Low」 | AC は攻撃手法の困難度であり、PoC の有無とは別軸 |

### Environmental の補正タイミング

Base スコアを確定したあと、対象組織固有の条件で補正する：

| 状況 | 補正方法 |
|------|---------|
| 対象システムが内部 LAN 限定 | MAV=Adjacent or Local |
| 緩和策（WAF / IPS）が攻撃を阻止する | MAV / MAC / MPR で再評価 |
| データの重要度が高い（PII / 認証 DB） | CR=High |
| ログ収集サーバなど機密性が低い資産 | CR=Low |
| 可用性が最重要（決済・医療） | AR=High |

Environmental は **対象組織ごとに別**。ベンダー公表値（Base のみ）と Environmental 補正後の値が乖離するのは想定どおりであって、間違いではない。

---

## kedalab 個別ファイルでの併記ルール（運用）

各脆弱性ファイル（`02_Initial_Access/Web_Vulnerabilities/*` 等）で severity に触れるときは：

- **単独スコアと、現実的なチェーン込みスコアを別立てで書く**（`Open_Redirect.md` 形式）
- **v3.1 と v4.0 のどちらを書いているか明示する**
- スコア値だけでなく Vector string も書くのが望ましい（読み手が CR/IR/AR を差し替えやすい）

「スコアは X.Y」で終わらせない。脆弱性 → スコアの導出ロジックが本質。

---

## 関連技術

- 関連：[`./Pentest_Fundamentals.md`](./Pentest_Fundamentals.md)（レポート構造全体）
- 関連：[`../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md`](../02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md)（単独 vs チェーン併記の実例）
- 関連：[`./Variant_Hunting.md`](./Variant_Hunting.md)（CVE 申請時のスコア算定）
