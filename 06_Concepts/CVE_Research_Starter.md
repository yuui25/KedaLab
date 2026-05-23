# CVE 研究スターター

## このファイルの位置づけ

CVE 研究 / 脆弱性報告に着手するときの **入口知識** を集約したファイル。
個別手法（バリアントハント・特定バグクラス探索）の手順書ではなく、
「どこから情報を引くか」「どのライブラリ仕様を読むか」「CVE 申請時に何を選ぶか」といった
**研究手順のメタ知識** をまとめる。

参照元：

- [`Variant_Hunting.md`](./Variant_Hunting.md)（バリアントハント手法の本体。Step 1 の起点となる「既知 CVE」をどこから引くかをここで補う）
- [`CVSS_Scoring.md`](./CVSS_Scoring.md)（CVE 申請時の severity 算定）
- CVE 研究 / 脆弱性報告に新規着手するとき

> 本ファイルは **kedalab 側のスターター** として、研究着手前に引く一般的なメタ知識のみを置く。

---

## 起点 CVE / 脆弱性情報の入手元

バリアントハンティングや CVE 研究は「既知 CVE を起点に類似バグを探す」アプローチが多いので、**起点となる脆弱性情報をどこから引くか** が初動の質を決める。
情報源は「権威性（公式 advisory か速報か）」「速報性（公開からどのくらい早く見られるか）」「網羅性」が異なるので、用途で使い分ける。

### 1) 一次 advisory データベース（権威性：高）

修正済み・採番済みの公開 CVE を引くときの第一参照。

| ソース | URL | 特徴・引きどころ |
|--------|-----|----------------|
| **NVD** | `https://nvd.nist.gov/` | MITRE 採番 CVE に NVD analyst が CVSS / CWE / CPE を後付けした権威 DB。CPE で「特定製品 × 特定バージョン」の照合が可能 |
| **MITRE CVE List** | `https://www.cve.org/` | CNA から流入直後の CVE。NVD analysis が付く前の素の advisory が見える |
| **GitHub Security Advisories (GHSA) Database** | `https://github.com/advisories` | npm / PyPI / RubyGems / Maven / NuGet / Go / Rust など OSS エコシステム別に索引化。GHSA ID は CVE と独立して採番される |
| **OSV.dev** | `https://osv.dev/` | Google 運営。GHSA / RustSec / OSS-Fuzz / PyPA Advisory を横断検索。バージョン範囲指定のクエリ API あり |

**使い分けの目安：**

- 「この製品の既知 CVE を網羅」→ NVD で CPE 検索
- 「この OSS パッケージの advisory」→ GHSA / OSV
- 「採番直後・NVD 反映前の最新」→ MITRE CVE List

### 2) ベンダー Security Bulletin / PSIRT（権威性：高）

商用製品・エッジアプライアンス・OS ベンダーは独自に PSIRT を運営している。NVD より早く詳細が出ることが多い。

- Microsoft Security Response Center (MSRC) — Patch Tuesday・Exchange / Windows 系
- Cisco Security Advisories — ASA / IOS XE 系
- Fortinet PSIRT — FortiOS / FortiGate 系
- Citrix Security Bulletins — NetScaler / Gateway 系
- Ivanti Security Advisories — Connect Secure 系
- Palo Alto Networks Security Advisories — PAN-OS / GlobalProtect 系
- F5 Security Advisories — BIG-IP iControl / TMUI 系
- Atlassian Security Advisories — Confluence / Jira 系
- Apache Project Security — Tomcat / HTTP Server / Struts 系
- WordPress / プラグイン作者の changelog

> エッジアプライアンス系の CVE 照合は [`../02_Initial_Access/Edge_Appliance_CVEs.md`](../02_Initial_Access/Edge_Appliance_CVEs.md) と組み合わせて引く。

### 3) 研究者起点・メーリングリスト（速報性：高、権威性：中）

公式 advisory より早く動きが見える。バグクラスのディスカッションも追える。

| ソース | 特徴 |
|--------|------|
| **oss-security** (`https://oss-security.openwall.org/`) | OSS 脆弱性の事前共有・調整 ML。embargo 中の議論も多い |
| **Full Disclosure** (`https://seclists.org/fulldisclosure/`) | 即時公開志向の ML。CNA を通さず full disclosure する研究者の投稿が混じる |
| **seclists.org** | Bugtraq 後継として Full Disclosure / oss-security / nmap-dev を集約 |
| **CERT/CC VINCE notes** | 大型 / マルチベンダー脆弱性の coordinated disclosure |

> Full Disclosure / SNS 由来の情報は **「報告者の主張」であって独立検証されていない** ことがある。必ず NVD / ベンダー bulletin で裏取りしてから引用する。

### 4) コード変更・コミット観察（silent fix 発見）

CVE 採番されない「silent security fix」を探すための情報源。バリアント探索ではここが宝庫になる。

- **GitHub の commit / PR / issue 検索**：`fix CVE` `security fix` `XSS` `RCE` `SSRF` `sanitize` `escape` `allowlist` 等のキーワードで全文検索
- **CHANGELOG / Release Notes の "Security" セクション**：CVE 未採番でも記載されることが多い
- **GitHub の "Compare" 機能**：前リリースと最新の diff を読む。`v1.2.3...v1.2.4` 形式
- **Dependabot Advisory の更新通知**：依存パッケージの脆弱性検知時に表示される PR
- **maintainer の private security advisory drafts**（GitHub PVR）：外部からは見えないが、`pull/N.diff` で merge 後に観察可能

**着眼点：**

- 「入力検証追加」「エンコード追加」「allowlist 追加」「length check 追加」「regex の anchor 追加（`^...$`）」「`raw` → `escape` への置換」のような diff は CVE 未採番のセキュリティ修正である確率が高い
- 起点 CVE の修正コミットを読み、**同じ修正パターンが他ファイル / 他プロジェクトに適用されているか** を grep で確認する

### 5) 集約・通知サービス（網羅性：高）

複数ソースを横断して索引化したサービス。「自分が触っている技術スタックに関連する CVE のみ」を購読する用途。

- **GitHub Dependabot / Advisory Subscription**：リポジトリの依存パッケージに関連する advisory を自動通知
- **Snyk Vulnerability DB** (`https://security.snyk.io/`)：商用 DB だが Web 検索は無料
- **Socket.dev**：npm 中心、supply chain 観点を含む
- **VulnCheck / vulners.com**：商用寄りの集約サービス
- **CISA KEV Catalog** (`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`)：**実際にエクスプロイトされている** CVE。バリアント探索の優先度判定に有用
- **EPSS** (`https://www.first.org/epss/`)：今後 30 日でエクスプロイトされる確率。優先度付けの補助指標

### 6) SNS・コミュニティ（速報性：最高、権威性：低）

「採番される前に話題になっているバグクラス」を拾うためのチャネル。裏取り必須。

- **Twitter / X のセキュリティリサーチャー**：`#bugbounty` `#0day` `#infosec` タグ・著名研究者のフォロー
- **Mastodon `infosec.exchange`**：Twitter 移行組の議論
- **Reddit `r/netsec` `r/cybersecurity`**：CVE 関連の投稿が集約される
- **CVE Trends / cvecrowd**：Twitter での CVE 言及をスコア化
- **ProjectDiscovery `nuclei-templates`** の更新コミット：PoC 化された脆弱性が日次で追加される
- **PortSwigger Research / Web Security Academy ブログ**：新しい Web 攻撃技術の論文化

### 7) 入手元の組み立て方

複数ソースを順に引く。1 つだけでは穴ができる。

1. **NVD / GHSA** で起点 CVE の公式情報を確定（バージョン範囲・CWE・CVSS）
2. **ベンダー bulletin** で修正バージョン・パッチ内容を確認
3. **GitHub の修正コミット** を読みバグクラスを 3 要素（条件 + sink + 結果）で言語化（→ バリアントハント Step 1 へ）
4. **oss-security / 研究者ブログ** でバグクラスのディスカッションを追加収集（同種実装への言及がないかチェック）
5. **OSV / GHSA** で「同 OSS エコシステムの類似 advisory」を探す（既出バリアントがないかの重複確認）

**落とし穴：**

- NVD の published 日と実際の公開日にラグがある（数日〜数週間）。最新を追うなら GHSA / MITRE CVE List も併用する
- **未公開 CVE / embargo 中の advisory を扱う場合は固有情報を kedalab に書かない**（→ WRITING_GUIDE「CVE 研究・バリアントハント由来の固有値検出」grep セットでチェック）
- SNS 速報は「報告者の主張」段階。**裏取り前に PoC 構築や advisory 化を開始しない**

---

## ターゲットライブラリの仕様・ソースコードを調べる手順

PoC 解析・脆弱コードのデータフロー確認をするとき、未知のクラスやメソッドに当たる。以下の順で仕様を確認する。

**調べる順序（速い順）：**

1. **公式ドキュメント** — `[LIBRARY_NAME] docs` で検索
   - API リファレンスが充実していれば、クラス/メソッドの引数・デフォルト値・戻り値がすぐわかる
2. **PyPI ページ** — `https://pypi.org/project/[LIBRARY_NAME]/`
   - ホームページリンクとドキュメントリンクへの入口
3. **GitHub README** — リポジトリの README に基本的な使用例が載っていることが多い
4. **ターミナルで直接調べる**（ライブラリがインストール済みなら）

   ```bash
   python -c "import [MODULE]; help([MODULE].[CLASS])"
   ```

   デフォルト引数・メソッドシグネチャが即確認できる
5. **GitHub の raw URL でソースコードを固定バージョンで読む**

   ```
   https://raw.githubusercontent.com/[ORG]/[REPO]/refs/tags/v[VERSION]/[FILE_PATH]
   ```

   特定バージョンのコードを固定して読むことで、「このバージョンに本当にバグがあるか」をテキストで直接確認できる

**注意：行番号は Advisory に書かない**

GitHub の UI や WebFetch で見えた行番号は、バージョンやブランチが変わるとズレる。
Advisory ドラフトに行番号を書くと次のリリースで誤情報になる。
「関数名 + コード片」で特定する。

---

## GHSA / CVE 提出時の CWE 選定

CWE (Common Weakness Enumeration) は GHSA / CVE 申請フォームで必須の欄。
2,000 件以上あるが、実際に使うのは限られた「よく使う型」がほとんど。

### 適切な番号を見つける手順

**Step 1：脆弱性の「何が問題か」を1文で書く**

例: 「展開後のデータサイズに上限がない」「ユーザー入力を SQL にそのまま埋め込む」

**Step 2：CWE 公式サイトで検索**

- URL: `https://cwe.mitre.org/`
- 検索ボックスに英語キーワードを入力（例: `decompression`, `injection`, `path traversal`）

**Step 3：公開済み同型 CVE の CWE を参照する**

- 同型バグの公開済み CVE を NVD (`https://nvd.nist.gov/`) で検索
- その CVE に記載されている CWE を参考にする

**Step 4：GHSA フォームの候補から選ぶ**

- CWE 欄に番号またはキーワードを入力すると名称付きで候補が出る
- 名称を読んで「今回のバグの説明と一致するか」を確認する

### よく使う CWE 早見表

| CWE | 名称 | 代表的なバグ |
|-----|------|------------|
| CWE-409 | Improper Handling of Highly Compressed Data | decompression bomb |
| CWE-22  | Path Traversal | `../` によるディレクトリ脱出 |
| CWE-79  | XSS | Stored / Reflected / DOM XSS |
| CWE-89  | SQL Injection | ユーザー入力の生補間 |
| CWE-94  | Code Injection | テンプレートへのコード混入 |
| CWE-918 | SSRF | サーバー経由の内部リクエスト |
| CWE-400 | Uncontrolled Resource Consumption | 無制限ループ・メモリ消費 |
| CWE-502 | Deserialization of Untrusted Data | Java/Python デシリアライズ |

> 主分類として最も具体的な CWE を1つ選び、副分類として二次的な影響（例: CWE-400）を追加することが多い。フォームが1つしか許さない場合は「主分類のみ」でよい。

---

## 関連技術

- 関連：[`./Variant_Hunting.md`](./Variant_Hunting.md)（バリアント探索手法・本ファイルの入手元情報を起点に動く）
- 関連：[`./CVSS_Scoring.md`](./CVSS_Scoring.md)（CVE 申請時の severity 算定・vector 記載）
- 関連：[`../02_Initial_Access/Edge_Appliance_CVEs.md`](../02_Initial_Access/Edge_Appliance_CVEs.md)（エッジ製品の既知 CVE 照合）
