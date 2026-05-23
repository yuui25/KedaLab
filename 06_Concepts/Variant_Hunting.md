# バリアントハンティング（Variant Hunting）

## このファイルの位置づけ

**参照元**: CVE 研究・脆弱性調査全般

既知の CVE を起点に「同じバグクラスの脆弱性を別プロジェクトで探す」手法の原理と思考プロセスを解説する。
新規研究者が最初の CVE を取得するための最も実績が高いアプローチ。

> **前提知識：** 起点 CVE をどこから引くか・CVE 申請時の CWE 選定・ライブラリ仕様の調べ方は
> [`CVE_Research_Starter.md`](./CVE_Research_Starter.md) に集約。本ファイルは Step 1 以降の
> 「バリアント探索手法」に絞る。

---

## 概念：なぜバリアントが存在するのか

セキュリティ修正は「報告された箇所だけ直す」ことが多い。以下の理由でバリアントが生まれる。

| 理由 | 具体例 |
|------|-------|
| **同じパターンが別ファイルに存在する** | sink を持つファイル A は修正されたが、同じバグクラスを持つ sibling ファイル B（同じエンコーダ・同じレンダリング経路を使う別画面コンポーネント）が未修正のまま残る |
| **フォークが修正を取り込んでいない** | 親リポが DOMPurify を追加したが fork 先はそのまま |
| **姉妹プロジェクトが同じコードを共有している** | 公開済み CVE があるプロジェクトの fork、または同カテゴリ（例：「Electron ノートアプリ」「Java ベース MQ クライアント」等）の別実装が、ライブラリ・UI コンポーネント・サニタイズロジックの同一パターンを保持しているケースは頻出 |
| **修正が不完全（partial fix）** | `resolveClass()` は修正したが `resolveProxyClass()` は未対応のまま。あるいは、テンプレートエンジンの `set` ディレクティブハンドラは prototype pollution を防いだが、同じエンジンの `foreach` ループ変数 / `macro` の名前バインディング / `macro` のパラメータ binding が同型 sink を残しているケース |

---

## 手順：5ステップ

> Step 1 は「起点 CVE が既に手元にある」前提で始まる。起点 CVE の入手元は [`CVE_Research_Starter.md`](./CVE_Research_Starter.md) を参照。

### Step 1 — バグクラスを抽出する

既知 CVE の advisory / diff を読み、「何が危険パターンか」を一言で言語化する。

例（バグクラスの言語化フォーマット）：
- 「Electron 系デスクトップアプリで **サーバー保存値 → サニタイズなし innerHTML 代入 + `nodeIntegration:true`** → XSS が RCE まで到達する」
- 「Java の `ObjectInputStream` で **`resolveClass()` には allowlist があるが `resolveProxyClass()` が同等チェックを通らない** → 任意クラスデシリアライズ RCE」
- 「`decodeURIComponent` 等の URL デコードが **HTML 用エンコーダの脅威モデル外** で適用され、`%XX` エンコード `<` がエンコーダを素通りして innerHTML に到達する」

バグクラスは「ライブラリ名」「製品名」ではなく **「条件 + sink + 結果」の3要素** で書く。
こう書いておくと、別実装に当てはめたときに「この条件は揃うか？」を 1 つずつ照合できる。

### Step 2 — 類似プロジェクトを見つける

バグクラスが同じカテゴリのプロジェクトを探す。

**探し方の例**:
- GitHub search: `"nodeIntegration: true" language:typescript` のように **危険パターンそのもの** をキーワードに検索（プロジェクト名で探さない。コード片で探す）
- カテゴリ検索: 「Electron note app」「self-hosted wiki」「Electron markdown editor」
- awesome-xxx 系リスト: `awesome-selfhosted` / `awesome-electron` 等でカテゴリを一覧する
- GitHub の "Similar repositories" / "Related topics" を辿る
- フォーク一覧: 元リポの fork を調べる（Settings → Insights → Forks）

### Step 3 — 危険パターンを grep で探す

対象リポジトリのソースコードを取得し、バグクラスの「危険パターン」を grep する。

```bash
# [Attacker] ローカルにクローン済みの場合
grep -rn "\.html(" src/ --include="*.ts"
grep -rn "innerHTML" src/ --include="*.ts"
grep -rn "nodeIntegration" src/ --include="*.ts"

# [外部API] GitHub API 経由で直接ファイルを確認する場合
# (クローンしなくても生ファイルを取得できる)
gh api repos/[ORG]/[REPO]/contents/src/path/to/file.ts \
  --jq '.content' | base64 -d
```

**シグナル**: grep でヒットしたら「exists = 候補確定」ではなく「データフローを確認する必要がある」という意味。

### Step 4 — データフローを確認する（脆弱性の確認）

sink を見つけたら「ユーザーが制御できるデータがその sink に到達するか」を確認する。

```
ユーザー入力
  → サーバー保存（PUT /api/... ）
  → サーバー返却（GET /api/... → JSON）
  → クライアント描画
  → sink: .html(data) ← ここにユーザー制御データが到達するか？
```

中間にサニタイズがあれば safe。なければ脆弱。

### Step 5 — PoC を段階的に構築する

| レベル | 内容 | 提出可能か |
|--------|------|---------|
| Level 1 | コードを読んで「理論上脆弱」 | 弱い（証拠なし） |
| Level 2 | ブラウザ単体で危険パターンが動作することを確認 | 可（原理の証明） |
| Level 3 | 実際のアプリで発火を確認（alert 等） | 強い（実証済み） |

Level 3 は必ず自分が所有・管理するインスタンスで確認する。第三者環境には一切ペイロードを送らない。

### Step 5.5 — 提出前の最終 verification ゲート（必須）

Level 3 PoC が動作しても、advisory ドラフトを CNA に提出する**直前**に「最新の対象環境で
再現するか」を必ず再確認する。これを怠ると、提出後に「ランタイム / 依存ライブラリが既に
修正済み」「依存パッケージの上位バージョンで挙動が変わっていた」が判明し、advisory
取り下げや誤報告という事態になる。

**確認すべき前提:**

- **ランタイムバージョン**: 言語のメジャー/マイナー更新で標準ライブラリ挙動が変わる
  (例: Python 3.11.9 で `ipaddress` モジュールの IPv4-mapped IPv6 自動展開が組み込まれた)
- **依存ライブラリの上位バージョン**: PoC 構築時点と提出時点でリリースされた新版で
  挙動が変わっていないか
- **OS / Docker base image のデフォルト**: `alpine` と `debian` で musl vs glibc 等の差異
- **対象アプリの最新リリース**: 起点 CVE と独立して、対象アプリのメンテナーが類似領域を
  改修している可能性

**実行方法:**

```bash
# [Attacker] 最新の公式 Docker image で PoC を再実行
docker run --rm -it python:3.11-slim sh -c "pip install [TARGET_LIB] && python -c '...'"
docker run --rm -it node:lts sh -c "npm install [TARGET_LIB] && node -e '...'"
```

**判定:**

| 結果 | 判断 |
|------|------|
| 想定通り発火する | advisory 提出に進む |
| 想定と挙動が違う（例: `is_loopback=True` が返るはずが False） | バージョン下限を二分探索で特定 → 「affected 範囲」を狭めて報告するか、対象が既に修正済みなら **取り下げ** |
| そもそも対象環境では bug class が成立しない | DROP。経緯を残し、教訓を汎用化して kedalab に反映 |

**落とし穴:**

- 「コードを読んで脆弱に見える」だけでは不十分。**実機で再現できなければ advisory に書いてはいけない**
- 自分の開発機（古い Python / 古い Node）で動いただけで「OK」としない。
  **最新の official base image で必ず再確認**
- 提出寸前のこの最終ゲートを「面倒だから skip」しない。前提崩壊した advisory を提出すると
  CNA / メンテナーから信用を失う

### Step 5.6 — インパクト判定ゲート（必須）

Step 5.5 で「最新環境で PoC が発火する」ことを確認したら、次に「これが独立 CVE として
価値があるか」を判定する。**PoC 発火 ≠ CVE 価値**。発火しても以下のどちらかに該当する
場合は DROP または fix-completion（メンテナーへの通常 issue 報告）に切り替える。

**判定軸 (a): バグクラスの典型インパクトに達するか**

各バグクラスには「これが起きないと CVE 採番されにくい」典型インパクトのラインがある。
PoC のインパクトがそのラインを下回ると、独立 CVE 価値は急落する。

| バグクラス | 典型インパクトの古典ライン | ラインに達しない例 |
|----------|---------|---------|
| Prototype Pollution (CWE-1321) | **グローバル `Object.prototype` 汚染**（プロセス全体に伝播） | インスタンスのみの prototype 変更（他オブジェクトに伝播しない） |
| SSRF (CWE-918) | 内部サービス / クラウドメタデータ API への到達 | 同一ホスト loopback のみで他に害なし |
| Template Injection (CWE-94 / CWE-1336) | 任意 JS / Python 実行（SSTI 経由 RCE） | コンテキスト外プロパティ参照のみの情報漏洩 |
| Path Traversal (CWE-22) | OS 任意ファイル読み取り | アプリ内データディレクトリのみ |

**判定軸 (b): 上位バグクラスで吸収される副次効果ではないか**

「攻撃成立条件」がより上位のバグクラスで吸収されてしまう場合、独立 CVE として打ち出すと
「上位バグクラスと何が違うのか」と却下されるリスクがある。

例:

- テンプレート完全制御前提の Prototype Pollution → SSTI で議論される（任意 JS 実行が独立して立証可能）
- 認証済みユーザのみで起きる Stored XSS → 認証バイパスや権限昇格が並存していれば後者が主因
- セルフ XSS → ユーザの自発操作前提 = CVE 化されにくい

**判定フロー:**

1. PoC が古典ラインに達するインパクトを実証できるか?
2. できない場合、上位バグクラスで議論される副次効果ではないか?
3. 両方 NO なら独立 CVE 価値あり → 提出
4. 一方でも YES なら DROP / fix-completion 報告に切替

**落とし穴:**

- 「PoC は動いた = CVE 取れる」と早合点しない。**インパクトの古典ラインを必ず確認**
- 上位バグクラスを当てはめずに無理に独立 CVE 化すると「Won't fix as security」
  「Informational」で却下され、報告側の信用を消耗する
- 古典ラインを下回る発見は通常 GitHub issue で fix-completion 報告に切り替えるのが穏当
  （メンテナンス改善としては価値がある）

---

## 思考トレースのモデルケース（Electron アプリの XSS→RCE バリアントを探す場合）

特定プロジェクトの固有値を伏せて、5ステップが実際にどう回るかを思考の流れで残す。
別のバグクラスに置き換えるときも同じ骨格が使える。

```
1. 起点となる公開 CVE / advisory を読む
   → バグクラスを 3 要素で言語化する：
     条件: Electron アプリで webPreferences に nodeIntegration:true（または contextIsolation:false）
     sink: jQuery .html() / innerHTML / dangerouslySetInnerHTML
     結果: ユーザー制御データが描画される → require('child_process') 到達 → RCE

2. 同カテゴリの類似プロジェクトを列挙する
   → 検索軸: カテゴリ（例「self-hosted note app (Electron)」）/ awesome-XXX リスト
            / 起点プロジェクトの fork 一覧 / 「Similar repositories」
   → 起点 CVE が修正していない 同パターン保持プロジェクトを候補化（[CANDIDATE_REPO]）

3. 候補リポジトリを grep する（危険パターンそのものを探す）
   → grep -rn "\.html(" src/client/ --include="*.ts"
   → grep -rn "innerHTML\s*=" src/ --include="*.ts"
   → 例: [CLIENT_RENDERING_FILE]:[LINE] で
        this.$[ELEMENT].html([SERVER_RESPONSE_FIELD]) のような形でヒット

4. データフローを確認する（grep ヒット ≠ 脆弱）
   → [SERVER_RESPONSE_FIELD] が API レスポンス由来（例: GET /api/[RESOURCE]/[ID]）
   → 経路上に DOMPurify.sanitize() などのサニタイズなし
   → ユーザーが書き込めるフィールド（タイトル・名前・コメント等）→ 到達確認

5. webPreferences を確認する（RCE エスカレーションゲート）
   → grep -rn "nodeIntegration" src/ --include="*.ts"
   → nodeIntegration: true が複数箇所で明示されている
   → contextIsolation: false / webSecurity: false の有無も確認

6. PoC Level 2: ブラウザ単体（poc_xss_sim.html）で innerHTML ペイロードが
   alert を発火できることを原理確認
7. PoC Level 3: 自分が所有・管理する候補アプリの脆弱バージョンをインストールし、
   実機で XSS → require('child_process') による RCE を発火確認
   （第三者環境には一切ペイロードを送らない）
8. ベンダー報告 → CNA を通じて CVE 申請
```

> 上の `[CANDIDATE_REPO]` `[CLIENT_RENDERING_FILE]:[LINE]` `[SERVER_RESPONSE_FIELD]` 等は、
> 本番では実体名に置き換わる。**自分の調査ノートで使うときも、kedalab に逆輸入する際は
> 角括弧プレースホルダに戻す**（特に発見が未公開 / 報告中の段階では絶対に固有値を持ち込まない）。

---

## 同一仕様の言語別独立実装へのバグクラス水平伝播

### パターンの概要

ネットワークプロトコル・バイナリシリアライズ仕様は、複数の言語で **互いに独立に実装** されていることが多い。1 言語のリファレンス実装で脆弱性が発見・修正されても、**他言語実装にはパッチが自動適用されない**。各実装チームは別組織であることが多く、修正通知が届かない（または届いても対応が遅れる）ため、同一バグクラスが複数の独立実装に長期間残存する。

### 着火条件

- 起点 CVE が「プロトコル仕様に由来する処理」に存在するとき
- バグクラスが「ライブラリ固有のコードバグ」ではなく「仕様の構造的な難所（再帰的入れ子・デコーダの処理フロー等）」に起因するとき
- 同仕様を実装する多言語ライブラリが存在するとき

### 探し方

1. 起点 CVE を読み、バグが「プロトコル仕様のどの部分」に起因するかを言語化する
2. 「同じ仕様を実装する他言語ライブラリ」を列挙する
   - 公式リポジトリの "Language Support" / "Client Libraries" 一覧
   - npm / PyPI / Maven / crates.io で仕様名をキーワード検索
3. 各実装の当該処理関数を探し、**修正前と同じパターンが残っていないか** grep する
4. 起点 CVE の修正 diff で「何が追加されたか」を確認し、同じ追加が各実装にあるかをチェックする

### 優先すべき実装の選び方

| 優先度 | 条件 |
|--------|------|
| 高 | 実装が独立（別 org / 別メンテナ）で、起点 CVE の修正をそもそも知らない可能性がある |
| 高 | エコシステムで広く使われている（ダウンロード数・依存プロジェクト数が多い） |
| 中 | 起点 CVE の修正後に開発開始または fork したが、修正が取り込まれていない |
| 低 | 同じ org が管理していて修正を受け取っている可能性が高い |

### 落とし穴

- **「他言語は既に直した」を確認してから報告する**: 同種の修正が既に同リポジトリの別 issue / PR に存在する場合は報告済みとして扱われる
- **修正の有無は「バージョン比較」ではなく「コード確認」で**: changelog に記載がなくても修正されているケースがある
- **仕様の deprecated 機能でも対象になる**: 後方互換のために残された処理経路が未修正のまま残ることが多い

---

## よくある落とし穴

| 落とし穴 | 対処 |
|---------|------|
| **修正済み CVE の変種を探して既存の CVE と重複してしまう** | OSV / GHSA で対象リポジトリの既知 CVE を先に確認する |
| **fork 先が既に修正している** | fork 先のコミット履歴や PR を確認してから報告する |
| **「コードが存在する」と「ユーザーが到達できる」は別** | 認証なしで到達できるエンドポイントかを確認する |
| **PoC なしで報告する** | Level 2 以上の PoC を必ず添付する。「理論上危険」だけでは CVE が通りにくい |
| **リポジトリが archived でも諦める** | 脆弱バージョンのユーザーはいる。CVE 申請は有効 |

---

## 探索対象の優先度付け

| 優先度 | 条件 |
|--------|------|
| 高 | フォーク元と同じコードを持つ fork（修正未反映の可能性）|
| 高 | 同じ問題ドメイン（ノートアプリ / メールクライアント等）の別プロジェクト |
| 中 | 同じライブラリ・フレームワークを使う別プロジェクト |
| 低 | 問題ドメインが違うが同じ技術スタック（Electron）を使うだけ |

---

## 関連技術

- 関連：[`./CVE_Research_Starter.md`](./CVE_Research_Starter.md)（起点 CVE 入手元・CWE 選定・ライブラリ仕様調査の前提知識）
- 関連：[`./CVSS_Scoring.md`](./CVSS_Scoring.md)（advisory 提出時の severity 算定）
- 関連：`../05_Tools_Reference/CVE_Notes.md`（既知 CVE エクスプロイト集）

