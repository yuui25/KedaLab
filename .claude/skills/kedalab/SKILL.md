---
name: kedalab
description: 現在の会話や貼り付けた実行ログ・演習結果から汎用ナレッジを抽出し、kedalab に反映する。実行結果のレビュー（誤り・見落とし・欠落の仕分け）込みで、技術ファイルの追記/新規作成、Triage ルール（triage_rules.js）・Worksheet 型（worksheet_template.js）・各種索引への追記まで扱う。「kedalab に追加して」「これを見て反映して」「今のナレッジを反映して」と言われたら起動。`/kedalab` / `/kedalab <トピック>` で発火。kedalab フォルダ内で直接 CC を起動した場合の専用スキル。
---

# kedalab — ナレッジ抽出と反映（kedalab プロジェクト直接版）

kedalab は keda の汎用ナレッジ集。**現在の会話で扱った技術・手法・落とし穴・判断ロジック** を、
特定プロジェクト・特定演習に依存しない形に翻訳して蓄積する。

本 skill は kedalab プロジェクト直接版で、**カレント会話のみを抽出対象**とする。

---

# 起動時に必ず Read するファイル

以下 4 ファイルは **kedalab の規範ソース**。これらに書かれた内容を絶対正として従う。
skill 本文と矛盾した場合は **4 ファイル側が優先**。

1. `./CLAUDE.md` — 書き込み手順・フォルダ構成
2. `./WRITING_GUIDE.md` — 書き方ルール・禁止事項・自己チェック grep
3. `./README.md` — 全体方針・状況からの導線テーブル
4. `./TECHNIQUES_INDEX.md` — 既存ナレッジ一覧

加えて状況に応じて：

- `./TECHNIQUES_INDEX_AI_ML.md` — AI/ML 系トピック扱い時
- `./TECHNIQUES_INDEX_MITRE.md` / `./TECHNIQUES_INDEX_WSTG.md` — 該当 ID がある時
- `./TECHNIQUES_INDEX_GUIDELINES.md` — NIST SP 800-115 章 / PTES フェーズに明確該当する時
- `./_pending/README.md` — `_pending/` への新規作成時
- `./_workspace/conventions/Folder_Convention_20260515.md` — フォルダ規約
- `./99_kedaweb/SPEC.md` — **kedaweb の拡張点（Triage の `js/triage_rules.js` / Worksheet の `js/worksheet_template.js`）に反映する時**

---

# 大原則

## 既存ファイル優先

- **新規ファイルを作る前に既存ファイルへの追記で済むかを必ず検討**
- `TECHNIQUES_INDEX.md` を keyword 検索して関連トピックを確認
- 既存ファイルの構造・トーンに従う

## 配置先判定

WRITING_GUIDE.md の「公開コンテンツと作業領域の区別」表に従う：

| 内容 | 配置先 |
|---|---|
| 技術手順・概念（汎用化済み）| `00_Playbook/` 〜 `07_AI_Red_Teaming/` |
| 未公開 CVE 関連（embargo 中）| `_pending/` |
| レビュー・メタ文書・下書き・タスク・定義 | `_workspace/<分類>/` |

`_` 始まりのトップレベルは公開対象外（kedaweb 不可視・GitHub 非 push）。

## システム固有値の徹底排除

WRITING_GUIDE.md「禁止事項」「例示に使ってはいけない具体値」表に従う：

- プロジェクト名・製品名は記載しない（CVE 番号は published のもののみ）
- ファイルパス・関数名・行番号は記載しない（バグクラス表現に書き換える）
- バージョン番号は「修正の境界として意味があるとき」のみ
- 演習由来語・固有値・Kali 名指しは禁止

## ナレッジの粒度・テンプレート

- **新規ファイルは新構造（技術単位ブロック方式）で書く**: 各 `## N.` ブロックに「`**コマンド:**` → 観測される出力→次のアクションの表 → `**注意:**`」を局所化する。旧構造（`観点・着眼点` / `手順` を独立セクション）は既存ファイル読解用。詳細は WRITING_GUIDE.md「ファイルテンプレート（新構造）」
- コマンド集ではなく**攻撃者の思考トレース**（なぜその手を選ぶか・何が出たら次に何をするか）を残す
- **「必ず実行する動作」は必ずコードブロックで出す**。`>` 引用・太字・リンク送りの散文に埋めると読み飛ばされて実行されない（WRITING_GUIDE.md「書き方」参照）

---

# 標準ワークフロー

## Step 1 — 現在の会話から学びを抽出

会話で扱った内容を以下に分類：

| カテゴリ | 例 |
|---|---|
| 技術手順 | 新コマンド・新 exploit pattern・新ツール使用法 |
| 概念（なぜ）| プロトコル仕様・ライブラリ挙動・OS 振る舞いの「知らなかった原理」|
| 落とし穴 | 「こう書くと通らない」「環境差でこう変わる」具体例 |
| 方法論 | 「この判断はこうフローで進める」等のメタ手順 |

各項目について `TECHNIQUES_INDEX.md` で既存有無を確認。

## Step 2 — 配置先を決定

1. 既存ファイルに追記できるならその該当セクションへ
2. 既存ファイルの「関連」リンクで参照されるべきならリンク追加
3. 新規ファイル必要なら配置フォルダ判定（CLAUDE.md 手順 3 に従う）

## Step 3 — ユーザに反映方針を確認

抽出した学びと配置候補を提示し、実行可否を確認。
**ユーザ承認なく既存ファイルを編集しない**。

提示フォーマット例：

```
今回の会話から以下を kedalab に反映できます:

[既存ファイル追記]
- <filepath> に「XXX」セクションを追加（現状の章立てに沿った形で挿入）

[既存ファイル参照リンク]
- <filepath> の「関連技術」に <new_concept> へのリンクを追加

[新規 _pending ファイル]
- _pending/<FILENAME>.md を新規作成（理由: <embargo 関連 / 固有値含む可能性>）

進めてよいですか?
```

## Step 4 — 反映実行

ユーザ承認後：

1. 該当ファイルを Edit または新規 Write
2. 主インデックス（`TECHNIQUES_INDEX.md` / AI 系は `TECHNIQUES_INDEX_AI_ML.md`）を更新
   - 同一ファイル由来の複数行は「Basic → 高難度」順を保つ
   - `_pending/` 配下はインデックス登録しない。代わりに `_pending/README.md` に「公開時に追加するインデックスエントリ」として記録
3. 二次インデックスも該当があれば 1 行追記（**無理に当てはめない・発散させない**）
   - MITRE ATT&CK ID → `TECHNIQUES_INDEX_MITRE.md`（AD/Linux/ネットワーク系）
   - OWASP WSTG ID → `TECHNIQUES_INDEX_WSTG.md`（Web 系）
   - NIST SP 800-115 章 / PTES フェーズ → `TECHNIQUES_INDEX_GUIDELINES.md`（**既存の包括行（例「02_Initial_Access/ 全般」）で間接カバーされるものは追記しない**）
4. **kedaweb 拡張点への反映（該当する場合）**: SPEC.md に従い、**データ配列だけ編集し `app.js`/`index.html`/`css` は触らない**
   - Triage に新シグナル → `99_kedaweb/js/triage_rules.js` の `rules` に 1 オブジェクト追記（`pattern` + `targets[{file, why}]`、`version` 更新）
   - Worksheet（型）にチェック項目 → `99_kedaweb/js/worksheet_template.js` の `sections`/`items` を編集（`version` 更新）
   - **`targets[].file` / `file` / `playbook` は必ず実在パスを確認**
5. README.md 導線テーブル更新が必要なら実施（`00_Playbook/` 新規作成時）
6. **PostToolUse hook（`C:\keda\.shared\hooks\kedaweb-compat.ps1`）が自動実行される**
   - kedaweb 不変条件チェック + WRITING_GUIDE 自己チェック grep + 公開リポ衛生の追加パターン
   - 違反があれば追加コンテキストとして報告される（新規ファイルは TECHNIQUES_INDEX 登録漏れを `[I2]` で指摘）

## Step 5 — 完了報告

ユーザに以下を伝える：

- 変更したファイルのリスト
- 公開待ち項目があれば embargo 期限と公開時の移動先
- hook のチェック結果（違反検出ゼロを確認）

---

# 変種モード: 実行ログ・実施結果からの反映（レビュー込み）

ユーザが**自分でペネトレ/演習を実施した結果**（会話への貼り付け、または `_workspace/` 配下の `.txt` 等）を示して
「kedalab に反映して」「これを見て追加して」と言った場合は、いきなり追記せず**まずレビューしてから**進める。
今回の標準パターン。

## R1 — レビュー（追記の前に必ず提示）

実行ログを読み、以下に仕分けて提示する：

| 区分 | 内容 |
|---|---|
| 実行の誤り | コマンド誤用・前提の取り違え・見落とした必須手順（例: `-p-` 未実施、`-L` と接続の混同、存在しない辞書を指定） |
| 見落とし | **kedalab に既にあるのに使えていない**情報（該当ファイル・セクションを示す）。**＝findability の失敗。発火トリガが観測可能な出力（エラー文字列・バナー・http-title の製品名・ツールの無反応）なら、最優先で Triage ルール化の候補**（下記 R1.5）|
| 欠落 | **そもそも kedalab に無い**技術（＝追記候補。今回の本丸） |
| kedaweb 反映候補 | triage の新シグナル / worksheet の型チェック項目になりそうなもの |

## R1.5 — 見落とし → Triage ルール化（既定ステップ）

**R1 で「見落とし」が出たら、その都度 Triage ルール化を既定で提案する。** 見落としは「知識が無い」のではなく「観測した症状から該当ファイルに辿り着けなかった」＝ findability の失敗。kedalab はフェーズ索引（Playbook）中心のため、症状起点（エラー文字列・想定外バナー・http-title の製品名・ツールの無反応など）で引く知識はピンポイントに届きにくい。この穴を埋めるのが Triage（症状 → ファイルの逆引き）であり、**ファイルが増えるほど「量」より「引きやすさ」がボトルネックになるため、見落としの Triage ルール化を追記より優先度の高い投資として扱う**。

判定と提案:

- **発火トリガが観測可能な出力**（例: `unsupported protocol`、`no matching key exchange`、`http-title: [製品名]`、`curl -s` の無反応）→ `99_kedaweb/js/triage_rules.js` に **`pattern`（その出力の正規表現）→ `targets`（該当ファイル + why の 1 行）** のルールを 1 件提案する
- **まず既存ルールを grep し、既に拾えるなら追加しない**（重複回避）
- トリガが文字列化できない（判断・思考プロセスの話）なら Triage 化せず、方法論として該当ファイルの散文に残す

提案は R3 の一覧に **`[Triage ルール]`** 区分として必ず立てる。「今回詰まった症状を、次回は貼れば即ファイルに飛べる」状態にして終わるのを既定とする。

## R2 — 汎用化して抽出

欠落・更新分を WRITING_GUIDE に従い汎用化（**演習名・実 IP・CTF 語・ホスト名・固有値を完全排除**）。
「特定の演習を知る人にしか伝わらない記述」になっていないか自問する。

## R3 — 反映方針を提示 → 承認 → 実行

標準ワークフローの Step 3〜5 に合流。新規ファイル / 既存追記 / triage / worksheet / 索引 を一覧で出し、
着手順（効果順）も添える。承認後に Step 4 で実行。

> **重要**: 実行ログ由来でも、kedalab 本文には会話の経緯・ターゲット IP・ホスト名・フラグ値を持ち込まない。
> 「この条件が揃ったら」の汎用形に翻訳する。検証用サンプルが要るなら `_workspace/` 配下（非公開）に置く。

---

# やってはいけない

- **kedalab 配下の既存ファイルをユーザ承認なく書き換えない**
- **`_pending/README.md` の登録を忘れない**
- **CVE 番号を「ありそう」で記載しない**（NVD/GHSA で published 確認）
- **会話の全項目を機械的に書こうとしない**（「次に同じ状況に出会ったら役立つか」でフィルタ）
- **会話の経緯・タイムスタンプ・案件 ID を kedalab 本文に書かない**（汎用化方針違反）
- **kedaweb 拡張時に `app.js` / `index.html` / `css/styles.css` を触らない**（`triage_rules.js` / `worksheet_template.js` のデータ配列のみ編集。UI ロジック変更は別タスク）
- **必須コマンドを散文に埋めない**（実行されるべきコマンドはコードブロックで出す）

---

# 引数による起動

- `/kedalab` のみ: 現在の会話全体を対象に抽出
- `/kedalab <トピック>`: トピックに絞って抽出（例: `/kedalab SSRF` / `/kedalab Samba`）
- **実行ログを貼って `/kedalab`（または `/kedalab <トピック>`）**: 「変種モード: 実行ログからの反映（レビュー込み）」を実行 — 誤り・見落とし・欠落を仕分けてから汎用化追記。`_workspace/` 配下の `.txt` 等を指して「これを見て」でも同じ
- `/kedalab pending-review`: `_pending/` 配下の棚卸し（関連 CVE が published になっていないか確認）

---

# 関連コマンド

- `/check-kedaweb` — kedalab 全体に対する kedaweb 不変条件 + WRITING_GUIDE 自己チェックの一括実行
- `/promote <file>` — `_pending/` または `_workspace/drafts/` のファイルを正規フォルダへ昇格

---

# 規範

詳細は以下を参照：

- `./CLAUDE.md`
- `./WRITING_GUIDE.md`
- `./_workspace/conventions/Folder_Convention_20260515.md`
