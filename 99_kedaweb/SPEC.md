# kedaweb 仕様書

kedalab のナレッジを実行時に MD パースして表示する SPA。フレームワーク非使用、Vanilla JS。

## 設計原則

**kedalab MD が単一の真実。** あらゆる表示要素は実行時に MD ファイルを fetch し、パースしてレンダリングする。kedalab を更新したら kedaweb はリロードだけで反映される。

例外: **新しいトップ番号フォルダの追加時のみ** `js/data.js` の `phases` 配列と `js/app.js` の `phaseFromPath()` の更新が必要。

## データソースと取得タイミング

| 用途 | 取得元 | タイミング |
|------|--------|----------|
| 技術ノード | `TECHNIQUES_INDEX.md` + `TECHNIQUES_INDEX_AI_ML.md` のテーブル全行 | 起動直後 |
| Playbook ノード | `README.md` + 上記 INDEX を正規表現 `00_Playbook/*.md` で走査 | 起動直後 |
| Quick Start カード | `README.md` の「最初に開くファイル」テーブル | 起動直後 |
| Playbook プレビュー | 各 Playbook MD の H1 + `## フロー概要` 系セクション | カードクリック時 |
| 関連技術エッジ | 各 MD の `## 関連技術` または `### 関連技術` セクション | Navigator 初回起動時 |
| Navigator orphan ノード | エッジ参照先で `D.techniques` に未登録のファイル | Navigator 初回起動時 |
| 本文検索インデックス | `D.techniques` 全ファイルの MD を小文字化キャッシュ | Top Search 初回入力時 |

## ページ構成

### Top Bar (`<header>`)
- ロゴ + バージョン + loader pill (起動状態 / クリックで全再読込)
- 検索ボックス `#topSearch` (placeholder: `技術・CVE・ツール名・本文で検索…`)
- ナビリンク: `Start` / `Chain` / `Browser` / `Navigator` / `Raw`

### Hero (`<section.hero>`)
- KEDALAB タイトル + 5 統計カウンタ (Techniques / Phases / Playbooks / CVE / AI Red Team)
- 起動時に easing アニメ

### Quick Start (`#quickstart`) — collapsible / 既定展開
- README の「最初に開くファイル」表をパースして 9 状況カード
- カードクリック → 該当 Playbook プレビュー (H1 + 概要本文) を下に展開
- プレビュー内「📖 開く」で本体モーダル
- 詳細ヒント (STEP 0/2/3/4) は `<details>` で折り畳み

### Technique Browser (`#browser`) — collapsible / 既定折り畳み
- フェーズフィルタチップ (All + 8 フェーズ・件数バッジ付き)
- マッチング対象: 技術名 / タグ / ファイルパス / **MD 本文** (本文は遅延インデックス完成後)
- Top Search 入力時に自動展開

### Navigator (`#navigator`) — タブモード (`body.nav-mode`)
- 右上 `Navigator` クリックで他セクション非表示・Matrix 表示。他ナビクリックで通常モードに戻る
- 8 列 (フェーズ) × N セル (技術ファイル) の MITRE ATT&CK Navigator 風マトリックス
- セルクリック → フォーカス。前 (青 `#00d4ff`) / 後 (橙 `#ffb800`) / 関連 (緑 `#00ff9c`) でハイライト、他セルは opacity 0.18 で dim
- フォーカス中セルを再クリック → 本体モーダル表示
- 専用検索ボックス: 文字列フィルタ → Enter で第一ヒットにフォーカス
- フォーカス詳細パネル: 前・後・関連 をラベル別リストで表示、各リンクから他セルへフォーカス遷移
- 凡例チップ (FOCUS / 前 / 後 / 関連) + ✕ クリアボタン
- ステータス行: `N files (incl. M auto-discovered) · K edges parsed from 関連技術 sections`

### Raw Index (`#raw`) — collapsible / 既定折り畳み
- `data.js > indexFiles` の各 MD (TECHNIQUES_INDEX 系 / README / WRITING_GUIDE / CLAUDE.md) を直接開くカード

### Cmd Palette (`#palette`) — モーダル
- `Ctrl+K` / `Cmd+K` で開閉
- 同じ `matchQuery` を使うので本文インデックスの恩恵を受ける
- `↑↓` で移動、`Enter` で開く、`Esc` で閉じる

### MD Viewer Modal (`#modal`)
- ファイル fetch → 軽量 Markdown レンダラで整形
- 本文中の `.md` プレーンテキストパスを自動でクリック可能リンクに変換 (現ファイル基準で resolve)
- 対応構文: heading / table / fenced code / list (ul/ol) / blockquote / inline code / bold / italic / link / auto-link
- 簡易構文ハイライト: bash / python / powershell / sql の予約語、文字列、コメント、CVE 番号

## キーボード

| キー | 動作 |
|------|------|
| `Ctrl+K` / `Cmd+K` | コマンドパレット開閉 |
| `↑` / `↓` | パレット内移動 |
| `Enter` | パレット選択を開く / Navigator 検索で第一ヒットにフォーカス |
| `Esc` | パレット / モーダル / Navigator 検索フィルタを閉じる |

## フェーズ定義 (`data.js`)

| id | code | folder | color | jp |
|----|------|--------|-------|----|
| `playbook` | 00 | `00_Playbook/` | `#94a3b8` | 判断フロー |
| `recon` | 01 | `01_Reconnaissance/` | `#00ff9c` | 偵察・列挙 |
| `initial` | 02 | `02_Initial_Access/` | `#00d4ff` | 初期アクセス |
| `linux` | 03 | `03_Post_Access_Linux/` | `#ffb800` | Linux 侵入後 |
| `windows` | 04 | `04_Post_Access_Windows_AD/` | `#ff3d8a` | Windows AD 侵入後 |
| `tools` | 05 | `05_Tools_Reference/` | `#a78bfa` | ツール辞典 |
| `concepts` | 06 | `06_Concepts/` (非 AI_ML) | `#64ffda` | 原理・背景 |
| `ai` | 07 | `07_AI_Red_Teaming/` + `06_Concepts/AI_ML/` | `#ff00ff` | AI レッドチーム |

`phaseFromPath(file)` がパスからフェーズ id を決定。`06_Concepts/AI_ML/` 配下は `ai` に集約 (07 と同じ列)。

## 関連技術セクションの書式

各 MD ファイル末尾に置く。Navigator のエッジソース。

```markdown
## 関連技術              ← H2 (##) または H3 (###) どちらでも可

- 前：状況の説明 → `相対パス.md`
- 後：状況の説明 → `相対パス.md`
- 関連：状況の説明 → `相対パス.md`
```

**ラベル:**
- `前：` — このファイルの前に通る (precondition / predecessor)
- `後：` — このファイルの後に試す (successor)
- `関連：` — 並列的に関連 (sibling / related)

**書式の許容:**
- コロンは全角 `：` / 半角 `:` どちらも可
- 1 行に複数のバッククォート付き `.md` パスを含めると全て抽出
- パスは現ファイル基準の相対 (`./`、`../`、またはプレフィックスなしの兄弟ファイル名)
- セクション本体は次の同レベル以上の見出しまで

**現状の運用 (kedalab 全体):**
- H2 形式・H3 形式どちらも有効（パーサは両方を透過的に処理）
- ファイル数は kedaweb 起動時の Browser カウントを参照（SPEC.md には記載しない）

## Navigator のエッジ計算

### 順方向 (forward) — authoritative
全 `D.techniques` の MD を `parseRelatedTech(file, md)` でパースし `_edges.set(file, {prev, next, related})` に格納。**ファイル自身の関連技術セクションが真実。**

### 逆方向 (inverse) — フォーカス時に on-the-fly
`effectiveEdges(file)` で計算:

1. 順方向の `prev` / `next` / `related` をそのまま採用
2. 他のファイルが `前：file` を持つなら、`file` 視点では `next` (file を済ませた後に進む先) として追加
3. 同様に `後：file` → `prev`、`関連：file` → `related`
4. **既に順方向で分類済みのセルは inverse でスキップ** → 衝突時は順方向が勝つ

意味論的な保証: 自身に `関連技術` セクションが無いファイル (Web_Enumeration、Playbook 等の foundation) でも、参照側からの逆エッジでフォーカス時に dependents が照射される。

### Orphan auto-discovery
INDEX に載っていないが他から参照される Concept ファイル等を自動的にセル化:

1. ナビ起動時に `ensureContentIndex()` で `D.techniques` 全 MD をフェッチ
2. `buildEdgesIndex()` で順方向エッジを構築
3. エッジ参照先で `D.techniques` に未登録のファイルを収集
4. それらの MD を追加 fetch して `D.techniques` + `_edges` に登録 (`tags: [phase, "auto"]`)
5. 新規 orphan が出なくなるまで最大 4 パス反復

orphan 解決後に `recomputeStats()` + `renderToolbar()` + `renderTechniques()` で Browser のカウントも更新。

## 状態フラグ / キャッシュ

| 変数 | 意味 | クリア |
|------|------|-------|
| `dataLoaded` | TECHNIQUES_INDEX + situations のロード完了 | pill リロード |
| `_contentIndexBuilt` | 全 MD 小文字化キャッシュ完了 | pill リロード |
| `_navLoaded` | Navigator 初回構築完了 | pill リロード |
| `_navFocus` | 現在のフォーカスファイルパス | クリア / 別セルクリック |
| `body.nav-mode` | Navigator タブモード | 他ナビクリック |
| `body.has-nav-focus` | Navigator フォーカス有効状態 | クリア時 |

| キャッシュ | 中身 |
|---------|------|
| `_mdCache` | `file → 原文 MD` |
| `_contentIndex` | `file → 小文字化 MD` (本文検索用) |
| `_edges` | `file → {prev, next, related}` (順方向のみ) |

## 起動シーケンス

1. スクリプト評価 → IIFE 実行 → boot 演出開始 (ターミナルログ + ASCII アート)
2. `renderAll()` 1 回目: scaffold 描画 (techniques=[] で「fetching…」表示)
3. `loadKedalabData()` 非同期開始:
   - `loadTechniques()` → TECHNIQUES_INDEX 系を fetch、ファイル重複排除
   - `loadPlaybookNodes()` → README + INDEX から 00_Playbook 系を収集、`D.techniques` に追加
   - `loadSituations()` → README の「最初に開くファイル」表をパース
   - `playbookList` → 各 Playbook の H1 をフェッチして prettify
4. `finalizeLoad()`:
   - `dataLoaded = true`
   - `renderAll()` 2 回目: 実データで再描画
   - `animateCounters()`
   - `setLoadedPill()`
   - 既に `body.nav-mode` なら `ensureNavReady()` をキック

`#navigator` ハッシュで起動した場合は boot 後に自動で `enterNavMode()`。

## 検索の動作

### スコアリング (`scoreEntry`)

Top Search と Cmd Palette はともに `scoreEntry(t, q)` を経由する。各トークンが以下のどこに当たるかで重みを加算し、**全トークンがどこかに当たれば**スコアを合算、1 つでも完全に当たらないトークンがあれば 0 を返して除外する:

| 当たり所 | 重み |
|---|---|
| 技術名 (`t.n`) | +100 |
| ファイル名のベース部分 (path 末尾) | +80 |
| タグ (`t.tags`) | +50 |
| ファイルパス全体 (`t.f`) | +30 |
| 本文 (`_contentIndex` の小文字化 MD) | +5 |

旧 `matchQuery` は `scoreEntry > 0` を返すだけのシンとなり、過去の「全トークン部分一致」セマンティクスを保つ。

### Top Search (`#topSearch`)
- 入力 → Browser 自動展開、フェーズフィルタは現在値維持
- 同時に `ensureContentIndex()` をキック (初回のみ)。構築中は loader pill に `⋯ indexing N/M` 進捗
- `renderTechniques()` で以下を実施:
  1. `D.techniques` の全行を `scoreEntry` でスコアリング、0 は除外
  2. ファイル (`t.f`) ごとにグルーピング → 1 ファイル 1 カード化。複数の技術行は `.tech-hits` 内に `<li>` で列挙 (最大 6 件、超過分は `+N more`)
  3. ファイルをフェーズ id ごとに分け、`D.phases` の順 (00 → 01 → 02 → …) に `.tb-group` セクションで描画
  4. クエリありの場合はファイルをスコア降順、なしの場合はパス昇順でソート
- 本文ヒットがあれば、`bodySnippet(t, q)` で**最初のヒット位置を中心に ±60 文字**を抽出、全マッチトークンを `<mark>` で囲んだスニペットをカード末尾に表示。原文の大小は `_mdCache` から取得し、位置検出は `_contentIndex` (小文字化) で行う

### Navigator Search (`#navSearch`)
- 入力 → セルに `.qfilter-out` クラスを付けて `display: none`
- マッチング: セル表示テキスト + ファイルパスに対し全トークン部分一致 (スコアリングは未適用、Navigator はフィルタ用途のみ)
- Enter → 第一ヒットを `setNavFocus()`
- Esc → 入力クリア + フィルタ解除

### Cmd Palette
- 同じ `scoreEntry` を使い、**スコア降順でソートしてから上位 60 件**を表示
- `<mark>` ハイライトやグルーピングはなし (Browser よりコンパクトな UI を維持)

## ファイル構成

```
99_kedaweb/
├── index.html         # SPA エントリ、各セクション markup
├── css/styles.css     # サイバーパンクテーマ、全コンポーネントスタイル
├── js/
│   ├── data.js        # フェーズメタデータ + indexFiles リスト (静的)
│   ├── matrix.js      # 背景マトリックスレイン Canvas
│   └── app.js         # ローダ・パーサ・全 UI ロジック (single file)
├── README.md          # 起動方法・機能サマリ
└── SPEC.md            # このファイル
```

依存: Google Fonts (JetBrains Mono / Inter) のみ CDN。他のフレームワーク・ライブラリは未使用。

## 起動

`.md` を fetch するため HTTP サーバ経由が必須 (`file://` だと CORS で本文取得不可)。kedalab ルートで:

```powershell
python -m http.server 8000
# → http://localhost:8000/99_kedaweb/
```

`file://` で開いた場合:
- 警告バナーが上部に常駐
- Quick Start・Browser・Navigator のステータスがエラー表示
- MD ビューア・統計カウンタ・決定木関連は空 / プレースホルダ

## メンテナンス指針

| 変更内容 | 必要な作業 |
|---------|----------|
| 技術ファイル追加 → TECHNIQUES_INDEX に登録 | なし (kedaweb リロードのみ) |
| 関連技術セクションの追加・編集 | なし (リロード時に自動反映) |
| Concept ファイル (06_Concepts/) 追加 | 他ファイルから参照されていれば orphan discovery で自動取り込み。孤立させたい場合は INDEX に手動登録 |
| Playbook ファイル追加 (`00_Playbook/*.md`) | README または INDEX から 1 回以上参照すれば自動収集 |
| 新トップ番号フォルダ (例: `08_Cloud_Identity/` を本格化) | `js/data.js > phases` に 1 行 + `js/app.js > phaseFromPath()` に 1 行 |
| `_` 接頭辞ディレクトリの追加・編集 (`_pending/` `_workspace/` 等) | なし。`phaseFromPath` が null を返すため自動的に kedaweb から除外される |
| UI 改修 / 演出変更 | `99_kedaweb/` 配下のみ編集、kedalab MD は触らない |

## スケーラビリティの保証

各 MD が以下を満たしていれば、ファイルが増えても kedaweb 側は何もする必要がない:

1. `## 関連技術` または `### 関連技術` セクションを末尾に持つ
2. セクション内に `- 前：説明 → \`相対パス.md\`` 形式で記述
3. ラベルは `前：` / `後：` / `関連：` のいずれか (全角・半角コロン両対応)
4. パスはバッククォートで囲み、現ファイル基準の相対表記

満たさないケースの挙動:
- **関連技術セクションが無い** → そのファイルからの順方向エッジは 0。逆エッジで照射される可能性あり
- **どこからも参照されない孤立ファイル** → Matrix から不可視。TECHNIQUES_INDEX に追加すれば解決
- **新トップフォルダの追加** → `phaseFromPath` 未更新だとフェーズ判定 null で `D.techniques` 入りせず除外
