# 技術名が分からない状態からの調査フロー

## このファイルの用途

発見した機能・エラー・プロトコルが何の脆弱性クラスに当たるか分からないとき、「名前を特定して攻撃手法を選択するまで」の思考プロセス。searchsploit に限らず、どの技術に当たっても使える汎用フロー。

---

## フロー

```
[機能・挙動を観察する]
       ↓
[機能を英語の動詞+目的語で言語化する]
       ↓
[「機能名 + vulnerability / exploit / security」でGoogle検索]
       ↓
[脆弱性クラス名を特定する]（例: XSLT injection / XXE / SSTI 等）
       ↓
[そのクラスの標準ペイロードを見つける]（PayloadsAllTheThings / HackTricks 等）
       ↓
[ペイロードをターゲット環境に合わせてカスタマイズする]
       ↓
[エラーメッセージを手がかりに絞り込む]
```

---

## Step 1：「何が起きているか」を英語で言語化する

技術名を検索する前に、**アプリが何をしているかを一文にする**。

| 観察した機能 | 英語化の例 | 想定される脆弱性クラス |
|------------|------------|---------------------|
| XMLファイルとスタイルシートをアップロードするとHTMLに変換される | "XML stylesheet server-side transform" | XSLT Injection |
| XMLを入力として受け取りサーバーが処理する | "XML external entity" | XXE |
| ユーザー入力がテンプレートとして処理され出力される | "template injection" | SSTI（Server-Side Template Injection）|
| URLパラメータがサーバー側でHTTPリクエストを発生させる | "server-side request" | SSRF |
| ファイルパスをパラメータとして渡すとファイルが返る | "file path parameter read" | パストラバーサル |
| ユーザー入力がコマンドラインに渡される | "command injection" | OSコマンドインジェクション |

---

## Step 2：脆弱性クラスを特定するための検索

### 基本パターン

```
[機能の英語説明] + vulnerability
[機能の英語説明] + exploit
[機能の英語説明] + security
[技術名] + injection
[エラーメッセージの一部] （エラー文字列をそのまま検索する）
```

### よく使うリファレンス

| リソース | URL | 向いている用途 |
|---------|-----|--------------|
| PayloadsAllTheThings | https://github.com/swisskyrepo/PayloadsAllTheThings | 脆弱性クラスごとのペイロード一覧。カスタマイズの起点 |
| HackTricks | https://book.hacktricks.xyz/ | 手順のガイド・環境別の注意点。日本語より英語版が充実 |
| PortSwigger Web Security Academy | https://portswigger.net/web-security | 仕組みの解説 + 対話型ラボ。「なぜ成立するか」を理解したいとき |
| OWASP Testing Guide | https://owasp.org/www-project-web-security-testing-guide/ | 網羅的な確認項目リスト |

---

## Step 3：ペイロードをカスタマイズする

PayloadsAllTheThings 等のペイロードは**汎用テンプレート**であり、そのまま動かないことが多い。以下を確認して差し替える。

| 項目 | 確認内容 |
|------|---------|
| ファイルパス | OSのパス形式（Linux: `/etc/passwd`、Windows: `c:/windows/win.ini`） |
| プロトコルスキーム | `file://` / `file:///` / `php://` / `http://` の違い |
| コールバックIP | Blind系ペイロードの `ATTACKER_IP` をテスター側の到達可能インターフェースのIPに変える（`ip a` で全インターフェース確認、環境により物理LAN・VPN・専用線等） |
| 識別子・変数名 | `&xxe;` 等の名前は任意。宣言と参照が一致していればよい |
| プロセッサ・言語固有の構文 | プロセッサや言語によって使える関数が異なる（XSLTならフィンガープリントで確認） |

---

## Step 4：エラーメッセージを手がかりにする

エラーメッセージは「何が問題か」を直接教えてくれる。以下のパターンを検索に使う。

| エラー文字列 | 意味 | 次の手 |
|------------|------|-------|
| `Cannot resolve URI` | ファイル読み込みが制限されている | 別のURIスキーム（`file://` vs `file:///`）や別の手法を試す |
| `Entity 'xxx' not defined` | DOCTYPE内にエンティティ宣言がない | 宣言構文を確認する → `../02_Initial_Access/Web_Vulnerabilities/XXE.md` |
| `XPath evaluation returned no result` | PHP拡張関数が無効 | `php:function()` が `registerPHPFunctions()` で有効化されていない |
| `DTD is prohibited` | DOCTYPEブロッキングが有効 | XXEは使えない。別の攻撃面を探す |
| `TemplateNotFoundException` / `render error` | テンプレートエンジンが使われている | SSTIを疑う |

エラー文字列をそのままGoogleで検索すると、同じ環境での解決方法が見つかることが多い。

> **▶ 記録:** 特定した脆弱性クラス名・効いた（効かなかった）ペイロード・手がかりになったエラー文字列を控える。→ Worksheet「NOTES」欄、または該当機能を扱う「[02-W] WEB 脆弱性」項目のメモ欄。

---

## 関連技術
- 前：Web脆弱性の機能別確認表 → `Web_Vuln_Flow.md`（Step 2）
- 前：ペネトレ目的の Web 列挙中に未知技術に当たった場合 → `Linux_Attack_Flow.md`（Step 2）
- 後：CVEが特定できた場合の絞り込み → `../05_Tools_Reference/Searchsploit.md`（複数候補の絞り込み基準）
- 後：脆弱性クラスが XXE と特定できた場合 → `../02_Initial_Access/Web_Vulnerabilities/XXE.md`（Step 4 のエラーメッセージ表からの遷移先）
