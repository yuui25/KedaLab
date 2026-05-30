# XSLT・XML外部エンティティの動作原理

## このファイルの位置づけ

以下の作業ファイルで参照される動作原理を説明する：
- `02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md`（②XXE-via-XSLTのエンティティ宣言構文が効く理由）
- `02_Initial_Access/Web_Vulnerabilities/XXE.md`（⑥PHPラッパーが機能する条件）

---

## なぜXXEが成立するか

### XMLパーサーの外部エンティティ処理

XML仕様（XML 1.0）では、DTD（Document Type Definition）内で外部エンティティを宣言し、ドキュメント内でそれを参照できる。

```xml
<!ENTITY xxe SYSTEM "file:///etc/passwd">
```

`SYSTEM` キーワードは「このURIを解決してエンティティの値とせよ」という指示。`file://` スキームを使えばローカルファイルを、`http://` を使えば任意のURLを読み込める。

**XXEが成立する3条件：**
1. XMLパーサーがDTD処理を有効にしている
2. パーサーが外部エンティティ（`SYSTEM` キーワード）の解決を許可している
3. エンティティの値がレスポンスに含まれる、またはOOB経由で外部に送出できる

条件1・2はXML仕様の機能だが、現代のライブラリ（libxml2 2.9+・Java JAXP 等）は**デフォルトで外部エンティティ処理を無効化**している。古い設定・カスタムパーサー・旧バージョンのフレームワークで有効なことがある。

---

## なぜXSLT内でXXEが成立するか（XXE-via-XSLT）

XSLTファイルはXML文書の一種であるため、XML自体のDTD処理ルールが適用される。XSLTファイルのDTD内でエンティティを宣言すると、XSLTプロセッサがXSLTをパースする際に内部のXMLパーサーが外部エンティティを解決しようとする。

```
XSLTプロセッサ受信
      ↓
XMLパーサーが XSLTファイルをパース
      ↓   ← ここで DOCTYPE 内のエンティティ宣言を処理
XSLT変換エンジンが実行         ← XSLT固有の関数・テンプレートを実行
```

重要なポイントは**「XSLT実行エンジン」と「XMLパーサー」が別レイヤー**であること。外部エンティティの解決はXMLパース段階（XSLT実行前）に行われる。エンティティ `&xxe;` をXSLTテンプレート内に書くと、XMLパースの時点でファイルの内容に置換される。

---

## libxslt の特徴と制限

`xsl:vendor-url = http://xmlsoft.org/XSLT/` が返る場合、XSLTプロセッサは **libxslt**（Cライブラリ）。

**libxslt 1.x の主な制限：**

- XSLT 1.0 のみサポート（2.0/3.0の `unparsed-text()` 等は使えない）
- `document()` 関数での外部ファイル読み込み：ビルドオプションと libxml2 のバージョンによって許可・不許可が異なる。`file:///etc/passwd` は多くのビルドで `Cannot resolve URI` になる（セキュアビルドまたは libxml2 2.9+ のデフォルト外部エンティティ無効化が原因）
- PHP XSL 拡張（`php:function()`）：`XSLTProcessor::registerPHPFunctions()` が明示的に呼ばれていないと動作しない。PHPアプリ側のコードに依存する

**libxslt でも試す価値がある攻撃面：**

- XXE-via-XSLT：libxml2 のバージョンとビルド設定次第で成立することがある
- `document('http://ATTACKER_IP/')` でのSSRF：ファイル読み込みがブロックされても外部HTTP接続が通る場合がある

---

## パラメータエンティティと一般エンティティの違い

XXEペイロードでよく混同される2種類のエンティティ：

| 種別 | 宣言 | 参照方法 | 主な用途 |
|------|------|---------|---------|
| 一般エンティティ | `<!ENTITY xxe SYSTEM "...">` | `&xxe;` | コンテンツ内での値の参照 |
| パラメータエンティティ | `<!ENTITY % xxe SYSTEM "...">` | `%xxe;` | DTD内での参照（Blind XXEで外部DTDを引き込む際に使う） |

Blind XXEで外部DTDを読み込む際は**パラメータエンティティ**（`%`）を使い、コンテンツ内の置換には**一般エンティティ**（`&`）を使う。これを混同すると意図しないパースエラーになる。

---

## PHP ラッパー（`php://filter`）が機能する条件

PHPのXMLパースに `php://filter/convert.base64-encode/resource=/etc/passwd` を使う場合：

- PHP の `libxml` 拡張が有効
- `allow_url_fopen` または `allow_url_include` の設定次第で動作が変わる（`file://` は `allow_url_fopen` と無関係）
- Base64 化することで `/etc/passwd` 内の `<` 等のXML特殊文字を回避できる

---

## 環境が変わったときに確認する点

- XMLパーサーライブラリのバージョン（libxml2・Expat・Xerces 等）とそのデフォルト設定
- アプリケーションフレームワークのXML設定（Spring の場合 `XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES = false` が標準など）
- XSLTプロセッサの種類（`system-property()` でフィンガープリント）→ プロセッサ固有の拡張関数の可用性を確認
- サーバーが `document()` 関数を制限しているか（アプリ側のサニタイズかライブラリ側のビルドオプションか）

---

## 関連技術

- 関連：`../02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md`（XXE-via-XSLT のエンティティ宣言構文）
- 関連：`../02_Initial_Access/Web_Vulnerabilities/XXE.md`（PHP ラッパー含む XXE 全般）

- 関連：../02_Initial_Access/Web_Vulnerabilities/XXE.md（PHP ラッパー含む XXE 全般）
