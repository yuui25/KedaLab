# ファイルメタデータ解析

## 概要

Office ドキュメント・PDF・画像等のファイルには、作成者・組織名・使用ソフトウェア・作成日時などのメタデータが埋め込まれている。FTP / SMB / Web 経由で取得したファイルをそのまま開くのではなく、**まずメタデータを読む**ことで、有効なドメインユーザー名・組織内ドメイン名が手に入る。

---

## パターン1: exiftool によるメタデータ一括確認

### 着火条件

FTP 匿名アクセス・SMB 共有・Web ディレクトリから **Office 系ドキュメント（.docx / .xlsx / .pptx）・PDF・画像（.jpg / .png）** が取得できた場合。内容が空・意味不明でもメタデータに情報が含まれていることがある。

**攻撃者の思考トレース：** 「ファイルの中身に有益情報がない」と判断する前に、メタデータを確認する。作成者フィールドに書かれた名前がそのままドメインユーザー名に対応することが多い。

### 環境前提

- 実行環境: テスター端末
- 必要なツール: `exiftool`（ペネトレ用Linuxディストリ標準搭載。なければ `sudo apt install libimage-exiftool-perl`）/ `pdfimages` / `pdftotext` / `pdfdetach`（PDF 内部抽出、`poppler-utils` に同梱）
- オフライン代替: `file [filename]`（最小限の情報のみ）/ `pdfinfo`（PDFのみ、`poppler-utils` に同梱）
- 任意（OSINT 段階の自動収集）: `metagoofil`（パターン1.5 参照）/ `getfattr`（Linux 側で Windows ADS 読取）

### 観点・着眼点

**先に確認すること：** 対象ファイルが本当にバイナリ/ドキュメントファイルか `file` コマンドで確認してから exiftool を実行する。テキストファイルにもメタデータがある場合があるが、優先度は低い。

**何が出たら次に何をするか：**

| 出力フィールド | 示唆 | 次のアクション |
|-------------|------|--------------|
| `Author` / `Creator` / `Last Modified By` にユーザー名が含まれる | ドメインユーザー名の候補 | そのユーザー名でユーザー列挙（LDAP / Kerbrute）・ASREPRoasting・Kerberoasting を試す |
| `Company` / `Publisher` にドメイン名らしき文字列 | 内部ドメイン名の候補 | `/etc/hosts` への登録・LDAP クエリの `-b` パラメータに使用 |
| `Producer` / `Creator Tool` にアプリ名・バージョン | 使用ソフトウェアの特定 | そのソフトのCVEを searchsploit / NVD で確認 |
| `GPS Latitude / Longitude` | 物理位置情報 | 本番では報告対象（プライバシー影響） |
| `Creation Date` / `Modify Date` | タイムゾーン・稼働時間帯の推測 | 夜間バッチ・メンテナンスウィンドウの推測に活用 |
| 複数ファイルで同じ `Author` | 高い信頼性のユーザー名 | 単一ファイルの Author より優先して試す |
| JPEG の `Software` / `Make` / `Model` フィールドが書かれている | 撮影端末（スマホ・カメラ機種）が判明 | **社員端末の機種特定**（社用 iPhone / Android のモデル列挙）→ 社会工学・モバイル MDM ポリシー推測 |
| PDF の `Producer` に `Adobe Acrobat 11.0` / `Microsoft Print to PDF` 等 | 印刷経路・使用ソフトの特定 | 古い Producer 表記 = 古い Office / Acrobat 利用 → 関連 CVE 確認 |
| PDF 内に埋め込み画像・別文書 | 画像 / 文書本体に追加メタデータ | `pdfimages` / `pdftotext` で抽出 → 抽出物に対して再度 exiftool |

### 手順

```bash
# [Attacker] 単一ファイルの確認
exiftool [filename]

# [Attacker] ディレクトリ内の全ファイルを再帰的に確認
exiftool -r [directory]/

# [Attacker] 認証情報関連フィールドだけ絞り込む（Author / Creator / Company 等）
exiftool -r [directory]/ | grep -iE "Author|Creator|Company|Publisher|Producer|Last.Modified|Subject|Title"

# [Attacker] 全ファイルのAuthorを一覧表示（複数ファイルの突合に便利）
exiftool -r -Author [directory]/ 2>/dev/null | grep -v "^$"
```

**メタデータから取れたユーザー名候補の形式変換：**

```
# 「Firstname Lastname」形式 → よくあるADユーザー名形式に変換して試す
# Firstname.Lastname   (最多)
# FLastname            (頭文字+苗字)
# FirstnameL           (名前+頭文字)
# FirstnameLastname    (スペースなし結合)
```

> **ユーザー名の形式が不明な場合は：** LDAP 匿名バインドで sAMAccountName を確認する（`LDAP_Enumeration.md`）か、Kerbrute でユーザー名候補リストを検証する（`../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md` の Kerbrute セクション）。

**PDF 内部資産の抽出（exiftool だけでは届かない）：**

```bash
# [Attacker] PDF 内部の画像を全部書き出して、各画像の exiftool を回す
pdfimages -all [filename.pdf] /tmp/pdfimg_   # /tmp/pdfimg_-000.{png,jpg} 等が出る
for f in /tmp/pdfimg_-*; do exiftool "$f"; done

# [Attacker] PDF 本文をテキスト化 — 本文中に書かれた社内 URL / 内部ホスト名 / メールアドレスを grep
pdftotext [filename.pdf] -
pdftotext [filename.pdf] - | grep -iE "@[a-z0-9.-]+|\\\\\\\\[a-z0-9.-]+|http[s]?://[a-z0-9./-]+"

# [Attacker] PDF の添付ファイル（attachments）を取り出す（社内テンプレ・元データが添付されている場合あり）
pdfdetach -list [filename.pdf]
pdfdetach -saveall -o /tmp/pdf_attachments/ [filename.pdf]
```

**JPEG / 画像 EXIF の重点項目：**

```bash
# [Attacker] スマホ・カメラの機種情報を一括抽出
exiftool -Software -Make -Model -LensModel -SerialNumber -OwnerName [filename.jpg]

# [Attacker] ディレクトリ全体で機種統計を取る（社員端末の支給機種推定）
exiftool -r -Make -Model [directory]/ | sort | uniq -c | sort -rn
```

> `Make` / `Model` がほぼ全ファイルで揃っている場合、**社用端末が支給機種で統一されている**示唆。`SerialNumber` / `OwnerName` が稀に残っているとさらに具体的（個人情報含むため finding は適切に処理）。

---

## パターン1.5: OSINT 段階の文書一括収集（metagoofil）

### 着火条件

対象ドメインが判明していて、**まだファイルを 1 つも取得していない**段階で、検索エンジン経由で公開文書を根こそぎ集めたい場合。スコープに OSINT 段階が含まれているときに使う（被害組織のサーバーに直接アクセスせず、Google / Bing 等の検索結果のみを使う）。

### 環境前提

- 必要なツール: `metagoofil`（`pipx install metagoofil` または `git clone https://github.com/opsdisk/metagoofil`）
- 外部リソース: Google / Bing 等の検索結果に依存（API キー不要だが大量実行で CAPTCHA / 429 が出る）

### 手順

```bash
# [Attacker] 対象ドメインから .pdf / .docx / .xlsx / .pptx を一括収集
metagoofil -d [TARGET_DOMAIN] -t pdf,docx,xlsx,pptx,doc,xls,ppt -l 100 -n 25 -o ./meta_out
# -d : 対象ドメイン
# -t : ファイル種別（カンマ区切り）
# -l : 検索結果の最大件数
# -n : ダウンロードする最大件数
# -o : 出力ディレクトリ

# 取得後にパターン 1 / 2 の exiftool / unzip 解析を回す
exiftool -r ./meta_out/ | grep -iE "Author|Creator|Company|Last.Modified"
```

> **使い分け:** 対象組織サーバーへの直接アクセスが厳しく制限されているスコープでも、**検索エンジンキャッシュ経由のファイル収集は痕跡が対象組織に残らない**。OSINT 段階の偵察として最初に回し、その結果から取れた「Author 一覧」「内部パス言及」「使用ソフトのバージョン」を本格スキャンの起点にする。

> **注意:** 大量実行で Google の CAPTCHA / 429 が出る。本番では `-l` / `-n` を抑えめ（100 / 25 程度）に。

---

## パターン2: strings / binwalk による隠しメタデータ探索

### 着火条件

exiftool での標準メタデータ確認後、さらに詳細を調べたい場合。特にバイナリファイルや特殊なフォーマットに対して使う。

### 手順

```bash
# [Attacker] バイナリ中の全文字列を抽出（メタデータが構造化されていない場合）
strings [filename] | grep -iE "author|creator|user|email|@|domain|\.local|\.test|\.invalid"

# [Attacker] ドキュメントが ZIP ベース（.docx / .xlsx / .pptx）の場合は直接解凍して確認
unzip -o [filename.docx] -d /tmp/doc_extracted/
cat /tmp/doc_extracted/docProps/core.xml    # 作成者・更新日時
cat /tmp/doc_extracted/docProps/app.xml     # アプリ名・バージョン・会社名
cat /tmp/doc_extracted/docProps/custom.xml  # **社内独自フィールド**（部署名・案件番号・分類ラベル等が入る）
ls /tmp/doc_extracted/word/embeddings/      # 埋め込みオブジェクト（OLE / 他 Office 文書 / バイナリ）
ls /tmp/doc_extracted/word/media/           # 埋め込み画像（EXIF が残っている可能性）
```

> `docProps/custom.xml` は **組織独自のメタデータプロパティ**（DLP ラベル・案件管理番号・部署コード・「社外秘」分類タグ等）が入っており、**社内ワークフローの仕組みが透けて見える**。exiftool は読まないので zip 直接展開が必要。

**`core.xml` の典型的な出力例：**

```xml
<cp:coreProperties>
  <dc:creator>Firstname Lastname</dc:creator>
  <cp:lastModifiedBy>another.user</cp:lastModifiedBy>
  <dcterms:created>2021-03-15T10:30:00Z</dcterms:created>
  <dcterms:modified>2021-10-01T18:22:14Z</dcterms:modified>
</cp:coreProperties>
```

> `dc:creator` と `cp:lastModifiedBy` が異なる場合、**複数のユーザー名候補が得られる**。

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `Author` が空・"unknown" | ファイル保存時にメタデータを意図的に削除している（セキュリティ意識の高い組織）。他のフィールド（`Software` / `Creator Tool`）を見る |
| 名前がローマ字でなくニックネーム | LDAP で sAMAccountName を列挙してニックネームと照合する |
| ドメイン名候補が複数出てきて絞れない | nmap の `-sC` スキャン結果の `ssl-cert` / Kerberos バナーで正規ドメイン名を確認する |
| FTP で取得したファイルがバイナリで `file` コマンドで判別できない | `xxd [filename] | head -5` でマジックバイトを確認してフォーマットを判定 |

---

## 注意点・落とし穴

- ファイル名に使われている名前とメタデータの Author が一致しない場合がある。どちらも記録しておく
- Last Modified By は「最後に保存した人」であり、実際の作成者と異なることがある
- メタデータのユーザー名は「表示名」（Full Name）であることが多く、sAMAccountName と異なる可能性がある → Kerbrute で形式を確認する
- **Windows 代替データストリーム（ADS）の `Zone.Identifier`**: SMB / Web 経由で取得した Windows ファイルには `Zone.Identifier` ADS（NTFS のメタストリーム）に **元のダウンロード URL / ReferrerUrl が残っている**ことがある。`getfattr -d -m - [filename]`（Linux 側）/ `Get-Content -Stream Zone.Identifier [filename]`（Windows 側）で読める。**社内 SharePoint / 社内 Confluence URL が漏れる経路として有名**
- **`mat2` への防御側理解**: `mat2` は対象組織がメタデータを意図的に削除している場合に使われるツール（Python・`apt install mat2`）。クリーンナップ済みファイルは `Author=""` / `Producer=""` 等が綺麗に空になっており、**「綺麗すぎる」こと自体が「相手は mat2 / Document Inspector を使っている」というシグナル**になる。clean 済みなら別経路で名前を取りに行く

---

## 関連技術

- 前：FTP 匿名アクセスでファイルを取得した → `../02_Initial_Access/FTP.md`
- 前：SMB 共有からファイルを取得した → `./SMB_Enumeration.md`
- 後：取得したユーザー名で ASREPRoasting を試す → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`
- 後：取得したドメイン名で LDAP 列挙 → `./LDAP_Enumeration.md`
- 後：取得したユーザー名で Kerbrute 検証 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`（Kerbrute セクション）
