# ファイルメタデータ解析

> **スコープ**: FTP / SMB / Web 経由で取得したファイル（Office 文書・PDF・画像）からのメタデータ抽出に徹する。作成者フィールド由来のユーザー名・内部ドメイン名・使用ソフトのバージョンを取り出し、ユーザー列挙 / Kerberos 攻撃 / CVE 検索の起点にする。取得したユーザー名・ドメイン名を使った攻撃は `LDAP_Enumeration.md` / `../04_Post_Access_Windows_AD/Kerberos_Attacks/` を参照。

## 着火条件

FTP 匿名アクセス・SMB 共有・Web ディレクトリから **Office 系ドキュメント（.docx / .xlsx / .pptx）・PDF・画像（.jpg / .png）** が取得できた場合、または OSINT 段階で対象ドメインから公開文書を集めたい場合（§4）。内容が空・意味不明でもメタデータに情報が含まれていることがある。

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `exiftool`（ペネトレ用Linuxディストリ標準搭載。なければ `sudo apt install libimage-exiftool-perl`）/ `pdfimages` / `pdftotext` / `pdfdetach` / `pdfinfo`（`poppler-utils` 同梱）/ `unzip` / `strings` / `binwalk`
- オフライン代替: `file [filename]`（最小限の情報のみ）/ `xxd`（マジックバイト確認）
- 任意（OSINT 段階の自動収集）: `metagoofil`（§4。`pipx install metagoofil`）/ `getfattr`（Linux 側で Windows ADS 読取）

## 先に確認すること

- 対象ファイルが本当にバイナリ/ドキュメントファイルか `file` コマンドで確認してから exiftool を実行する。テキストファイルにもメタデータがある場合があるが優先度は低い
- メタデータから取れたユーザー名は「表示名（Full Name）」であることが多く sAMAccountName と異なる可能性がある → `LDAP_Enumeration.md` の sAMAccountName 確認 / Kerbrute で形式を検証する

**攻撃者の思考トレース:** 「ファイルの中身に有益情報がない」と判断する前にメタデータを確認する。作成者フィールドの名前がそのままドメインユーザー名に対応することが多く、複数ファイルで同じ Author が出れば信頼度が高い。

---

## 1. exiftool による標準メタデータの一括確認

**コマンド:**

```bash
# [Attacker] 単一ファイル / ディレクトリ再帰
exiftool [filename]
exiftool -r [directory]/

# [Attacker] 認証情報関連フィールドだけ絞り込む
exiftool -r [directory]/ | grep -iE "Author|Creator|Company|Publisher|Producer|Last.Modified|Subject|Title"

# [Attacker] 全ファイルの Author を一覧表示（複数ファイルの突合に便利）
exiftool -r -Author [directory]/ 2>/dev/null | grep -v "^$"
```

**取れたユーザー名候補の形式変換（AD ユーザー名形式に変換して試す）:**

```
# 「Firstname Lastname」形式 →
# Firstname.Lastname   (最多)
# FLastname            (頭文字+苗字)
# FirstnameL           (名前+頭文字)
# FirstnameLastname    (スペースなし結合)
```

**観測される出力 → 次のアクション:**

| 出力フィールド | 示唆 | 次のアクション |
|-------------|------|--------------|
| `Author` / `Creator` / `Last Modified By` にユーザー名 | ドメインユーザー名の候補 | LDAP / Kerbrute でユーザー列挙・ASREPRoast・Kerberoast → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md` |
| `Company` / `Publisher` にドメイン名らしき文字列 | 内部ドメイン名の候補 | `/etc/hosts` 登録・LDAP の `-b` パラメータに使用 → `LDAP_Enumeration.md` |
| `Producer` / `Creator Tool` にアプリ名・バージョン | 使用ソフトの特定 | CVE を searchsploit / NVD で確認 |
| `GPS Latitude / Longitude` | 物理位置情報 | 本番では報告対象（プライバシー影響） |
| `Creation Date` / `Modify Date` | タイムゾーン・稼働時間帯の推測 | 夜間バッチ・メンテナンスウィンドウ推測 |
| 複数ファイルで同じ `Author` | 信頼性の高いユーザー名 | 単一ファイルの Author より優先して試す |

**注意:** ファイル名の名前と Author が一致しないことがあるので両方記録する。`Last Modified By` は「最後に保存した人」で実際の作成者と異なることがある。

---

## 2. PDF / 画像の内部資産抽出（exiftool だけでは届かない）

**コマンド:**

```bash
# [Attacker] PDF 内部の画像を全部書き出して、各画像の exiftool を回す
pdfimages -all [filename.pdf] /tmp/pdfimg_   # /tmp/pdfimg_-000.{png,jpg} 等が出る
for f in /tmp/pdfimg_-*; do exiftool "$f"; done

# [Attacker] PDF 本文をテキスト化 — 社内 URL / 内部ホスト名 / メールアドレスを grep
pdftotext [filename.pdf] - | grep -iE "@[a-z0-9.-]+|\\\\\\\\[a-z0-9.-]+|http[s]?://[a-z0-9./-]+"

# [Attacker] PDF の添付ファイルを取り出す（社内テンプレ・元データが添付されている場合あり）
pdfdetach -list [filename.pdf]
pdfdetach -saveall -o /tmp/pdf_attachments/ [filename.pdf]

# [Attacker] JPEG / 画像 EXIF の重点項目（撮影端末の機種）
exiftool -Software -Make -Model -LensModel -SerialNumber -OwnerName [filename.jpg]
exiftool -r -Make -Model [directory]/ | sort | uniq -c | sort -rn   # 機種統計（支給機種推定）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| PDF 内に埋め込み画像・別文書 | 画像/文書本体に追加メタデータ | 抽出物に対して再度 exiftool（§1）|
| `pdftotext` で社内 URL / メールアドレス | 内部ホスト名・連絡先 | `/etc/hosts` 登録・ユーザー名候補に追加 |
| JPEG の `Software` / `Make` / `Model` | 撮影端末（社員端末）の機種特定 | 社用 iPhone/Android のモデル列挙 → 社会工学・MDM ポリシー推測 |
| `Make` / `Model` がほぼ全ファイルで揃っている | 社用端末が支給機種で統一 | `SerialNumber` / `OwnerName` が残っていればさらに具体的（個人情報含むため finding 処理）|

**注意:** `SerialNumber` / `OwnerName` は個人情報を含むため finding として適切に処理する。

---

## 3. ZIP ベース文書の直接展開と strings 探索

Office 系（.docx / .xlsx / .pptx）は ZIP ベース。直接解凍すると exiftool が読まない `docProps/custom.xml` の組織独自メタデータが取れる。

**コマンド:**

```bash
# [Attacker] ドキュメントを直接解凍して docProps を確認
unzip -o [filename.docx] -d /tmp/doc_extracted/
cat /tmp/doc_extracted/docProps/core.xml    # 作成者・更新日時
cat /tmp/doc_extracted/docProps/app.xml     # アプリ名・バージョン・会社名
cat /tmp/doc_extracted/docProps/custom.xml  # 社内独自フィールド（部署名・案件番号・分類ラベル等）
ls /tmp/doc_extracted/word/embeddings/      # 埋め込みオブジェクト（OLE / 他 Office 文書 / バイナリ）
ls /tmp/doc_extracted/word/media/           # 埋め込み画像（EXIF が残っている可能性）

# [Attacker] バイナリ中の全文字列を抽出（構造化されていないメタデータ）
strings [filename] | grep -iE "author|creator|user|email|@|domain|\.local|\.test|\.invalid"
```

**`core.xml` の典型的な出力例:**

```xml
<cp:coreProperties>
  <dc:creator>Firstname Lastname</dc:creator>
  <cp:lastModifiedBy>another.user</cp:lastModifiedBy>
  <dcterms:created>2021-03-15T10:30:00Z</dcterms:created>
  <dcterms:modified>2021-10-01T18:22:14Z</dcterms:modified>
</cp:coreProperties>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `dc:creator` と `cp:lastModifiedBy` が異なる | 複数のユーザー名候補が得られる | 両方をユーザー名候補リストに追加 |
| `docProps/custom.xml` に DLP ラベル・案件番号・部署コード | 社内ワークフローの仕組みが透ける | 社内構造の理解・social engineering 材料 |
| `word/media/` に画像 | EXIF が残っている可能性 | §2 の手順で抽出物に exiftool |

**注意:** `docProps/custom.xml` は組織独自のメタデータ（「社外秘」分類タグ等）が入っており exiftool は読まないので zip 直接展開が必要。

---

## 4. OSINT 段階の文書一括収集（metagoofil）

**着火条件:** 対象ドメインが判明していて、まだファイルを 1 つも取得していない段階で、検索エンジン経由で公開文書を根こそぎ集めたい場合。スコープに OSINT 段階が含まれるときに使う（被害組織のサーバーに直接アクセスせず、検索結果のみを使う）。

**コマンド:**

```bash
# [Attacker] 対象ドメインから .pdf / .docx / .xlsx / .pptx を一括収集
metagoofil -d [TARGET_DOMAIN] -t pdf,docx,xlsx,pptx,doc,xls,ppt -l 100 -n 25 -o ./meta_out
# -d 対象ドメイン / -t ファイル種別 / -l 検索結果最大件数 / -n DL最大件数 / -o 出力先

# [Attacker] 取得後にパターン §1 / §3 の exiftool / unzip 解析を回す
exiftool -r ./meta_out/ | grep -iE "Author|Creator|Company|Last.Modified"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 大量の公開文書が収集できる | OSINT で痕跡を残さず材料取得 | §1 / §3 で Author 一覧・内部パス・使用ソフトを抽出し本格スキャンの起点に |
| Google の CAPTCHA / 429 | レート制限 | `-l` / `-n` を抑えめ（100 / 25 程度）に |

**注意:** 検索エンジンキャッシュ経由のファイル収集は痕跡が対象組織に残らない。OSINT 段階の偵察として最初に回す。外部リソース（Google / Bing）に依存するためインターネットアクセス要。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 対処 |
|------|---------|------|
| `Author` が空・"unknown" | メタデータを意図的に削除（mat2 / Document Inspector）| 他フィールド（`Software` / `Creator Tool`）を見る。「綺麗すぎる」こと自体が「相手は clean ツールを使っている」シグナル → 別経路で名前を取る |
| 名前がローマ字でなくニックネーム | 表示名がニックネーム | LDAP で sAMAccountName を列挙して照合 → `LDAP_Enumeration.md` |
| ドメイン名候補が複数で絞れない | 複数の Company 表記 | nmap `-sC` の `ssl-cert` / Kerberos バナーで正規ドメイン名を確認 |
| バイナリで `file` 判別できない | マジックバイト未知 | `xxd [filename] | head -5` でマジックバイトを確認しフォーマット判定 |

---

## 注意点・落とし穴

- **Windows 代替データストリーム（ADS）の `Zone.Identifier`**: SMB / Web 経由で取得した Windows ファイルには `Zone.Identifier` ADS に**元のダウンロード URL / ReferrerUrl が残っている**ことがある。`getfattr -d -m - [filename]`（Linux 側）/ `Get-Content -Stream Zone.Identifier [filename]`（Windows 側）で読める。社内 SharePoint / Confluence URL が漏れる経路として有名
- **`mat2` への防御側理解**: クリーンナップ済みファイルは `Author=""` / `Producer=""` が綺麗に空になる。clean 済みなら別経路で名前を取りに行く

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術

- 前：FTP 匿名アクセスでファイルを取得した → `../02_Initial_Access/FTP.md`
- 前：SMB 共有からファイルを取得した → `SMB_Enumeration.md`
- 後：取得したユーザー名で ASREPRoasting を試す → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`
- 後：取得したドメイン名で LDAP 列挙 → `LDAP_Enumeration.md`
- 後：取得したユーザー名で Kerbrute 検証 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`（Kerbrute セクション）
