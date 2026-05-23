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
- 必要なツール: `exiftool`（ペネトレ用Linuxディストリ標準搭載。なければ `sudo apt install libimage-exiftool-perl`）
- オフライン代替: `file [filename]`（最小限の情報のみ）/ `pdfinfo`（PDFのみ、`poppler-utils` に同梱）

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
```

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

---

## 関連技術

- 前：FTP 匿名アクセスでファイルを取得した → `../02_Initial_Access/FTP.md`
- 前：SMB 共有からファイルを取得した → `./SMB_Enumeration.md`
- 後：取得したユーザー名で ASREPRoasting を試す → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`
- 後：取得したドメイン名で LDAP 列挙 → `./LDAP_Enumeration.md`
- 後：取得したユーザー名で Kerbrute 検証 → `../04_Post_Access_Windows_AD/Kerberos_Attacks/ASREPRoasting.md`（Kerbrute セクション）
