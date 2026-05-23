# Searchsploit クイックリファレンス

## 概要

`searchsploit` は Exploit-DB のオフラインミラーを検索するコマンドラインツール。インターネット接続なしで既知のエクスプロイト・PoC を検索できる。ペネトレ用Linuxディストリ（Kali Linux / Parrot OS 等）に標準搭載。

---

## 着火条件

- サービスのバージョンが特定できた
- そのバージョンに既知の脆弱性があるか確認したい
- エクスプロイトコードをすぐに入手したい

---

## 基本的な使い方

### キーワード検索

```bash
# サービス名とバージョンで検索
searchsploit grafana 8.0

# アプリ名のみで検索（バージョン未特定の場合）
searchsploit wordpress

# OS の脆弱性を検索
searchsploit "ubuntu 18.04"
```

### 検索のコツ

```bash
# バージョン番号は「メジャー.マイナー」で絞り込む（パッチバージョンまで指定すると漏れが出ることがある）
searchsploit grafana 8

# CVE番号で検索
searchsploit CVE-2021-43798

# 複数キーワードをスペース区切りで指定（AND 検索）
searchsploit apache tomcat 9.0

# タイトル検索のみ（デフォルト）
searchsploit -t grafana
```

---

## 出力の読み方

```
---------------------------------------------------------------------
 Exploit Title                     |  Path
---------------------------------------------------------------------
 Grafana 8.x - Path Traversal      | multiple/webapps/50581.py
 Grafana - Stored XSS              | php/webapps/44324.py
---------------------------------------------------------------------
```

| カラム | 説明 |
|-------|------|
| Exploit Title | 脆弱性の概要 |
| Path | ローカルのエクスプロイトファイルパス（`/usr/share/exploitdb/exploits/` 以下） |

---

## エクスプロイトファイルの操作

### ファイルを確認する

```bash
# エクスプロイトの内容を直接表示
searchsploit -x multiple/webapps/50581.py

# ファイルパスを取得（コピーしてから編集したい場合）
searchsploit -p multiple/webapps/50581.py
```

### 現在のディレクトリにコピーする

```bash
searchsploit -m multiple/webapps/50581.py

# ファイルが作業ディレクトリにコピーされる
# ls → 50581.py
```

---

## よく使うオプション一覧

| オプション | 説明 |
|-----------|------|
| `-t` | タイトルのみを検索（デフォルト動作と同じ） |
| `-x [PATH]` | エクスプロイトの内容をターミナルに表示 |
| `-m [PATH]` | 現在のディレクトリにエクスプロイトをコピー |
| `-p [PATH]` | エクスプロイトのフルパスを表示 |
| `--id` | CVE ID や EDB ID を表示 |
| `--nmap [FILE]` | Nmap の XML ファイルを読み込んで脆弱なサービスを自動検索 |
| `--exclude="[KEYWORD]"` | 特定キーワードを含む結果を除外 |
| `-w` | Exploit-DB の Web ページ URL を表示 |
| `-u` | データベースを最新に更新（`sudo` が必要な場合がある） |

---

## Nmap XML との連携（自動スキャン）

```bash
# Nmap スキャン時に XML を出力（-oA で .xml/.nmap/.gnmap を同時出力）
nmap -sC -sV -oA nmap_initial TARGET_IP   # [Attacker]

# 出力した XML に対して searchsploit を実行
searchsploit --nmap nmap_initial.xml   # [Attacker]
```

**`--nmap` の出力例（80/22 のみ開いている環境の場合）：**

```
[i] SearchSploit's XML mode (without verbose enabled).   To enable: searchsploit -v --xml...
[i] Reading: 'nmap_initial.xml'

[-] Skipping term: ssh   (Term is too general. Please re-search manually: /usr/bin/searchsploit -t ssh)

[i] /usr/bin/searchsploit -t openssh
----------------------------------- ---------------------------------
 Exploit Title                     |  Path
----------------------------------- ---------------------------------
OpenSSH 2.3 < 7.7 - Username Enume | linux/remote/45210.py
OpenSSH 7.2p2 - Username Enumerati | linux/remote/40136.py
OpenSSH < 6.6 SFTP - Command Execu | linux/remote/45001.py
...
----------------------------------- ---------------------------------

[-] Skipping term: http   (Term is too general. Please re-search manually: /usr/bin/searchsploit -t http)

[i] /usr/bin/searchsploit -t nginx
----------------------------------- ---------------------------------
 Exploit Title                     |  Path
----------------------------------- ---------------------------------
Nginx 1.4.0 (Generic Linux x64) -  | linux_x86-64/remote/32277.txt
PHP-FPM + Nginx - Remote Code Exec | php/webapps/47553.md
...
----------------------------------- ---------------------------------
```

**出力の読み方：**

| 出力内容 | 意味 | 対応 |
|---------|------|------|
| `[-] Skipping term: ssh` | "ssh" は一般的すぎてスキップ | `searchsploit -t openssh 8.4` のように具体的なバージョン付きで手動検索 |
| `[-] Skipping term: http` | "http" も同様にスキップ | `searchsploit nginx 1.18` のように Web サーバー名で検索 |
| `[i] /usr/bin/searchsploit -t openssh` | openssh として検索中 | バージョン文字列が長い場合は完全一致しないこともある |
| 結果が大量に出る | バージョン範囲が広いヒット | NVD でバージョン一致確認が必要 |

**`--nmap` の出力が大量に出たときの絞り込み：**

`--nmap` は nmap が検出したすべてのサービス×バージョンに対してヒットする結果を一括表示するため、数十件以上出ることがある。以下の手順で優先度をつける：

1. **現在のシェルアクセス状況と一致するカテゴリだけ見る**：シェルを持っていないなら Local系（Local Privilege Escalation）より Remote系（Remote Code Execution・WebApp）を優先
2. **バージョンが完全に一致するものだけ残す**：`8.x` のように幅広くヒットしているものはバージョン不一致の可能性が高い。NVD で正確な影響範囲を確認する（「複数の候補が出た場合の絞り込み基準」参照）
3. **DoS は除外する**：ペンテスト中のサービス停止は原則禁止。`DoS` / `Denial of Service` のタイトルはスキップする
4. **`--nmap` がスキップした "too general" なサービス（ssh・http）は手動で個別検索する**

---

## 技術名が分からない状態からの調査フロー

発見した機能・エラーから脆弱性クラスを特定する汎用フロー（searchsploit に限らない）は以下を参照：

→ `../00_Playbook/01_Unknown_Tech_Research.md`

---

## 複数の候補が出た場合の絞り込み基準

searchsploit や Exploit-DB Web で複数の結果が返った場合、以下の優先度で絞り込む。この基準はWebアプリ・カーネル・サービス等、対象を問わず共通で使える。

| 優先度 | 確認内容 | 判断方法 |
|-------|---------|---------|
| 1 | **バージョンが完全一致するか** | NVD の CPE 欄（affected versions）で自分のバージョンが範囲内か確認 |
| 2 | **OS・ディストリビューションが一致するか** | Ubuntu向けとRHEL向けで動作が異なる場合がある。タイトルを確認する |
| 3 | **パッチ前であることを確認** | CVEの公開日 vs 対象のビルド日時・パッケージバージョンを比較する |
| 4 | **実績があるか** | GitHub Star数・Issue・動作報告の有無。新しい PoC ほど環境互換性の問題が少ないことが多い |
| 5 | **コードが読めるか** | ブラックボックスの PoC は環境が合わないと無症状で失敗する。コードを読んで何をしているか理解できるものを選ぶ |
| 6 | **前提条件が現環境で満たされているか** | 特定のモジュール有効・ライブラリ要件・ユーザー名前空間の有効化等の前提を確認 |

**よくある失敗パターン：**

- EDB番号（searchsploit の Path 欄の数字）だけを見てコードを落とす → バージョン確認を省略しているため環境が合わず `mount failed` / `exploit failed` 等で失敗する
- 複数の類似CVEを同じ `/tmp` で試行錯誤する → ディレクトリが混在してどのファイルを実行しているか不明になる。`mkdir /tmp/cve_[番号]` で分けて管理する

→ NVDで正確な影響範囲を確認する方法は後述の「Exploit-DB以外の情報源」セクションを参照

---

## 実際の使用例

### Grafana 8.0.0 のパストラバーサル（CVE-2021-43798）を探す

```bash
searchsploit grafana 8.0
# → Grafana 8.x - Plugin Page Path Traversal などが表示される

# エクスプロイトを確認
searchsploit -x multiple/webapps/50581.py

# 作業ディレクトリにコピー
searchsploit -m multiple/webapps/50581.py
```

### OpenSSH の脆弱性を探す

```bash
searchsploit openssh 7.6
# → 該当バージョンに影響するエクスプロイトが表示される
```

### Apache / Nginx のバージョン検索

```bash
searchsploit apache 2.4.49
# → CVE-2021-41773 (Path Traversal / RCE) などが表示される
```

---

## データベースの場所とオフライン利用

```bash
# エクスプロイトDBのローカルパス
ls /usr/share/exploitdb/exploits/

# カテゴリ一覧（windows, linux, multiple, webapps, php 等）
ls /usr/share/exploitdb/exploits/

# データベースを更新
sudo searchsploit -u
```

---

## 注意点・落とし穴

- **バージョンの絞り込みが甘すぎると大量にヒットする。** まずメジャー.マイナーで検索し、絞れない場合は CVE 番号を使う
- **PoC が古い場合がある。** 特にスクリプトの依存ライブラリが古いと動作しないことがある。使用前にコードを読んでパラメータを確認する
- **PoC がそのまま使えないケースが多い。** ターゲットの IP/URL 等のパラメータを書き換えてから使用する
- **searchsploit で見つからなくても諦めない。** GitHub や NVD (https://nvd.nist.gov/) も確認する
- **試したが動作しなかった手法も記録する。** 「searchsploit で 50581.py を試したが対象バージョンに合わず不成立」等

---

## 製品調査の検索コツ（Google / Web検索）

searchsploit はバージョン×CVE の検索には強いが、**「このアプリのデフォルトパスはどこか」「DBのスキーマはどうなっているか」** といった製品固有の構造調査には向かない。こちらは Google 等で調べる。

### なぜ製品構造を調べるか

パストラバーサルや任意ファイル読み取り系の脆弱性を使うとき、**何を読むべきか**を事前に知っておく必要がある。`/etc/passwd` はどの Linux でも使えるが、**アプリ固有の認証情報・DBファイルのパスはアプリごとに異なる**。

「どこに何があるか」を知るための検索が、攻撃の実効性を大きく左右する。

### 使える検索クエリのパターン

```
[製品名] default file path
[製品名] config file location
[製品名] database path
[製品名] sqlite schema
[製品名] source code github
[製品名] directory structure
```

**具体例（Grafana の場合）：**

| 知りたいこと | 検索クエリ |
|------------|-----------|
| データDBの場所 | `grafana default data path` / `grafana sqlite location` |
| 設定ファイルの場所 | `grafana config file path linux` |
| DBのテーブル構成 | `grafana sqlite schema` / `grafana user table password` |
| Docker での配置 | `grafana docker data directory` |
| secret_key の場所 | `grafana.ini secret_key` |

**GitHub のソースコードを直接確認する：**

OSSであれば GitHub にソースがある。設定ファイルのサンプルや DB 初期化スクリプトを読むと、パスやスキーマが正確にわかる。

```
# 検索例
site:github.com grafana grafana.db schema
site:github.com grafana "var/lib/grafana"

# または直接リポジトリを検索
grafana/grafana github
```

**公式ドキュメントを確認する：**

```
grafana documentation data directory
grafana docs configuration file
```

公式ドキュメントには「インストール時のデフォルトパス」が明示されていることが多い。

### 製品別：よく確認する検索パターン

| 製品 | 調べるべき内容 | 検索クエリ例 |
|-----|--------------|------------|
| Grafana | DB・設定ファイルパス | `grafana default data path` / `grafana sqlite schema` |
| WordPress | DB接続情報・設定ファイル | `wordpress config file location wp-config.php` |
| Jenkins | 初期パスワード・シークレットの場所 | `jenkins initialAdminPassword location` |
| GitLab | 設定ファイル・シークレット | `gitlab.rb config file path` |
| Tomcat | 管理者認証ファイル | `tomcat-users.xml location default` |
| Kibana | 設定ファイル・ログパス | `kibana config file path linux` |

### 調査の流れ（パストラバーサル発見後の例）

```
① バージョン確認 → Grafana 8.0.0 と判明
    ↓
② CVE 検索（searchsploit）→ CVE-2021-43798 パストラバーサルと判明
    ↓
③ 「何を読むか」の調査（Google）
   検索: "grafana sqlite path" → /var/lib/grafana/grafana.db と判明
   検索: "grafana sqlite schema" → user テーブルに password/salt カラムがあると判明
    ↓
④ パストラバーサルで grafana.db を取得
    ↓
⑤ sqlite3 でパスワードハッシュを取得 → Hashcat でクラック
```

③を省略すると「ファイルをどこで読めばいいか」で詰まる。**CVEを見つけた後、すぐに実行するのではなく、製品構造の調査を挟む**のが重要。

---

## Exploit-DB（Web）の活用

searchsploit は CLI で素早く検索できるが、Exploit-DB の Web サイト（https://www.exploit-db.com/）には CLI にない機能がある。

### searchsploit と Exploit-DB Web の使い分け

| 目的 | 推奨 |
|-----|-----|
| 素早くエクスプロイトを探す | `searchsploit` CLI |
| エクスプロイトの詳細・参考リンクを読む | Exploit-DB Web |
| CVSSスコア・影響範囲を確認する | Exploit-DB Web + NVD |
| PoC コードをブラウザで読む | Exploit-DB Web |
| 関連する他の CVE を芋づる式に探す | Exploit-DB Web |

### Exploit-DB Web の機能

**Advanced Search（詳細検索）：**

- タイプ別（Remote / Local / WebApp / DoS など）で絞り込める
- プラットフォーム別（Windows / Linux / Multiple / PHP 等）で絞り込める
- 日付範囲での検索が可能

**各エクスプロイトページで確認すべき情報：**

```
1. CVE番号（NVDへのリンクがある）
2. 影響するバージョンの範囲
3. 著者のコメント・使い方の説明
4. References（関連するブログ記事・公式アドバイザリへのリンク）
5. PoC コードの全文
```

**`-w` オプションで CLI から URL を取得：**

```bash
# CLI から Exploit-DB の URL を直接取得
searchsploit -w grafana 8.0
# → https://www.exploit-db.com/exploits/50581
```

ブラウザで開いて References を読むと、より詳細な背景・利用条件がわかる。

### Exploit-DB 以外の情報源と使い分け

| 情報源 | URL | 向いている用途 |
|--------|-----|--------------|
| **Exploit-DB** | https://www.exploit-db.com/ | PoC コード・エクスプロイト本体 |
| **NVD** | https://nvd.nist.gov/vuln/search | CVSSスコア・影響バージョン・公式パッチ情報 |
| **GitHub** | https://github.com/ | 新しめの PoC（Exploit-DB未掲載のものが多い） |
| **PacketStorm** | https://packetstormsecurity.com/ | Exploit-DB にないエクスプロイト・ツール |
| **ベンダーセキュリティブログ** | Akamai / SpecterOps / Trustedsec / Semperis / MSRC 等 | 公開直後の新規CVE・研究者記事 |
| **X（旧Twitter）** | x.com で `CVE-XXXX-XXXXX` 検索 | PoC公開の最速一次情報 |
| **GreyNoise / Shodan** | shodan.io | 実環境での稼働状況・バージョン分布 |

### searchsploit が0件のときのフロー

OS / 製品が**リリースから1年以内**・**最新ビルド**・**研究者公開直後の脆弱性**は Exploit-DB に未掲載なことが多い。以下の順で探す：

```
searchsploit → 0件
      ↓
① NVD で CVE と影響範囲を確定する（製品名 + バージョンで検索）
      ↓
② GitHub で "CVE-202X-XXXXX" / "CVE-202X-XXXXX PoC" を検索
   → Star数・最終コミット日・README の前提条件を確認
      ↓
③ 該当CVE を発見した研究機関のブログを直接読む
   （Akamai / SpecterOps / Trustedsec / Semperis / MSRC 等）
      ↓
④ X で CVE 番号を検索（一次情報・追加 PoC・回避策が出ることが多い）
      ↓
⑤ それでも見つからなければ「未公開CVE」または「PoCが流通していないCVE」
   → 該当機能の公式仕様・関連 OSS のソースコードを読んで自前で PoC を組む判断
```

**新しい OS / 製品で CVE を探すときの検索キーワード例：**

| 状況 | 検索パターン |
|------|------------|
| 新しい Windows Server / クライアント | `"Windows Server [年]" CVE [新機能名] privilege escalation` |
| AD の新機能（dMSA / Authentication Silos 等） | `"[機能名]" abuse exploit github` |
| 新しい Linux カーネル | `"linux [バージョン]" CVE LPE` |
| 新しい Web フレームワーク | `"[フレームワーク名] [バージョン]" RCE PoC` |

**GitHub での PoC 検索：**

Exploit-DB は掲載まで時間がかかることがある。新しい CVE は GitHub を先に確認する。

```
# Google 経由
site:github.com CVE-2021-43798

# GitHub 検索バー
CVE-2021-43798 PoC
grafana path traversal exploit
```

**NVD で正確な影響範囲を確認：**

searchsploit のタイトルだけでは「自分のバージョンが本当に対象か」が曖昧なことがある。NVD の CPE（Common Platform Enumeration）欄には影響を受ける正確なバージョン範囲が記載されている。

```
https://nvd.nist.gov/vuln/detail/CVE-2021-43798
→ Affected versions: 8.0.0 ～ 8.3.0 と確認できる
```

---

## 関連技術
- 前：`../01_Reconnaissance/Web_Enumeration.md`（サービスバージョン確認後に CVE を調査）
- 後：`../02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md`（パストラバーサル CVE の実施）
- 後：`../02_Initial_Access/Edge_Appliance_CVEs.md`（エッジアプライアンス CVE の実施）
- 関連：`./CVE_Notes.md`（具体的な CVE ペイロード集）

外部リソース: Exploit-DB（https://www.exploit-db.com/）/ NVD（https://nvd.nist.gov/vuln/search）/ PacketStorm（https://packetstormsecurity.com/）/ GitHub PoC 検索（`site:github.com CVE-[YEAR]-[NUMBER]`）
