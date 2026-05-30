# SMB列挙

> **スコープ**: 445 / 139 (SMB) に対する匿名・Guest・認証付き列挙。共有列挙〜NETLOGON / SYSVOL の認証情報探索〜GPP 復号〜AD オブジェクト一括列挙までを扱う。取得した認証情報での横展開・侵入後活動は `../02_Initial_Access/` 以降を参照。RPC エンドポイントの低レベル列挙は `RPC_Enumeration.md`。

## 着火条件
445 (SMB) が開いている場合。特に Windows AD 環境では最初に確認する。匿名・Guest でも部分情報が取れるが、認証情報が取れた後の再実行で取得情報が大幅に増える。

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `nxc`（NetExec の CLI ラッパー。SMB/WinRM/MSSQL への認証テストを一括で行う、ペネトレ用 Linux ディストリ標準搭載）/ `smbclient` / `smbmap` / `enum4linux-ng` / `rpcclient` / `impacket-smbclient` / `impacket-samrdump` / `gpp-decrypt`（いずれもペネトレ用 Linux ディストリ標準搭載または Impacket スイート同梱）
- 外部リソース依存: なし（内部ネットワーク内で完結）

## 先に確認すること

- **ゲストアカウントの有効状態**: §1 で `nxc smb [IP] -u 'guest' -p ''` を最初に確認する
- **真の null セッション（`-u '' -p ''`）と Guest（`-u 'guest'`）は別物**: 両方試す。`RestrictAnonymous=0` の古い環境では完全に空の null セッションが通ることが稀にある
- **SMB 署名の状態**: `Signing: True`（必須）なら NTLM リレーが使えない（§刺さらなかったとき参照）

**標準共有と非標準共有の区別:**

| 標準共有名 | 用途 | 確認優先度 |
|-----------|------|-----------|
| `ADMIN$` | リモート管理 | 低（通常アクセス不可） |
| `C$` | Cドライブ（管理者のみ） | 低（通常アクセス不可） |
| `IPC$` | プロセス間通信 | 低 |
| `NETLOGON` | ログオンスクリプト | **必ず確認**（認証情報が平文で埋め込まれたスクリプトが置かれることがある） |
| `SYSVOL` | グループポリシー・スクリプト | **必ず確認**（GPP 認証情報・スクリプト） |

→ **上記以外の共有名が存在する場合は必ずアクセスを試みる**

**攻撃者の思考トレース:** SMB は AD で「最初に当てる」サービス。共有内のスクリプト・GPO に平文/復号可能なパスワードが眠っていることが多く、列挙だけで初期認証情報が取れる。匿名で取れる範囲をまず確認し、cred が取れたら同じ列挙を認証付きで回し直す。

---

## 1. 匿名・ゲストアクセスの確認と共有列挙

**コマンド:**

```bash
# [Attacker] Guest アカウントが有効か確認（最初の一手）
nxc smb [IP] -u 'guest' -p ''

# [Attacker] Guest 有効時は impacket-smbclient でも接続できる
impacket-smbclient -no-pass guest@[IP]

# [Attacker] 共有の一覧を取得（匿名）
smbclient -L //[IP] -N

# [Attacker] 共有の一覧を取得（認証あり）
smbclient -L //[IP] -U '[DOMAIN]\[USER]%[PASSWORD]'

# [Attacker] 非標準共有にアクセスしてファイル一覧を確認
smbclient //[IP]/[SHARE_NAME] -N -c "ls"
smbclient //[IP]/[SHARE_NAME] -U '[USER]%[PASSWORD]'

# [Attacker] ファイルをダウンロード
smbclient //[IP]/[SHARE_NAME] -N -c "get [FILENAME] /tmp/[FILENAME]"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `[+] ...\guest:` | Guest アカウント有効 → 認証情報なしで共有列挙できる可能性 | 続けて共有列挙 → NETLOGON / SYSVOL（§2・§3）優先 |
| `[-] STATUS_ACCOUNT_DISABLED` | Guest 無効 | null 認証（`-u '' -p ''`）でも試す。ともに失敗なら認証情報が必要 |
| `NETLOGON` / `SYSVOL` 以外の共有名が見える | カスタム共有 | 必ずアクセスを試みる |
| `IPC$` のみ表示 | 匿名で見える共有が実質ない | 認証情報取得後に再列挙 |

**注意:** null 認証（`-N`）が拒否されても、Guest が有効なら `-u 'guest' -p ''` で通ることがある。`.exe` / `.zip` があれば必ずダウンロードして内容確認（→ `../02_Initial_Access/Binary_Analysis.md`）。

> **`-L`（一覧）と接続（中身）を混同しない:** `smbclient -L //[IP]` は**サーバの共有一覧を表示するだけ**。共有名を足して `smbclient -L //[IP]/[SHARE]` としても一覧表示に戻るだけで中には入れない。**共有の中身を見るには `-L` を外して接続する** → `smbclient //[IP]/[SHARE] -N -c "ls"`。非標準共有（`IPC$` / `ADMIN$` 以外）は必ずこの形で接続して中を確認する。

---

## 2. NETLOGON 共有の確認

**着火条件:** NETLOGON 共有が存在し、匿名またはゲストでアクセスできる場合。NETLOGON はドメインのログオンスクリプト置き場で、管理者が作成した `.bat` / `.ps1` に**平文パスワードが埋め込まれている**ことがある。

**コマンド:**

```bash
# [Attacker] NETLOGON 共有にアクセス
smbclient -N //[IP]/NETLOGON -c "ls"
# または impacket-smbclient で shares → use NETLOGON → ls → cat [script_name].bat
impacket-smbclient -no-pass guest@[IP]

# [Attacker] ファイルをダウンロードして確認
smbclient -N //[IP]/NETLOGON -c "get [SCRIPT_NAME] /tmp/[SCRIPT_NAME]"
cat /tmp/[SCRIPT_NAME]

# [Attacker] 取得した認証情報を即検証
nxc smb [IP] -u '[USER]' -p '[PASSWORD]'
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| スクリプト内に `net use ... /user:[USER] [PASSWORD]` | 平文認証情報が埋め込まれている | `nxc` で検証 → `../02_Initial_Access/Credential_Discovery.md` |
| `if %USERNAME%==[USER] ...` 条件分岐 | ユーザー別の認証情報分岐 | 各分岐の cred を抽出 |
| スクリプトはあるが cred なし | 認証情報未埋め込み | §3 SYSVOL の GPP / スクリプトへ |

**注意:** スクリプト内の `net use`・`/user:`・`-p`・`-password`・`PASSWORD=` を探す。

---

## 3. SYSVOL / Replication の確認とナビゲーション

**着火条件:** SYSVOL または Replication 共有（SYSVOL を DFSR でレプリケーションしたもの）にアクセスできた場合。`scripts/` や `Policies/` 配下のスクリプトに平文パスワードが含まれることがある。

**フォルダの優先度と意味:**

| フォルダ | 優先度 | 中身 |
|---------|--------|------|
| `[domain.name]/`（例: `example.local/`） | **必ず降りる** | SYSVOL の GPO 構造。ドメイン名と同名のフォルダがルート直下にあるのが正常 |
| `Policies/` | **必ず降りる** | 各 GPO が `{GUID}` フォルダとして存在 |
| `{GUID}/MACHINE/Preferences/` | **必ず確認** | `Groups/Groups.xml` に GPP 認証情報（§4）|
| `{GUID}/MACHINE/Scripts/` | 確認 | ログオン・ログオフスクリプト |
| `scripts/` | 確認 | `.bat` / `.ps1` → 平文パスワードの可能性 |
| `DfsrPrivate/` | スキップ可 | DFSR 複製メタデータ（通常は空またはアクセス不可） |

**コマンド:**

```bash
# [Attacker] 再帰的に一覧を取得して全体像を把握する（まずこれ）
smbclient //[IP]/[SHARE] -N -c "recurse ON; ls" 2>/dev/null | tee smb_recursive.txt

# [Attacker] ファイルを一括取得（候補が絞れたら）
# -D はサーバー側ディレクトリ。ローカル保存先は `lcd` で指定する
mkdir -p /tmp/smb_dump
smbclient //[IP]/[SHARE] -N -c "lcd /tmp/smb_dump; recurse ON; prompt OFF; mget *"

# [Attacker] サーバー側で特定サブディレクトリから開始したい場合に -D を使う
smbclient //[IP]/SYSVOL -N -D '[DOMAIN]/Policies' -c "lcd /tmp/smb_dump; recurse ON; prompt OFF; mget *"
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| ドメイン名と同名フォルダ（例 `example.local`）が見える | SYSVOL の正常な構造 | 迷わず降りる。中の `Policies/` `scripts/` を見る |
| `Groups.xml` が存在 | GPP 認証情報の可能性 | §4 GPP 取得へ |
| `.bat` / `.ps1` スクリプト | 平文パスワードの可能性 | ダウンロードして `net use` / `/user:` を探す |

**注意:** 再帰 `ls` の出力には `DfsrPrivate/` のような不要フォルダも混在する。`Policies/` と `scripts/` 配下を中心に見る。`{GUID}` 形式のフォルダは複数存在することがあるので、**すべての GUID 配下を確認する**。`-D` はサーバー側の初期ディレクトリ指定であってローカル保存先ではない（保存先は `lcd`）。

---

## 4. GPP (Group Policy Preferences) 認証情報の取得

**着火条件:** SYSVOL / Replication にアクセスでき、`Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml` が存在する。

**コマンド:**

```bash
# [Attacker] Groups.xml のダウンロード（場所を §3 の再帰 ls で特定後）
smbclient //[IP]/[SHARE] -N \
  -c "get Policies/{GUID}/MACHINE/Preferences/Groups/Groups.xml /tmp/Groups.xml"

# [Attacker] SYSVOL 配下を横断的に cpassword 検索（Groups.xml 以外も対象）
grep -ril cpassword /tmp/smb_dump

# [Attacker] cpassword の復号（gpp-decrypt はペネトレ用Linuxディストリ標準搭載）
gpp-decrypt '[CPASSWORD_VALUE]'
```

**Groups.xml の読み方:**

```xml
<!-- 重要な属性 -->
<Properties
  userName="DOMAIN\USERNAME"   ← 対象ユーザー名
  cpassword="edBSHOwh..."      ← 復号するとパスワードが得られる
  action="U"                   ← U=Update（既存ユーザーの変更）
/>
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Groups.xml` に `cpassword=` 属性がある | 認証情報確定（誰でも即復号できる） | `gpp-decrypt` で復号 → `nxc` で検証 → `../02_Initial_Access/Credential_Discovery.md` |
| `Services.xml` / `ScheduledTasks.xml` / `Drives.xml` / `DataSources.xml` / `Printers.xml` に cpassword | これらも cpassword を持ちうる | 同様に復号 |
| `gpp-decrypt` の結果が空・改行のみ | パスワードが意図的に空 / ローテーション済み | 他の SYSVOL スクリプトの平文探索へ |

**注意:** `Groups.xml` 以外にも複数の XML が `cpassword` を持つため、SYSVOL 配下は `grep -ril cpassword` で横断的に確認する。原理（なぜ AES 暗号化されていても誰でも復号できるのか・MS14-025 適用後の挙動）→ `../06_Concepts/GPP_Credential.md`

---

## 5. enum4linux-ng / smbmap / nxc / rpcclient での網羅的な列挙

**着火条件:** 445 が開いており、ユーザー・グループ・パスワードポリシー等の AD オブジェクト情報・共有のアクセス権マトリクスを一括取得したい場合。匿名でも実行できるが、認証情報取得後の再実行で取得情報が大幅に増える。

**ツールごとの役割:**

- `smbclient` → 共有の**ファイル内容を操作する**ためのツール（§1〜§4）
- `enum4linux-ng` → **AD オブジェクト情報（ユーザー / グループ / SID / パスワードポリシー）の一括取得**。Python 製・JSON 出力対応の新版。**旧 Perl 版 `enum4linux` はメンテ停止状態なので新規環境ではこちらを使う**
- `smbmap` → **共有ごとの READ / WRITE アクセス権マトリクス** + 再帰ファイル検索
- `nxc smb` → 認証テスト + パスワードポリシー / 共有 / SAM / LSA / セッション列挙のオールインワン
- `rpcclient` → 名前付きパイプ経由で SAMR / LSAT を叩く低レベル列挙（詳細は `RPC_Enumeration.md`）

**コマンド:**

```bash
# [Attacker] enum4linux-ng（推奨・新版）
enum4linux-ng -A [IP] | tee enum4linux_ng_anon.txt           # 匿名で全機能（-A = all）
enum4linux-ng -A -u '[USER]' -p '[PASSWORD]' [IP] | tee enum4linux_ng_auth.txt
enum4linux-ng -A -oJ enum4linux_ng.json [IP]                 # JSON 出力（後段スクリプトに渡す場合）

# [Attacker] 真の null セッションの明示確認
nxc smb [IP] -u '' -p ''                # 完全に空
smbclient -L //[IP] -N                  # smbclient での null セッション一覧
rpcclient -U "" -N [IP] -c 'getdompwinfo; querydominfo; enumdomusers; enumdomgroups'

# [Attacker] パスワードポリシー取得（スプレー前の lockout 閾値判定に直結）
nxc smb [IP] --pass-pol                                                # 匿名で試す
nxc smb [IP] -u '[USER]' -p '[PASSWORD]' --pass-pol                    # 認証あり

# [Attacker] 共有のアクセス権マトリクス（READ / WRITE 一覧）
nxc smb [IP] -u '' -p '' --shares                                      # 匿名
nxc smb [IP] -u '[USER]' -p '[PASSWORD]' --shares                      # 認証あり

# [Attacker] smbmap で共有ごとのアクセス権 + 再帰ファイル検索
smbmap -H [IP]                                                         # 匿名で共有一覧 + 権限
smbmap -H [IP] -u 'guest' -p ''                                        # guest
smbmap -H [IP] -u 'guest' -p '' -R --search "password"                 # 全共有を再帰検索
smbmap -H [IP] -u '[USER]' -p '[PASSWORD]' -R [SHARE_NAME] --depth 5   # 特定共有を 5 階層まで再帰

# [Attacker] impacket-samrdump（SAM 経由のユーザー列挙・rpcclient 拒否時の代替）
impacket-samrdump '[IP]'                                               # 匿名
impacket-samrdump '[DOMAIN]/[USER]:[PASSWORD]@[IP]'                    # 認証あり
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `enum4linux-ng` でユーザー / グループ一覧が返る | AD オブジェクト情報取得 | パスワードスプレー対象に → `../05_Tools_Reference/Netexec.md` |
| `--pass-pol` で lockout 閾値が判明 | スプレー設計に必須 | `../02_Initial_Access/Account_Lockout_Recon.md` で閾値決定 |
| `--shares` で WRITE 権限のある共有 | 書込経路の可能性 | persistence / ファイル設置の検討 |
| 匿名で情報が薄い | 認証情報が必要 | cred 取得後に `-u`/`-p` 付きで再実行 |

**注意:** SMB 経由で 445 が開いていれば自動的に RPC エンドポイントも露出しているため、SMB 列挙の延長として `rpcclient` を実行する。rpcclient の詳細（`enumdomusers` / `lookupsid` / RID bruteforce / Account Flags 解釈）は `RPC_Enumeration.md` に集約。

---

## 刺さらなかったとき（全体）

| 観測される症状 | 推定原因 | 代替手段 |
|--------------|---------|---------|
| `nxc smb [IP] -u 'guest' -p ''` で `STATUS_ACCOUNT_DISABLED` | Guest 無効 | (a) 真の null セッション `nxc smb [IP] -u '' -p ''` / `smbclient -L //[IP] -N` を試す。(b) ともに失敗なら認証情報取得（`../00_Playbook/Windows_AD_Attack_Flow.md` Step 3）へ |
| `smbclient -N //[IP]` が `NT_STATUS_ACCESS_DENIED` | 匿名・Guest 共に閉じている | `enum4linux-ng -A` / `nxc smb --shares` / `rpcclient -U "" -N` で別経路（RPC over SMB）を試す |
| 共有が `IPC$` のみ表示される | 匿名で見える共有が実質ない | 認証情報取得後に再列挙する（`-u [USER] -p '[PASSWORD]'`） |
| SMB 署名が必須（`Signing: True`）と表示される | NTLM リレー攻撃が使えない | リレー以外の経路（Kerberos 認証強制 / Coerce 系・Pass-The-Hash）を検討 |
| `OS=[Unix]` / `OS=[Samba x.x.x]` が表示される | 対象は Linux 上の Samba | Windows 想定の SAM/LSA dump・GPP 列挙は適用外。**版数を確定し既知 CVE を照合** → `../02_Initial_Access/Samba_Exploitation.md`（usermap script / SambaCry 等の未認証 RCE） |
| SYSVOL に降りても `Groups.xml` が見つからない | GPP 認証情報未配布 / 撤去済み（MS14-025 適用後） | `Services.xml` / `ScheduledTasks.xml` / `Drives.xml` / `DataSources.xml` / `Printers.xml` も `grep -ril cpassword` で横断確認 |
| GPP の `cpassword` を復号しても無効値（空・改行のみ） | パスワードが意図的に空、または既にローテーション済み | 他の SYSVOL 配下スクリプト（`.bat` / `.ps1`）の平文探索に切替 |

---

## 注意点・落とし穴

- Null 認証（`-N`）が拒否されても、Guest が有効なら `-u 'guest' -p ''` で通ることがある。`nxc smb [IP] -u 'guest' -p ''` で事前確認
- SMB 署名が有効（必須）な場合は中間者攻撃（NTLM リレー）は使えない
- `{GUID}` 形式のフォルダ名は複数存在することがある。すべての GUID 配下を確認する

> **個別ブロック固有の注意は各 §N の「注意:」を参照。**

---

## 関連技術
- 前：ポートスキャンで 445 / 139 を発見 → `Network_Scanning.md`
- 前：AD 攻撃フロー上の現在地確認 → `../00_Playbook/Windows_AD_Attack_Flow.md`
- 後：GPP で認証情報取得 → `../02_Initial_Access/Credential_Discovery.md`（GPP パターン）
- 後：スクリプトに平文パスワード → `../02_Initial_Access/Credential_Discovery.md`
- 後：実行ファイルが取得できた → `../02_Initial_Access/Binary_Analysis.md`
- 後：対象が Linux 上の Samba（`OS=Unix (Samba x.x.x)`）で版数が古い → `../02_Initial_Access/Samba_Exploitation.md`
- 後：取得したドキュメント・画像のメタデータ確認 → `Metadata_Analysis.md`
- 後：認証情報が取得できた → `LDAP_Enumeration.md` へ進む
- 関連：RPC エンドポイント詳細列挙（rpcclient / samrdump / lookupsid / RID bruteforce）→ `RPC_Enumeration.md`
- 関連：パスワードスプレー前の lockout 閾値確認 → `../02_Initial_Access/Account_Lockout_Recon.md`
