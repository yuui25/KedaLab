# 12_kerberos_asrep_kerberoast_成立条件

## 前提知識（最低限）
- AS-REP/Serviceチケットの違い

## 次に試すこと
- `14_delegation（unconstrained_constrained_RBCD）.md`へ接続
Kerberosの成立条件（事前認証/SPN/暗号方式/証跡）を観測で確定し、次の一手を決める

## 目標（この技術で到達する状態）
- ディレクトリ/認証基盤（AD/Kerberos）を「資格情報の境界装置」として捉え、次を満たす
  1) AS-REP Roast / Kerberoast が成立し得るアカウント状態の条件を、属性とログで説明できる
  2) 発見した条件が実務上のリスク（横展開・特権化）にどう繋がるか優先度を付けられる
  3) 対策を設計要件として具体化できる（属性/暗号方式/監査）

## 前提・対象・範囲・想定
- 対象
  - Active Directory ドメイン（オンプレ/クラウドIaaS上のAD含む）
  - ドメインコントローラ（KDC）と、ユーザー/サービスアカウント、SPN登録主体
- ここで扱う「成立条件」の意味
  - 攻撃手順ではなく、成立する/しない分岐を属性・暗号方式・証跡から判定する条件分解
- 典型シナリオ
  - WebアプリがWindows統合認証（Negotiate/Kerberos）やバックエンドでAD資格情報を使う
  - サービスアカウントが長期運用/パスワード固定、暗号方式がRC4許容のまま
- 安全な取り扱い
  - 本ファイルは監査/診断のための観測と判定が中心。無断環境でのチケット取得や解析は行わない

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
- 観測対象
  - Kerberos AS-REQ/AS-REP（TGT）、TGS-REQ/TGS-REP（サービスチケット）
  - ディレクトリ属性（LDAP）
    - AS-REP Roast：`userAccountControl` の DONT_REQ_PREAUTH
    - Kerberoast：`servicePrincipalName`（SPNの有無/内容）
    - 暗号方式：`msDS-SupportedEncryptionTypes`
- 境界
  - 資産境界：どのDCがKDCを担い、どこまでが対象ドメイン/フォレストか
  - 信頼境界：フォレスト/ドメイン信頼、外部IdP/SSO連携
  - 権限境界：通常ユーザー/サービスアカウント/特権グループ/委任/ACL
- 証跡（ログ）
  - DCのSecurityログ（4768/4769）
  - 相関キー：Account / Service / Client IP / 時間帯 / TicketEncryptionType

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 1) AS-REP Roast（事前認証不要ユーザー）
- 言える
  - 事前認証が要求されないユーザーが存在する
  - そのユーザーの鍵強度（実質パスワード強度）次第で入口になり得る
- 言えない
  - 直ちに侵害可能/侵害済みとは断定できない
  - 実運用で有効に使われているかは別観測

### 2) Kerberoast（SPN主体）
- 言える
  - SPNを持つ主体が存在し、サービスチケット発行の前提が整っている
  - 暗号方式（RC4許容）とパスワード運用が弱いと狙われやすい
- 言えない
  - SPNがあるだけで危険とは言えない（正常運用でも必須）
  - AESのみなら安全と断定はできない（運用/権限は別）

### 3) 暗号方式（msDS-SupportedEncryptionTypes）
- 言える
  - 主体が許容する暗号方式の境界
  - 未定義/空は既定挙動に依存し、RC4が残っていることが多い
- 言えない
  - 常にその暗号が使われるとは断定できない（交渉結果で変わる）

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- 優先度（現実的な攻め筋に直結する順）
  1) DONT_REQ_PREAUTH かつ権限が高い/横展開に直結する
  2) SPN主体が特権に近い（adminCount=1等）
  3) SPN主体が長期パスワード運用
  4) DCログでTGS要求の偏り/増加が見える
- 攻め筋の分岐
  - AS-REP Roast：事前認証の壁がなく、アカウント強度評価が重要
  - Kerberoast：強度/暗号方式/権限のどれが弱いかで狙い所が決まる
- 横展開への接続
  - `14_delegation` / `15_acl_abuse` を満たすと権限境界を越えやすい
  - SMB/WinRM/RDP/MSSQL等の到達性（`05_scanning`）と組み合わせる

## 次に試すこと（仮説A/Bの分岐と検証）
### 仮説A：DONT_REQ_PREAUTH ユーザーが存在
- 検証
  - LDAPで対象ユーザー一覧を抽出し、無効/ロック/期限切れを除外
  - 利用先（ログオン先/サービス/アプリ）を棚卸し
  - 権限（グループ/委任/ACL）と到達性を結び付ける
- 次の一手
  - 原則：事前認証を有効化（例外は用途を明文化）
  - 例外が必要なら：強度/鍵管理/監視（4768/4771）を強化

### 仮説B：SPN主体が多くRC4許容が残る
- 検証
  - SPN主体の棚卸し（用途/所有者/最終更新/権限）
  - `msDS-SupportedEncryptionTypes` の未定義/RC4混在を抽出
  - DCログ（4769）でTicketEncryptionTypeの傾向を観測
- 次の一手
  - gMSA化、最小権限、定期ローテ
  - AES優先、RC4/DES排除（互換性確認）

### 仮説C：典型条件が見当たらない
- 次の一手
  - `10_ntlm_relay` / `15_acl_abuse` / `13_adcs` を優先する
  - 4768/4769のベースラインを取り、将来の逸脱検出を整える

## 手を動かす検証（Labs連動：観測点を明確に）
### 目的
- 属性とログで「成立する/しない」の差を再現して理解する

### 構成例（最小）
- DC1（KDC） + Member Server + Client（Windows）
- アカウント
  - user_normal（通常ユーザー）
  - user_nopreauth（事前認証不要）
  - svc_app（SPN主体、最小権限）

### 観測点
- LDAP属性：userAccountControl / servicePrincipalName / msDS-SupportedEncryptionTypes / pwdLastSet
- DCログ：4768（TGT）/ 4769（TGS）

### 手順（設計としての流れ）
1) 属性で状態を作る（preauth無効/SPN付与/暗号方式）
2) 通常利用でログを取る（通常ログオン/サービスアクセス）
3) 差分を説明する（属性とログの関係）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
# DONT_REQ_PREAUTH（0x400000）の抽出（LDAPフィルタ例）

## 前提知識（最低限）
- AS-REP/Serviceチケットの違い

## 次に試すこと
- `14_delegation（unconstrained_constrained_RBCD）.md`へ接続
(&(objectCategory=person)(objectClass=user)
 (userAccountControl:1.2.840.113556.1.4.803:=4194304))

# SPN主体の抽出（LDAPフィルタ例）

## 前提知識（最低限）
- AS-REP/Serviceチケットの違い

## 次に試すこと
- `14_delegation（unconstrained_constrained_RBCD）.md`へ接続
(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))
~~~~
- ここで観測すること：成立条件（preauth無効/SPN/暗号方式）
- 出力の注目点：該当アカウントの存在と権限/運用情報
- 使えないケース：LDAP列挙が不可（`11_ldap_enum` で境界を確認）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：認証/鍵管理/特権ID運用の境界を固定し、監査/是正まで回す
- WSTG：Webの認証基盤がADに依存する場合の前提を観測で確定する
- PTES：`11_ldap_enum` の入力から成立条件を抽出し、`14_delegation` / `15_acl_abuse` へ接続する
- MITRE ATT&CK：Credential Access / Lateral Movement / Discovery

## 参考（必要最小限）
- 監査の軸：userAccountControl / servicePrincipalName / msDS-SupportedEncryptionTypes / DCイベント（4768/4769）
- 設計の軸：gMSA化/最小権限/ローテ、AES優先、ベースライン監視

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
