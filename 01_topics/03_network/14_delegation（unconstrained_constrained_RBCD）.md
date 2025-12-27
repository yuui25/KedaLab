# 14_delegation（unconstrained_constrained_RBCD）

## 前提知識（最低限）
- 委任の種類と適用範囲
委任（Delegation）をタイプ別に分解し、権限がどこに置かれているかを観測で確定する

## 目標（この技術で到達する状態）
- 委任を“危険/安全”の二択で語らず、次を状態として言い切れる
  1) 自組織に存在する委任タイプ（Unconstrained / Constrained / RBCD）
  2) 権限が置かれている場所（Source側/Target側）を説明できる
  3) 到達性（NW）と権限（AD）から横展開経路を優先度付けできる
  4) 是正を削除だけでなく代替設計（gMSA/KCD限定/非委任）として提示できる
  5) 監査（変更検知/ログ）まで運用品質として閉じられる

## 前提・対象・範囲・想定
### 委任の本質
- サービスAがユーザーXの代わりにサービスBへアクセスする仕組み
- 「誰として」「どこへ」「どの条件で」が境界

### 3つの型（どこに権限が置かれるか）
- Unconstrained
  - 権限の置き場所：Source（委任を受ける側）
  - 影響：接続ユーザーの認証素材が前方に渡りやすい
- Constrained（KCD）
  - 権限の置き場所：SourceのAllowedToDelegateTo
  - 影響：委任先SPNで限定。運用が雑だと実質無制約
- RBCD
  - 権限の置き場所：TargetのAllowedToActOnBehalfOfOtherIdentity
  - 影響：Target側の許可＋ACLと結合すると危険度が跳ねる

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) 資産境界：委任主体の種類
- Computer（サーバ）、User（サービス）、gMSA

### 2) 信頼境界：どのドメイン/フォレストで成立するか
- 同一ドメインか、信頼関係を跨ぐか

### 3) 権限境界：どこで“他者としてアクセス可能”が決まるか
- Unconstrained/KCD：Source側属性
- RBCD：Target側属性＋ACL（`15_acl_abuse` と直結）

### 4) 観測すべき最小属性
- Unconstrained：userAccountControl（TrustedForDelegation）
- KCD：msDS-AllowedToDelegateTo / userAccountControl（TrustedToAuthForDelegation）
- RBCD：msDS-AllowedToActOnBehalfOfOtherIdentity
- 例外境界：NOT_DELEGATED（高価値IDの非委任）

## 結果の意味（その出力が示す状態：何が言える/言えない）
- Unconstrainedあり：影響範囲が広くなりやすい。接続者運用が鍵
- KCDあり：委任先SPNの範囲と運用が境界
- RBCDあり：Target側の許可とACLで境界が決まる
- 委任なし：守る側境界（NOT_DELEGATED等）や変更検知の有無を評価する

## 攻撃者視点での利用（意思決定：どれから見るか、何が揃うと危険か）
- 優先順位
  1) Unconstrained
  2) RBCD（Targetが重要＋ACLで作れる）
  3) KCD（委任先SPNが重要/範囲が広い）
- 危険度が跳ねる条件
  - 高価値IDが委任サーバにログオン
  - 委任先が管理系/基幹SPN
  - RBCDを作れるACLが低権限に近い
  - 変更検知が無い

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：Unconstrainedが存在
- 次の一手
  - サーバ役割/接続者を確定し影響範囲を固定
  - 代替設計（KCD/RBCD）移行計画を作る
- 分岐
  - 管理者が接続しない運用＋NOT_DELEGATED済み：中優先
  - 管理者が接続する/不明：最優先是正

### 仮説B：KCDが存在
- 次の一手
  - AllowedToDelegateToのSPNを重要度で分類
  - 到達性（`05_scanning`）と権限（`15_acl_abuse`）で鎖を確定
- 分岐
  - SPNが最小で要件明確：微調整＋監査強化
  - SPNが広い/不明：削減計画を提案

### 仮説C：RBCDが設定済み or 書けるACLが存在
- 次の一手
  - Targetが重要サーバかを確定
  - TargetのACLを評価し、誰がRBCDを書けるかを固定
- 分岐
  - 設定済みで許可主体が妥当：監査強化で根拠化
  - 書ける主体が広い：ACL是正を最優先

### 仮説D：委任設定は見当たらない
- 次の一手
  - NOT_DELEGATED/Protected Users等の守る側境界を確認
  - 別経路（`10_ntlm_relay`/`13_adcs`/`15_acl_abuse`/`18_winrm`/`19_rdp`/`20_mssql`）へ移る
  - 変更検知が無いなら監査整備を提案

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（列挙→解釈→影響→是正→検知）
#### Step 0：入力固定
- ドメインDN、観測点、（可能なら）低権限アカウント、DCログ協力

#### Step 1：委任タイプ別の棚卸し
~~~~
# Unconstrained（Computer）

## 前提知識（最低限）
- 委任の種類と適用範囲
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=<TRUSTED_FOR_DELEGATION_BIT>))" \
  cn dNSHostName userAccountControl

# Unconstrained（User）

## 前提知識（最低限）
- 委任の種類と適用範囲
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=<TRUSTED_FOR_DELEGATION_BIT>))" \
  sAMAccountName userAccountControl servicePrincipalName

# KCD

## 前提知識（最低限）
- 委任の種類と適用範囲
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(msDS-AllowedToDelegateTo=*)" \
  cn sAMAccountName dNSHostName servicePrincipalName msDS-AllowedToDelegateTo userAccountControl

# RBCD

## 前提知識（最低限）
- 委任の種類と適用範囲
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
  cn dNSHostName msDS-AllowedToActOnBehalfOfOtherIdentity
~~~~

#### Step 2：影響評価（到達性×権限×運用）
- 到達性（`05_scanning`）と委任先SPNを結合
- 高価値IDのログオン運用を確認

#### Step 3：是正案と検知
- Unconstrainedは原則廃止、KCD/RBCDへ
- KCDはSPN最小化、gMSA化
- RBCDはTargetの許可主体とACLを最小化
- 変更検知（Directory Service監査）とTGS傾向監視

### 04_labs設計
- DC/フロント/バックエンドで委任タイプを1つずつ切り替え、差分を観測

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub "(msDS-AllowedToDelegateTo=*)" cn msDS-AllowedToDelegateTo
~~~~
- ここで観測すること：KCDの委任先SPN
- 出力の注目点：SPN範囲の広さ/役割との一致
- 使えないケース：LDAP列挙が不可（`11_ldap_enum` で境界確認）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：委任境界を最小権限/例外境界/監査まで落とす
- WSTG：IWA/SSOの前提条件として委任境界を観測する
- PTES：列挙→成立条件→影響→是正→検知で閉じる
- MITRE ATT&CK：正規機能の濫用としての横展開条件を固定する

## 参考（必要最小限）
- msDS-AllowedToDelegateTo: https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto
- msDS-AllowedToActOnBehalfOfOtherIdentity: https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity
- userAccountControl flags: https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/13_adcs_証明書サービス悪用の境界.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
- `01_topics/03_network/18_winrm_psremoting_到達性と権限.md`
