# 11_ldap_enum_ディレクトリ境界（匿名_bind）

## 具体例（出力の見方）
- 件数と属性の有無で権限範囲を推定

## 失敗パターンと対処
- 匿名bind不可: 最小権限の認証で再試行
RootDSE→Naming Context→検索境界を段階分離し、匿名bindで何が見えるかを観測で確定する

## 目標（この技術で到達する状態）
- LDAPが開いている環境で、次を“観測根拠つき”で言い切れる。
  1) どのLDAP面が露出しているか（389/636/3268/3269、StartTLS有無、SASL機構）
  2) RootDSEに匿名でアクセスできるか（RootDSEは名前空間外の特別エントリ）
  3) Naming Context（Base DN候補：defaultNamingContext / namingContexts）が何か
  4) 匿名bindで検索がどこまで許容されるか（RootDSEのみ、特定OUのみ、全体、属性制限、件数制限）
  5) 取得できる情報が後工程（12_kerberos/13_adcs/15_acl_abuse）にどう影響するか
- さらに実務品質として
  - 匿名bindが不可でも「何が境界になっているか（署名要求/CBT/ポリシー/ACL/FW）」を説明できる
  - ログ突合（DC/LDAPサーバ）で「検知/設定」を確証化できる

## 前提・対象・範囲・想定
### 対象（典型）
- AD DS（DC/GC）
- AD LDS / 製品LDAP / アプライアンスLDAP
- LDAPS終端（LB/Proxy）を挟む構成

### 代表ポート（最初に固定する）
- 389/tcp：LDAP（平文、StartTLSで暗号化に遷移する場合あり）
- 636/tcp：LDAPS（TLS直）
- 3268/tcp：Global Catalog（LDAP）
- 3269/tcp：Global Catalog over SSL（LDAPS）

### 用語（混ぜると判断が壊れる）
- bind（認証/セッション確立）
  - 匿名bind：資格情報なし
  - simple bind：DN+パスワード（平文なので原則TLS前提）
  - SASL bind：GSSAPI/Kerberos等
- RootDSE：ディレクトリの“ルート情報”の特殊エントリ（名前空間外）
- Naming Context：ディレクトリの“木”の根（Base DN候補）
- search scope：base / one / sub（検索範囲の境界）

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
> LDAP列挙の失敗は原因が混ざりやすい。以下の順に境界を固定する。

1) 到達性（L4）：389/636/3268/3269が開いているか（`05_scanning`）
2) TLS境界：StartTLS/LDAPSが成立するか（証明書/ALPNではなくTLSそのもの）
3) RootDSE境界：匿名でRootDSEが読めるか
4) bind境界：匿名bind自体が許容されるか（RootDSEのみ可の構成もある）
5) search境界：匿名でsearchが許容されるか（どのBase DN、どのscope、どの属性、何件まで）
6) 運用境界：署名要求/チャネルバインディング/監査で安全側に倒せているか（外形＋設定＋ログ）

## 結果の意味（その出力が示す状態：何が言える/言えない）
### 状態A：RootDSEは読めるが、searchは拒否
- 言える：ルート情報は露出しているが、ディレクトリ本体の検索は境界で抑止されている可能性
- 注意：RootDSEは仕様上/運用上“見えていても直ちに致命”とは限らない
- 次の一手：認証済みテストアカウントでの列挙計画、または検索拒否の根拠（ACL/ポリシー）確認

### 状態B：匿名bindでNaming Context配下の検索が成立（ユーザ/グループ/コンピュータが取れる）
- 言える：ディレクトリ境界が崩れている可能性（少なくとも匿名に情報が出る）
- 次の一手：出ている属性の“質”を評価（個人情報/組織情報/認証に効く属性）→ 12/15/13へ入力化

### 状態C：匿名bind不可（credentialsなしは拒否）
- 言える：匿名の境界は成立している側（ただし認証済み低権限での露出は別）
- 次の一手：テストアカウントで“最小権限の露出”を評価

### 状態D：TLS/署名/チャネル保護が強制される
- 言える：チャネル保護（LDAP signing/Channel Binding）が強化されている可能性
- 次の一手：管理者協力で設定値・監査イベントを確認し「設計意図どおり」に落とす

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- “匿名でどこまで見えるか”は、Kerberos/ADCS/ACLへ渡す入力の質を決める
- 取れる情報は「量」より「使える属性」の質が重要
- 取得情報の使い道（次工程への入力）
  - `12_kerberos_asrep_kerberoast_成立条件.md`：ユーザ名母集団（sAMAccountName/UPN）
  - `15_acl_abuse（AD権限グラフ）.md`：グループ名、member関係、OU命名規則
  - `13_adcs_証明書サービス悪用の境界.md`：CA/PKI関連オブジェクトの露出有無

## 次に試すこと（仮説A/Bの分岐と検証）
### 分岐1：RootDSEは匿名で取れるが検索不可
- 次の一手
  - 低権限テストアカウントでの列挙（匿名ではなく最小権限境界の確認）
  - 監査ログで匿名bind/検索拒否の事実を確証（相手側ログ突合）
  - 12/15/13は入力不足になり得るため、他経路（SMB/WinRM/RDP）で情報を作る計画へ

### 分岐2：匿名でユーザ/グループ/コンピュータが取れる
- 次の一手
  - 取得属性を“影響観点”で評価（個人情報/組織情報/認証に効く情報）
  - 12へ：ユーザ名母集団を入力として整理（重複排除、命名規則の注記）
  - 15へ：グループ関係の最小グラフ化

### 分岐3：LDAPSのみ成立、389は拒否/遮断
- 次の一手
  - 証明書（SAN/Issuer）で終端点を推定（`06_service_fingerprint` / `08_firewall_waf`へ）
  - ログ/設定で「平文禁止」「署名/CBT要求」の設計意図を確証化

## 手を動かす検証（Labs連動：観測点を明確に）
### 実施方法（RootDSE→Base DN→検索境界→ログ確証）
> 低侵襲で“境界”を確定 → 必要なら深掘り（属性/関係）へ。
> いきなり大量検索しない。件数/時間制限を最初から入れる。

#### Step 0：入力と成果物を固定する
- 入力：`target`（IP/FQDN）、到達性（389/636/3268/3269）
- 成果物
  - rootdse_access / base_dn / anon_bind / anon_search / security_controls

#### Step 1：NmapでRootDSEと匿名bindの入口を観測
~~~~
nmap -Pn -n -p 389,636,3268,3269 --script ldap-rootdse <ip> -oN 11_ldap_rootdse_<ip>.txt
~~~~

#### Step 2：ldapsearchでRootDSEを最小クエリで確定
~~~~
ldapsearch -x -H ldap://<ip>:389 -s base -b "" \
  namingContexts defaultNamingContext dnsHostName supportedLDAPVersion supportedSASLMechanisms supportedControl supportedExtension
~~~~
~~~~
ldapsearch -x -H ldaps://<ip>:636 -s base -b "" \
  namingContexts defaultNamingContext dnsHostName supportedLDAPVersion supportedSASLMechanisms
~~~~

#### Step 3：Base DNを決めて検索境界を小さく試す
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 50 -l 10 \
  "(objectClass=*)" dn
~~~~

#### Step 4：カテゴリ別・最小属性で列挙
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName userPrincipalName mail dn
~~~~
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(objectClass=group)" cn distinguishedName member
~~~~
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(objectClass=computer)" cn dNSHostName operatingSystem distinguishedName
~~~~

#### Step 5：RootDSEのみ匿名OK問題を分離して記録
- RootDSE：可/不可
- search：可/不可（Base DN、scope、フィルタ、件数制限、属性範囲）

#### Step 6：チャネル保護・署名要求の確証（外形＋設定＋ログ）
- 監査ログ（例：Event ID 2889）で署名なしbindの痕跡を突合
- 設定値と併せて“設計意図どおり”を確認

#### Step 7：Pivot越しのLDAP列挙（観測点移動）
~~~~
ssh -L 127.0.0.1:1389:<dc_ip>:389 -N <user>@<pivot_ip>
ldapsearch -x -H ldap://127.0.0.1:1389 -s base -b "" namingContexts defaultNamingContext
~~~~

### 04_labs と接続：境界を体で理解する
- Lab A：RootDSE匿名OK / search匿名NG
- Lab B：特定OUのみ匿名OK
- Lab C：LDAPS強制 + 監査ログ（2889等）

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
nmap -Pn -n -p 389,636,3268,3269 --script ldap-rootdse <ip> -oN 11_ldap_rootdse_<ip>.txt
ldapsearch -x -H ldap://<ip>:389 -s base -b "" namingContexts defaultNamingContext
~~~~
- ここで観測すること：RootDSEの可否、Naming Contextの確定
- 出力の注目点：defaultNamingContext / namingContexts / supportedSASLMechanisms
- 使えないケース：観測点が外側すぎる、TLS/署名要求が強い

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：ディレクトリ情報の匿名/低権限露出を境界として確定し、最小権限・機微情報保護・監査へ落とす
- WSTG：WebのAuthN/AuthZ評価に影響するユーザ名/組織情報の前提をLDAPから作る
- PTES：RootDSE→Base DN→検索境界→ログ確証の順で少量・再現性高く列挙する
- MITRE ATT&CK：Discovery（アカウント/グループ/システム）としての列挙可否を確定する

## 参考（必要最小限）
- OpenLDAP ldapsearch man page: https://www.openldap.org/software/man.cgi?query=ldapsearch
- Microsoft LDAP Signing and Channel Binding: https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/ldap-signing-and-channel-binding

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/05_scanning_到達性把握（nmap_masscan）.md`
- `01_topics/03_network/06_service_fingerprint（banner_tls_alpn）.md`
- `01_topics/03_network/07_pivot_tunneling（ssh_socks_chisel）.md`
- `01_topics/03_network/08_firewall_waf_検知と回避の境界（観測中心）.md`
- `01_topics/03_network/09_smb_enum_共有・権限・匿名（null_session）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/12_kerberos_asrep_kerberoast_成立条件.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
