## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - この技術で満たす/破れる点：
    - 破れる：認証基盤（Kerberos/AD）の「委任（delegation）」が不適切だと、Webアプリに直接の脆弱性がなくても、認証素材・権限の“伝播”により横展開・特権化へ接続する。
    - 満たす：委任を“必要最小限”に設計し、例外（高価値ID）には非委任（NOT_DELEGATED）等の境界を設定、さらに監査（変更検知・TGS傾向）で運用品質として担保する。
- WSTG
  - 該当テスト観点への接続：
    - WebがIWA（Kerberos/Negotiate）やバックエンド（SQL/SMB/LDAP）を使う場合、委任は“Webの認証強度・セッション境界”に影響する前提条件。
    - したがってWSTGの認証/認可評価は、AD側の委任境界（どのサービスが誰としてどこへ行けるか）を観測入力として取り込む必要がある。
- PTES
  - 位置づけ：
    - Enumeration（AD/LDAP）で委任設定を棚卸し → Vulnerability Analysis（成立条件の判定）→ Post-Exploitationの経路評価（到達性・権限グラフと結合）→ Reporting（設計是正と検知設計）
  - 前後の繋がり（1行）：
    - `11_ldap_enum` で得たアカウント/属性を、`05_scanning` の到達性と `15_acl_abuse` の権限グラフに結合し、委任が“横展開の橋”になっている箇所を優先度付けして固定する。
- MITRE ATT&CK
  - 戦術：Lateral Movement / Privilege Escalation / Credential Access / Defense Evasion（環境により）
  - 位置づけ：委任は「他者としてアクセスする」ための正規機能であり、境界が緩いと“正規機能の濫用”として攻撃経路になる。

---

# 14_delegation（unconstrained_constrained_RBCD）

## タイトル
Delegation（委任）：Unconstrained / Constrained / RBCD を「権限が置かれている場所（source側・target側）」で分解し、列挙→影響→是正→検知まで落とす

---

## 目的（この技術で到達する状態）
- 委任（delegation）を“危険/安全”の二択で語らず、次を**状態として言い切れる**ようにする。
  1) 自組織の委任はどのタイプが存在するか（Unconstrained / Constrained / RBCD）
  2) それぞれ「どこに権限が置かれているか」（Source主体/Target主体/テンプレ・運用）を説明できる
  3) その設定が、到達性（NW）と権限（AD）により、どの横展開経路に接続するかを優先度付けできる
  4) 是正が「削除」だけでなく、代替設計（gMSA、KCDの限定、非委任設定、高価値IDの隔離）として提示できる
  5) 監査（変更検知・Kerberosログ）まで含めて“運用品質”として閉じられる

---

## 前提（用語：まず混ぜない）
### 委任の本質
- 委任は「サービスAが、ユーザーXの代わりに、サービスBへアクセスする」ための仕組み。
- 重要なのは **“誰として（誰の権限で）”“どこへ（どのSPNへ）”“どの条件で（プロトコル遷移や制限）”** が許されるか。

### 3つの型（超要約：どこに権限が置かれるか）
- Unconstrained Delegation（無制約委任）
  - 権限の置き場所：**委任を受ける側（Source：サーバ/サービスアカウント）**
  - 影響の特徴：対象サービスに接続したユーザーの“認証素材が前方に渡る”運用が成立しやすく、影響範囲が広い。
- Constrained Delegation（制約付き委任：KCD）
  - 権限の置き場所：**委任を行う側（Source：サーバ/サービスアカウント）**に「どのSPNへ委任して良いか」のリストが置かれる。
  - 影響の特徴：委任先がSPNで限定されるため、設計次第で強い。だが運用が甘いと“限定が実質限定にならない”。
- Resource-Based Constrained Delegation（RBCD：リソースベース制約委任）
  - 権限の置き場所：**委任される側（Target：リソース/コンピュータオブジェクト）**
  - 影響の特徴：Target側の属性（許可リスト）により、どの主体が“他者として”アクセス可能かが決まる。ACLと結合すると危険度が跳ねる。

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
> ここが薄いと、委任は「用語まとめ」で終わる。必ず“観測→判断→次の手”に繋ぐ。

### 1) 資産境界：どの主体が“委任を実行する主体”か
- 観測対象（ADオブジェクト種別）
  - Computer アカウント（サーバ）
  - User（サービスアカウント）
  - gMSA（推奨される形だが、設定が雑だと委任境界が緩む）
- 目的：委任設定を「人（ユーザー）」と「機械（コンピュータ）」で混ぜずに棚卸しする

### 2) 信頼境界：どのドメイン/フォレストで委任が成立しているか
- 観測対象
  - 同一ドメイン内だけか
  - 信頼関係を跨ぐか（環境依存、設計と更新ポリシーが重要）
- 目的：委任が“境界を跨いで伝播”し得る条件の有無を確認し、レポートで誤解を防ぐ

### 3) 権限境界：どこで“他者としてアクセス可能”が決まるか
- Unconstrained / Constrained（KCD）
  - Source側：UACビット/属性で決まる（例：Trusted for delegation、AllowedToDelegateTo 等）
- RBCD
  - Target側：msDS-AllowedToActOnBehalfOfOtherIdentity（許可リスト）＋ その属性に書き込めるACL（=15_acl_abuseと直結）

### 4) 観測対象の属性（最小セット：これだけは毎回取る）
- Unconstrained（Source：computer/user）
  - userAccountControl（TrustedForDelegation 相当が立つ）
- Constrained（Source）
  - msDS-AllowedToDelegateTo（委任先SPNリスト）
  - userAccountControl（TrustedToAuthForDelegation：プロトコル遷移の可否に関係）
- RBCD（Target：computer）
  - msDS-AllowedToActOnBehalfOfOtherIdentity（誰が“他者として”アクセスできるか）

### 5) “高価値IDの例外境界”（守るべき側の設定）
- userAccountControl：NOT_DELEGATED（「このアカウントは委任させない」）
- 高価値ID（Domain Admin相当、Tier0/管理者、DC、認証連携アカウント等）は、委任経路に乗らないことが原則。

---

## 実施方法（最高に具体：列挙→解釈→影響→是正→検知）
> 目的は「できる/できない」の断言ではなく、委任が“どの鎖”として成立しているかを固定すること。

---

### Step 0：入力を固定する（再現性）
- 必須入力
  - ドメインDN（例：DC=corp,DC=local）
  - Configuration NC（ADCS等にも使う：CN=Configuration,DC=...）
  - 観測点（どこから見ているか）
    - 内部端末 / VPN / ピボット越し（07_pivot）
- 追加入力（あると強い）
  - テスト用の低権限ドメインユーザー（匿名は基本不可）
  - DCのログ閲覧協力（監査確認のため）

---

### Step 1：委任タイプ別の棚卸し（LDAPで“事実”を作る）
#### 1-1 Unconstrained（Source側：Trusted for delegation）
- 目的：無制約委任がどのサーバ/サービスで有効かを一覧化する
- 実務での見方：
  - 「サーバが無制約委任」＝そのサーバに接続するユーザーの認証素材が委任経路に乗りやすい
  - つまり“誰がそのサーバに接続するか”が影響範囲になる（後で到達性と結合）

~~~~
# 例：委任系属性の“棚卸し”を行う（baseDNは環境に合わせる）
# 実務では「Computer」「User（サービス）」「gMSA」を分けて出すと判断が速い

# Computer（サーバ）側の委任フラグ等を出す（属性は最小＋識別に必要なもの）
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(&(objectClass=computer)(userAccountControl:1.2.840.113556.1.4.803:=<TRUSTED_FOR_DELEGATION_BIT>))" \
  cn dNSHostName userAccountControl

# User（サービスアカウント）側も同様に
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=<TRUSTED_FOR_DELEGATION_BIT>))" \
  sAMAccountName userAccountControl servicePrincipalName
~~~~

- 判断（次の一手）
  - 0件：Unconstrainedは少なくとも“見える範囲では”不在 → KCD/RBCDを優先評価
  - 1件以上：**最優先で影響評価**へ（Step 2）。特に“ユーザーが多く接続するサーバ”は危険度が跳ねる

#### 1-2 Constrained（KCD：msDS-AllowedToDelegateTo）
- 目的：Sourceが「どのSPNへ委任できるか」を確定する
- 実務での見方：
  - AllowedToDelegateTo は“委任先の具体名（SPN）”なので、到達性（05_scanning）と結合しやすい
  - ここが広い・雑だと、KCDが実質Unconstrainedに近づく

~~~~
# Constrained Delegation（委任先SPNリスト）を持つ主体を棚卸し
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(msDS-AllowedToDelegateTo=*)" \
  cn sAMAccountName dNSHostName servicePrincipalName msDS-AllowedToDelegateTo userAccountControl
~~~~

- 判断（次の一手）
  - AllowedToDelegateTo が “cifs/”“host/”“http/” 等で広範囲に見える場合：委任先SPNの業務要件を確認し、過剰を削る計画へ
  - 併せて userAccountControl の TrustedToAuthForDelegation（プロトコル遷移）相当が立つ場合：**“入口がKerberosに限られない”**前提が強くなり、影響評価の優先度が上がる（ただし環境設計依存）

#### 1-3 RBCD（Target側：msDS-AllowedToActOnBehalfOfOtherIdentity）
- 目的：Target（サーバ/コンピュータ）側が「誰に委任させるか」を持っている状態を確定する
- 実務での見方：
  - RBCDは“Target側の許可リスト”なので、**どのサーバがTargetになっているか**が重要
  - さらに“その属性を書き換えられる権限”があると、委任境界がACL経由で崩れる（=15へ直結）

~~~~
# RBCD設定が入っているコンピュータを棚卸し（属性の中身はバイナリ/SDなので、まず“存在”を確認する）
ldapsearch -x -H ldap://<DC_IP> -b "<DOMAIN_DN>" -s sub \
  "(msDS-AllowedToActOnBehalfOfOtherIdentity=*)" \
  cn dNSHostName msDS-AllowedToActOnBehalfOfOtherIdentity
~~~~

- 判断（次の一手）
  - 0件：RBCDが“設定済みとしては”見えない → ただし「ACLで書ける潜在リスク」は残るため Step 3 へ進む
  - 1件以上：そのTargetが重要サーバか（ファイル/DB/管理）を評価し、Step 2/3を最優先で回す

---

### Step 2：影響評価（到達性×権限×利用実態 で“危険度”を決める）
> 委任は“設定がある”だけで危険度は決まらない。影響は「誰がそこに接続するか」「その先に何があるか」で決まる。

#### 2-1 到達性（NW）と結合する
- 入力：
  - 委任主体のホスト（dNSHostName）
  - 委任先SPN（msDS-AllowedToDelegateTo）
- 見たいもの：
  - そのサーバはユーザーから到達可能か（RDP/WinRM/SMB/HTTP 等）
  - バックエンドはどこか（KCDの委任先SPN＝バックエンド候補）

結論の書き方（例：状態として）
- 状態U（Unconstrained）：
  - 「多数ユーザーがアクセスするフロント（例：アプリ/ファイル）に無制約委任が有効」
  - 影響：高価値ユーザーがそのフロントに接続する運用なら、影響範囲が広い
- 状態K（KCD）：
  - 「フロントAが、バックエンドB（SPN=...）への委任が可能」
  - 影響：バックエンドが高価値（管理系/DB/ファイル）なら優先度が上がる
- 状態R（RBCD）：
  - 「ターゲットTが、主体Sに“他者としてアクセス”を許可している（あるいは許可を書ける権限がある）」
  - 影響：Tが管理/基幹であれば致命度が高い

#### 2-2 “高価値IDが委任経路に乗るか”を確認する
- 原則：Tier0/管理者が日常的に委任が有効なサーバへログオンしない
- 観測（実務で取りやすい順）
  1) 運用ヒアリング（管理者はどこにログオンするか）
  2) ログ（4624/4768/4769）で、管理者アカウントが対象サーバへアクセスしている痕跡を相関
  3) 高価値IDに NOT_DELEGATED が設定されているか（例外境界）

---

### Step 3：成立条件の深掘り（委任タイプごとの“境界”を固定する）
#### 3-1 Unconstrained：守りで言うべき境界
- 境界（設計として）
  - 無制約委任は原則避ける（必要最小限でも例外扱い）
  - 代替はKCD/RBCD（委任先を限定・責任主体を明確化）
- 観測で言い切るポイント
  - 対象サーバは何の役割で、誰がアクセスするか
  - 特権IDがアクセスする運用があるか
  - 監査で追えるか（ログ収集の有無）

#### 3-2 Constrained（KCD）：msDS-AllowedToDelegateTo を“限定”として機能させる
- 境界（設計として）
  - AllowedToDelegateTo のSPNは最小（必要なバックエンドだけ）
  - サービスアカウントは gMSA 等で運用強化（権限最小＋ローテ）
- 観測で言い切るポイント
  - AllowedToDelegateTo のSPNが多すぎないか/役割と一致するか
  - TrustedToAuthForDelegation（プロトコル遷移）が必要か（必要なら入口の管理を強化）

#### 3-3 RBCD：Target側に置かれた“許可”＋“書き込み可能性”が境界
- 境界（設計として）
  - Target側に誰を許可するか（msDS-AllowedToActOnBehalfOfOtherIdentity）は最小
  - さらに重要なのは「その属性を誰が書けるか」
    - ここが雑だと、RBCDを“後から作られる”
- 実施（観測の要点）
  - RBCDが既に設定されているTargetは、許可主体が妥当か（運用要件）
  - RBCDが未設定でも、コンピュータオブジェクトACLで “書ける主体” がいるか（=15_acl_abuseの範囲）
    - ここは必ず「Target（重要サーバ）」を優先して見る（全部は見ない）

---

### Step 4：是正案（削除だけでなく“代替設計”まで書く）
> 診断で価値が出るのは「危険」ではなく「じゃあどう設計するか」。

- Unconstrainedがある場合
  - 原則：廃止 → KCD/RBCDへ移行（委任先限定/責任の明確化）
  - 例外：どうしても必要なら
    - 対象を最小化（役割・接続者）
    - 管理者/高価値IDはログオンさせない運用へ
    - 高価値IDに NOT_DELEGATED（委任不可）を適用
- KCDがある場合
  - AllowedToDelegateTo のSPNを削る（業務要件で根拠化）
  - サービスアカウントをgMSA化（運用で鍵強度を上げる）
  - TrustedToAuthForDelegation が不要なら無効化（入口を限定）
- RBCDがある場合
  - Target側の許可主体を最小化
  - コンピュータオブジェクトACLを見直し（GenericWrite/WriteProperty/WriteDACL 等の過剰を削る）
  - 重要サーバ（Tier0相当）のコンピュータオブジェクトは変更できる主体を限定

---

### Step 5：検知（変更検知＋振る舞い検知の“二段構え”にする）
#### 5-1 変更検知（Directory Serviceの監査）
- 狙い：委任は“設定変更”が本質なので、まず変更を捕まえる
- 監視対象（イベント種別は環境の監査ポリシーに依存）
  - userAccountControl の変更（TrustedForDelegation / TrustedToAuthForDelegation / NOT_DELEGATED）
  - msDS-AllowedToDelegateTo の変更
  - msDS-AllowedToActOnBehalfOfOtherIdentity の変更（RBCD）
- 実務の書き方（相関キー）
  - 変更対象DN / 変更者 / 変更前後 / 時刻 / 管理チケットID（あるなら）

#### 5-2 振る舞い検知（KerberosのTGS傾向）
- 狙い：委任はKerberosチケット要求に反映される
- 監視観点（例）
  - 特定サーバからのTGS要求が急増
  - 高価値ユーザーに関連するTGS要求が“通常の接続経路”から外れている
- 注意：
  - ここは環境差が大きいので、まずベースライン（通常業務）を取ることが必須
  - “単発のイベント番号”で断言せず、相関（Account×Service×ClientIP×時間帯）で見る

---

## 攻撃者視点での利用（意思決定：どれから見るか、何が揃うと危険か）
> ここも“手口”ではなく“意思決定”に落とす。

- 優先順位の原則
  1) Unconstrained（存在するだけで影響範囲が広くなりやすい）
  2) RBCD（Targetが重要サーバ、かつACLで作れる/広いと危険度が跳ねる）
  3) KCD（委任先SPNが重要、または範囲が広い/入口が広い場合）
- “危険度が跳ねる条件”（状態として）
  - 高価値IDが委任サーバにログオンする運用がある
  - 委任先が管理系/基幹（cifs/host/mssqlsvc 等の重要SPN）に向いている
  - RBCDをTarget側で作れる（=ACLで書ける）主体が低権限に近い
  - 変更検知がなく、委任設定を“静かに”変えられる

---

## 次に試すこと（仮説A/B：条件で手が変わる）
### 仮説A：Unconstrainedが存在する
- 次の一手（優先）
  - そのサーバの役割・接続者（特に管理者）を確定し、影響範囲を“運用”として固定
  - 代替設計（KCD/RBCD移行）を前提に、必要な委任先SPNだけを再設計する計画を作る
- 分岐
  - 管理者が接続しない運用＋NOT_DELEGATED適用済：是正は中優先（ただし“例外の根拠”を文書化）
  - 管理者が接続する/不明：最優先是正（または運用変更）

### 仮説B：KCDが存在する（msDS-AllowedToDelegateTo が出る）
- 次の一手（優先）
  - AllowedToDelegateTo のSPNを「重要度」で分類（基幹/管理/一般）
  - フロント→バックエンドの経路として、到達性（05）と権限（15）で“鎖”を確定
- 分岐
  - SPNが最小で要件が明確：是正は微調整＋監査強化
  - SPNが広い/要件不明：削減計画（責任者・期限）まで報告に含める

### 仮説C：RBCDが設定済み、または“書けるACL”が存在する
- 次の一手（優先）
  - Targetが重要サーバかを確定（最優先）
  - TargetのコンピュータオブジェクトACLを評価（15_acl_abuse）し、「誰がRBCDを設定できるか」を状態として固定
- 分岐
  - 設定済みで許可主体が妥当：監査（変更検知）を強化し、例外として根拠化
  - 書ける主体が広い/不明：ACL是正を最優先（“RBCDを後から作れる”境界破断）

### 仮説D：委任設定は見当たらない（見える範囲で0件）
- 次の一手
  - 高価値ID側のNOT_DELEGATEDやProtected Users等、守る側の境界が整っているか確認
  - 別の横展開経路（10_ntlm_relay / 13_adcs / 15_acl_abuse / 18_winrm / 19_rdp / 20_mssql）へ主軸を移す
  - ただし「変更検知（属性変更監査）」が無いなら、委任は将来の“静かな改変点”として残るため監査整備は提案する

---

## 手を動かす検証（04_labs と連動：設計として書く）
> labsは手順書ではなく、境界と観測点を固定して“差分が出る状態”を作る。

### Lab設計（最小構成）
- DC（KDC）
- フロントサーバ（委任主体：Computerまたはサービスアカウント）
- バックエンドサーバ（委任先：SPNが立つサービス）
- 管理者アカウント（高価値ID）と一般ユーザー

### 変数（1つずつ変えて差分を見る）
- Unconstrained をON/OFF
- KCD（msDS-AllowedToDelegateTo）を “最小SPN/広いSPN” で比較
- RBCD（Target側許可）を “最小主体/広い主体” で比較
- 高価値IDに NOT_DELEGATED をON/OFF

### 観測点（必須）
- LDAP属性（変更前後）
  - userAccountControl（委任/非委任）
  - msDS-AllowedToDelegateTo
  - msDS-AllowedToActOnBehalfOfOtherIdentity
- ログ
  - Directory Service（属性変更の監査を有効化して差分が出ること）
  - Security（Kerberos要求のベースラインと差分：Account×Service×ClientIP）

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：認証基盤の“権限伝播（delegation）”が、アプリの認証強度を上書きし得る点を前提条件として扱い、最小権限・例外境界（NOT_DELEGATED）・監査（変更検知）まで落とす。
- WSTG：IWA/SSOを使うWebでは、委任が「アプリ→バックエンド」連携時の“誰としてアクセスするか”を決めるため、認証/認可の評価入力として委任境界を観測する。
- PTES：列挙（LDAP）→成立条件（タイプ別）→影響（到達性×権限×運用）→是正（代替設計）→検知（変更＋振る舞い）で閉じる。
- ATT&CK：委任の濫用は正規機能の悪用として横展開・特権化に接続するため、Discovery（委任設定/ACL）を入口に、経路が成立する条件を状態として固定する。

---

## 深掘りリンク（作成済み / 予定：最大8件）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `13_adcs_証明書サービス悪用の境界.md`
- `15_acl_abuse（AD権限グラフ）.md`
- `18_winrm_psremoting_到達性と権限.md`

---

## 参考（一次情報：最小）
- Microsoft：ms-DS-Allowed-To-Delegate-To（KCDの委任先SPNリスト）
  - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtodelegateto
- Microsoft：ms-DS-Allowed-To-Act-On-Behalf-Of-Other-Identity（RBCDの許可属性）
  - https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-allowedtoactonbehalfofotheridentity
- Microsoft：UserAccountControl flags（NOT_DELEGATED等）
  - https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/useraccountcontrol-manipulate-account-properties
- Microsoft：Kerberos delegation（gMSA/KCD運用の設計例）
  - https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/configure-kerberos-delegation-group-managed-service-accounts
- Microsoft（例）：RBCDの設定例が含まれる（Second hopの説明内）
  - https://learn.microsoft.com/en-us/powershell/scripting/security/remoting/ps-remoting-second-hop?view=powershell-7.5
