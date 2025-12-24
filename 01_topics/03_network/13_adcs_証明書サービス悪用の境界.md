# ADCS（Active Directory Certificate Services）証明書サービス悪用の境界
（テンプレート／登録権限／発行・失効／Web Enrollment／監査で「何ができる状態か」を切る）

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：認証（証明書ベース認証/SSO）・暗号鍵管理・重要操作の強制再認証（step-up）の前提として、**「証明書＝認証素材」**の安全な発行/失効/監査を扱う
- WSTG：Webのテスト観点そのものではないが、WebアプリがTLSクライアント証明書や企業PKIを認証要素として使う場合、**Webの認証強度評価の前提**（証明書の発行権限/テンプレート/失効）を支える
- PTES：Intelligence Gathering → Vulnerability Analysis →（許可がある場合のみ）Exploitation → Post-Exploitation（永続化/横展開）→ Reporting の“境界条件”を固める
- MITRE ATT&CK：T1649（Steal or Forge Authentication Certificates）を中心に、Discovery（ADCS/CA/Templateの探索）→ Credential Access/Privilege Escalation/Persistence に接続

---

## 目的（この技術で到達する状態）
ADドメイン内にADCSが存在する場合に、次を**観測だけで言える状態**に到達する。

1) **ADCSが攻撃面として成立しているか**（CA/Enrollment/Template/Web Enrollment/Relayの入口があるか）  
2) 成立しているなら、**どの“境界”が弱いのか**（資産境界・信頼境界・権限境界）  
3) 弱い境界があるなら、**攻撃者が何を狙える状態か**（昇格・永続化・横展開・痕跡の出方）  
4) それを踏まえ、**次に試す検証がA/Bで分岐**できる（安全に、段階的に）

---

## 前提（対象・範囲・想定）
- 想定シーン：内部ネットワーク（VPN/社内LAN/侵入後ピボット）でのドメイン調査〜横展開導線確立
- 対象資産（ADCSの“どこが資産か”）
  - Enterprise CA（認証局サーバ、CA秘密鍵、CA DB）
  - Enrollment（証明書要求/発行の受付口：RPC/DCOM、HTTPベースのEnrollment、CEP/CES等）
  - Certificate Templates（発行ルール＋権限の“政策エンジン”）
  - 監査ログ（CA側イベント、DC側ログ、認証ログ）
- 本ファイルは「悪用手順書」ではなく、**成立条件（境界）を観測で確定する**ことが主目的
  - 実際の“発行要求を伴う検証”は、契約/許可/影響制御（失効・証跡・再現性）を前提に、最小限のPoCに留める

---

## 観測ポイント（何を見ているか：プロトコル/データ/境界）

### 1) まず「ADCSがあるか」を最短で確定する（Discovery）
ADCSの存在は、スキャンやOSINTよりも、**AD構成（Configuration Naming Context）**のLDAP観測が最短で確実。

- 代表的なADCS関連コンテナ（Configuration配下）
  - Enrollment Services（CAの公開情報・発行可能テンプレート）
  - Certificate Templates（テンプレート定義）
  - AIA/Certification Authorities（CA証明書公開）

#### LDAP観測（例：攻撃端末がドメイン情報を取れる前提）
- 概念：`objectClass=pKIEnrollmentService` が「Enterprise CA（発行局）」を示す
- そこで見るべき属性（“到達性”ではなく“成立条件”）
  - `dNSHostName`：CAサーバ候補（到達性スキャンの起点）
  - `cn`：CA名（構成識別子）
  - `certificateTemplates`：そのCAが実際に発行するテンプレート（重要：テンプレートはADにあっても発行されてない場合がある）

~~~~
# 例：Linuxから（baseDNは環境に合わせる）
ldapsearch -x -H ldap://<DC_IP> \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local" \
  "(objectClass=pKIEnrollmentService)" cn dNSHostName certificateTemplates
~~~~

> 判断：この出力が取れた時点で「ADCSがある」は確定。以降は **Templateと権限の境界**に集中する。

---

### 2) 「CAの入口（Enrollment経路）」を観測する（資産境界＋信頼境界）
ADCSは“CA本体”だけでなく、**要求受付の入口**が攻撃面になる。
観測すべき入口は大きく2系統。

- AD統合のEnterprise CA（ドメイン内認証前提）  
  - RPC/DCOM（内部向け、ポート的には135＋動的RPCなど）
- HTTP系Enrollment（信頼境界が崩れやすい）
  - CA Web Enrollment（IIS上の証明書申請UI/エンドポイント）
  - CEP/CES（Enrollment Policy/Enrollment Web Service）
  - NDES/SCEP（モバイル/機器向け）

#### 到達性スキャンは「入口特定」だけに使う（深追いしない）
- 目的は「Web Enrollmentがあるか」「IISがCA近傍に出ているか」を見つけること
- 深い探索（ディレクトリ総当たり等）は、契約と影響制御が前提

~~~~
# 例：最小限の到達性確認（あくまで入口の発見）
# CA候補ホストに対して：HTTP(80/443), RPC(135), SMB(445) など“入口になり得る”ものを確認
nmap -Pn -sS -p 80,443,135,445 <CA_HOST_OR_IP>
~~~~

> 判断：HTTP系Enrollmentが露出している場合、**NTLM Relay等の“信頼境界の破断”**と結びつく可能性が上がる（後段で扱う）。

---

### 3) Templateを“政策エンジン”として読む（権限境界の本丸）
ADCS悪用の多くは、Templateの「設定」と「ACL（誰がEnrollできるか）」が作る権限境界の弱さから始まる。

#### Template観測で最低限見るべき項目（チェックの順序）
優先度は「攻撃者が“認証素材”として使える証明書を取れるか」。

1) **発行される用途（EKU/用途）**  
   - 認証に使える（例：Client Authentication、Smartcard Logon等）か  
2) **主体情報の指定権限（Subject/SANを誰が決めるか）**  
   - “本人以外”の識別子（UPN等）を入れられる余地があるか  
3) **発行プロセスの制御（Manager approval / RA署名 / 承認）**  
   - 自動発行か、承認待ちになるか  
4) **Enroll権限（誰が要求できるか）**  
   - Domain Users等の広い集団に Enroll が許可されているか  
5) **Template自体のACL（書き換え可能か）**  
   - WriteDACL/WriteOwner/GenericWrite などでTemplateを改変できるか

#### LDAPでTemplateを引く（例）
Templateオブジェクトは通常、以下付近にいる。

~~~~
ldapsearch -x -H ldap://<DC_IP> \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local" \
  "(objectClass=pKICertificateTemplate)" \
  cn displayName pKIExtendedKeyUsage msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag nTSecurityDescriptor
~~~~

> 判断：Template一覧が取れたら「発行されるテンプレート（CA側の certificateTemplates）」と突合し、**“実際に取れるテンプレート”**だけを評価対象に落とす。  
> これをやらないと、評価が“紙の上”になって薄くなる。

---

### 4) Web Enrollment / Relay成立の観測（信頼境界の崩れ方）
ADCS文脈で危険度が跳ね上がるのは、「HTTP系Enrollmentがあり、かつ認証がNTLM等で受け付けられる」場合。
この場合、**“要求者本人が操作していないのに、要求者として発行が進む”**（=信頼境界破断）ルートが現実的になる。

観測としては次を押さえる：
- Enrollment用IISが存在するか（URL/証明書/サーババナー）
- Windows統合認証（Negotiate/NTLM）が有効そうか（401のWWW-Authenticate）
- EPA（Extended Protection for Authentication）等の防御が有効そうか（これは環境依存で“推定”に留まることが多い）

~~~~
# 例：HTTP入口の“認証方式”を観測する（破壊はしない）
curl -k -I https://<CA_OR_ENROLLMENT_HOST>/ \
  | sed -n '1,30p'
# 401が返る場合、WWW-Authenticate の値に Negotiate/NTLM が出るかを観測
~~~~

> 判断：HTTP Enrollmentがあり、統合認証が見えるなら、後続の「NTLM relay成立条件（SMB署名/LLMNR等）」や「強制認証（coerce）」と“鎖”として繋がる可能性がある。  
> つまりADCSは単体でなく、**別ファイルの成立条件を束ねるハブ**になる。

---

### 5) 監査ログを“検知境界”として読む（Blue視点も同時に確立）
ADCSは「証明書要求」「発行」「拒否」がCA側の監査イベントに残る。
観測・再現性・報告品質（いつ誰が何を要求したか）に直結するため、**攻める前にログの出方を押さえる**。

最低限、CA側で以下が取れるか（取れないなら、それ自体が運用品質の問題）。
- 4886：要求を受けた
- 4887：発行した
- 4888：拒否した
- 4889：保留にした（承認待ち）

> 判断：検知が取れない（監査無効・収集されない）場合、攻撃者は“静か”になれる。  
> 逆に検知が整っているなら、こちらは**“安全なPoC設計（少回数・即失効・証跡提示）”**ができる。

---

## 結果の意味（その出力が示す状態：何が言える/言えない）

### A) ADCSが見つかった（pKIEnrollmentServiceが存在）
- 言えること：
  - Enterprise CAが存在し、ADに統合された証明書発行基盤がある
  - CA名・CAホスト候補・発行テンプレート候補が得られる
- 言えないこと（この時点では）：
  - 実際に“認証に使える”テンプレが取れるか（EKU/Enroll権限/発行条件が未評価）
  - HTTP Enrollmentがあるか（別観測）

### B) CAの `certificateTemplates` が取れた
- 言えること：
  - 「紙のテンプレ定義」ではなく、**実際に発行されるテンプレの集合**が確定する
- 重要な意味：
  - Template評価の対象が絞れ、薄いチェックリストから脱却できる（=実務で判断できる情報量になる）

### C) Templateで「認証用途（Client Auth等）＋広いEnroll」が見つかった
- 言えること：
  - “認証素材（証明書）”が低権限から取得できる可能性がある
- 追加で要る観測（次の手）：
  - Subject/SANを誰が制御できるか（本人限定か、識別子を詰め替えられる余地があるか）
  - 承認が必要か（即時発行か、Pendingになるか）

### D) Web Enrollmentがあり、統合認証（Negotiate/NTLM）が観測できた
- 言えること：
  - 信頼境界が“HTTP”に拡張されており、リレー/強制認証と結びつく余地がある
- 言えないこと：
  - 実際にrelayが成立するか（それはネットワーク側条件・署名・名前解決汚染等、別の成立条件が必要）

### E) CA監査イベントが取れる（4886/4887/4888/4889）
- 言えること：
  - “要求→発行/拒否”が追跡可能で、PoCの影響と範囲を明確化できる
- 実務上の意味：
  - 報告が強くなる（要求IDを軸に、いつ誰が何を要求し、どう処理されたかを追える）

---

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
ここは「できること」列挙ではなく、**優先順位の付け方**を固定する。

### 1) ADCSを“ハブ”として見る
攻撃者の狙いはADCS自体ではなく、ADCSが提供する「認証素材（証明書）」を使った以下：
- 権限昇格（高権限主体として認証できる状態を作る）
- 永続化（パスワード変更の外側に残る認証素材を持つ）
- 横展開（証明書でリモート認証できる経路に繋げる）

このための最短ルートは、概ね次のどれか：
- **（Template起点）低権限が認証用証明書を取れる**
- **（Web Enrollment起点）信頼境界を破って“別主体として”発行させられる**
- **（CA権限起点）CA/Templateを操作できる**

### 2) 優先度の付け方（観測→判断）
- 最優先：Template評価で「認証用途＋低権限Enroll＋本人以外の識別子混入余地」が揃う兆候  
  - 理由：成立した場合、**“認証素材を得る”**が最短で、後段の横展開も選択肢が増える
- 次点：Web Enrollment（HTTP）入口があり、統合認証が見える  
  - 理由：別ファイル（NTLM relay / coercion）と“鎖”になると危険度が跳ねる
- 次点：Template/CAのACLが弱く、改変できる兆候  
  - 理由：直接の発行よりも、**設定そのものを“悪い形”に変えられる**可能性がある

---

## 次に試すこと（仮説A/Bの分岐と検証）

### 分岐0：ADCSが無い（またはEnterprise CAが見えない）
- A（標準）：
  - ADCS探索を打ち切り、Kerberos/LDAP/SMB/委任/ACL等の主要経路に戻る
- B（例外）：
  - “独立CA/外部PKI”やクラウド証明書基盤が疑われるなら、SaaS/IdP側（証明書ログイン・デバイス証明書）へ視点を移す  
  - ※この場合も「証明書＝認証素材」の境界モデルは流用できる

### 分岐1：ADCSはあるが、発行テンプレートが限定的（堅い）
- A：
  - “認証用途テンプレが発行されていない”なら、ADCSの優先度を下げる  
  - ただし **監査ログが無い/弱い**場合は、運用品質として指摘対象（攻撃者に静音性を与える）
- B：
  - “テンプレは堅いがWeb Enrollmentがある”なら、信頼境界（relay/強制認証）側に評価軸を移す

### 分岐2：Templateに弱い境界がある疑い（観測で兆候が揃う）
ここから先は「やるなら安全に」が重要。検証の粒度を段階化する。

- A（観測のみで止める：最小リスク）
  - Template設定（用途/EKU、承認要否、Enroll権限）を根拠に、攻撃パス“成立可能性”として提示
  - 監査ログ設定（CA監査、収集経路）が不足なら併せて指摘（再現性/追跡性の欠如）
- B（契約上許可がある場合のみ：最小PoC）
  - “本人以外になりすます要求”ではなく、**自分（テスト用低権限アカウント）自身の証明書要求**に留める
  - 目的は「要求が通る/承認待ちになる/拒否される」を確定すること  
  - 発行された場合は、即時失効（または有効期限の短いテンプレートで実施）と、要求IDの提示で影響を限定する

### 分岐3：Web Enrollmentがあり、統合認証が観測できた
- A：
  - まずは“入口の存在”と“認証方式”を報告根拠にする（ここでも破壊的検証は不要）
- B：
  - 既に別観点（NTLM relay / LLMNR / 強制認証）を評価しているなら、**鎖として結合**して「成立条件が揃うと危険度が跳ねる」ことを示す  
  - 具体的には「署名/保護設定」「名前解決汚染」「HTTP側の保護（EPA等）」の境界条件でA/B分岐させる

### 04_labsへ接続（“理解の巻き戻し”）
ADCSは文章だけだと薄くなりやすい。最短で理解を固める検証設計（例）：
- ドメイン＋Enterprise CAを立てる
- 1つだけ“危険なテンプレ（低権限Enroll＋認証用途）”を作り、発行/拒否/保留の差を出す
- CA監査イベント（4886/4887/4888/4889）がどう出るかを確認し、WEC/WEF等の収集設計に繋げる  
（labsは手順書ではなく、境界・観測点・巻き戻し設計として別ファイル化する）

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS
  - 認証（証明書/端末証明書/クライアント証明書）を認証要素に含めるシステムで、発行/失効/監査が“認証強度”の前提になる
  - 鍵管理（秘密鍵の保護、失効、証跡）と、重要操作時の再認証（step-up）を支える基盤として位置づけ
- WSTG
  - アプリがクライアント証明書や企業PKIを使う場合、Webアプリ側のAuthN評価の前提（証明書が誰でも取れるならAuthNが崩壊）として接続
- PTES
  - Intelligence Gathering：ADCS/CA/Template/Web Enrollmentの存在と入口特定
  - Vulnerability Analysis：Template設定＋権限＋承認フローから成立条件を評価
  - Exploitation（許可がある場合のみ）：最小PoCで「要求が通る/拒否/保留」を確定
  - Post-Exploitation：証明書が認証素材として使える場合、横展開/永続化の前提になる（ただし本ファイルは成立条件の確定が主）
- MITRE ATT&CK
  - T1649 Steal or Forge Authentication Certificates（ADCS由来の証明書取得・悪用を包括）
  - Discovery：ADCS/CA/Templateの列挙 → 認証素材化の可否判断
  - （環境により）Web Enrollmentを入口にしたリレー等の攻撃鎖に接続

---

## 参考（必要最小限）
- ADCSとテンプレート概念（Microsoft公式）
- ADCS悪用研究（Certified Pre-Owned）
- CA監査イベント（4886/4887/4888/4889）と収集設計（Microsoft公式）
- ATT&CK T1649（Authentication Certificates）
