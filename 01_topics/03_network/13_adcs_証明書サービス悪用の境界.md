# 13_adcs_証明書サービス悪用の境界
ADCS（証明書基盤）の成立条件を観測で確定し、境界の弱点と次工程を判断する

## 目標（この技術で到達する状態）
- ADドメイン内にADCSが存在する場合に、次を観測だけで言える状態に到達する
  1) ADCSが攻撃面として成立しているか（CA/Enrollment/Template/Web Enrollment/Relay入口）
  2) どの境界が弱いのか（資産境界/信頼境界/権限境界）
  3) 攻撃者が何を狙える状態か（昇格/永続化/横展開/証跡）
  4) 次に試す検証がA/Bで分岐できる（安全に段階的）

## 前提・対象・範囲・想定
- 想定シーン：内部ネットワーク（VPN/社内LAN/侵入後ピボット）でのドメイン調査
- 対象資産（ADCSの“資産”）
  - Enterprise CA（認証局サーバ、CA秘密鍵、CA DB）
  - Enrollment入口（RPC/DCOM、HTTP Enrollment、CEP/CES、NDES/SCEP）
  - Certificate Templates（発行ルール＋権限）
  - 監査ログ（CA側イベント、DC側ログ、認証ログ）
- 本ファイルは悪用手順書ではなく、成立条件（境界）を観測で確定することが主目的
- 発行要求を伴う検証は、契約/許可/影響制御を前提に最小PoCに留める

## 観測ポイント（何を見ているか：プロトコル/データ/境界）
### 1) ADCSの存在確認（Discovery）
- Configuration Naming Context からADCS関連コンテナを確認する
  - Enrollment Services（CA情報/発行テンプレート）
  - Certificate Templates（テンプレート定義）
  - AIA/Certification Authorities（CA証明書公開）
~~~~
ldapsearch -x -H ldap://<DC_IP> \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local" \
  "(objectClass=pKIEnrollmentService)" cn dNSHostName certificateTemplates
~~~~
- 判断：これが取れた時点でADCSの存在は確定

### 2) CAの入口（Enrollment経路）の観測
- 入口は大きく2系統
  - RPC/DCOM（内部向け）
  - HTTP Enrollment（IIS/CEP/CES/NDES/SCEP）
~~~~
nmap -Pn -sS -p 80,443,135,445 <CA_HOST_OR_IP>
~~~~
- 判断：HTTP系Enrollmentが見えるなら信頼境界破断の可能性が上がる

### 3) Templateを政策エンジンとして読む
- 最低限見る項目（優先順）
  1) 認証用途（EKU）
  2) Subject/SANの指定権限
  3) 承認要否（Manager approval/RA署名）
  4) Enroll権限（低権限が含まれるか）
  5) Template ACL（改変可能性）
~~~~
ldapsearch -x -H ldap://<DC_IP> \
  -b "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local" \
  "(objectClass=pKICertificateTemplate)" \
  cn displayName pKIExtendedKeyUsage msPKI-Certificate-Name-Flag msPKI-Enrollment-Flag nTSecurityDescriptor
~~~~
- 判断：CA側の certificateTemplates と突合し、実際に発行されるテンプレのみ評価対象にする

### 4) Web Enrollment / Relay成立の観測
- HTTP Enrollmentがあり、統合認証が有効かを観測する
~~~~
curl -k -I https://<CA_OR_ENROLLMENT_HOST>/ | sed -n '1,30p'
~~~~
- 判断：Negotiate/NTLMが見えるなら、`10_ntlm_relay` の成立条件と鎖になる

### 5) 監査ログ（検知境界）
- CA監査イベントの取得可否
  - 4886（要求受信）/ 4887（発行）/ 4888（拒否）/ 4889（保留）
- 監査が取れないなら運用品質として指摘対象

## 結果の意味（その出力が示す状態：何が言える/言えない）
### A) ADCSが見つかった
- 言える：Enterprise CAの存在、CA名/ホスト候補/テンプレ候補が得られる
- 言えない：認証用途テンプレが取れるかは未評価

### B) CAのcertificateTemplatesが取れた
- 言える：実際に発行されるテンプレ集合が確定する
- 意味：評価対象が絞れ、実務判断に使える

### C) 認証用途テンプレ＋広いEnrollが見つかった
- 言える：低権限から認証素材を取得できる可能性
- 次の観測：Subject/SAN制御、承認要否

### D) Web Enrollmentがあり統合認証が観測できた
- 言える：HTTP信頼境界が存在し、relay等と鎖になる可能性
- 言えない：relay成立は別条件（署名/名前解決等）が必要

### E) CA監査イベントが取れる
- 言える：要求→発行/拒否が追跡可能
- 実務上の意味：PoCの影響を最小化し報告品質を上げられる

## 攻撃者視点での利用（意思決定：優先度・攻め筋・次の仮説）
- ADCSは“認証素材”のハブ
  - 権限昇格/永続化/横展開の入口になり得る
- 優先度の付け方
  - 最優先：認証用途テンプレ＋低権限Enroll＋本人以外の識別子混入余地
  - 次点：Web Enrollment入口＋統合認証（relay鎖になり得る）
  - 次点：Template/CAのACLが弱い（改変可能性）

## 次に試すこと（仮説A/Bの分岐と検証）
### 分岐0：ADCSが見つからない
- A：ADCS探索を打ち切り、Kerberos/LDAP/SMB/委任/ACLへ戻る
- B：独立CA/外部PKIが疑われるならSaaS/IdP側へ視点移動

### 分岐1：ADCSはあるがテンプレが堅い
- A：認証用途テンプレが無いなら優先度を下げる
- B：Web Enrollmentがあるなら信頼境界側の評価へ移る

### 分岐2：テンプレに弱い境界がある
- A（観測のみ）：設定根拠で成立可能性を提示
- B（許可ありのみ）：最小PoC（本人の低権限証明書要求）で成立/拒否/保留を確定

### 分岐3：Web Enrollmentがあり統合認証が観測できた
- A：入口の存在と認証方式を根拠として報告
- B：`10_ntlm_relay` と鎖として結合し、成立条件の分岐を示す

## 手を動かす検証（Labs連動：観測点を明確に）
### 04_labsへ接続（理解の巻き戻し）
- ドメイン＋Enterprise CAを立てる
- 危険テンプレ（低権限Enroll＋認証用途）を1つ作る
- 発行/拒否/保留の差とCA監査ログの出方を確認する

## コマンド/リクエスト例（例示は最小限・意味の説明が主）
~~~~
ldapsearch -x -H ldap://<DC_IP> \
  -b "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,DC=example,DC=local" \
  "(objectClass=pKIEnrollmentService)" cn dNSHostName certificateTemplates

curl -k -I https://<CA_OR_ENROLLMENT_HOST>/ | sed -n '1,30p'
~~~~
- ここで観測すること：ADCS存在、Enrollment入口、認証方式の手がかり
- 出力の注目点：CAホスト、発行テンプレ、WWW-Authenticate
- 使えないケース：LDAPが到達できない/観測点が外側すぎる

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS：証明書発行/失効/監査が認証強度の前提になる
- WSTG：クライアント証明書利用時のAuthN前提を支える
- PTES：ADCS/CA/Template/Web Enrollmentの存在と入口を確定し成立条件を評価する
- MITRE ATT&CK：T1649（Authentication Certificates）を中心にDiscovery→Credential Accessへ接続

## 参考（必要最小限）
- ADCS/Templateの公式ドキュメント
- Certified Pre-Owned（ADCS悪用研究）
- CA監査イベント（4886/4887/4888/4889）
- ATT&CK T1649

## リポジトリ内リンク（最大3つまで）
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`

## 深掘りリンク（最大8）
- `01_topics/03_network/10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `01_topics/03_network/11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `01_topics/03_network/14_delegation（unconstrained_constrained_RBCD）.md`
- `01_topics/03_network/15_acl_abuse（AD権限グラフ）.md`
