フォルダ名: `01_topics/03_network/`
ファイル名: `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
STEP名: `NW03-11 LDAP Enum：RootDSE→Naming Context→検索境界を段階分離し、“匿名bindで何が見えるか”を観測で確定する`

```md
## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 位置づけ：LDAP/ADは“認証・認可の源泉”そのもの。匿名bind（あるいは匿名に近いアクセス）でディレクトリ情報が露出するなら、アクセス制御・機微情報保護・最小権限の設計が崩れる。
  - このファイルの役割：アプリ要件（ASVS）以前に、アイデンティティ基盤の境界（誰が何を列挙できるか）を外形とログで確定する。
- WSTG
  - 位置づけ：Web単体の診断でも、LDAP/ADの露出は「ユーザ名母集団」「メール/部署」「サービスアカウント痕跡」等を通じて認証攻撃・権限探索の前提を変える。WebのAuthN/AuthZ評価の“外部入力”になる。
  - このファイルの役割：Webテストに持ち込むべき“ユーザ名/組織情報/認証方式の前提”を、推測ではなく観測で作る。
- PTES
  - 位置づけ：Enumerationの中核。LDAPは「ディレクトリ境界」「権限グラフ」「委任/証明書/ACL」の入口。重要なのは“派手な手口”ではなく、境界（匿名/認証済み/署名要求）を固定し、次工程に正しい入力を渡すこと。
- MITRE ATT&CK
  - Discovery：T1087 Account Discovery / T1069 Permission Groups Discovery（列挙が可能な範囲の確定）
  - Discovery：T1018 Remote System Discovery（コンピュータ/サーバ情報の列挙）
  - Discovery：T1482 Domain Trust Discovery（環境によっては信頼/フォレスト情報が見える）
  - 横展開の前段：Kerberos（12）/ADCS（13）/ACL（15）へ“入力（名前/属性/関係）”を供給する

---

# 11_ldap_enum_ディレクトリ境界（匿名_bind）

## タイトル
LDAP Enum：RootDSE→Naming Context→検索（base/one/sub）を分離し、匿名bindで「どこまで見えるか」を境界として確定する

---

## 目的（この技術で到達する状態）
- LDAPが開いている環境で、次を“観測根拠つき”で言い切れる。
  1) どのLDAP面が露出しているか（389/636/3268/3269、StartTLS有無、SASL機構）
  2) RootDSE（ルート情報）に匿名でアクセスできるか（RootDSEは名前空間外の特別エントリ）:contentReference[oaicite:0]{index=0}
  3) Naming Context（Base DN候補：defaultNamingContext / namingContexts）が何か
  4) 匿名bindで“検索（search）がどこまで許容されるか”（RootDSEだけ、特定OUだけ、全体、属性制限、件数制限）
  5) 取得できる情報が後工程（12_kerberos、13_adcs、15_acl_abuse）にどう影響するか（入力の形に落ちる）
- さらに実務品質として
  - “匿名bindが不可”でも「何が境界になっているか（署名要求/CBT/ポリシー/ACL/FW）」を説明できる
  - ログ突合（DC/LDAPサーバ）で「検知/設定」を確証化できる

---

## 前提（対象・範囲・用語）
### 対象（典型）
- Active Directory Domain Services（AD DS：DC/GC）
- AD LDS / その他LDAPサーバ（製品LDAP、アプライアンスLDAP）
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
- RootDSE：ディレクトリの“ルート情報”の特殊エントリ（名前空間外）:contentReference[oaicite:1]{index=1}
- Naming Context：ディレクトリの“木”の根（Base DN候補）
- search scope：base / one / sub（検索範囲の境界）

---

## 観測ポイント（どの境界で止まっているかを分解）
> LDAP列挙の失敗は、原因が混ざりやすい。以下の順に境界を固定する。

1) 到達性（L4）：389/636/3268/3269が開いているか（05_scanning）
2) TLS境界：StartTLS/LDAPSが成立するか（証明書/ALPNではなくTLSそのもの）
3) RootDSE境界：匿名でRootDSEが読めるか（読める＝以後のBase DN確定が容易）
4) bind境界：匿名bind自体が許容されるか（RootDSEだけ許容、という構成もある）
5) search境界：匿名でsearchが許容されるか（どのBase DN、どのscope、どの属性、何件まで）
6) 運用境界：署名要求/チャネルバインディング/監査で“安全側”に倒せているか（外形＋設定＋ログ）

---

## 結果の意味（状態を固定して報告できるようにする）
### 状態A：RootDSEは読めるが、searchは拒否される
- 言える：ルート情報は露出しているが、ディレクトリ本体の検索は境界で抑止されている可能性
- 注意：RootDSEは仕様上/運用上“見えていても直ちに致命”とは限らない（ただし環境情報露出としては事実）
- 次の一手：認証済み（テストアカウント）での列挙計画、または検索拒否の根拠（ACL/ポリシー）確認

### 状態B：匿名bindでNaming Context配下の検索が成立する（ユーザ/グループ/コンピュータが取れる）
- 言える：ディレクトリ境界が崩れている可能性（少なくとも匿名に情報が出る）
- 次の一手：出ている属性の“質”を評価（個人情報・組織情報・認証に効く属性）→ 12/15/13へ入力化

### 状態C：匿名bind不可（credentialsなしは拒否）
- 言える：匿名の境界は成立している側（ただし認証済み低権限でどこまで見えるかは別）
- 次の一手：テストアカウントで“最小権限の露出”を評価（匿名でなければOKではない）

### 状態D：TLS/署名/チャネル保護が強制され、平文/単純bindが弾かれる
- 言える：チャネル保護（LDAP signing/Channel Binding）を強めている可能性（設定とログで確証が必要）:contentReference[oaicite:2]{index=2}
- 次の一手：管理者協力で設定値・監査イベントを確認し「設計意図どおり」に落とす

---

## 実施方法（最高に具体：RootDSE→Base DN→検索境界→ログ確証）
> 方針：低侵襲（少量）で“境界”を確定 → 必要なら深掘り（属性/関係）へ  
> いきなり大量検索しない。件数制限・ページング・時間制限を最初から入れる。

---

### Step 0：入力と成果物を固定する（再現性）
- 入力
  - `target`：IP/FQDN
  - 到達性：389/636/3268/3269 のどれがopenか（05_scanningの結果）
- 成果物（最終的に表へ）
  - `rootdse_access`：匿名でRootDSE可否
  - `base_dn`：defaultNamingContext / namingContexts
  - `anon_bind`：匿名bind可否（RootDSEのみ可、などの注記）
  - `anon_search`：匿名検索可否（base/one/sub、対象NC、フィルタ例、件数制限）
  - `security_controls`：StartTLS/LDAPS、署名要求の示唆、ログ（可能なら）

---

### Step 1：Nmapで“RootDSEと匿名bindの入口”を安全に観測する
- 目的：外形で RootDSE と、（可能なら）searchが“匿名で成立しそうか”の当たりをつける
- 実施
~~~~
# RootDSEの取得（安全カテゴリのdiscovery）
nmap -Pn -n -p 389,636,3268,3269 --script ldap-rootdse <ip> -oN 11_ldap_rootdse_<ip>.txt
~~~~
- 重要ポイント
  - `ldap-rootdse` は RootDSE から namingContexts/defaultNamingContext を取り、base未指定時の基準にもなる（nmapのldap-search側の前提にもなる）:contentReference[oaicite:3]{index=3}
- 追加（searchの可否を“軽く”見る：やりすぎない）
~~~~
# ldap-search は匿名bindを最後の手段として試す設計（環境によっては出力が多くなるので対象/フィルタを絞る）:contentReference[oaicite:4]{index=4}
nmap -Pn -n -p 389 --script ldap-search --script-args 'ldap-search.filter=(objectClass=*)' <ip> -oN 11_ldap_search_probe_<ip>.txt
~~~~
- 判断
  - RootDSEが取れる → Step 2へ（ldapsearchで同じ情報を根拠化）
  - RootDSEが取れない → 08_firewall_waf（観測中心）へ戻り、TLS/中間装置/到達性を再確認（LDAPがFW/IPSで制御されることがある）

---

### Step 2：ldapsearchでRootDSEを“最小クエリ”で確定する（匿名）
- 目的：Base DN（Naming Context）を確定し、以降の検索の土台を作る
- 実施（389：平文。ただしRootDSE取得自体は最小で行う）
~~~~
# RootDSE（base=""; scope=base）を匿名で取得（-x: simple、匿名）
# -LLL: 余計な注釈を落とす（環境により）
ldapsearch -x -H ldap://<ip>:389 -s base -b "" \
  namingContexts defaultNamingContext dnsHostName supportedLDAPVersion supportedSASLMechanisms supportedControl supportedExtension
~~~~
- LDAPS（636）が使えるなら、原則こちらで観測（証明書エラーは“事実”として残す）
~~~~
ldapsearch -x -H ldaps://<ip>:636 -s base -b "" \
  namingContexts defaultNamingContext dnsHostName supportedLDAPVersion supportedSASLMechanisms
~~~~
- RootDSEは“名前空間外の特別エントリ”であることを前提に、ここが取れる/取れないを境界として記録する:contentReference[oaicite:5]{index=5}
- 判断（次の一手）
  - `defaultNamingContext` / `namingContexts` が得られた → Step 3へ
  - 取れない → 389/636の到達性・TLS・中間装置・アクセス制御（ACL/ポリシー）を疑う（08へ戻す）

---

### Step 3：Base DNを決める（ADの典型）と“検索境界”を小さく試す
- 目的：匿名でsearchが許されるかを、少量・短時間・少件数で確定する
- Base DNの選び方（典型）
  - まず `defaultNamingContext` をBase DN候補にする
  - 併せて `configurationNamingContext` / `schemaNamingContext` がRootDSEに出る環境もある（出たら控える：後で必要になる）
- 小さく検索する（サイズ/時間制限を最初から入れる）
~~~~
# 例：defaultNamingContext を base に、件数/時間を絞って“検索が通るか”だけ確認
# -z: size limit（例：50件）、-l: time limit（例：10秒）
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 50 -l 10 \
  "(objectClass=*)" dn
~~~~
- 判断
  - 検索が通る → Step 4へ（何が見えるか：ユーザ/グループ/コンピュータを最小属性で）
  - `Insufficient access` / `Operations error` 等で拒否 → “匿名search不可”として確定。RootDSEのみ可の状態Aに分類して成果物化

---

### Step 4：匿名で見える情報を“カテゴリ別・最小属性”で列挙する（やりすぎない）
> ここは「全部吸う」ではなく、後工程に必要な“入力”を作る。属性を絞り、件数制限＋ページングを使う。

#### 4-1 ユーザ（存在と識別子だけ）
- 目的：ユーザ名母集団（後でKerberos/認証検証の入力になる）を“最小”で作る
~~~~
# 例：ADの典型属性を最小で（環境差あり）
# 取得属性は最小：sAMAccountName / userPrincipalName / mail（あれば）/ dn
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(&(objectCategory=person)(objectClass=user))" \
  sAMAccountName userPrincipalName mail dn
~~~~

#### 4-2 グループ（権限グラフの入口）
- 目的：高権限グループ名や運用グループ命名規則を把握（15_acl_abuseの前段）
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(objectClass=group)" cn distinguishedName member
~~~~

#### 4-3 コンピュータ（台帳・役割推定）
- 目的：サーバ/端末の命名規則、OS/役割の手がかり（横展開の地図）
~~~~
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -z 200 -l 20 \
  "(objectClass=computer)" cn dNSHostName operatingSystem distinguishedName
~~~~

#### 4-4 “件数制限で途中で切れる”場合の扱い（ページング）
- 症状：size limit exceeded / 結果が途中で終わる
- 対応：ページング制御（Paged Results Control）を使う（環境によりサポート）
~~~~
# OpenLDAP系クライアントのページング例（pr=1000）
# 結果が多い環境では、属性とフィルタを絞るのが第一
ldapsearch -x -H ldap://<ip>:389 -b "<defaultNamingContext>" -s sub -E pr=200/noprompt \
  "(&(objectCategory=person)(objectClass=user))" sAMAccountName dn
~~~~

---

### Step 5：匿名bindの“本当の境界”を見誤らない（RootDSEだけ匿名OK問題）
- よくある落とし穴
  - RootDSEは匿名で取れるが、ディレクトリ配下の検索は全拒否
  - 逆に、あるOUだけ匿名で見える（公開アドレス帳用途など）
- したがって成果物は必ず分ける
  - RootDSE：可/不可
  - search：可/不可（Base DN、scope、フィルタ、件数制限、取れる属性の範囲）
- “可/不可”だけでなく、**どこまで（境界）** を書く

---

### Step 6：チャネル保護・署名要求の確証（外形＋設定＋ログ）
> LDAPは外形だけだと断言しにくい。可能なら運用者協力で“確証”を取り、対策・検知に落とす。

#### 6-1 監査（イベント）で「安全でないbind」を見える化
- 例：Windows Serverの追加ログ設定により、**署名されていないLDAP bindが発生したときに Event ID 2889 を記録**できる（クライアントIP等が記録される）:contentReference[oaicite:6]{index=6}
- 実務手順（合意して進める）
  - あなた：テスト時刻、送信元IP、対象DC/LDAP、実施コマンド（匿名RootDSE/検索）を提示
  - 相手：Directory Serviceログで該当イベント（例：2889）を突合して提示
- 成果
  - “匿名/平文/署名なしのbindが実際に来ているか”を推測ではなく証跡で示せる

#### 6-2 LDAPチャネルバインディング/署名の要件（ポリシー側の前提）
- LDAP channel binding / LDAP signing は、DCの安全でない既定構成を是正するための重要論点としてMicrosoftが整理している:contentReference[oaicite:7]{index=7}
- 診断としては「設定値の有無」だけでなく
  - 例外運用が存在していないか（レガシークライアント）
  - 監査→段階的強制の計画があるか
  を併せて確認する（ここは“境界の運用”）

---

### Step 7：Pivot越しのLDAP列挙（観測点移動の定石）
- 前提：セグメント制御でLDAPが外から見えない/不安定な場合、観測点を移す（07_pivotと接続）
- 典型：ローカルフォワードで “localhost:1389 → 内部DC:389” に固定し、ツールの挙動を安定させる
~~~~
# 例：SSHローカルフォワード
ssh -L 127.0.0.1:1389:<dc_ip>:389 -N <user>@<pivot_ip>

# 以降は localhost をLDAPとして扱える
ldapsearch -x -H ldap://127.0.0.1:1389 -s base -b "" namingContexts defaultNamingContext
~~~~

---

## 取得情報の“使い道”を次工程へ接続（入力の形に落とす）
- 12_kerberos_asrep_kerberoast_成立条件.md へ渡す
  - ユーザ名母集団（sAMAccountName / UPN）
  - サービスアカウントの痕跡（サービス関連属性が見えるなら“存在”として）
- 15_acl_abuse（AD権限グラフ）へ渡す
  - グループ名、member関係（取れる範囲で）
  - OU/命名規則（委任や運用境界の推定材料）
- 13_adcs へ渡す
  - CA/PKI関連オブジェクトが見えるかは環境依存だが、“ディレクトリ情報がどの権限で見えるか”は前提として重要

---

## 次に試すこと（分岐：観測結果ごとに次の一手）
### 分岐1：RootDSEは匿名で取れるが検索不可
- 次の一手
  - 低権限テストアカウントでの列挙（“匿名”ではなく“最小権限”の境界確認）
  - 監査ログで匿名bind/検索拒否の事実を確証（相手側ログ突合）
  - 12/15/13は“入力不足”になるので、他経路（SMB/WinRM/RDP）から情報を作る計画へ

### 分岐2：匿名でユーザ/グループ/コンピュータが取れる
- 次の一手
  - 取得属性を“影響観点”で評価（個人情報、組織情報、認証に効く情報）
  - 12へ：ユーザ名母集団を入力として整理（重複排除、命名規則の注記）
  - 15へ：グループ関係の最小グラフ化（取れる範囲で）

### 分岐3：LDAPSのみ成立、389は拒否/遮断
- 次の一手
  - 証明書（SAN/Issuer）を観測し終端点を推定（06/08へ接続）
  - ログ/設定で「平文禁止」「署名/CBT要求」の設計意図を確証化（監査と合わせて報告）

---

## 手を動かす検証（04_labs と接続：境界を体で理解する）
### 最小ラボ設計（差分が出る構成だけ作る）
- Lab A：RootDSE匿名OK / search匿名NG
  - 目的：RootDSEとsearchの境界を分離して理解する
- Lab B：公開アドレス帳用途（特定OUのみ匿名OK）
  - 目的：“部分公開”が成立する場合の報告の書き方（範囲・属性・目的）を固定する
- Lab C：LDAPS強制 + 監査（イベントで不正bindが見える）
  - 目的：外形観測だけでなく“ログ確証”で診断品質が上がることを体験する（2889等）:contentReference[oaicite:8]{index=8}

---

## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回）
- ASVS：認証・認可の根幹であるディレクトリ情報が、匿名/低権限でどこまで露出するかを“境界”として確定し、最小権限・機微情報保護・監査へ落とす。
- WSTG：WebのAuthN/AuthZ評価に影響する“ユーザ名母集団・組織情報・統合認証前提”をLDAPから作る（作れない場合は作れないと確定する）。
- PTES：RootDSE→Base DN→検索境界→ログ確証の順で、少量・再現性高く列挙を進め、後工程（Kerberos/ADCS/ACL）へ入力化する。
- MITRE ATT&CK：Discovery（アカウント/グループ/システム）としての列挙可否を確定し、攻撃者が利用し得る“前提情報”をどこまで与えているかを評価する。

---

## 深掘りリンク（作成済み / 予定：最大8件）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `08_firewall_waf_検知と回避の境界（観測中心）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `10_ntlm_relay_成立条件（SMB署名_LLMNR）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `15_acl_abuse（AD権限グラフ）.md`
```
