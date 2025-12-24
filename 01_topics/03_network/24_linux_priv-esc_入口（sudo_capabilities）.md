## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：アプリが堅くても、ホスト側の特権境界（sudoers / capabilities）が緩いと、侵入後の権限昇格で “アプリ外” へ一気に影響が拡大する。特に「限定sudo（NOPASSWD/引数ワイルドカード）」や「file capabilities（cap_*+ep）」は、正規運用の延長に見えて破壊力が高い。
  - 満たす：最小権限の実装（sudoは最小コマンド/固定パス/固定引数、NOPASSWD最小化、SETENV抑止、sudoログ/IOログ）、capabilitiesは必要最小（cap_sys_admin等を極力排除）、変更管理と監査を設計へ落とす。
  - 参照（ASVS本体）：https://github.com/OWASP/ASVS
- WSTG
  - WSTG-CONF-01：基盤設定（OS/ミドル/権限/管理機構）の不備は、Webの外側であっても攻撃面を決定する。sudo/capabilitiesは典型の「構成・デプロイ管理」検証対象。  
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - Post-Exploitation / Privilege Escalation の入り口として、(1) sudo権限の列挙 → (2) file capabilities の列挙 → (3) 境界（許可範囲/ログ/監査）確定 → (4) 影響評価 → (5) 是正提案、の順で “推測ゼロ” に落とす。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1548.003 Sudo and Sudo Caching：sudoers/キャッシュを利用した権限昇格の枠組み。  
    https://attack.mitre.org/techniques/T1548/003/
  - T1548.001 Setuid and Setgid：SUID/SGIDに代表される“Elevation Control Mechanism”悪用。file capabilities は同系統の「実行ファイルに特権を付与する」機構として同じ境界で扱う。  
    https://attack.mitre.org/techniques/T1548/001/
  - 検知戦略（例）
    - DET0052：sudo利用・sudoers改変・キャッシュ乱用の相関（auditd等）  
      https://attack.mitre.org/detectionstrategies/DET0052/
    - DET0110：setuid/setgid 変更・異常なEUID実行の相関（auditd等）  
      https://attack.mitre.org/detectionstrategies/DET0110/

---

## タイトル
Linux Priv-Esc 入口：sudoers と File Capabilities を“観測→境界判定→安全な検証→是正”で確定する

---

## 目的（このファイルで到達する状態）
- 侵入後（低権限シェル想定）に、以下を **Yes/No/Unknown** で説明できる（=報告で刺さる状態）。
  1) sudo：実行可能コマンド（固定パス/引数範囲/ユーザ指定/ホスト指定/RunAs）と、NOPASSWD/SETENV/NOEXEC/secure_path/env_keep などの境界
  2) sudoキャッシュ：timestamp_timeout / tty_tickets 等、再認証境界（セッション内の昇格持続）
  3) file capabilities：どのバイナリがどのcapを持つか（cap_*+ep 等）、危険capの有無と影響
  4) 証跡：sudo実行/設定変更/capabilities付与のログ・相関キー（Blueが追えるか）
  5) 是正：最小権限へ戻す具体策（sudoers設計/権限制約/監査）を優先度付きで提示

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - sudo（列挙・解釈・境界判定・安全な検証）
  - Linux file capabilities（getcap/setcap概念、列挙・解釈・危険度分類・安全な検証）
  - 監査・検知（auditd等に落とす相関キー）
- 扱わない（別ファイルへ接続）
  - カーネル脆弱性の具体的なExploit（CVE単位）→ 別途「カーネル/ローカル権限昇格」ユニット
  - 資格情報ダンプ → `26_credential_dumping_所在（LSA_DPAPI）.md`（Linux版が必要なら別ユニット化）
  - 永続化 → `27_persistence_永続化（schtasks_services_wmi）.md`（Linux版が必要なら別ユニット化）
  - 横展開の実行 → `18_winrm...` `19_rdp...` 等

---

## 前提：sudo と capabilities は「正規運用」なので診断が薄くなりやすい
- 重要なのは「機能の有無」ではなく、
  - 何が許可されているか（Allow）
  - どこまで許可されているか（Scope：パス/引数/ユーザ/環境）
  - 監査できるか（Auditability）
  を “観測結果” と “設定根拠” で確定すること。

---

## 用語（最低限）
- sudo：許可されたユーザが別ユーザ（多くはroot）としてコマンド実行できる仕組み。`sudo -l` で許可一覧を確認可能（sudo manual）。  
  https://www.sudo.ws/docs/man/sudo.man/
- sudoers：sudoのポリシー（/etc/sudoers, /etc/sudoers.d/*）。`timestamp_timeout` 等のDefaultsや、コマンド定義の解釈は sudoers(5) に明記。  
  https://www.man7.org/linux/man-pages/man5/sudoers.5.html
- Linux capabilities：root権限を“分割”した権限ビット。ファイルにcapabilityを付与でき（file capabilities）、実行時に権限が付与され得る（capabilities(7)）。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html
- getcap/setcap：file capabilities の確認・設定コマンド（getcap(8)/setcap(8)）。  
  https://man7.org/linux/man-pages/man8/getcap.8.html  
  https://www.man7.org/linux/man-pages/man8/setcap.8.html

---

## 境界モデル（事故が成立する条件を固定する）
### 境界1：sudoの許可範囲（何をroot相当で実行できるか）
- NOPASSWD：認証境界が消える（ただし監査ログは残る設計も可能）
- 引数/ワイルドカード：意図しない対象ファイルやサブコマンドに到達する（sudoers(5)はワイルドカード/正規表現の解釈やエスケープ要件を明記）  
  https://www.man7.org/linux/man-pages/man5/sudoers.5.html
- SETENV / env_keep：環境変数境界が緩む（PATH/LD_*等が混入しやすい）
- secure_path：sudo実行時のPATHが固定される（逆にsecure_pathが無い/弱いと境界が曖昧）

### 境界2：sudoキャッシュ（権限が“続く”）
- timestamp_timeout により、一定時間パスワード再入力なしでsudoが通る（sudoers manual）。  
  https://www.sudo.ws/docs/man/sudoers.man/
- tty_tickets（端末ごとのチケット）無効化等により、想定外に“他セッションへ効く”設計になり得る（sudoers timestamp manual）。  
  https://www.sudo.ws/docs/man/sudoers_timestamp.man/

### 境界3：file capabilities（SUIDの亜種：必要最小を超えると危険）
- 実行ファイルにcapabilityが付くと、execve後の権限セットが変化する（capabilities(7)）。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html
- 特に危険なcap（例）
  - `cap_setuid`, `cap_setgid`：ID操作（昇格へ直結し得る）
  - `cap_dac_override`, `cap_dac_read_search`：ファイル権限無視（情報アクセスに直結）
  - `cap_sys_admin`：広範（“実質root”として扱われることが多い）
  - `cap_net_admin`：NW制御（踏み台化/トンネル/防御回避に寄る）
  - `cap_sys_ptrace`：他プロセス観測（資格情報/機密に接続し得る）
  ※capabilityの意味はcapabilities(7)に定義。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> ルール：本番影響を避ける。検証（PoC）は “無害なファイル作成/読み取り” を最小にし、後片付けまでを手順に含める。

---

## 0) 事前準備：証跡と作業ディレクトリ（必須）
~~~~
# 証跡保存（端末上で実行ログを残す）
mkdir -p ~/keda_evidence/linux_priv_esc_24
cd ~/keda_evidence/linux_priv_esc_24

# 無害テスト用（後で削除）
mkdir -p /tmp/keda_test_24 2>/dev/null || true
~~~~

保存する証跡（最低限）
- `whoami_id.txt`：id/グループ
- `sudo_list.txt`：sudo -l 出力
- `sudo_version.txt`：sudo -V（可能なら）
- `cap_find.txt`：getcap結果
- `notes.md`：判断（Yes/No/Unknown）と根拠の対応付け

---

## 1) 初動：現在の権限コンテキストを固定（id / groups）
~~~~
( whoami; id; groups ) | tee whoami_id.txt
uname -a | tee uname.txt
~~~~

判断
- グループ（wheel/sudo/admin 等）があるなら sudoersのグループ許可が疑われる
- コンテナ/名前空間の可能性があれば、capabilities評価が変わる（ただし本ユニットでは“入口”まで）

---

## 2) sudo入口：sudo -l で “許可範囲” を確定する
### 2-A) sudo -l（最優先）
- `sudo -l` は許可されたコマンド一覧の確認手段として、sudo manual に -l の構文が記載。  
  https://www.sudo.ws/docs/man/sudo.man/
~~~~
sudo -l | tee sudo_list.txt
~~~~

補助（必要時）
~~~~
# 詳細表示（sudo実装・環境により差がある）
sudo -ll 2>/dev/null | tee sudo_list_verbose.txt || true
~~~~

### 2-B) sudoers上の “list” built-in（-U）に注意
- `sudo -l -U otheruser` はsudoersに“list”権限が許可されると利用できる、とsudoers(5)に明記。  
  https://www.man7.org/linux/man-pages/man5/sudoers.5.html
~~~~
# 通る環境のみ（通らなければエラーが証跡）
sudo -l -U root 2>&1 | tee sudo_list_as_root_query.txt || true
~~~~

#### 判定テンプレ（Yes/No/Unknown）
- NOPASSWD がある：Yes/No（sudo_listに明示される）
- (root) として任意コマンド：Yes/No
- 特定コマンドのみ：Yes（=範囲が限定されている）だが、次の “引数/パス” を精査する
- sudo自体が禁止/パスワード不明：Unknown（ただし“入口”としては capabilities 側へ進む）

---

## 3) sudoの読み解き：危険パターンを“境界”として判定する（攻め方ではなく設計不備として）
> ここが薄いと「sudoで昇格できます」で終わる。必ず「なぜ危ないか（境界）」を書ける形にする。

### 3-A) まず確認する観点（sudo_listから拾う）
- RunAs（誰として実行できるか）：`(root)` だけでなく、特権ユーザ/サービスユーザも対象
- コマンドの指定方法
  - フルパス固定か（/usr/bin/xxx）
  - ワイルドカードがあるか（*）
  - 引数が固定か（許容範囲が広いか）
- オプション
  - `NOPASSWD:` が付くか
  - `SETENV:` が付くか（環境変数を持ち込める）
  - `NOEXEC:` の有無（“子プロセス起動”抑止の意図があるか）

### 3-B) sudoersの解釈根拠（ワイルドカード等）
- sudoers(5)は、コマンド引数のマッチングと、エスケープが必要な文字（, : = \ など）を明記。  
  https://www.man7.org/linux/man-pages/man5/sudoers.5.html

結論の書き方（例）
- 「sudo許可はフルパス固定かつ引数固定で、ワイルドカードを含まない（境界が明確）」  
- 「sudo許可にワイルドカード/広い引数許容があり、意図しない対象へ到達し得る（境界が曖昧）」

---

## 4) sudoキャッシュ境界：timestamp_timeout / tty分離を確認（再認証の有無）
- `timestamp_timeout` の意味と0/負値の扱いは sudoers manual に明記。  
  https://www.sudo.ws/docs/man/sudoers.man/
- タイムスタンプの仕組み（1ユーザ1ファイル/端末別など）は sudoers_timestamp manual に整理。  
  https://www.sudo.ws/docs/man/sudoers_timestamp.man/

実務の観測（権限が無い場合は “Unknown” で良い）
~~~~
# sudo自体の情報（出る範囲で証跡化）
sudo -V | tee sudo_version.txt

# 直近でsudoが通っているか（監査目的で “状態” を記録）
sudo -v 2>&1 | tee sudo_validate_cache.txt || true
~~~~

判断
- timestamp_timeout が長い/無期限：権限境界が“続く”設計（運用レビュー）
- tty分離が弱い：セッション横断の影響（運用レビュー）

---

## 5) capabilities入口：file capabilities を列挙して “危険cap” を抽出する
### 5-A) getcap の最小スコープ列挙（まずは標準パス）
- getcap(8) はファイルのcapabilityを表示するコマンド。  
  https://man7.org/linux/man-pages/man8/getcap.8.html
~~~~
# まず標準パスを対象にして時間/負荷を抑える
( getcap -r /usr/bin /usr/sbin /bin /sbin 2>/dev/null ) | tee cap_find_stdpaths.txt
~~~~

### 5-B) “全体”列挙（許可・時間がある場合のみ）
~~~~
# 重いので、許可と時間があるときだけ
( getcap -r / 2>/dev/null ) | tee cap_find_all.txt
~~~~

### 5-C) 結果の読み方（capabilities(7)の根拠）
- file capabilities は拡張属性 `security.capability` として保持され、execve後のcapabilityセットが決まる（capabilities(7)）。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html
- 表記例：`/path/to/bin = cap_net_bind_service+ep`
  - `+e`（effective）：実行時に有効化され得る
  - `+p`（permitted）：許可セットに入る
  - `+i`（inheritable）：継承セット
  ※定義はcapabilities(7)参照。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html

---

## 6) 危険度分類（capability別）：何が起き得るかを“影響”で書く
> ここは「出来る」ではなく「境界が崩れる」を書く。capabilityの定義根拠は capabilities(7)。

### 高（優先レビュー）
- `cap_setuid`, `cap_setgid`：実行主体（UID/GID）境界の崩壊に直結し得る  
- `cap_dac_override`, `cap_dac_read_search`：ファイル権限境界の崩壊（機密読み取り/探索に直結し得る）
- `cap_sys_admin`：広範な管理権限（実務上“実質root級”として扱う）  
- `cap_sys_ptrace`：他プロセスの観測・操作に接続し得る
- 根拠：capabilityの意味は capabilities(7)。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html

### 中（用途次第）
- `cap_net_admin`：ネットワーク制御（踏み台化/経路/防御設定へ影響し得る）
- `cap_setfcap`：他ファイルへcapability付与（拡散の入口になり得る）
- 根拠：capabilities(7)。  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html

### 低（限定的だが棚卸し必須）
- `cap_net_bind_service`：低ポートbind（運用目的が多い）。ただし “不要なら除去” が原則。

---

## 7) 安全な検証（PoC）：無害な操作で “境界の実在” を確定する
> 重要：権限昇格シェル等の攻撃的PoCは、合意が無い限り実施しない。  
> ここでは「許可の範囲が本当に想定どおりか」を無害に確かめる。

### 7-A) sudoの安全PoC（無害ファイル作成/読み取り）
- 例：許可コマンドが “特定ファイル編集/閲覧” の場合
  - 目的：指定外ファイルに触れないこと、監査ログに残ることを確認
~~~~
# 例（sudoで許可されているコマンドに合わせて置換すること）
# 1) 無害ファイル作成（rootが作る必要があるか、そもそも許可されているか）
sudo /usr/bin/touch /tmp/keda_test_24/sudo_poc_$(date +%s).txt 2>&1 | tee sudo_poc_touch.txt || true

# 2) 所有者/権限を観測して証跡化
ls -la /tmp/keda_test_24 | tee sudo_poc_ls.txt
~~~~

判断
- “許可コマンドが想定より広く動く” / “想定外のパスを扱える” 兆候があるなら、sudoers設計不備としてまとめる。

### 7-B) capabilitiesの安全PoC（“読める/できる”の確認は最小限）
- 原則：capabilityが付いたバイナリは “存在” と “capの種類” の時点で既に論点になる。
- 追加で確認する場合でも、対象は `/tmp/keda_test_24` など無害領域のみ、または “機密に触れない” ことを合意してから。

---

## 8) 証跡（レポート品質を上げる：貼るべき出力）
- sudo
  - `sudo -l`（最重要）
  - `sudo -V`（バージョン/プラグイン/設定のヒント）
  - 可能なら `/etc/sudoers` と `/etc/sudoers.d/*` の “存在/権限/変更管理状況”（閲覧許可がある場合のみ）
- capabilities
  - `getcap -r ...` の結果（危険capをハイライト）
  - capabilities(7)の根拠（capの意味）をURLで添付
- ATT&CK接続
  - sudo：T1548.003 / DET0052
  - “実行ファイルに特権を付与する機構”：T1548.001 / DET0110（SUID/SGIDの同系統として境界に含める）

---

## 9) 是正（最小コストで効く順：現場で通る言い方）
### sudoers
1. NOPASSWDを最小化（必要な運用だけ、対象ホスト/ユーザ/コマンドを限定）
2. コマンドはフルパス固定、引数も固定（ワイルドカードを避ける）  
   根拠（マッチング/エスケープの複雑さ）：sudoers(5)  
   https://www.man7.org/linux/man-pages/man5/sudoers.5.html
3. SETENV/env_keep を最小化（特にPATH/LD_*等は原則持ち込ませない）
4. secure_path を設定して実行環境を固定（運用要件と両立させる）
5. 監査：sudoログ/IOログを有効化し、誰が何をしたかの相関を取れるようにする（DET0052の観点）  
   https://attack.mitre.org/detectionstrategies/DET0052/

### capabilities
1. 不要なfile capabilitiesを除去（まずは “なぜ必要か” の正当化を要求）
2. 高危険cap（cap_setuid/cap_dac_* / cap_sys_admin等）を原則禁止（代替設計へ）
3. 変更管理：capability付与（xattr）を監査対象にする（ファイル変更/属性変更の監視）
4. 定期棚卸：標準パス配下の getcap 棚卸を運用に組み込む

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- sudo manual（-lの構文、sudoの基本）  
  https://www.sudo.ws/docs/man/sudo.man/
- sudoers(5)（sudoersの解釈、list built-in、ワイルドカード/エスケープ等）  
  https://www.man7.org/linux/man-pages/man5/sudoers.5.html
- sudoers manual（timestamp_timeout 等のDefaults）  
  https://www.sudo.ws/docs/man/sudoers.man/
- sudoers timestamp manual（認証キャッシュ/タイムスタンプ形式）  
  https://www.sudo.ws/docs/man/sudoers_timestamp.man/
- capabilities(7)（Linux capabilities、file capabilities、execve後の変化）  
  https://www.man7.org/linux/man-pages/man7/capabilities.7.html
- getcap(8) / setcap(8)（capability列挙/設定）  
  https://man7.org/linux/man-pages/man8/getcap.8.html  
  https://www.man7.org/linux/man-pages/man8/setcap.8.html
- MITRE ATT&CK：T1548.003 Sudo and Sudo Caching  
  https://attack.mitre.org/techniques/T1548/003/
- MITRE ATT&CK：T1548.001 Setuid and Setgid（同系統境界）  
  https://attack.mitre.org/techniques/T1548/001/
- MITRE ATT&CK：DET0052（sudo乱用の検知戦略）  
  https://attack.mitre.org/detectionstrategies/DET0052/
- MITRE ATT&CK：DET0110（setuid/setgid乱用の検知戦略）  
  https://attack.mitre.org/detectionstrategies/DET0110/
- OWASP WSTG-CONF-01  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `11_ldap_enum_ディレクトリ境界（匿名_bind）.md`
- `12_kerberos_asrep_kerberoast_成立条件.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
- `27_persistence_永続化（schtasks_services_wmi）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
