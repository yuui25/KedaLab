## ガイドライン対応（ASVS / WSTG / PTES / MITRE ATT&CK：毎回記載）
- ASVS
  - 破れる：NFS は「共有＝運用のための便利機能」だが、到達性・export設定・UID/GID整合が噛み合うと、**機密データの収集**と**横展開の足場**になり得る。特に `no_root_squash` は “クライアントrootをサーバrootとして扱う” 境界を開くため、設計ミス時の爆発力が大きい。https://man7.org/linux/man-pages/man5/exports.5.html
  - 満たす：到達性最小化（管理網/アプリ網のみ）、exportの最小化（ホスト/ネット範囲限定、ro優先、root_squash維持、anonuid/anongid明示）、監査（exports変更/マウント/ファイルアクセス）を“相関できる形”で固定する。
- WSTG
  - WSTG-CONF-01：インフラ構成管理の観点で、管理・配布・共有（NFS/CIFS 等）を含む「周辺要素の設定不備」がアプリ全体のリスクになる、と明示。NFSのexportは典型の検証対象。  
    https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES
  - 到達性→サービス同定→共有列挙→権限境界（ro/rw/UID/GID/root_squash）→影響範囲（どのサーバ/端末がマウントできるか）→監査/是正、の順で “推測ゼロ” に落とす。  
    https://pentest-standard.readthedocs.io/
- MITRE ATT&CK
  - T1039 Data from Network Shared Drive：NFS を含むネットワーク共有からのデータ収集（持ち出し前段）を明示。  
    https://attack.mitre.org/techniques/T1039/
  - DET0410：共有アクセスの監視・相関（ネットワーク共有アクセス/ファイル作成等）の検知戦略。  
    https://attack.mitre.org/detectionstrategies/DET0410/

---

## タイトル
NFS：共有（exports）・UID/GIDマッピング・root_squash を“観測と設定”で確定し、横展開/持ち出し境界へ落とす

---

## 目的（このファイルで到達する状態）
- 対象の NFS について、次を **Yes/No/Unknown** で説明できる（＝報告で刺さる状態）。
  1) 到達性：どこから RPC/NFS（111/2049 等）に到達できるか
  2) 共有：どのパスが export され、誰（どのネット/ホスト）がアクセス可能か
  3) アクセス権：ro/rw、subtree_check、secure/insecure 等の境界がどうなっているか
  4) IDマッピング：root_squash/no_root_squash/all_squash、anonuid/anongid がどう設定されているか  
     - root_squash の仕様（uid0→匿名uid）は exports(5) に明記。https://man7.org/linux/man-pages/man5/exports.5.html
  5) NFSv3 と NFSv4 の違いが “観測結果” にどう影響するか（showmountの限界含む）
  6) 証跡：マウント/アクセス/設定変更を Blue 側が追えるか（監査・相関キーは何か）

---

## 扱う範囲（本ファイルの守備範囲）
- 扱う
  - NFS 到達性（RPC/portmap/rpcbind・2049）
  - export列挙（v2/v3：showmount相当、v4の注意点）
  - root_squash/no_root_squash の成立条件と検証方法
  - anonuid/anongid/all_squash の意味と“実務の落とし穴”
  - 監査/検知の最小設計（“何をログとして残すか”）
- 扱わない（別ファイルへ接続）
  - SMB 共有 → `09_smb_enum_共有・権限・匿名（null_session）.md`
  - 侵入後の資格情報奪取 → `26_credential_dumping_所在（LSA_DPAPI）.md`
  - 外部への持ち出し（経路設計） → `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`

---

## 前提：NFSの“見え方”を決める重要ポイント（ここを外すと診断が薄くなる）
### 1) NFSは「RPCサービスの集合」
- よくある構成（v3系）：rpcbind/portmap（111）＋ mountd（可変）＋ nfsd（2049）＋ lock/statd 等。
- したがって “2049だけ見て終わり” は薄い。まず RPC登録状況（111）を観測するのが堅い。

### 2) showmount は万能ではない（NFSv4の注意）
- showmount は NFSv2/v3 の exports を表示する、NFSv4 exports は表示しない、と整理されている。  
  （＝ showmount -e が空でも “共有が無い” とは断定できない）  
  https://download.oracle.com/docs/cd/E23823_01/pdf/816-4555.pdf

### 3) root_squash は “境界” そのもの
- exports(5) は、root_squash を「uid/gid 0 を匿名uid/gidへマップする（デフォルト）」とし、no_root_squash で無効化できる、と明示。  
  https://man7.org/linux/man-pages/man5/exports.5.html
- anonuid/anongid で匿名uid/gid（デフォルト 65534）を上書きできる。  
  https://man7.org/linux/man-pages/man5/exports.5.html

### 4) 暗号化/保護（“sec=sys”のまま運用されがち）
- exports(5) は NFSサーバが RPC-with-TLS（RFC 9289）を使えること、export単位で xprtsec= により TLS を要求できることを記載。  
  https://man7.org/linux/man-pages/man5/exports.5.html
- RPC-with-TLS 概要（RFC 9289 への言及を含む）  
  https://docs.oracle.com/en/operating-systems/uek/8/relnotes8.0/8.0-feature-nfs-rpc-tls.html

---

## 境界モデル（何が揃うと事故るか：診断で“成立条件”として書く）
### 境界1：到達性（111/2049 へ誰が届くか）
- 共有が安全でも、到達性が広いと “収集（T1039）” の面が広がる。https://attack.mitre.org/techniques/T1039/

### 境界2：exportのスコープ（誰に何を出しているか）
- `*(rw)` のような広すぎる指定は、誤用時の影響が最大化する。
- ネット範囲/ホスト名の指定は “最小化” が基本（運用で増えがちなので台帳化が重要）。

### 境界3：IDマッピング（root_squash / all_squash / anonuid）
- root_squash が有効なら “クライアントroot” の危険を匿名化できる（ただし rw の場合は匿名権限で書ける範囲が残る）。
- no_root_squash は “クライアントrootをサーバroot相当” にし得るため、設計上の例外（ディスクレス等）でのみ正当化される。https://man7.org/linux/man-pages/man5/exports.5.html

### 境界4：整合性（UID/GIDの一致）
- NFSは RPC要求に含まれる uid/gid を基にアクセス制御する、と exports(5) に明記。  
  “同じUIDを使っている” 前提が崩れると、意図しないアクセスが起きる。  
  https://man7.org/linux/man-pages/man5/exports.5.html

### 境界5：監査（見えるか/追えるか）
- 共有アクセスは「正規機能の悪用」になりやすく、検知は “アクセス行動の相関” が中心になる（DET0410）。  
  https://attack.mitre.org/detectionstrategies/DET0410/

---

## 実施方法（最高に具体的）：観測→判断→次の一手
> 方針：まず “観測だけで確定できる” ところを埋め、次に “許可された範囲で最小のマウント” を実施して境界を確定する。  
> 注意：rw export の検証で書き込みが必要な場合でも、業務影響を避けるため **テスト用の無害ファイル**（例：keda_test_*.txt）に限定し、必ず削除する。

---

## 0) 事前準備：NFS観測台帳（必須）
- `target`: IP/FQDN/環境（prod/stg）
- `observer`: 観測元（あなたの端末/踏み台/pivot）とセグメント
- `ports`: 111/2049 の状態、その他 RPC（mountd 等）の状態
- `exports`: 共有一覧（パス、クライアント許可範囲）
- `nfs_version`: v3/v4（推定ではなく根拠付き）
- `root_squash`: yes/no/unknown（根拠：exports設定 or 実マウント時のuid観測）
- `anonuid/anongid`: 値（分かるなら）
- `evidence`: コマンド出力保存先

---

## 1) 到達性：111/2049 を“経路別”に確定する
### 1-A) nmap（最小）
~~~~
# rpcbind(111) と nfs(2049) をまず押さえる
nmap -Pn -n -sT -p 111,2049 --open <target_ip> -oN nfs_reach_<target>.txt
~~~~

#### 判断
- 111 open：RPCサービス列挙（rpcinfo相当）で “何が動いているか” を確定する価値が高い
- 2049 open：NFS本体到達はある（ただし export有無やバージョンは次で確定）
- filtered：FW/ACLの境界が効いている（観測元を変え、設計として評価に落とす）

---

## 2) RPC登録状況の観測：何のRPCが提供されているか
### 2-A) rpcinfo（使える環境の場合）
- rpcinfo は RPCサービスの登録状況を表示するコマンドとして説明されている。  
  https://docs.oracle.com/cd/E19455-01/806-0916/rfsrefer-41/index.html
~~~~
rpcinfo -p <target_ip>
~~~~

#### 観測ポイント
- nfs / mountd / nlockmgr / status などが見えるか
- TCP/UDPどちらで提供されているか（運用要件・監視要件に直結）

#### 次の一手
- mountd がある（v3系が濃厚）→ 3) exports列挙へ
- 2049はあるが mountd が見えにくい/出ない → NFSv4 の可能性を疑い、4) v4前提の確認へ

---

## 3) exports列挙（v2/v3系）：showmount / nmap nfs-showmount
### 3-A) showmount -e（最短）
- showmount は “exportされたファイルシステムとアクセス情報を表示”するコマンドとして説明され、  
  かつ “NFSv2/v3のexportsのみ表示（v4は表示しない）” と注意がある。  
  https://download.oracle.com/docs/cd/E23823_01/pdf/816-4555.pdf
~~~~
showmount -e <target_ip>
~~~~

### 3-B) nmap nfs-showmount（showmount相当）
- nfs-showmount は “showmount -e のようにexportsを表示する” NSE と説明されている。  
  https://cocalc.com/github/nmap/nmap/blob/master/scripts/nfs-showmount.nse
~~~~
nmap -Pn -n -p 111 --script nfs-showmount <target_ip> -oN nmap_nfs_showmount_<target>.txt
~~~~

#### 判断（ここで台帳の“exports”を埋める）
- export パス
- 許可クライアント（IP/ネットマスク/ホスト）
- “誰でも(*)” が含まれるか（含まれるなら強い論点）

#### 次の一手
- exportが列挙できた → 5) マウント前提の権限検証へ（ただし影響最小で）
- exportが列挙できない
  - 111/2049 open なのに showmount が出ない → NFSv4 の可能性、または mountd遮断 → 4) へ

---

## 4) NFSv4 を疑うときの実務判断（showmountが空＝“無い”ではない）
### 4-A) 観測の結論の出し方（推測を避ける）
- showmount が “v4 exportsを表示しない” 以上、次のように書く：
  - 「showmountベースでは exports を確認できなかった。これは NFSv4 環境では仕様上起こり得るため、NFSv4 を前提とした追加確認（実マウント/サーバ設定確認）が必要」  
    根拠：showmountはNFSv2/v3のみ表示。https://download.oracle.com/docs/cd/E23823_01/pdf/816-4555.pdf

### 4-B) 許可がある場合の追加確認（影響最小のマウントで“存在”を確定）
- この段階で “勝手に総当たりマウント” はしない。  
- 既知の共有パス（運用担当から提示/設計書/構成管理）を元に、後述の 5) の手順で “最小マウント” を行い、到達性と権限境界を確定する。

---

## 5) 安全なマウント手順（影響を最小化して権限を観測する）
> ポイント：マウントは “読むため” に行い、rw export でも最初は ro でマウントする。  
> クライアント側のマウントオプションで **nosuid,nodev,noexec** を付け、リスクを抑える。

### 5-A) クライアント（Linux）で隔離用マウントポイント作成
~~~~
sudo mkdir -p /mnt/keda_nfs/<target>/<export_sanitized>
sudo chmod 700 /mnt/keda_nfs/<target>/<export_sanitized>
~~~~

### 5-B) まず ro + 安全オプションでマウント（v3例）
~~~~
# vers は環境に合わせる（不明なら運用確認が優先）
sudo mount -t nfs -o ro,nosuid,nodev,noexec,vers=3,proto=tcp <target_ip>:/<export_path> /mnt/keda_nfs/<target>/<export_sanitized>
~~~~

### 5-C) v4例（共有パスの指定が v4運用に依存する点に注意）
~~~~
sudo mount -t nfs4 -o ro,nosuid,nodev,noexec,vers=4,proto=tcp <target_ip>:/<export_path_or_pseudoroot> /mnt/keda_nfs/<target>/<export_sanitized>
~~~~

#### 判断
- マウント成功：共有の存在・到達性・基本権限（読める/読めない）は確定
- マウント失敗：
  - “Permission denied” → exports側のクライアント制限が効いている可能性
  - “No such file or directory” → v4の疑似ルート/パス設計の可能性（運用確認必須）
  - “RPC: Program not registered” → mountd/バージョン整合の問題（rpcinfoに戻る）

---

## 6) 共有の権限・IDマッピング（UID/GID）の観測（root_squash判定の前提）
### 6-A) 数値UID/GIDで一覧（名前解決に引きずられない）
~~~~
# 数値で見る（-n）ことで、クライアント側 /etc/passwd 差分の誤解を避ける
ls -lan /mnt/keda_nfs/<target>/<export_sanitized> | head
~~~~

### 6-B) “誰が書けるか” を観測（ro前提でまず確認）
- ここでは “できる/できない” を確定するだけ。
- rwであることが疑われても、最初は ro で “見える範囲” を評価し、次に最小の書込みテストへ進む。

---

## 7) root_squash の境界判定（最小のテストで Yes/No を確定）
> 目的：`root_squash`（uid0→匿名uid）か `no_root_squash`（uid0を維持）かを “観測” で確定する。  
> 根拠（仕様）：root_squash/no_root_squash/all_squash/anonuid/anongid の定義は exports(5) に明記。  
> https://man7.org/linux/man-pages/man5/exports.5.html

### 7-A) 前提：書込みテストのルール（必ず守る）
- 書込みは **許可がある場合のみ**
- 対象は export 直下または運用が許容する “テスト用ディレクトリ” のみ
- 作るのは **無害な短命ファイル**（例：keda_test_<timestamp>.txt）だけ
- 作成後に “所有者（uid）” を観測し、即削除する

### 7-B) rw が許可されている場合のみ：テストファイル作成→所有者観測
~~~~
# 1) rootとしてテストファイルを作る（影響最小）
sudo sh -c 'echo keda_nfs_test > /mnt/keda_nfs/<target>/<export_sanitized>/keda_test_$(date +%Y%m%d_%H%M%S).txt'

# 2) 数値UID/GIDを観測（ここが結論）
ls -lan /mnt/keda_nfs/<target>/<export_sanitized> | tail -n 5
~~~~

#### 判断（結論の書き方）
- もし作成ファイルの所有者UIDが **65534（または anonuid に相当する値）** になっている  
  → root_squash が効いている可能性が高い（exports(5) の “匿名uid/gid（デフォルト 65534）” と一致）。  
  https://man7.org/linux/man-pages/man5/exports.5.html
- もし作成ファイルの所有者UIDが **0（root）** のまま  
  → no_root_squash の可能性（高リスク）。  
  https://man7.org/linux/man-pages/man5/exports.5.html
- もし rw ではなく作成自体が失敗  
  → root_squash以前に “書込み不可（ro/権限不足）” が境界として成立。root_squash判定は Unknown とし、exports設定（サーバ側）確認が必要。

### 7-C) 後片付け（必須）
~~~~
sudo rm -f /mnt/keda_nfs/<target>/<export_sanitized>/keda_test_*.txt
~~~~

---

## 8) exports設定（サーバ側）で “root_squash/anonuid/insecure 等” を確定できる場合
> 可能なら、ネット観測より強い根拠になる（＝報告品質が上がる）。

### 8-A) exports(5) に基づく確認観点（読むべきオプション）
- IDマッピング
  - root_squash / no_root_squash / all_squash
  - anonuid / anongid（匿名uid/gidの上書き）
- 安全性/運用
  - subtree_check / no_subtree_check（既定が変遷している点も exports(5) に記載）  
    https://man7.org/linux/man-pages/man5/exports.5.html
  - secure / insecure（クライアント側ソースポート制約）
- 暗号
  - xprtsec=（RPC-with-TLS を export単位で要求可能、など）  
    https://man7.org/linux/man-pages/man5/exports.5.html

---

## 9) “典型的に危ない設定” を診断コメントへ落とす（攻撃手順ではなく境界として）
- no_root_squash
  - 境界：クライアントrootがサーバrootとして扱われ得る（仕様上の意味が明確）  
    https://man7.org/linux/man-pages/man5/exports.5.html
  - 報告の書き方（例）：
    - 「当該exportは no_root_squash が有効であり、クライアント上のroot操作がサーバ側で匿名化されない。共有のrw範囲が広い場合、サーバ上の権限境界を弱め得る」
- `*(rw)` など広範囲クライアント許可
  - 境界：到達性と組み合わさると “共有データ収集（T1039）” の面が広がる。https://attack.mitre.org/techniques/T1039/
- UID/GID不整合（運用でありがち）
  - 境界：NFSは要求内の uid/gid に基づきアクセス制御する（同一UID前提）ため、整合が崩れると意図しないアクセスが発生し得る。  
    https://man7.org/linux/man-pages/man5/exports.5.html

---

## 10) 検知・証跡（Blueが“何を見ればよいか”を固定する）
- ATT&CK 観点
  - T1039：共有からのデータ収集は、正規機能悪用であり予防しにくい → “共有アクセスの監視と相関” が中心。  
    https://attack.mitre.org/techniques/T1039/
  - DET0410：共有アクセスの監視・相関（アクセス主体/時間帯/プロセス/大量読み取り等）。  
    https://attack.mitre.org/detectionstrategies/DET0410/
- 実務の最小方針（例）
  - サーバ側：exports変更（/etc/exports、exportfs 実行）を監査対象にする
  - サーバ側：NFSマウント/アクセスのログ（OS/ディストリ依存）を集中管理し、クライアントIP・ユーザ（可能なら）・パスの相関キーを残す
  - ネットワーク：111/2049 への異常なスキャン/大量アクセスをフローで検知（“誰がいつ増えたか”）

---

## 11) 是正（最小コストで効く順：現場で通る言い方）
1. 到達性を絞る：NFS は原則 “必要セグメントのみ” に限定（111/2049 を含む）
2. exportsを絞る：`*` を避け、ホスト/ネットを最小化。まず ro を基本に
3. root_squash を維持：no_root_squash を例外運用に閉じる（正当化できる用途のみ）  
   https://man7.org/linux/man-pages/man5/exports.5.html
4. anonuid/anongid を明示：匿名権限の意図を設計に落とし、ディレクトリ権限と整合させる  
   https://man7.org/linux/man-pages/man5/exports.5.html
5. 暗号/保護：可能なら RPC-with-TLS / xprtsec= 等で transport を保護（少なくともVPN等で包む）  
   https://man7.org/linux/man-pages/man5/exports.5.html  
   https://docs.oracle.com/en/operating-systems/uek/8/relnotes8.0/8.0-feature-nfs-rpc-tls.html
6. 監査：exports変更と共有アクセスを相関できるログ設計へ（DET0410の考え方を参照）  
   https://attack.mitre.org/detectionstrategies/DET0410/

---

## 参考URL（本文の根拠として使用：そのまま貼る）
- exports(5)（root_squash/no_root_squash/all_squash/anonuid/anongid、RPC-with-TLS/xprtsec 等）  
  https://man7.org/linux/man-pages/man5/exports.5.html
- showmount（v2/v3 exportsのみ表示、v4 exportsは表示しない）  
  https://download.oracle.com/docs/cd/E23823_01/pdf/816-4555.pdf
- rpcinfo（RPCサービス登録状況を表示）  
  https://docs.oracle.com/cd/E19455-01/806-0916/rfsrefer-41/index.html
- nmap nfs-ls（exportsを列挙・マウントして属性/ACL/一覧を取得するNSE）  
  https://nmap.org/nsedoc/scripts/nfs-ls.html
- nmap nfs-showmount（showmount -e 相当）※コードも含む  
  https://cocalc.com/github/nmap/nmap/blob/master/scripts/nfs-showmount.nse
- RPC-with-TLS（RFC 9289 への言及）  
  https://docs.oracle.com/en/operating-systems/uek/8/relnotes8.0/8.0-feature-nfs-rpc-tls.html
- MITRE ATT&CK：T1039 Data from Network Shared Drive  
  https://attack.mitre.org/techniques/T1039/
- MITRE ATT&CK：DET0410 Detection Strategy for Data from Network Shared Drive  
  https://attack.mitre.org/detectionstrategies/DET0410/
- OWASP WSTG：WSTG-CONF-01 Test Network Infrastructure Configuration  
  https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/01-Test_Network_Infrastructure_Configuration
- PTES  
  https://pentest-standard.readthedocs.io/
- OWASP ASVS（参照元）  
  https://github.com/OWASP/ASVS

---

## 深掘りリンク（最大8）
- `05_scanning_到達性把握（nmap_masscan）.md`
- `06_service_fingerprint（banner_tls_alpn）.md`
- `07_pivot_tunneling（ssh_socks_chisel）.md`
- `09_smb_enum_共有・権限・匿名（null_session）.md`
- `19_rdp_設定と認証（NLA）.md`
- `20_mssql_横展開（xp_cmdshell_linkedserver）.md`
- `28_exfiltration_持ち出し経路（DNS_HTTP_SMB）.md`
- `26_credential_dumping_所在（LSA_DPAPI）.md`
