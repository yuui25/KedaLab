/* =============================================================
   kedalab — worksheet template（作戦ノート＝「型」の定義）
   =============================================================

   HTB / OSCP / ペネトレで毎回埋める作戦ノートのひな形。kedaweb の
   Worksheet セクションがこの定義を読んで記入フォームを描画し、
   チェック/記入は localStorage に自動保存、`.md`/`.txt` で書き出せる。

   ★ この配列が「あなたの型(メソッド)」そのもの。
     毎回同じ手順で回して過不足を見つけ、ここを直して締めていく。
     項目を足す/減らす/並べ替える = テンプレ追記だけ(app.js は不変)。

   ── 構造 ──────────────────────────────────────────────────────
   meta:     上部の単一行入力(ターゲット情報)。[{ id, label, placeholder }]
   sections: 本体。type で描画が変わる。
     type:"checklist" — items:[{ label, file?, hint? }]
        file があればその kedalab ファイルへ ↗ リンク(クリックで本文表示)。
        各項目に1行メモ欄が付く。hint があればメモ欄の placeholder
        （「ここに何を書くか」の記載例）になる。省略時は「メモ…」。
        note があれば節末尾に「振り返り/改善メモ」欄(複数行・自由記述)を出す。
        値は placeholder（その節で何を振り返るかの記載例）。
     type:"text"      — 自由記述の textarea(placeholder 可)。
     共通: playbook を指定するとセクション見出しに「▶ flow」リンクが出る。

   file / playbook のパスは kedalab ルート相対。実在すること。
   ============================================================= */
window.KEDA_WORKSHEET = {
  version: "2026-06-08",

  meta: [
    { id: "target",   label: "TARGET",   placeholder: "[TARGET_IP]" },
    { id: "hostname", label: "HOSTNAME", placeholder: "" },
    { id: "os",       label: "OS",       placeholder: "Linux / Windows + 版数 (例: Windows 7 / 2008 R2)" },
    { id: "date",     label: "DATE",     placeholder: "2026-..." },
    { id: "scope",    label: "SCOPE / RULES", placeholder: "本番のみ: 実施可否・除外・連絡先を先に合意（演習は空欄可）" }
  ],

  sections: [
    { id: "ports", title: "PORTS / SERVICES (nmap 抜粋)", type: "text",
      placeholder: "21/tcp  open  ftp    [VERSION]\n22/tcp  open  ssh    [VERSION]\n445/tcp open  smb    Samba [VERSION]\n3632/tcp open distccd [VERSION]" },
    {
      id: "recon",
      title: "[01] RECON / 列挙",
      type: "checklist",
      playbook: "00_Playbook/00_OS_Identification.md",
      note: "この節で詰まった所・見落とし・型に足したい列挙項目 / 次回試すこと",
      items: [
        { label: "全ポートスキャン (nmap -p- → 詳細)",   file: "01_Reconnaissance/Network_Scanning.md", hint: "やったか確認: top-1000で止めてないか / -p- 完了。結果一覧は上部 PORTS 欄へ" },
        { label: "サービス/バージョン特定",              file: "01_Reconnaissance/Network_Scanning.md", hint: "例) OpenSSH 8.2 / Apache 2.4.41 / Samba 4.x" },
        { label: "OS版数/ビルド特定",                    file: "00_Playbook/00_OS_Identification.md", hint: "やったか確認: 版数まで詰めたか(古いほど昇格CVE)。確定値は上部 OS 欄へ" },
        { label: "FTP/サービス別 enum (21/22 等)",       file: "02_Initial_Access/FTP.md", hint: "例) anon可? 書込可? iisstart等=webroot疑い" },
        { label: "Web 列挙 (80/443)",                    file: "01_Reconnaissance/Web_Enumeration.md", hint: "例) CMS名・版 / 当たりのパス(/admin,/backup)。" },
        { label: "Web レスポンス精査 (ヘッダ/エラー)",   file: "01_Reconnaissance/Web_Response_Triage.md", hint: "例) Server/X-Powered-By / TRACE等の危険メソッド / スタックトレース" },
        { label: "SMB 列挙 (139/445)",                   file: "01_Reconnaissance/SMB_Enumeration.md", hint: "例) 共有名 / null可否 / SMBv1 / 署名" },
        { label: "SNMP 列挙 (161/udp)",                  file: "01_Reconnaissance/SNMP_Enumeration.md", hint: "例) community名 / 取得できたMIB" },
        { label: "LDAP/AD 列挙 (389/636)",               file: "01_Reconnaissance/LDAP_Enumeration.md", hint: "例) ドメイン名 / ユーザ / SPN" },
        { label: "公開ファイル/露出の確認",              file: "01_Reconnaissance/Exposed_Files.md", hint: "例) .git / .env / backup / swagger" }
      ]
    },
    {
      id: "web",
      title: "[02-W] WEB 脆弱性",
      type: "checklist",
      playbook: "00_Playbook/Web_Vuln_Flow.md",
      note: "Web で詰まった所・刺さった/外したシグナル・型に足したいチェック",
      items: [
        { label: "Triage で当たりを付ける (.req/.res 照合)", file: "01_Reconnaissance/Web_Response_Triage.md", hint: "例) 当たったシグナル → 見るファイル" },
        { label: "SQLi (エラー/数値パラメータ)",         file: "02_Initial_Access/Web_Vulnerabilities/SQLi.md", hint: "例) 注入点パラメータ / DBMS / 手法" },
        { label: "ファイルアップロード",                 file: "02_Initial_Access/Web_Vulnerabilities/File_Upload.md", hint: "例) 許可拡張子 / 回避手段 / 着弾URL" },
        { label: "パストラバーサル / LFI",               file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md", hint: "例) パラメータ / 読めたファイル" },
        { label: "コマンドインジェクション",             file: "02_Initial_Access/Web_Vulnerabilities/Command_Injection.md", hint: "例) 注入点 / 区切り文字 / 実行ユーザ" },
        { label: "SSRF / Open Redirect",                 file: "02_Initial_Access/Web_Vulnerabilities/SSRF.md", hint: "例) パラメータ / 到達できた内部先" },
        { label: "認証系 (JWT/OAuth/IDOR)",              file: "02_Initial_Access/Web_Vulnerabilities/IDOR.md", hint: "例) トークン種別 / 弱点 / 連番ID" }
      ]
    },
    {
      id: "initial",
      title: "[02] INITIAL ACCESS",
      type: "checklist",
      note: "初期侵入で詰まった所・刺さった経路・型に足したい手法",
      items: [
        { label: "default / 弱い資格情報",               file: "02_Initial_Access/Default_Credentials.md", hint: "例) 試した cred / 成功した組合せ" },
        { label: "資格情報の発見 (露出/再利用)",         file: "02_Initial_Access/Credential_Discovery.md", hint: "例) 入手元 / 値 / 使い回し先" },
        { label: "既知 CVE 照合 (バージョン → exploit)", file: "05_Tools_Reference/Searchsploit.md", hint: "例) version → CVE / PoC有無 (xmlは-sV版を渡す)" },
        { label: "エッジ機器/アプライアンス CVE",        file: "02_Initial_Access/Edge_Appliance_CVEs.md", hint: "例) 製品 / 版 / CVE" },
        { label: "サービス別侵入 (SSH/FTP/MSSQL 等)",    file: "02_Initial_Access/MSSQL_Exploitation.md", hint: "例) サービス / 手法 / 得た権限" }
      ]
    },
    {
      id: "privesc_lin",
      title: "[03] POST / PRIVESC — Linux",
      type: "checklist",
      playbook: "00_Playbook/Linux_Attack_Flow.md",
      note: "Linux 昇格で詰まった所・型に足したいチェック / 次回試すこと",
      items: [
        { label: "シェル安定化 (TTY/PATH)",              file: "03_Post_Access_Linux/Shell_Stabilization.md", hint: "例) PTY化済 / PATH / SHELL設定" },
        { label: "列挙 (linpeas/手動チェックリスト)",    file: "03_Post_Access_Linux/Enumeration_Checklist.md", hint: "例) 気になった点(sudo/SUID/cron/書込先)" },
        { label: "sudo 設定の悪用",                      file: "03_Post_Access_Linux/Sudo_Misconfig.md", hint: "例) sudo -l の結果 / GTFOBins" },
        { label: "SUID/SGID",                            file: "03_Post_Access_Linux/SUID_SGID.md", hint: "例) 非標準の SUID binary" },
        { label: "capabilities",                         file: "03_Post_Access_Linux/Capabilities.md", hint: "例) cap_setuid 等を持つ binary" },
        { label: "カーネル exploit (最後の手段)",        file: "03_Post_Access_Linux/Kernel_Exploits.md", hint: "例) uname -r / 候補CVE" }
      ]
    },
    {
      id: "privesc_win",
      title: "[04] POST / PRIVESC — Windows / AD",
      type: "checklist",
      playbook: "00_Playbook/Windows_AD_Attack_Flow.md",
      note: "Windows/AD 昇格で詰まった所・型に足したい手法 / 次回試すこと",
      items: [
        { label: "ドメイン列挙 (BloodHound 等)",         file: "04_Post_Access_Windows_AD/Enumeration_Checklist.md", hint: "例) 最短経路 / 狙う ACE" },
        { label: "資格情報ダンプ",                       file: "04_Post_Access_Windows_AD/Credential_Dumping.md", hint: "例) 取得した hash / 平文 / チケット" },
        { label: "特権トークン",                         file: "04_Post_Access_Windows_AD/Privilege_Tokens.md", hint: "例) whoami /priv の有効特権" },
        { label: "ローカル昇格 (Meterpreter: suggester→kernel/local exploit)", file: "05_Tools_Reference/Metasploit.md", hint: "例) sysinfo arch → local_exploit_suggester → 効いた exploit / 書込可能 cwd へ cd" },
        { label: "DPAPI / ブラウザ資格情報",             file: "04_Post_Access_Windows_AD/DPAPI_Browser_Creds.md", hint: "例) 復号できた資格情報" }
      ]
    },

    { id: "loot",     title: "LOOT  (cred : where-found : works-on)", type: "text",
      placeholder: "例)\nadmin:[PASSWORD] : /admin login : web, SMB\nsvc_sql / [NTLM_HASH] : MSSQL : ..." },
    { id: "foothold", title: "FOOTHOLD  (どう入ったか)", type: "text",
      placeholder: "vector / 使った exploit / 取得したシェルのユーザ" },
    { id: "privesc",  title: "PRIVESC  (どう昇格したか)", type: "text",
      placeholder: "vector → root/SYSTEM までの経路" },
    { id: "proof",    title: "PROOF", type: "text",
      placeholder: "低権限ユーザー取得確認 (id):\nroot / SYSTEM 取得確認 (id):" },
    { id: "next",     title: "NEXT / 中断メモ (再開時の一手)", type: "text",
      placeholder: "中断時に「次の一手」をここへ。再開はここから読む。\n例) 明日: FTP anon 書込テスト → webroot同一の疑い(689一致) → .aspx webshell 設置\n例) feroxbuster 結果を回収 / searchsploit IIS FTP は DoS のみ=RCE無し(再検索不要)\n[確認] コマンドの IP / ポートが TARGET と一致しているか送信前に照合" }
  ]
};
