/* =============================================================
   kedalab — triage rules (signal → kedalab ファイル の対応表)
   =============================================================

   アップロード/貼り付けした .req / .res / .txt(nmap 等) の本文から
   「意味のある指標(シグナル)」だけを正規表現で拾い、対応する kedalab
   ファイルを示唆するためのルール表。app.js の照合エンジンはこの配列を
   汎用的に回すだけなので、**ルールを増やすときはこのファイルに 1 オブジェクト
   追記するだけ**でよい(app.js / index.html / styles.css は触らない)。

   ── ルールの書式 ──────────────────────────────────────────────
   {
     id:       一意の識別子(kebab-case)。重複不可。
     label:    UI に出す人間向けのシグナル名。
     category: グルーピング用。"tech-stack" | "web-vuln" | "auth"
               | "info-leak" | "infra-service" のいずれか(自由に増やしてよい)。
     weight:   確証度の重み(整数)。発火したルールの weight 合計が
               ファイルのスコアになる。「これが出たらほぼ確定」なシグナルは
               高め(3〜4)、状況証拠レベルは低め(1)にする。
     pattern:  正規表現、または正規表現の配列(配列はいずれか1つ当たれば発火)。
               入力本文(原文のまま)に対して .match() される。
     targets:  [{ file, why }] の配列。
               file = kedalab ルート相対パス(実在すること)。
               why  = なぜそのファイルを見るべきかの 1 行理由(UI に表示)。
   }

   ── 育てるときの指針 ──────────────────────────────────────────
   - 偽陽性が怖いシグナルは pattern を厳しめ(ポート番号やヘッダ名で固定)に。
   - 1 シグナルが複数ファイルに効くなら targets を複数並べてよい。
   - 新しい技術ファイルを kedalab に追加したら、対応するシグナルもここに足す。
   - file のパスは必ず実在を確認すること(存在しないと開けないリンクになる)。

   version はメンテの目安。ルールを増やしたら日付を更新しておくと
   UI のフッタ表示で「いつ時点のルールか」が分かる。
   ============================================================= */
window.KEDA_TRIAGE = {
  version: "2026-05-30",
  rules: [
    /* ── tech-stack:レスポンスから判定できる土台技術 ───────────── */
    {
      id: "stack-php",
      label: "PHP アプリケーション",
      category: "tech-stack",
      weight: 2,
      pattern: [/x-powered-by:\s*php/i, /\bphpsessid\b/i, /\.php(\?|\b)/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/File_Upload.md", why: "PHP は拡張子トリック(.phar/.pht 等)でアップロード制限を抜けやすい" },
        { file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md", why: "include()/require() ベースの LFI/RFI が定番" },
        { file: "02_Initial_Access/Web_Vulnerabilities/Command_Injection.md", why: "system()/exec() 経由の OS コマンド注入を確認" }
      ]
    },
    {
      id: "stack-aspnet",
      label: "ASP.NET アプリケーション",
      category: "tech-stack",
      weight: 2,
      pattern: [/x-powered-by:\s*asp\.net/i, /x-aspnet-version/i, /\basp\.net_sessionid\b/i, /\.aspx?(\?|\b)/i, /__viewstate/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md", why: "IIS/ASP.NET のパス正規化バグ・短縮名(8.3)列挙を確認" },
        { file: "01_Reconnaissance/Web_Enumeration.md", why: "ViewState・既定エンドポイント・トレース有効化など列挙の起点" }
      ]
    },
    {
      id: "stack-java",
      label: "Java / Servlet アプリケーション",
      category: "tech-stack",
      weight: 2,
      pattern: [/\bjsessionid\b/i, /x-powered-by:\s*(servlet|jsp)/i, /\.jsp(\?|\b)/i, /\.do(\?|\b)/i, /java\.[\w.]+(exception|error)/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/Java_Deserialization_Bypass.md", why: "Java スタックは ois.readObject() 経由のデシリアライズ RCE が刺さりやすい" },
        { file: "02_Initial_Access/Web_Vulnerabilities/XXE.md", why: "Java の XML パーサは既定で外部実体を解決しがち" }
      ]
    },
    {
      id: "server-apache",
      label: "Apache httpd バージョン露出",
      category: "tech-stack",
      weight: 2,
      pattern: /server:\s*apache\/[\d.]+/i,
      targets: [
        { file: "02_Initial_Access/Edge_Appliance_CVEs.md", why: "バージョン固定 → 既知 CVE(例: 2.4.49/2.4.50 のパストラバーサル CVE-2021-41773)を照合" },
        { file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md", why: "mod_cgi 有効時はトラバーサルから RCE に発展しうる" }
      ]
    },
    {
      id: "server-iis",
      label: "Microsoft IIS",
      category: "tech-stack",
      weight: 1,
      pattern: /server:\s*microsoft-iis/i,
      targets: [
        { file: "01_Reconnaissance/Web_Enumeration.md", why: "IIS バージョン別の既定ファイル・短縮名列挙・WebDAV を確認" }
      ]
    },

    /* ── web-vuln:エラー文字列・パラメータ形からの脆弱性示唆 ──────── */
    {
      id: "vuln-sqli-error",
      label: "SQL エラーのスタック露出",
      category: "web-vuln",
      weight: 4,
      pattern: [/you have an error in your sql syntax/i, /\bsql syntax\b/i, /mysql_fetch/i, /\bORA-\d{5}\b/, /unclosed quotation mark/i, /\bSQLSTATE\b/, /pg_query|psql:/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/SQLi.md", why: "DB エラーがそのまま返っている = エラーベース SQLi の典型サイン" }
      ]
    },
    {
      id: "vuln-id-param",
      label: "数値/識別子パラメータ",
      category: "web-vuln",
      weight: 1,
      pattern: /[?&](?:id|uid|user|userid|user_id|cat|category|pid|product|item|order|order_id|account|invoice|doc|file_id)=/i,
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/IDOR.md", why: "識別子を直接受けるパラメータ → 値の差し替えで他者リソースに到達できるか試す" },
        { file: "02_Initial_Access/Web_Vulnerabilities/SQLi.md", why: "同じパラメータに SQLi が同居しがち。シングルクォート/論理演算で確認" }
      ]
    },
    {
      id: "vuln-lfi",
      label: "ファイル指定パラメータ / トラバーサル痕跡",
      category: "web-vuln",
      weight: 3,
      pattern: [/[?&](?:file|page|path|include|template|doc|view|lang|dir|download)=/i, /\.\.(?:%2f|\/)+/i, /failed opening '[^']+' for inclusion/i, /\bphp:\/\/filter/i, /etc\/passwd/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/Path_Traversal.md", why: "ファイル名をパラメータで受けている → ../ や php://filter で LFI を確認" }
      ]
    },
    {
      id: "vuln-cmd",
      label: "コマンド実行を匂わせる入力",
      category: "web-vuln",
      weight: 2,
      pattern: [/[?&](?:cmd|exec|command|ping|host|ip|query|run|do)=/i, /[;|`]\s*(id|whoami|uname|cat|dir|type)\b/i, /\$\([^)]+\)/],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/Command_Injection.md", why: "OS コマンドに渡っていそうな入力点 → ;`|$() でインジェクションを確認" }
      ]
    },
    {
      id: "vuln-ssrf",
      label: "URL を受けるパラメータ",
      category: "web-vuln",
      weight: 2,
      pattern: [/[?&](?:url|uri|dest|destination|target|callback|webhook|proxy|fetch|domain|site|feed|load|image_url)=https?(:|%3a)/i, /[?&](?:url|uri|target|fetch)=(?:gopher|dict|file|ftp):/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/SSRF.md", why: "サーバが取りに行く URL を制御できる → 内部リソース・メタデータへ到達できるか" },
        { file: "02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md", why: "リダイレクト先制御なら open redirect、SSRF の踏み台にもなる" }
      ]
    },
    {
      id: "vuln-open-redirect",
      label: "リダイレクト先パラメータ",
      category: "web-vuln",
      weight: 1,
      pattern: [/[?&](?:redirect|redirect_uri|next|returnurl|return_to|return|continue|dest|goto|rurl)=https?(:|%3a|%2f)/i, /location:\s*https?:\/\//i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/Open_Redirect.md", why: "遷移先を外部に向けられるか → フィッシング・OAuth トークン奪取の足場" }
      ]
    },
    {
      id: "vuln-xss",
      label: "反射されうる入力 / スクリプト痕跡",
      category: "web-vuln",
      weight: 2,
      pattern: [/<script\b/i, /\bon(error|load|mouseover|click)\s*=/i, /javascript:/i, /[?&](?:q|search|query|name|msg|message|comment|s)=/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/XSS.md", why: "入力がそのまま HTML に反映されるか → コンテキスト別ペイロードで確認" }
      ]
    },
    {
      id: "vuln-xml",
      label: "XML を受理するエンドポイント",
      category: "web-vuln",
      weight: 3,
      pattern: [/content-type:\s*(application|text)\/xml/i, /<\?xml\b/i, /<!doctype\s+[\w-]+\s*\[/i, /soap(action|:envelope)/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/XXE.md", why: "XML body を受けている → DOCTYPE 外部実体で XXE/SSRF/ファイル読取を確認" },
        { file: "02_Initial_Access/Web_Vulnerabilities/XSLT_Injection.md", why: "XSLT 変換が絡むなら XSLT インジェクションも併せて確認" }
      ]
    },
    {
      id: "vuln-upload",
      label: "ファイルアップロード",
      category: "web-vuln",
      weight: 2,
      pattern: [/content-type:\s*multipart\/form-data/i, /content-disposition:\s*form-data;[^\n]*filename=/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/File_Upload.md", why: "アップロード機能あり → 拡張子/Content-Type/マジックバイト検証の抜けを確認" }
      ]
    },

    /* ── auth:認証方式とトークン ──────────────────────────────── */
    {
      id: "auth-jwt",
      label: "JWT(JSON Web Token)",
      category: "auth",
      weight: 3,
      pattern: [/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\./, /authorization:\s*bearer\s+eyJ/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/JWT_Attacks.md", why: "JWT を使用 → alg:none・弱い署名鍵・kid インジェクションを確認" }
      ]
    },
    {
      id: "auth-oauth",
      label: "OAuth / OpenID フロー",
      category: "auth",
      weight: 2,
      pattern: [/[?&](?:client_id|response_type|grant_type|redirect_uri|code_challenge)=/i, /\/(oauth|authorize|token|\.well-known\/openid)/i],
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/OAuth_Attacks.md", why: "OAuth フローあり → redirect_uri 検証不備・state 欠如・code 横取りを確認" }
      ]
    },
    {
      id: "auth-basic",
      label: "HTTP Basic 認証",
      category: "auth",
      weight: 2,
      pattern: [/www-authenticate:\s*basic/i, /authorization:\s*basic\s+/i],
      targets: [
        { file: "02_Initial_Access/Default_Credentials.md", why: "Basic 認証 → 既定/弱い資格情報の総当たりが最初の一手" },
        { file: "01_Reconnaissance/Web_Enumeration.md", why: "保護されているパスの範囲・realm 名から製品を推定" }
      ]
    },
    {
      id: "auth-ntlm",
      label: "NTLM / Negotiate 認証",
      category: "auth",
      weight: 2,
      pattern: /www-authenticate:\s*(ntlm|negotiate)/i,
      targets: [
        { file: "04_Post_Access_Windows_AD/Enumeration_Checklist.md", why: "NTLM/Negotiate = AD ドメイン参加ホスト。ドメイン情報の列挙へ" },
        { file: "01_Reconnaissance/LDAP_Enumeration.md", why: "ドメイン環境ならLDAPでユーザ/グループ/ポリシーを列挙" }
      ]
    },
    {
      id: "info-cookie-flags",
      label: "Cookie のセキュリティ属性",
      category: "info-leak",
      weight: 1,
      pattern: /set-cookie:(?![^\n]*httponly)[^\n]*/im,
      targets: [
        { file: "02_Initial_Access/Web_Vulnerabilities/XSS.md", why: "HttpOnly/Secure が無い Cookie → XSS でのセッション奪取が成立しやすい" }
      ]
    },

    /* ── info-leak:露出・設定ミスの痕跡 ──────────────────────────── */
    {
      id: "leak-dirlist",
      label: "ディレクトリリスティング",
      category: "info-leak",
      weight: 2,
      pattern: [/<title>index of \//i, /\bindex of \/[\w./-]*/i, /directory listing for/i],
      targets: [
        { file: "01_Reconnaissance/Exposed_Files.md", why: "一覧表示が有効 → バックアップ・設定・ソースの直接取得を狙う" },
        { file: "01_Reconnaissance/Web_Enumeration.md", why: "見えているパスを起点にさらにディレクトリ/ファイルを掘る" }
      ]
    },
    {
      id: "leak-vcs",
      label: ".git / VCS メタデータ露出",
      category: "info-leak",
      weight: 3,
      pattern: [/\/\.git\//i, /ref:\s*refs\/heads\//i, /\/\.svn\//i, /\/\.env\b/i],
      targets: [
        { file: "01_Reconnaissance/Exposed_Files.md", why: ".git/.env 露出 → リポジトリ/認証情報の丸ごと復元を試す" },
        { file: "02_Initial_Access/Credential_Discovery.md", why: "復元したファイルから資格情報・API キーを探す" }
      ]
    },

    /* ── infra-service:nmap 等のポートスキャン出力から ─────────────── */
    {
      id: "svc-smb",
      label: "SMB / NetBIOS",
      category: "infra-service",
      weight: 2,
      pattern: [/\b(445|139)\/tcp\s+open/i, /\bmicrosoft-ds\b/i, /\bnetbios-ssn\b/i],
      targets: [
        { file: "01_Reconnaissance/SMB_Enumeration.md", why: "共有・null セッション・バージョン列挙の起点" }
      ]
    },
    {
      id: "svc-ldap",
      label: "LDAP / Active Directory",
      category: "infra-service",
      weight: 2,
      pattern: [/\b(389|636|3268|3269)\/tcp\s+open/i, /\bldap(s|ssl)?\b/i, /microsoft windows active directory ldap/i],
      targets: [
        { file: "01_Reconnaissance/LDAP_Enumeration.md", why: "ドメインのユーザ/グループ/ポリシー/SPN を列挙" },
        { file: "04_Post_Access_Windows_AD/Enumeration_Checklist.md", why: "AD 環境確定 → ドメイン全体の列挙チェックリストへ" }
      ]
    },
    {
      id: "svc-mssql",
      label: "Microsoft SQL Server",
      category: "infra-service",
      weight: 2,
      pattern: [/\b1433\/tcp\s+open/i, /\bms-sql(-s)?\b/i, /microsoft sql server/i],
      targets: [
        { file: "02_Initial_Access/MSSQL_Exploitation.md", why: "認証→xp_cmdshell/リンクサーバ経由の実行・権限昇格を確認" }
      ]
    },
    {
      id: "svc-mysql",
      label: "MySQL / MariaDB",
      category: "infra-service",
      weight: 1,
      pattern: [/\b3306\/tcp\s+open/i, /\bmysql\b/i, /\bmariadb\b/i],
      targets: [
        { file: "02_Initial_Access/MySQL_Exploitation.md", why: "認証・UDF・ファイル読み書き権限を確認" }
      ]
    },
    {
      id: "svc-rdp",
      label: "RDP",
      category: "infra-service",
      weight: 1,
      pattern: [/\b3389\/tcp\s+open/i, /\bms-wbt-server\b/i],
      targets: [
        { file: "02_Initial_Access/RDP.md", why: "資格情報での接続・NLA 有無・既知 CVE を確認" }
      ]
    },
    {
      id: "svc-ssh",
      label: "SSH",
      category: "infra-service",
      weight: 1,
      pattern: [/\b22\/tcp\s+open/i, /\bopenssh\b/i, /\bssh-\d\.\d/i],
      targets: [
        { file: "02_Initial_Access/SSH.md", why: "バージョン別 CVE・鍵/パスワード認証・弱い資格情報を確認" }
      ]
    },
    {
      id: "svc-ftp",
      label: "FTP",
      category: "infra-service",
      weight: 1,
      pattern: [/\b21\/tcp\s+open/i, /\bvsftpd\b/i, /\bproftpd\b/i, /\bftp\s+anonymous\b/i],
      targets: [
        { file: "02_Initial_Access/FTP.md", why: "anonymous ログイン・書き込み可否・バージョン別 CVE を確認" }
      ]
    },
    {
      id: "svc-winrm",
      label: "WinRM / WS-Management",
      category: "infra-service",
      weight: 1,
      pattern: [/\b(5985|5986)\/tcp\s+open/i, /\bwinrm\b/i, /\bwsman\b/i],
      targets: [
        { file: "02_Initial_Access/WinRM.md", why: "資格情報があれば evil-winrm 等でシェル取得" }
      ]
    },
    {
      id: "svc-snmp",
      label: "SNMP",
      category: "infra-service",
      weight: 1,
      pattern: [/\b161\/udp\s+open/i, /\bsnmp\b/i],
      targets: [
        { file: "01_Reconnaissance/SNMP_Enumeration.md", why: "community string(public 等)経由でシステム情報を吸い出す" }
      ]
    },
    {
      id: "svc-mail",
      label: "メールサービス (SMTP/POP3/IMAP)",
      category: "infra-service",
      weight: 1,
      pattern: [/\b(25|465|587|110|143)\/tcp\s+open/i, /\bsmtp\b/i, /\bimap\b/i, /\bpop3\b/i],
      targets: [
        { file: "02_Initial_Access/Mail_Services.md", why: "VRFY/EXPN によるユーザ列挙・認証・既知 CVE を確認" }
      ]
    }
  ]
};
