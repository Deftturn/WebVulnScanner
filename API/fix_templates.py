# fix_templates.py — Language-specific fix templates for vulnerabilities
# Kept separate to keep api_server.py clean and allow easy extension

# SQL Injection fix templates by language
SQLI_CODE = {
    "PHP": {
        "before": "<?php\n$search = $_GET['{param}'];\n$query = \"SELECT * FROM table WHERE col LIKE '%$search%'\";\n$result = mysqli_query($conn, $query);\n?>",
        "after": "<?php\n$search = $_GET['{param}'];\n$stmt = $pdo->prepare(\"SELECT * FROM table WHERE col LIKE ?\");\n$stmt->execute(['%' . $search . '%']);\n$result = $stmt->fetchAll();\n?>",
    },
    "Java": {
        "before": "String search = request.getParameter(\"{param}\");\nString query = \"SELECT * FROM table WHERE col LIKE '%\" + search + \"%'\";\nStatement stmt = conn.createStatement();\nResultSet rs = stmt.executeQuery(query);",
        "after": "String search = request.getParameter(\"{param}\");\nPreparedStatement stmt = conn.prepareStatement(\n    \"SELECT * FROM table WHERE col LIKE ?\");\nstmt.setString(1, \"%\" + search + \"%\");\nResultSet rs = stmt.executeQuery();",
    },
    "Python": {
        "before": "search = request.args.get('{param}')\nquery = f\"SELECT * FROM table WHERE col LIKE '%{{search}}%'\"\ncursor.execute(query)",
        "after": "search = request.args.get('{param}')\ncursor.execute(\n    \"SELECT * FROM table WHERE col LIKE %s\",\n    ('%' + search + '%',)\n)",
    },
    "ASP.NET (C#)": {
        "before": "string search = Request.QueryString[\"{param}\"];\nstring query = \"SELECT * FROM table WHERE col LIKE '%\" + search + \"%'\";\nSqlCommand cmd = new SqlCommand(query, conn);",
        "after": "string search = Request.QueryString[\"{param}\"];\nSqlCommand cmd = new SqlCommand(\n    \"SELECT * FROM table WHERE col LIKE @search\", conn);\ncmd.Parameters.AddWithValue(\"@search\", \"%\" + search + \"%\");",
    },
    "JavaScript (Node.js)": {
        "before": "const search = req.query.{param};\nconst query = `SELECT * FROM products WHERE name LIKE '%${{search}}%'`;\ndb.query(query);",
        "after": "const search = req.query.{param};\nconst query = 'SELECT * FROM products WHERE name LIKE ?';\ndb.query(query, [`%${{search}}%`]);",
    },
    "Ruby": {
        "before": "search = params[:{param}]\nquery = \"SELECT * FROM products WHERE name LIKE '%#{search}%'\"\nresult = ActiveRecord::Base.connection.execute(query)",
        "after": "search = params[:{param}]\nresult = Product.where(\"name LIKE ?\", \"%#{search}%\")",
    },
    "Go": {
        "before": "search := r.URL.Query().Get(\"{param}\")\nquery := fmt.Sprintf(\"SELECT * FROM products WHERE name LIKE '%%%s%%'\", search)\ndb.Query(query)",
        "after": "search := r.URL.Query().Get(\"{param}\")\nquery := \"SELECT * FROM products WHERE name LIKE ?\"\ndb.Query(query, \"%\"+search+\"%\")",
    },
}

# XSS output encoding by language
XSS_ENCODE = {
    "PHP": "echo htmlspecialchars($search, ENT_QUOTES, 'UTF-8');",
    "Java": "out.print(StringEscapeUtils.escapeHtml4(search)); // Apache Commons Text",
    "Python": "from markupsafe import escape\nreturn f\"<div>{escape(search)}</div>\"",
    "ASP.NET (C#)": "Response.Write(Server.HtmlEncode(search));",
    "JavaScript (Node.js)": "const escapeHtml = (str) => str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');\nres.send(`<div>${{escapeHtml(search)}}</div>`);",
    "Ruby": "ERB::Util.html_escape(search)",
    "Go": "html.EscapeString(search)",
}

# SQLi technique labels
SQLI_TECHNIQUE_LABELS = {
    "boolean_based": "Boolean-Based SQL Injection",
    "union_based": "UNION-Based SQL Injection",
    "time_based": "Time-Based Blind SQL Injection",
    "error_based": "Error-Based SQL Injection",
    "destructive": "Destructive SQL Injection",
}

# SQLi technique impact descriptions
SQLI_TECHNIQUE_IMPACT = {
    "boolean_based": "An attacker could manipulate query logic to bypass filters (e.g. return all rows, or bypass a login check).",
    "union_based": "An attacker could append their own SELECT to pull data from unrelated tables (e.g. user credentials).",
    "time_based": "An attacker could confirm injection and extract data character-by-character purely from response timing, even with no visible output -- this also tends to evade signature-based WAFs.",
    "error_based": "An attacker could use verbose database error messages to extract data or map the schema.",
    "destructive": "An attacker could delete or corrupt data outright if the database account has DROP/DELETE privileges.",
}

# Additional defenses per technique
SQLI_TECHNIQUE_EXTRA_DEFENSES = {
    "boolean_based": ["Validate input against an allow-list of expected characters.", "Return generic error messages -- never expose raw database errors to the client."],
    "union_based": ["Restrict the application's database account to only the privileges it needs (e.g. SELECT on specific tables).", "Avoid `SELECT *`; name expected columns explicitly so injected columns can't blend in."],
    "time_based": ["Set a query/connection timeout so one request can't hang the database.", "Monitor for abnormal response-time patterns as a possible intrusion signal."],
    "error_based": ["Disable verbose database error output in production.", "Log detailed errors server-side only, never in the HTTP response body."],
    "destructive": ["Remove DROP/ALTER/DELETE privileges from the application's own database account entirely.", "Maintain backups independent of the application's own database access."],
}

# Language detection from URL
def detect_language_from_url(url: str):
    if not url: return None, None
    try:
        from urllib.parse import urlparse as _up
        path = _up(url).path
    except Exception:
        path = url
    if path.endswith(".php"): return "PHP", "inferred from .php URL extension"
    if path.endswith(".jsp") or "/do" in path.lower() or path.endswith(".do"): return "Java", "inferred from .jsp/.do URL extension"
    if path.endswith(".aspx") or path.endswith(".ashx"): return "ASP.NET (C#)", "inferred from .aspx/.ashx URL extension"
    if path.endswith(".py"): return "Python", "inferred from .py URL extension"
    if path.endswith(".js") or path.endswith(".ts") or path.endswith(".jsx") or path.endswith(".tsx"):
        return "JavaScript (Node.js)", "inferred from JavaScript file extension"
    if path.endswith(".html") or path.endswith(".htm"):
        return "JavaScript (Node.js)", "inferred from .html page (modern JS/Node.js stack)"
    if path.endswith(".rb"): return "Ruby", "inferred from .rb URL extension"
    if path.endswith(".go"): return "Go", "inferred from .go URL extension"
    return None, None

# Language detection from HTTP headers
def detect_language_from_headers(headers):
    if not headers:
        return None, None
    headers_lower = {k.lower(): str(v).lower() for k, v in headers.items()}
    server = headers_lower.get("server", "")
    powered_by = headers_lower.get("x-powered-by", "")
    if "express" in server or "express" in powered_by:
        return "JavaScript (Node.js)", "inferred from Express server header"
    if "php" in server or "php" in powered_by:
        return "PHP", "inferred from PHP server header"
    if "asp.net" in server or "asp.net" in powered_by:
        return "ASP.NET (C#)", "inferred from ASP.NET server header"
    if "tomcat" in server or "java" in server or "servlet" in server:
        return "Java", "inferred from Java/Tomcat server header"
    return None, None