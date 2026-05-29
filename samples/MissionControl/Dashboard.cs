namespace MissionControl;

/// <summary>
/// Returns the full HTML dashboard for the Mission Control governance UI.
/// </summary>
public static class Dashboard
{
    public static string GetHtml(string psUrl) => $@"<!DOCTYPE html>
<html lang=""en"">
<head>
  <meta charset=""UTF-8"" />
  <meta name=""viewport"" content=""width=device-width, initial-scale=1.0"" />
  <title>🎮 Mission Control</title>
  <style>
    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      font-family: -apple-system, BlinkMacSystemFont, ""Segoe UI"", Roboto, Helvetica, Arial, sans-serif;
      background: #1a1a2e;
      color: #e0e0e0;
      min-height: 100vh;
    }}

    header {{
      background: #0f0f23;
      padding: 1rem 1.5rem;
      border-bottom: 1px solid #2a2a4a;
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 0.5rem;
    }}

    header h1 {{
      font-size: 1.25rem;
      font-weight: 600;
    }}

    header .ps-url {{
      font-size: 0.8rem;
      color: #7f8c8d;
      font-family: monospace;
    }}

    main {{
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
      padding: 1rem;
      max-width: 1600px;
      margin: 0 auto;
    }}

    @media (max-width: 900px) {{
      main {{ grid-template-columns: 1fr; }}
    }}

    .panel {{
      background: #16213e;
      border-radius: 8px;
      border: 1px solid #2a2a4a;
      overflow: hidden;
    }}

    .panel-header {{
      padding: 0.75rem 1rem;
      background: #0f0f23;
      font-weight: 600;
      font-size: 0.95rem;
      border-bottom: 1px solid #2a2a4a;
    }}

    .panel-body {{
      padding: 0.75rem 1rem;
    }}

    .empty-msg {{
      color: #7f8c8d;
      font-style: italic;
      padding: 1rem 0;
      text-align: center;
    }}

    /* Mission list */
    .mission-item {{
      padding: 0.6rem 0.75rem;
      border-bottom: 1px solid #2a2a4a;
      cursor: pointer;
      transition: background 0.15s;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }}

    .mission-item:last-child {{ border-bottom: none; }}
    .mission-item:hover {{ background: #1a2744; }}
    .mission-item.selected {{ background: #1e3a5f; }}

    .mission-item .agent-name {{
      font-weight: 600;
      flex-shrink: 0;
    }}

    .mission-item .desc-preview {{
      color: #95a5a6;
      font-size: 0.85rem;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      flex: 1;
      min-width: 0;
    }}

    /* Badges */
    .badge {{
      display: inline-block;
      padding: 0.15rem 0.5rem;
      border-radius: 10px;
      font-size: 0.7rem;
      font-weight: 600;
      text-transform: uppercase;
      flex-shrink: 0;
    }}

    .badge-pending   {{ background: #f39c12; color: #1a1a2e; }}
    .badge-active    {{ background: #2ecc71; color: #1a1a2e; }}
    .badge-terminated {{ background: #95a5a6; color: #1a1a2e; }}
    .badge-granted   {{ background: #2ecc71; color: #1a1a2e; }}
    .badge-denied    {{ background: #e74c3c; color: #fff; }}
    .badge-info      {{ background: #3498db; color: #fff; }}
    .badge-warning   {{ background: #e67e22; color: #1a1a2e; }}
    .badge-error     {{ background: #e74c3c; color: #fff; }}
    .badge-log       {{ background: #7f8c8d; color: #fff; }}

    /* Mission detail */
    .detail-section {{
      margin-bottom: 1rem;
    }}

    .detail-section h3 {{
      font-size: 0.85rem;
      color: #7f8c8d;
      text-transform: uppercase;
      margin-bottom: 0.4rem;
      letter-spacing: 0.05em;
    }}

    .detail-section p,
    .detail-section pre {{
      font-size: 0.9rem;
      line-height: 1.5;
    }}

    .detail-section pre {{
      white-space: pre-wrap;
      word-break: break-word;
    }}

    .tools-list {{
      list-style: none;
      display: flex;
      flex-wrap: wrap;
      gap: 0.3rem;
    }}

    .tools-list li {{
      background: #2a2a4a;
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.8rem;
      font-family: monospace;
    }}

    /* Log */
    .log-container {{
      max-height: 300px;
      overflow-y: auto;
      border: 1px solid #2a2a4a;
      border-radius: 4px;
      background: #0f0f23;
    }}

    .log-entry {{
      padding: 0.4rem 0.6rem;
      border-bottom: 1px solid #1a1a2e;
      font-size: 0.82rem;
      display: flex;
      align-items: flex-start;
      gap: 0.5rem;
    }}

    .log-entry:last-child {{ border-bottom: none; }}

    .log-entry .log-time {{
      color: #7f8c8d;
      font-family: monospace;
      font-size: 0.75rem;
      flex-shrink: 0;
      min-width: 70px;
    }}

    .log-entry .log-summary {{
      flex: 1;
      min-width: 0;
    }}

    /* Action items */
    .action-item {{
      padding: 0.75rem;
      border-bottom: 1px solid #2a2a4a;
    }}

    .action-item:last-child {{ border-bottom: none; }}

    .action-item .action-desc {{
      font-size: 0.9rem;
      margin-bottom: 0.5rem;
    }}

    .action-item .action-name {{
      font-weight: 600;
      font-family: monospace;
      font-size: 0.85rem;
    }}

    /* Buttons */
    .btn {{
      display: inline-block;
      padding: 0.35rem 0.75rem;
      border: none;
      border-radius: 4px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      transition: opacity 0.15s;
    }}

    .btn:hover {{ opacity: 0.85; }}
    .btn:disabled {{ opacity: 0.4; cursor: not-allowed; }}

    .btn-approve {{ background: #2ecc71; color: #1a1a2e; }}
    .btn-deny    {{ background: #e74c3c; color: #fff; }}
    .btn-action  {{ background: #3498db; color: #fff; }}

    .btn-group {{
      display: flex;
      gap: 0.4rem;
      margin-top: 0.4rem;
      flex-wrap: wrap;
      align-items: center;
    }}

    .btn-group input[type=""text""] {{
      flex: 1;
      min-width: 120px;
      padding: 0.35rem 0.5rem;
      border-radius: 4px;
      border: 1px solid #2a2a4a;
      background: #0f0f23;
      color: #e0e0e0;
      font-size: 0.8rem;
    }}

    .btn-group input[type=""text""]::placeholder {{ color: #555; }}

    /* Scrollbar */
    ::-webkit-scrollbar {{ width: 6px; }}
    ::-webkit-scrollbar-track {{ background: #0f0f23; }}
    ::-webkit-scrollbar-thumb {{ background: #2a2a4a; border-radius: 3px; }}
  </style>
</head>
<body>
  <header>
    <h1>🎮 Mission Control — Agent Governance Dashboard</h1>
    <span class=""ps-url"">{psUrl}</span>
  </header>

  <main>
    <div>
      <div class=""panel"" id=""missions-panel"">
        <div class=""panel-header"">Missions</div>
        <div class=""panel-body"" id=""mission-list""></div>
      </div>
      <div class=""panel"" id=""detail-panel"" style=""margin-top:1rem; display:none;"">
        <div class=""panel-header"" id=""detail-header"">Mission Detail</div>
        <div class=""panel-body"" id=""detail-body""></div>
      </div>
    </div>

    <div id=""actions-panel"">
      <div class=""panel"">
        <div class=""panel-header"">Pending Permissions</div>
        <div class=""panel-body"" id=""permissions-list""></div>
      </div>
      <div class=""panel"" style=""margin-top:1rem;"">
        <div class=""panel-header"">Pending Interactions</div>
        <div class=""panel-body"" id=""interactions-list""></div>
      </div>
    </div>
  </main>

  <script>
    const PS_URL = '{psUrl}';
    let selectedMissionId = null;
    let lastLogCount = 0;

    function esc(str) {{
      const d = document.createElement('div');
      d.textContent = str ?? '';
      return d.innerHTML;
    }}

    function fmtTime(ts) {{
      if (!ts) return '';
      const d = new Date(ts);
      if (isNaN(d.getTime())) return String(ts);
      return d.toLocaleString(undefined, {{
        month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      }});
    }}

    function badgeHtml(status) {{
      const cls = {{
        pending: 'badge-pending',
        active: 'badge-active',
        terminated: 'badge-terminated',
        granted: 'badge-granted',
        denied: 'badge-denied',
      }}[status] || 'badge-log';
      return '<span class=""badge ' + cls + '"">' + esc(status) + '</span>';
    }}

    function logBadgeHtml(type) {{
      const cls = {{
        info: 'badge-info',
        warning: 'badge-warning',
        error: 'badge-error',
        tool_call: 'badge-info',
        permission: 'badge-warning',
        interaction: 'badge-pending',
        completion: 'badge-active',
      }}[type] || 'badge-log';
      return '<span class=""badge ' + cls + '"">' + esc(type) + '</span>';
    }}

    async function apiPost(path, body) {{
      try {{
        const res = await fetch(path, {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: body ? JSON.stringify(body) : undefined
        }});
        if (!res.ok) {{
          const text = await res.text();
          alert('Error: ' + text);
        }}
        await refresh();
      }} catch (e) {{
        alert('Request failed: ' + e.message);
      }}
    }}

    function renderMissionList(missions) {{
      const el = document.getElementById('mission-list');
      if (!missions || missions.length === 0) {{
        el.innerHTML = '<div class=""empty-msg"">No missions yet</div>';
        return;
      }}
      el.innerHTML = missions.map(function(m) {{
        const firstLine = (m.description || '').split('\n')[0].substring(0, 100);
        const sel = m.id === selectedMissionId ? ' selected' : '';
        return '<div class=""mission-item' + sel + '"" data-id=""' + esc(m.id) + '"">'
          + '<span class=""agent-name"">' + esc(m.agent || 'Agent') + '</span>'
          + badgeHtml(m.status)
          + '<span class=""desc-preview"">' + esc(firstLine) + '</span>'
          + '</div>';
      }}).join('');

      el.querySelectorAll('.mission-item').forEach(function(item) {{
        item.addEventListener('click', function() {{
          selectedMissionId = item.getAttribute('data-id');
          refresh();
        }});
      }});
    }}

    function renderMissionDetail(missions) {{
      const panel = document.getElementById('detail-panel');
      const header = document.getElementById('detail-header');
      const body = document.getElementById('detail-body');

      if (!selectedMissionId || !missions) {{
        panel.style.display = 'none';
        return;
      }}

      const m = missions.find(function(x) {{ return x.id === selectedMissionId; }});
      if (!m) {{
        panel.style.display = 'none';
        selectedMissionId = null;
        return;
      }}

      panel.style.display = 'block';
      header.textContent = 'Mission: ' + (m.agent || m.id);

      const tools = m.tools || [];
      const toolsLabel = m.status === 'pending' ? 'Proposed Tools' : 'Approved Tools';
      const toolsHtml = tools.length > 0
        ? '<ul class=""tools-list"">' + tools.map(function(t) {{
            var label = (typeof t === 'string') ? t : (t.name || JSON.stringify(t));
            var desc = (typeof t === 'object' && t.description) ? ' — ' + esc(t.description) : '';
            return '<li>' + esc(label) + desc + '</li>';
          }}).join('') + '</ul>'
        : '<span style=""color:#7f8c8d;"">None</span>';

      let actionsHtml = '';
      if (m.status === 'pending') {{
        actionsHtml = '<div class=""btn-group"">'
          + '<button class=""btn btn-approve"" onclick=""apiPost(\'/api/missions/' + esc(m.id) + '/approve\')"">✅ Approve</button>'
          + '<button class=""btn btn-deny"" onclick=""apiPost(\'/api/missions/' + esc(m.id) + '/deny\')"">❌ Deny</button>'
          + '</div>';
      }}

      const logs = m.log || m.logs || [];
      const newLogCount = logs.length;
      const shouldScroll = newLogCount !== lastLogCount;
      lastLogCount = newLogCount;

      let logsHtml = '';
      if (logs.length > 0) {{
        logsHtml = '<div class=""log-container"" id=""log-container"">'
          + logs.map(function(entry) {{
            return '<div class=""log-entry"">'
              + '<span class=""log-time"">' + fmtTime(entry.timestamp || entry.ts) + '</span>'
              + logBadgeHtml(entry.type)
              + '<span class=""log-summary"">' + esc(entry.summary || entry.message || '') + '</span>'
              + '</div>';
          }}).join('')
          + '</div>';
      }} else {{
        logsHtml = '<div class=""empty-msg"">No log entries</div>';
      }}

      body.innerHTML =
        '<div class=""detail-section""><h3>Description</h3><pre>' + esc(m.description || '') + '</pre></div>'
        + '<div class=""detail-section""><h3>' + toolsLabel + '</h3>' + toolsHtml + '</div>'
        + '<div class=""detail-section""><h3>Status</h3><p>' + badgeHtml(m.status)
          + (m.approved_at || m.approvedAt ? ' &nbsp; Approved: ' + fmtTime(m.approved_at || m.approvedAt) : '')
          + '</p></div>'
        + (actionsHtml ? '<div class=""detail-section"">' + actionsHtml + '</div>' : '')
        + '<div class=""detail-section""><h3>Mission Log</h3>' + logsHtml + '</div>';

      if (shouldScroll) {{
        const lc = document.getElementById('log-container');
        if (lc) lc.scrollTop = lc.scrollHeight;
      }}
    }}

    function renderPermissions(perms) {{
      const el = document.getElementById('permissions-list');
      if (!perms || perms.length === 0) {{
        el.innerHTML = '<div class=""empty-msg"">No pending permissions</div>';
        return;
      }}
      el.innerHTML = perms.map(function(p) {{
        return '<div class=""action-item"">'
          + '<div class=""action-name"">' + esc(p.action || p.name || '') + '</div>'
          + '<div class=""action-desc"">' + esc(p.description || '') + '</div>'
          + '<div class=""btn-group"">'
            + '<button class=""btn btn-approve"" onclick=""apiPost(\'/api/permissions/' + esc(p.id) + '/grant\')"">✅ Grant</button>'
            + '<input type=""text"" id=""deny-reason-' + esc(p.id) + '"" placeholder=""Reason (optional)"" />'
            + '<button class=""btn btn-deny"" onclick=""denyPermission(\'' + esc(p.id) + '\')"">❌ Deny</button>'
          + '</div>'
          + '</div>';
      }}).join('');
    }}

    function denyPermission(id) {{
      const input = document.getElementById('deny-reason-' + id);
      const reason = input ? input.value : '';
      apiPost('/api/permissions/' + id + '/deny', {{ reason: reason }});
    }}

    function renderInteractions(interactions) {{
      const el = document.getElementById('interactions-list');
      if (!interactions || interactions.length === 0) {{
        el.innerHTML = '<div class=""empty-msg"">No pending interactions</div>';
        return;
      }}
      el.innerHTML = interactions.map(function(item) {{
        const t = item.type || 'interaction';
        let controlsHtml = '';

        if (t === 'question') {{
          controlsHtml = '<div class=""btn-group"">'
            + '<input type=""text"" id=""answer-' + esc(item.id) + '"" placeholder=""Type your answer..."" />'
            + '<button class=""btn btn-action"" onclick=""answerInteraction(\'' + esc(item.id) + '\')"">Send Answer</button>'
            + '</div>';
        }} else if (t === 'completion') {{
          controlsHtml = '<div class=""btn-group"">'
            + '<button class=""btn btn-approve"" onclick=""apiPost(\'/api/interactions/' + esc(item.id) + '/accept\')"">✅ Accept Completion</button>'
            + '</div>';
        }} else {{
          const url = item.url || '';
          controlsHtml = (url ? '<div style=""margin-bottom:0.4rem;""><a href=""' + esc(url) + '"" target=""_blank"" style=""color:#3498db;"">' + esc(url) + '</a></div>' : '')
            + '<div class=""btn-group"">'
            + '<button class=""btn btn-action"" onclick=""apiPost(\'/api/interactions/' + esc(item.id) + '/accept\')"">Mark Done</button>'
            + '</div>';
        }}

        return '<div class=""action-item"">'
          + '<div style=""margin-bottom:0.3rem;"">' + badgeHtml(t) + '</div>'
          + '<div class=""action-desc"">' + esc(item.description || item.question || item.summary || '') + '</div>'
          + controlsHtml
          + '</div>';
      }}).join('');
    }}

    function answerInteraction(id) {{
      const input = document.getElementById('answer-' + id);
      const answer = input ? input.value : '';
      if (!answer.trim()) {{ alert('Please enter an answer.'); return; }}
      apiPost('/api/interactions/' + id + '/answer', {{ answer: answer }});
    }}

    async function refresh() {{
      try {{
        const res = await fetch('/api/dashboard');
        if (!res.ok) return;
        const data = await res.json();
        renderMissionList(data.missions || []);
        renderMissionDetail(data.missions || []);
        renderPermissions(data.pendingPermissions || []);
        renderInteractions(data.pendingInteractions || []);
      }} catch (e) {{
        // silently retry on next poll
      }}
    }}

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>
";
}
