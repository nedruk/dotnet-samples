using System.Net;
using System.Text.Json;

namespace FirstCallRegistration;

public static class InteractionPage
{
    public static string RenderConsentPage(string agentId, string code)
    {
        var safeAgentId = WebUtility.HtmlEncode(agentId);
        var safeCode = WebUtility.HtmlEncode(code);
        var codeJson = JsonSerializer.Serialize(code);

        return "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n<head>\n" +
            "  <meta charset=\"UTF-8\">\n" +
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "  <title>Authorization Request</title>\n" +
            "  <style>\n" +
            "    * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "    body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }\n" +
            "    .container { background: white; border-radius: 8px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15); max-width: 500px; width: 100%; padding: 40px; text-align: center; }\n" +
            "    h1 { font-size: 24px; color: #333; margin-bottom: 24px; font-weight: 600; }\n" +
            "    .message { font-size: 16px; color: #666; margin-bottom: 24px; line-height: 1.5; }\n" +
            "    .message strong { color: #333; font-weight: 600; }\n" +
            "    .code-section { background: #f5f5f5; border-radius: 6px; padding: 16px; margin-bottom: 32px; }\n" +
            "    .code-label { font-size: 12px; color: #999; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 8px; }\n" +
            "    .code { font-family: \"Monaco\", \"Courier New\", monospace; font-size: 14px; color: #333; word-break: break-all; }\n" +
            "    .button-group { display: flex; gap: 12px; justify-content: center; }\n" +
            "    button { flex: 1; padding: 12px 24px; font-size: 16px; font-weight: 600; border: none; border-radius: 6px; cursor: pointer; transition: all 0.2s ease; text-transform: uppercase; letter-spacing: 0.5px; }\n" +
            "    .btn-approve { background: #10b981; color: white; }\n" +
            "    .btn-approve:hover { background: #059669; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(16, 185, 129, 0.3); }\n" +
            "    .btn-approve:active { transform: translateY(0); }\n" +
            "    .btn-deny { background: #ef4444; color: white; }\n" +
            "    .btn-deny:hover { background: #dc2626; transform: translateY(-2px); box-shadow: 0 4px 12px rgba(239, 68, 68, 0.3); }\n" +
            "    .btn-deny:active { transform: translateY(0); }\n" +
            "    button:disabled { opacity: 0.6; cursor: not-allowed; }\n" +
            "  </style>\n</head>\n<body>\n" +
            "  <div class=\"container\">\n" +
            "    <h1>Authorization Request</h1>\n" +
            "    <div class=\"message\">\n" +
            $"      Agent <strong>{safeAgentId}</strong> is requesting access to this resource.\n" +
            "    </div>\n" +
            "    <div class=\"code-section\">\n" +
            "      <div class=\"code-label\">Interaction Code</div>\n" +
            $"      <div class=\"code\">{safeCode}</div>\n" +
            "    </div>\n" +
            "    <div class=\"button-group\">\n" +
            "      <button class=\"btn-approve\" onclick=\"handleApprove()\">Approve</button>\n" +
            "      <button class=\"btn-deny\" onclick=\"handleDeny()\">Deny</button>\n" +
            "    </div>\n" +
            "  </div>\n" +
            "  <script>\n" +
            $"    const code = {codeJson};\n" +
            "    async function handleApprove() { await submit('/interact/approve'); }\n" +
            "    async function handleDeny() { await submit('/interact/deny'); }\n" +
            "    async function submit(endpoint) {\n" +
            "      try {\n" +
            "        const buttons = document.querySelectorAll('button');\n" +
            "        buttons.forEach(btn => btn.disabled = true);\n" +
            "        const response = await fetch(endpoint, {\n" +
            "          method: 'POST',\n" +
            "          headers: { 'Content-Type': 'application/json' },\n" +
            "          body: JSON.stringify({ code })\n" +
            "        });\n" +
            "        const html = await response.text();\n" +
            "        document.open();\n" +
            "        document.write(html);\n" +
            "        document.close();\n" +
            "      } catch (error) {\n" +
            "        alert('Error: ' + error.message);\n" +
            "        const buttons = document.querySelectorAll('button');\n" +
            "        buttons.forEach(btn => btn.disabled = false);\n" +
            "      }\n" +
            "    }\n" +
            "  </script>\n" +
            "</body>\n</html>";
    }

    public static string RenderResultPage(bool approved)
    {
        var title = approved ? "Access Approved" : "Access Denied";
        var icon = approved ? "✓" : "✗";
        var message = approved
            ? "Access Approved — You can close this window."
            : "Access Denied — You can close this window.";
        var iconColor = approved ? "#10b981" : "#ef4444";
        var safeTitle = WebUtility.HtmlEncode(title);
        var safeMessage = WebUtility.HtmlEncode(message);

        return "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n<head>\n" +
            "  <meta charset=\"UTF-8\">\n" +
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            $"  <title>{safeTitle}</title>\n" +
            "  <style>\n" +
            "    * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "    body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }\n" +
            "    .container { background: white; border-radius: 8px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15); max-width: 500px; width: 100%; padding: 40px; text-align: center; }\n" +
            $"    .icon {{ font-size: 48px; margin-bottom: 20px; color: {iconColor}; }}\n" +
            "    h1 { font-size: 24px; color: #333; margin-bottom: 12px; font-weight: 600; }\n" +
            "    .message { font-size: 16px; color: #666; line-height: 1.5; }\n" +
            "  </style>\n</head>\n<body>\n" +
            "  <div class=\"container\">\n" +
            $"    <div class=\"icon\">{icon}</div>\n" +
            $"    <h1>{safeTitle}</h1>\n" +
            $"    <div class=\"message\">{safeMessage}</div>\n" +
            "  </div>\n" +
            "</body>\n</html>";
    }

    public static string RenderErrorPage(string message)
    {
        var safeMessage = WebUtility.HtmlEncode(message);

        return "<!DOCTYPE html>\n" +
            "<html lang=\"en\">\n<head>\n" +
            "  <meta charset=\"UTF-8\">\n" +
            "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\">\n" +
            "  <title>Error</title>\n" +
            "  <style>\n" +
            "    * { margin: 0; padding: 0; box-sizing: border-box; }\n" +
            "    body { font-family: -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, sans-serif; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }\n" +
            "    .container { background: white; border-radius: 8px; box-shadow: 0 10px 40px rgba(0, 0, 0, 0.15); max-width: 500px; width: 100%; padding: 40px; text-align: center; }\n" +
            "    .icon { font-size: 48px; margin-bottom: 20px; color: #f59e0b; }\n" +
            "    h1 { font-size: 24px; color: #333; margin-bottom: 12px; font-weight: 600; }\n" +
            "    .message { font-size: 16px; color: #666; line-height: 1.5; background: #fef3c7; border-left: 4px solid #f59e0b; padding: 16px; border-radius: 4px; text-align: left; }\n" +
            "  </style>\n</head>\n<body>\n" +
            "  <div class=\"container\">\n" +
            "    <div class=\"icon\">⚠</div>\n" +
            "    <h1>Error</h1>\n" +
            $"    <div class=\"message\">{safeMessage}</div>\n" +
            "  </div>\n" +
            "</body>\n</html>";
    }
}
