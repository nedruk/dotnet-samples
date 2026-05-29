using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace FirstCallRegistration;

public class PendingAuth
{
    public required string Id { get; init; }
    public required string Code { get; init; }
    public required string AgentId { get; init; }
    public required string AgentJkt { get; init; }
    public required DateTimeOffset CreatedAt { get; init; }
    public required DateTimeOffset ExpiresAt { get; init; }
    public string Status { get; set; } = "pending";
    public string? AccessToken { get; set; }
    public DateTimeOffset? ConsumedAt { get; set; }
    public bool IsExpired => DateTimeOffset.UtcNow >= ExpiresAt;
    public bool IsConsumed => ConsumedAt is not null;
}

public static class PendingStore
{
    private static readonly ConcurrentDictionary<string, PendingAuth> _pendingById = new();
    private static readonly ConcurrentDictionary<string, (string AgentId, string AgentJkt)> _tokenToAgent = new();
    private const string Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    private static readonly TimeSpan PendingLifetime = TimeSpan.FromMinutes(5);

    public static PendingAuth CreatePending(string agentId, string agentJkt)
    {
        var now = DateTimeOffset.UtcNow;
        var pending = new PendingAuth
        {
            Id = Guid.NewGuid().ToString(),
            Code = GenerateCode(),
            AgentId = agentId,
            AgentJkt = agentJkt,
            CreatedAt = now,
            ExpiresAt = now.Add(PendingLifetime),
        };

        _pendingById[pending.Id] = pending;
        return pending;
    }

    public static PendingAuth? GetPendingById(string id) =>
        _pendingById.TryGetValue(id, out var pending) ? pending : null;

    public static PendingAuth? GetPendingByCode(string code) =>
        _pendingById.Values.FirstOrDefault(p => p.Code == code);

    public static string ApprovePending(string id)
    {
        var pending = _pendingById.GetValueOrDefault(id)
            ?? throw new InvalidOperationException($"Pending authorization not found: {id}");

        var accessToken = Guid.NewGuid().ToString();
        pending.Status = "approved";
        pending.AccessToken = accessToken;
        _tokenToAgent[accessToken] = (pending.AgentId, pending.AgentJkt);
        return accessToken;
    }

    public static void DenyPending(string id)
    {
        var pending = _pendingById.GetValueOrDefault(id)
            ?? throw new InvalidOperationException($"Pending authorization not found: {id}");
        pending.Status = "denied";
    }

    public static void ExpirePending(string id)
    {
        var pending = _pendingById.GetValueOrDefault(id);
        if (pending is not null && !pending.IsConsumed)
            pending.Status = "expired";
    }

    public static PendingAuth? ConsumeApprovedPending(string id)
    {
        var pending = _pendingById.GetValueOrDefault(id);
        if (pending is null)
            return null;

        lock (pending)
        {
            if (pending.Status != "approved" || pending.IsConsumed || pending.AccessToken is null)
                return null;

            pending.Status = "consumed";
            pending.ConsumedAt = DateTimeOffset.UtcNow;
            return pending;
        }
    }

    public static bool ValidateAccessToken(string token, string agentJkt) =>
        _tokenToAgent.TryGetValue(token, out var agent) && agent.AgentJkt == agentJkt;

    private static string GenerateCode()
    {
        var chars = new char[9];
        for (var i = 0; i < 9; i++)
        {
            if (i == 4)
            {
                chars[i] = '-';
                continue;
            }

            chars[i] = Chars[RandomNumberGenerator.GetInt32(Chars.Length)];
        }

        return new string(chars);
    }
}
