using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.IdentityModel.Tokens;

namespace MissionControl;

public class ToolInfo
{
    [JsonPropertyName("name")]
    public string Name { get; set; } = "";

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";
}

public class MissionProposal
{
    public string Description { get; set; } = "";
    public List<ToolInfo>? Tools { get; set; }
}

public class MissionLogEntry
{
    [JsonPropertyName("timestamp")]
    public DateTimeOffset Timestamp { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = "";

    [JsonPropertyName("summary")]
    public string Summary { get; set; } = "";

    [JsonPropertyName("detail")]
    public string? Detail { get; set; }
}

public class Mission
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("approver")]
    public string Approver { get; set; } = "";

    [JsonPropertyName("agent")]
    public string Agent { get; set; } = "";

    [JsonPropertyName("approved_at")]
    public string? ApprovedAt { get; set; }

    [JsonPropertyName("description")]
    public string Description { get; set; } = "";

    [JsonPropertyName("proposed_tools")]
    public List<ToolInfo> ProposedTools { get; set; } = new();

    [JsonPropertyName("approved_tools")]
    public List<ToolInfo> ApprovedTools { get; set; } = new();

    [JsonPropertyName("capabilities")]
    public List<string> Capabilities { get; set; } = new();

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending";

    [JsonPropertyName("s256")]
    public string? S256 { get; set; }

    [JsonIgnore]
    public byte[]? BlobBytes { get; set; }

    [JsonPropertyName("log")]
    public List<MissionLogEntry> Log { get; set; } = new();
}

public class PendingPermission
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("missionId")]
    public string? MissionId { get; set; }

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("parameters")]
    public JsonElement? Parameters { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending";

    [JsonPropertyName("reason")]
    public string? Reason { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }
}

public class AuditRecord
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("missionId")]
    public string MissionId { get; set; } = "";

    [JsonPropertyName("action")]
    public string Action { get; set; } = "";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("parameters")]
    public JsonElement? Parameters { get; set; }

    [JsonPropertyName("result")]
    public JsonElement? Result { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }
}

public class PendingInteraction
{
    [JsonPropertyName("id")]
    public string Id { get; set; } = "";

    [JsonPropertyName("missionId")]
    public string? MissionId { get; set; }

    [JsonPropertyName("type")]
    public string Type { get; set; } = "interaction";

    [JsonPropertyName("description")]
    public string? Description { get; set; }

    [JsonPropertyName("url")]
    public string? Url { get; set; }

    [JsonPropertyName("code")]
    public string? Code { get; set; }

    [JsonPropertyName("question")]
    public string? Question { get; set; }

    [JsonPropertyName("summary")]
    public string? Summary { get; set; }

    [JsonPropertyName("status")]
    public string Status { get; set; } = "pending";

    [JsonPropertyName("answer")]
    public string? Answer { get; set; }

    [JsonPropertyName("createdAt")]
    public DateTimeOffset CreatedAt { get; set; }
}

public class InteractionData
{
    public string? Description { get; set; }
    public string? Url { get; set; }
    public string? Code { get; set; }
    public string? Question { get; set; }
    public string? Summary { get; set; }
}

public class DashboardState
{
    [JsonPropertyName("missions")]
    public List<Mission> Missions { get; set; } = new();

    [JsonPropertyName("pendingPermissions")]
    public List<PendingPermission> PendingPermissions { get; set; } = new();

    [JsonPropertyName("pendingInteractions")]
    public List<PendingInteraction> PendingInteractions { get; set; } = new();
}

public class GovernanceStore
{
    private readonly ConcurrentDictionary<string, Mission> _missions = new();
    private readonly ConcurrentDictionary<string, PendingPermission> _permissions = new();
    private readonly ConcurrentDictionary<string, AuditRecord> _audits = new();
    private readonly ConcurrentDictionary<string, PendingInteraction> _interactions = new();
    private readonly object _sync = new();

    private static string NewId() => Guid.NewGuid().ToString()[..8];

    public Mission CreateMission(MissionProposal proposal, string agent, string approver)
    {
        lock (_sync)
        {
            var mission = new Mission
            {
                Id = NewId(),
                Agent = agent,
                Approver = approver,
                Description = proposal.Description,
                ProposedTools = CloneTools(proposal.Tools ?? new List<ToolInfo>()),
                Status = "pending"
            };

            mission.Log.Add(new MissionLogEntry
            {
                Timestamp = DateTimeOffset.UtcNow,
                Type = "proposal",
                Summary = $"Mission proposed: {proposal.Description}"
            });

            _missions[mission.Id] = mission;
            return CloneMission(mission);
        }
    }

    public Mission ApproveMission(string id, List<ToolInfo>? approvedTools = null)
    {
        lock (_sync)
        {
            if (!_missions.TryGetValue(id, out var mission))
                throw new KeyNotFoundException($"Mission {id} not found");

            if (mission.Status != "pending")
                throw new InvalidOperationException($"Mission {id} is {mission.Status}, expected pending");

            mission.ApprovedAt = DateTimeOffset.UtcNow.ToString("o");
            mission.Status = "active";
            mission.ApprovedTools = CloneTools(approvedTools ?? mission.ProposedTools);
            mission.Capabilities = new List<string> { "interaction" };

            var blob = new
            {
                approver = mission.Approver,
                agent = mission.Agent,
                approved_at = mission.ApprovedAt,
                description = mission.Description,
                approved_tools = mission.ApprovedTools.Select(t => new { name = t.Name, description = t.Description }),
                capabilities = mission.Capabilities
            };
            mission.BlobBytes = JsonSerializer.SerializeToUtf8Bytes(blob);
            mission.S256 = Base64UrlEncoder.Encode(SHA256.HashData(mission.BlobBytes));

            mission.Log.Add(new MissionLogEntry
            {
                Timestamp = DateTimeOffset.UtcNow,
                Type = "approval",
                Summary = $"Mission approved with {mission.ApprovedTools.Count} tools"
            });

            return CloneMission(mission);
        }
    }

    public Mission TerminateMission(string id)
    {
        lock (_sync)
        {
            if (!_missions.TryGetValue(id, out var mission))
                throw new KeyNotFoundException($"Mission {id} not found");

            mission.Status = "terminated";

            mission.Log.Add(new MissionLogEntry
            {
                Timestamp = DateTimeOffset.UtcNow,
                Type = "termination",
                Summary = "Mission terminated"
            });

            return CloneMission(mission);
        }
    }

    public Mission? GetMission(string id)
    {
        lock (_sync)
        {
            return _missions.TryGetValue(id, out var mission) ? CloneMission(mission) : null;
        }
    }

    public Mission? FindMissionByS256(string s256)
    {
        lock (_sync)
        {
            var mission = _missions.Values.FirstOrDefault(m => m.S256 == s256);
            return mission is null ? null : CloneMission(mission);
        }
    }

    public List<Mission> GetAllMissions()
    {
        lock (_sync)
        {
            return _missions.Values.Select(CloneMission).ToList();
        }
    }

    public void AddMissionLogEntry(string missionId, MissionLogEntry entry)
    {
        lock (_sync)
        {
            if (!_missions.TryGetValue(missionId, out var mission))
                throw new KeyNotFoundException($"Mission {missionId} not found");

            mission.Log.Add(CloneMissionLogEntry(entry));
        }
    }

    public PendingPermission CreatePermission(string action, string? missionId = null, string? description = null, JsonElement? parameters = null)
    {
        lock (_sync)
        {
            var permission = new PendingPermission
            {
                Id = NewId(),
                MissionId = missionId,
                Action = action,
                Description = description,
                Parameters = CloneJsonElement(parameters),
                Status = "pending",
                CreatedAt = DateTimeOffset.UtcNow
            };

            _permissions[permission.Id] = permission;

            if (missionId is not null && _missions.TryGetValue(missionId, out var mission))
            {
                mission.Log.Add(new MissionLogEntry
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Type = "permission_requested",
                    Summary = $"Permission requested: {action}",
                    Detail = description
                });
            }

            return ClonePermission(permission);
        }
    }

    public PendingPermission ResolvePermission(string id, bool granted, string? reason = null)
    {
        lock (_sync)
        {
            if (!_permissions.TryGetValue(id, out var permission))
                throw new KeyNotFoundException($"Permission {id} not found");

            permission.Status = granted ? "granted" : "denied";
            permission.Reason = reason;

            if (permission.MissionId is not null && _missions.TryGetValue(permission.MissionId, out var mission))
            {
                mission.Log.Add(new MissionLogEntry
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Type = granted ? "permission_granted" : "permission_denied",
                    Summary = $"Permission {permission.Action} {permission.Status}",
                    Detail = reason
                });
            }

            return ClonePermission(permission);
        }
    }

    public PendingPermission? GetPermission(string id)
    {
        lock (_sync)
        {
            return _permissions.TryGetValue(id, out var permission) ? ClonePermission(permission) : null;
        }
    }

    public List<PendingPermission> GetPendingPermissions()
    {
        lock (_sync)
        {
            return _permissions.Values.Where(p => p.Status == "pending").Select(ClonePermission).ToList();
        }
    }

    public AuditRecord CreateAudit(string missionId, string action, string? description = null, JsonElement? parameters = null, JsonElement? result = null)
    {
        lock (_sync)
        {
            var audit = new AuditRecord
            {
                Id = NewId(),
                MissionId = missionId,
                Action = action,
                Description = description,
                Parameters = CloneJsonElement(parameters),
                Result = CloneJsonElement(result),
                CreatedAt = DateTimeOffset.UtcNow
            };

            _audits[audit.Id] = audit;

            if (_missions.TryGetValue(missionId, out var mission))
            {
                mission.Log.Add(new MissionLogEntry
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Type = "audit",
                    Summary = $"Audit: {action}",
                    Detail = description
                });
            }

            return CloneAudit(audit);
        }
    }

    public List<AuditRecord> GetAuditsForMission(string missionId)
    {
        lock (_sync)
        {
            return _audits.Values.Where(a => a.MissionId == missionId).Select(CloneAudit).ToList();
        }
    }

    public PendingInteraction CreateInteraction(string type, string? missionId = null, InteractionData? data = null)
    {
        lock (_sync)
        {
            var interaction = new PendingInteraction
            {
                Id = NewId(),
                MissionId = missionId,
                Type = type,
                Description = data?.Description,
                Url = data?.Url,
                Code = data?.Code,
                Question = data?.Question,
                Summary = data?.Summary,
                Status = "pending",
                CreatedAt = DateTimeOffset.UtcNow
            };

            _interactions[interaction.Id] = interaction;

            if (missionId is not null && _missions.TryGetValue(missionId, out var mission))
            {
                mission.Log.Add(new MissionLogEntry
                {
                    Timestamp = DateTimeOffset.UtcNow,
                    Type = "interaction_created",
                    Summary = $"Interaction created: {type}",
                    Detail = data?.Description
                });
            }

            return CloneInteraction(interaction);
        }
    }

    public PendingInteraction ResolveInteraction(string id, string? answer = null)
    {
        lock (_sync)
        {
            if (!_interactions.TryGetValue(id, out var interaction))
                throw new KeyNotFoundException($"Interaction {id} not found");

            interaction.Status = "completed";
            interaction.Answer = answer;

            return CloneInteraction(interaction);
        }
    }

    public PendingInteraction? GetInteraction(string id)
    {
        lock (_sync)
        {
            return _interactions.TryGetValue(id, out var interaction) ? CloneInteraction(interaction) : null;
        }
    }

    public List<PendingInteraction> GetPendingInteractions()
    {
        lock (_sync)
        {
            return _interactions.Values.Where(i => i.Status == "pending").Select(CloneInteraction).ToList();
        }
    }

    public DashboardState GetDashboardState()
    {
        lock (_sync)
        {
            return new DashboardState
            {
                Missions = _missions.Values.Select(CloneMission).ToList(),
                PendingPermissions = _permissions.Values.Where(p => p.Status == "pending").Select(ClonePermission).ToList(),
                PendingInteractions = _interactions.Values.Where(i => i.Status == "pending").Select(CloneInteraction).ToList()
            };
        }
    }

    private static Mission CloneMission(Mission mission) => new()
    {
        Id = mission.Id,
        Approver = mission.Approver,
        Agent = mission.Agent,
        ApprovedAt = mission.ApprovedAt,
        Description = mission.Description,
        ProposedTools = CloneTools(mission.ProposedTools),
        ApprovedTools = CloneTools(mission.ApprovedTools),
        Capabilities = new List<string>(mission.Capabilities),
        Status = mission.Status,
        S256 = mission.S256,
        BlobBytes = mission.BlobBytes?.ToArray(),
        Log = mission.Log.Select(CloneMissionLogEntry).ToList()
    };

    private static List<ToolInfo> CloneTools(IEnumerable<ToolInfo> tools) =>
        tools.Select(t => new ToolInfo { Name = t.Name, Description = t.Description }).ToList();

    private static MissionLogEntry CloneMissionLogEntry(MissionLogEntry entry) => new()
    {
        Timestamp = entry.Timestamp,
        Type = entry.Type,
        Summary = entry.Summary,
        Detail = entry.Detail
    };

    private static PendingPermission ClonePermission(PendingPermission permission) => new()
    {
        Id = permission.Id,
        MissionId = permission.MissionId,
        Action = permission.Action,
        Description = permission.Description,
        Parameters = CloneJsonElement(permission.Parameters),
        Status = permission.Status,
        Reason = permission.Reason,
        CreatedAt = permission.CreatedAt
    };

    private static AuditRecord CloneAudit(AuditRecord audit) => new()
    {
        Id = audit.Id,
        MissionId = audit.MissionId,
        Action = audit.Action,
        Description = audit.Description,
        Parameters = CloneJsonElement(audit.Parameters),
        Result = CloneJsonElement(audit.Result),
        CreatedAt = audit.CreatedAt
    };

    private static PendingInteraction CloneInteraction(PendingInteraction interaction) => new()
    {
        Id = interaction.Id,
        MissionId = interaction.MissionId,
        Type = interaction.Type,
        Description = interaction.Description,
        Url = interaction.Url,
        Code = interaction.Code,
        Question = interaction.Question,
        Summary = interaction.Summary,
        Status = interaction.Status,
        Answer = interaction.Answer,
        CreatedAt = interaction.CreatedAt
    };

    private static JsonElement? CloneJsonElement(JsonElement? element) =>
        element.HasValue ? element.Value.Clone() : null;
}
