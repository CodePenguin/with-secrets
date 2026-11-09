using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace WithSecrets;

/// <summary>
/// Small JSON Schema (draft 2020-12, as OpenAPI 3.1 uses it) building blocks. The same schema objects are written into the OpenAPI document and are what <see cref="ApiValidator" /> checks
/// a request body against, so the document and the validation cannot say different things.
/// </summary>
internal static class S
{
    private static JsonObject Typed(string type, bool nullable) => new() { ["type"] = nullable ? new JsonArray(type, "null") : JsonValue.Create(type) };

    public static JsonObject Str(int? max = null, int? min = null, string[]? values = null, string? format = null, bool nullable = false, string? description = null)
    {
        JsonObject schema = Typed("string", nullable);
        if (min is not null)
        {
            schema["minLength"] = min;
        }

        if (max is not null)
        {
            schema["maxLength"] = max;
        }

        if (values is not null)
        {
            JsonArray allowed = new([.. values.Select(item => (JsonNode?)JsonValue.Create(item))]);
            if (nullable)
            {
                allowed.Add(null);
            }

            schema["enum"] = allowed;
        }

        if (format is not null)
        {
            schema["format"] = format;
        }

        if (description is not null)
        {
            schema["description"] = description;
        }

        return schema;
    }

    public static JsonObject Time(bool nullable = false) => Str(format: "date-time", nullable: nullable);

    public static JsonObject Int(int? min = null, int? max = null, bool nullable = false, string? description = null)
    {
        JsonObject schema = Typed("integer", nullable);
        if (min is not null)
        {
            schema["minimum"] = min;
        }

        if (max is not null)
        {
            schema["maximum"] = max;
        }

        if (description is not null)
        {
            schema["description"] = description;
        }

        return schema;
    }

    public static JsonObject Bool(string? description = null)
    {
        JsonObject schema = Typed("boolean", false);
        if (description is not null)
        {
            schema["description"] = description;
        }

        return schema;
    }

    public static JsonObject Arr(JsonObject items) => new() { ["type"] = "array", ["items"] = items };

    public static JsonObject Ref(string name) => new() { ["$ref"] = "#/components/schemas/" + name };

    /// <summary>An object with these members and no others. Every member is listed in <c>required</c> unless named in <paramref name="optional" />.</summary>
    public static JsonObject Obj(IEnumerable<(string Name, JsonObject Schema)> members, IEnumerable<string>? optional = null, string? description = null)
    {
        HashSet<string> skip = [.. optional ?? []];
        JsonObject properties = [];
        JsonArray required = [];
        foreach ((string name, JsonObject schema) in members)
        {
            properties[name] = schema;
            if (!skip.Contains(name))
            {
                required.Add(name);
            }
        }

        JsonObject result = new() { ["type"] = "object", ["properties"] = properties, ["additionalProperties"] = false };
        if (required.Count > 0)
        {
            result["required"] = required;
        }

        if (description is not null)
        {
            result["description"] = description;
        }

        return result;
    }

    /// <summary>A free-form object whose members are all short text, numbers or true/false (the parameters of an operation).</summary>
    public static JsonObject Params(int maxMembers, int maxLength) => new()
    {
        ["type"] = "object",
        ["maxProperties"] = maxMembers,
        ["additionalProperties"] = new JsonObject { ["type"] = new JsonArray("string", "integer", "boolean"), ["maxLength"] = maxLength },
    };
}

/// <summary>Checks a JSON value against a schema built with <see cref="S" />. Returns the first problem as a short sentence (naming the member, never echoing its value), or null.</summary>
internal static class ApiValidator
{
    public static string? Validate(JsonElement value, JsonObject schema, JsonObject components, string path = "body")
    {
        if (schema["$ref"] is JsonValue reference)
        {
            string name = reference.GetValue<string>()["#/components/schemas/".Length..];

            return components[name] is JsonObject target ? Validate(value, target, components, path) : path + ": unknown schema";
        }

        if (schema["type"] is { } typeNode && !TypeMatches(value, typeNode, out string expected))
        {
            return path + " must be " + expected;
        }

        if (schema["enum"] is JsonArray allowed && !allowed.Any(item => Same(item, value)))
        {
            return path + " is not one of the allowed values";
        }

        switch (value.ValueKind)
        {
            case JsonValueKind.String:
                string text = value.GetString() ?? "";
                if (schema["maxLength"] is { } max && text.Length > max.GetValue<int>())
                {
                    return path + " is too long (at most " + max.GetValue<int>().ToString(CultureInfo.InvariantCulture) + ")";
                }

                if (schema["minLength"] is { } min && text.Length < min.GetValue<int>())
                {
                    return path + " is too short";
                }

                break;

            case JsonValueKind.Number:
                if (!value.TryGetInt64(out long number))
                {
                    return path + " must be a whole number";
                }

                if (schema["minimum"] is { } lower && number < lower.GetValue<int>())
                {
                    return path + " is below " + lower.GetValue<int>().ToString(CultureInfo.InvariantCulture);
                }

                if (schema["maximum"] is { } upper && number > upper.GetValue<int>())
                {
                    return path + " is above " + upper.GetValue<int>().ToString(CultureInfo.InvariantCulture);
                }

                break;

            case JsonValueKind.Object:
                return ValidateObject(value, schema, components, path);

            case JsonValueKind.Array:
                int count = 0;
                foreach (JsonElement item in value.EnumerateArray())
                {
                    count++;
                    if (schema["items"] is JsonObject items && Validate(item, items, components, path + "[]") is { } itemProblem)
                    {
                        return itemProblem;
                    }
                }

                if (schema["maxItems"] is { } maxItems && count > maxItems.GetValue<int>())
                {
                    return path + " has too many items";
                }

                break;
        }

        return null;
    }

    private static string? ValidateObject(JsonElement value, JsonObject schema, JsonObject components, string path)
    {
        JsonObject? properties = schema["properties"] as JsonObject;
        JsonNode? additional = schema["additionalProperties"];
        int members = 0;
        foreach (JsonProperty member in value.EnumerateObject())
        {
            members++;
            if (properties is not null && properties[member.Name] is JsonObject memberSchema)
            {
                if (Validate(member.Value, memberSchema, components, path + "." + member.Name) is { } problem)
                {
                    return problem;
                }
            }
            else if (additional is JsonObject extra)
            {
                if (Validate(member.Value, extra, components, path + "." + member.Name) is { } problem)
                {
                    return problem;
                }
            }
            else if (additional is JsonValue { } flag && flag.TryGetValue(out bool allowed) && allowed)
            {
                continue;
            }
            else
            {
                return path + " has a member that is not part of this request";
            }
        }

        if (schema["maxProperties"] is { } maxProperties && members > maxProperties.GetValue<int>())
        {
            return path + " has too many members";
        }

        if (schema["required"] is JsonArray required)
        {
            foreach (JsonNode? name in required)
            {
                if (name is not null && !value.TryGetProperty(name.GetValue<string>(), out _))
                {
                    return path + "." + name.GetValue<string>() + " is required";
                }
            }
        }

        return null;
    }

    private static bool Same(JsonNode? allowed, JsonElement value) => allowed is null
        ? value.ValueKind == JsonValueKind.Null
        : value.ValueKind == JsonValueKind.String && allowed is JsonValue text && text.TryGetValue(out string? expected) && expected == value.GetString();

    private static bool TypeMatches(JsonElement value, JsonNode typeNode, out string expected)
    {
        string[] types = typeNode is JsonArray array ? [.. array.Select(item => item!.GetValue<string>())] : [typeNode.GetValue<string>()];
        expected = string.Join(" or ", types);

        return types.Any(type => type switch
        {
            "string" => value.ValueKind == JsonValueKind.String,
            "integer" => value.ValueKind == JsonValueKind.Number,
            "number" => value.ValueKind == JsonValueKind.Number,
            "boolean" => value.ValueKind is JsonValueKind.True or JsonValueKind.False,
            "object" => value.ValueKind == JsonValueKind.Object,
            "array" => value.ValueKind == JsonValueKind.Array,
            "null" => value.ValueKind == JsonValueKind.Null,
            _ => false,
        });
    }
}
