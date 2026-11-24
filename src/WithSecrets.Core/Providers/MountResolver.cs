namespace WithSecrets;

/// <summary>Which mount, if any, selects a logical secret name (10.3.2): an exact individual mount first, else the longest whole-segment tree prefix.</summary>
public static class MountResolver
{
    public static Mount? Resolve(IReadOnlyList<Mount> mounts, string logicalName)
    {
        Mount? best = null;
        foreach (Mount mount in mounts)
        {
            if (mount.Kind == MountKind.Single)
            {
                if (string.Equals(mount.LogicalPath, logicalName, StringComparison.Ordinal))
                {
                    return mount;
                }
            }
            else if (logicalName.Length > mount.LogicalPath.Length && logicalName[mount.LogicalPath.Length] == '/'
                && logicalName.StartsWith(mount.LogicalPath, StringComparison.Ordinal) && (best is null || mount.LogicalPath.Length > best.LogicalPath.Length))
            {
                best = mount;
            }
        }

        return best;
    }
}
