using System.Runtime.Versioning;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;

namespace EkmMock.Cli.Infrastructure;

/// <summary>
/// Writes files that contain secrets (master key, test-PKI private keys) so that only the current user can read them, and never overwrites anything unless asked. The file is created
/// with restrictive permissions <em>before</em> the content is written (Unix mode 0600 at creation; on Windows the ACL is replaced with the current user right after creation and before any
/// content is written), so there is no moment where the secret is readable by others.
/// </summary>
internal static class SecureFile
{
    /// <summary>Writes <paramref name="content"/> to a new file readable by the owner only. Throws <see cref="IOException"/> when the file exists and <paramref name="overwrite"/> is false.</summary>
    public static void WriteSecret(string path, string content, bool overwrite = false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (File.Exists(path))
        {
            if (!overwrite)
            {
                throw new IOException($"The file '{path}' already exists and is not overwritten.");
            }

            File.Delete(path);
        }

        FileStream stream = OperatingSystem.IsWindows()
            ? CreateRestrictedOnWindows(path)
            : new FileStream(path, new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write, Share = FileShare.None, UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite });
        using (stream)
        {
            try
            {
                stream.Write(Encoding.UTF8.GetBytes(content));
            }
            catch
            {
                // Never leave an empty or half-written secret file behind: the next run would refuse it as "exists but invalid".
                stream.Dispose();
                File.Delete(path);
                throw;
            }
        }
    }

    /// <summary>Writes a public file (certificate, report). Same no-overwrite rule.</summary>
    public static void WritePublic(string path, string content, bool overwrite = false)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(path))!);
        if (File.Exists(path) && !overwrite)
        {
            throw new IOException($"The file '{path}' already exists and is not overwritten.");
        }

        File.WriteAllText(path, content, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false));
    }

    /// <summary>True when the file can only be read by its owner (Unix: no group/other bits; Windows: no ACE for anyone but the current user, SYSTEM and Administrators).</summary>
    public static bool IsOwnerOnly(string path)
    {
        if (!OperatingSystem.IsWindows())
        {
            return (File.GetUnixFileMode(path) & (UnixFileMode.GroupRead | UnixFileMode.GroupWrite | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherWrite | UnixFileMode.OtherExecute)) == 0;
        }

        return WindowsIsOwnerOnly(path);
    }

    /// <summary>Creates the file with a security descriptor that gives access to the current user only (inheritance off), in the same call that creates it: there is no moment where it is readable by others.</summary>
    [SupportedOSPlatform("windows")]
    private static FileStream CreateRestrictedOnWindows(string path)
    {
        var current = WindowsIdentity.GetCurrent().User ?? throw new IOException("The current user could not be determined.");
        var security = new FileSecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        security.AddAccessRule(new FileSystemAccessRule(current, FileSystemRights.FullControl, AccessControlType.Allow));
        return FileSystemAclExtensions.Create(new FileInfo(path), FileMode.CreateNew, FileSystemRights.FullControl, FileShare.None, 4096, FileOptions.None, security);
    }

    [SupportedOSPlatform("windows")]
    private static bool WindowsIsOwnerOnly(string path)
    {
        var current = WindowsIdentity.GetCurrent().User;
        var rules = new FileInfo(path).GetAccessControl().GetAccessRules(includeExplicit: true, includeInherited: true, typeof(SecurityIdentifier));
        foreach (FileSystemAccessRule rule in rules)
        {
            if (rule.AccessControlType != AccessControlType.Allow)
            {
                continue;
            }

            var sid = (SecurityIdentifier)rule.IdentityReference;
            if (sid != current && !sid.IsWellKnown(WellKnownSidType.LocalSystemSid) && !sid.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid))
            {
                return false;
            }
        }

        return true;
    }
}
