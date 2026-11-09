using System.Xml.Linq;
using Microsoft.AspNetCore.DataProtection.Repositories;

namespace EkmMock.Server.WebConsole;

/// <summary>
/// Where the console's ASP.NET Core Data Protection keys live (they protect the antiforgery tokens and, in <c>EntraId</c> mode, the sign-in cookie): files in <c>&lt;Data:Path&gt;/dataprotection</c>.
/// The framework's own <c>FileSystemXmlRepository</c> creates every key file through <c>Path.GetTempFileName()</c>, i.e. in <c>/tmp</c>, which fails in a container with a read-only root file system
/// and no tmpfs (M9: "the app must run with --read-only and a writable /data"). This repository writes its temporary file next to the final one, so <c>/data</c> is the only writable place needed.
/// Files are owner-only (mode 600) on Unix. The keys are not encrypted at rest (no XML encryptor): anyone who can read the data volume can already read the key store, so that adds nothing for this
/// threat model; the consequence of a leaked key is forged antiforgery tokens, not access to key material (see DECISIONS "M9: Data protection keys").
/// </summary>
internal sealed class DataFolderXmlRepository : IXmlRepository
{
    private readonly DirectoryInfo _folder;

    public DataFolderXmlRepository(DirectoryInfo folder)
    {
        _folder = folder;
    }

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        var elements = new List<XElement>();
        foreach (var file in _folder.EnumerateFiles("*.xml"))
        {
            try
            {
                using var stream = file.OpenRead();
                elements.Add(XElement.Load(stream));
            }
            catch (System.Xml.XmlException)
            {
                // A half-written or foreign file is ignored; the key ring is rebuilt from the valid ones.
            }
        }

        return elements;
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        var name = string.IsNullOrWhiteSpace(friendlyName) ? Guid.NewGuid().ToString("N") : Sanitize(friendlyName);
        var target = Path.Combine(_folder.FullName, name + ".xml");
        var temp = Path.Combine(_folder.FullName, "." + Guid.NewGuid().ToString("N") + ".tmp");
        try
        {
            using (var stream = new FileStream(temp, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                if (!OperatingSystem.IsWindows())
                {
                    File.SetUnixFileMode(temp, UnixFileMode.UserRead | UnixFileMode.UserWrite);
                }

                element.Save(stream);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temp, target, overwrite: true);
        }
        catch
        {
            try
            {
                File.Delete(temp);
            }
            catch (IOException)
            {
                // Best effort: the original failure is the one to report.
            }

            throw;
        }
    }

    private static string Sanitize(string name)
        => string.Concat(name.Select(static c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' ? c : '_'));

    /// <summary>True when a file can be created in the folder (the folder is on a writable volume). Used once at start-up to choose between this repository and the in-memory one.</summary>
    public static bool IsWritable(DirectoryInfo folder)
    {
        try
        {
            var probe = Path.Combine(folder.FullName, "." + Guid.NewGuid().ToString("N") + ".probe");
            File.WriteAllBytes(probe, []);
            File.Delete(probe);
            return true;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
        {
            return false;
        }
    }
}

/// <summary>Keys held in memory only: the fallback when the data folder is not writable. Tokens issued before a restart are invalid afterwards.</summary>
internal sealed class InMemoryXmlRepository : IXmlRepository
{
    private readonly object _gate = new();
    private readonly List<XElement> _elements = [];

    public IReadOnlyCollection<XElement> GetAllElements()
    {
        lock (_gate)
        {
            return [.. _elements];
        }
    }

    public void StoreElement(XElement element, string friendlyName)
    {
        lock (_gate)
        {
            _elements.Add(element);
        }
    }
}
