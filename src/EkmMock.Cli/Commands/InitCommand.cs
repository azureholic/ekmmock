using System.CommandLine;
using System.Text.Json;
using System.Text.Json.Serialization.Metadata;
using EkmMock.Cli.Infrastructure;
using EkmMock.Crypto;
using System.Security.Cryptography;

namespace EkmMock.Cli.Commands;

/// <summary>
/// <c>ekmmock init --data /data</c> (spec 6.2, 12): creates the data folders and a 32-byte master key (base64) in a file only the current user can read, and says how to hand it to the server.
/// Safe by construction: it never overwrites a master key that exists (a key store encrypted under it would become unreadable) and never creates a master key next to a key store that already
/// exists without one. The key itself is never printed unless <c>--print</c> is given.
/// </summary>
internal static class InitCommand
{
    public const string MasterKeyFileName = "master.key";
    public const string KeyStoreFileName = "keystore.json";

    private static readonly string[] Folders = ["tls", "inspector", "dataprotection"];

    public static Command Create(CliEnvironment env, GlobalOptions global)
    {
        var data = new Option<string>("--data") { Description = "The data folder of the server (Data:Path, /data in the container).", Required = true };
        var keyFile = new Option<string>("--master-key-file") { Description = $"Where to write the master key. Default: <data>/{MasterKeyFileName}. Keep it OUT of the data volume for anything but local use." };
        var print = new Option<bool>("--print") { Description = "Also print the new master key (base64) to stdout. Without this flag the key is never printed." };
        var force = new Option<bool>("--force") { Description = "Replace an existing master key file with a new one. Refused when a key store exists (every key in it would become unreadable)." };
        var output = new OutputOptionSet();

        var command = new Command("init", "Create the data folders and a master key for the server.\n\n" +
            "Examples:\n" +
            "  ekmmock init --data ./data\n" +
            "  ekmmock init --data /data --master-key-file /run/secrets/ekmmock_master_key\n\n" +
            "Running it again is safe: an existing master key is kept and nothing is changed.\n" +
            "Then start the server with EKMMOCK_MASTER_KEY_FILE pointing at the file (the command prints the exact line).\n" + ExitCodes.Documentation);
        command.Options.Add(data);
        command.Options.Add(keyFile);
        command.Options.Add(print);
        command.Options.Add(force);
        output.AddTo(command);

        CliApp.SetAction(command, env, global, (result, _) =>
        {
            var dataPath = env.ResolvePath(result.GetRequiredValue(data));
            var masterKeyPath = result.GetValue(keyFile) is { Length: > 0 } custom ? env.ResolvePath(custom) : Path.Combine(dataPath, MasterKeyFileName);
            var outcome = Run(dataPath, masterKeyPath, result.GetValue(force), result.GetValue(print));

            if (output.WantsJson(result))
            {
                env.Out.WriteLine(JsonSerializer.Serialize(outcome, CliOutputJson.Default.InitResult));
            }
            else
            {
                Print(env, outcome, result.GetValue(print));
            }

            return Task.FromResult(ExitCodes.Success);
        });
        return command;
    }

    internal static InitResult Run(string dataPath, string masterKeyPath, bool force, bool print)
    {
        var created = new List<string>();
        EnsureFolder(dataPath, created);
        foreach (var folder in Folders)
        {
            EnsureFolder(Path.Combine(dataPath, folder), created);
        }

        var keyStore = Path.Combine(dataPath, KeyStoreFileName);
        var keyStoreExists = File.Exists(keyStore);
        string? printed = null;
        var createdKey = false;

        if (File.Exists(masterKeyPath))
        {
            if (force)
            {
                if (keyStoreExists)
                {
                    throw CliException.Failure($"Refusing to replace the master key '{masterKeyPath}': a key store exists ({keyStore}) and every key in it is encrypted under the current master key. " +
                        "If you really want to start over, delete the key store and the master key yourself.");
                }

                printed = WriteNewKey(masterKeyPath, overwrite: true);
                createdKey = true;
            }
            else if (!IsValidMasterKeyFile(masterKeyPath))
            {
                throw CliException.Failure($"'{masterKeyPath}' exists but does not contain a valid master key (32 bytes, base64). It is left untouched; use another --master-key-file.");
            }
        }
        else
        {
            if (keyStoreExists)
            {
                throw CliException.Failure($"A key store exists ({keyStore}) but there is no master key at '{masterKeyPath}'. A new master key would make every stored key unreadable. " +
                    "Point --master-key-file at the original master key, or move the key store away first.");
            }

            printed = WriteNewKey(masterKeyPath, overwrite: false);
            createdKey = true;
        }

        var environment = new Dictionary<string, string> { [EnvironmentMasterKeyProvider.FileVariable] = masterKeyPath, ["Data__Path"] = dataPath };
        return new InitResult(dataPath, masterKeyPath, createdKey, created, SecureFile.IsOwnerOnly(masterKeyPath), environment, print ? printed : null);
    }

    private static string WriteNewKey(string path, bool overwrite)
    {
        var bytes = RandomNumberGenerator.GetBytes(MasterKey.SizeBytes);
        var text = Convert.ToBase64String(bytes);
        CryptographicOperations.ZeroMemory(bytes);
        try
        {
            SecureFile.WriteSecret(path, text + Environment.NewLine, overwrite);
        }
        catch (IOException exception)
        {
            throw CliException.Failure(exception.Message, exception);
        }

        return text;
    }

    internal static bool IsValidMasterKeyFile(string path)
    {
        try
        {
            Span<byte> buffer = stackalloc byte[MasterKey.SizeBytes + 8];
            return Convert.TryFromBase64String(File.ReadAllText(path).Trim(), buffer, out var written) && written == MasterKey.SizeBytes;
        }
        catch (IOException)
        {
            return false;
        }
    }

    private static void EnsureFolder(string path, List<string> created)
    {
        if (!Directory.Exists(path))
        {
            Directory.CreateDirectory(path);
            created.Add(path);
        }
    }

    private static void Print(CliEnvironment env, InitResult result, bool print)
    {
        var o = env.Out;
        o.WriteLine($"Data folder:      {result.DataPath}");
        foreach (var folder in result.CreatedFolders)
        {
            o.WriteLine($"  created         {folder}");
        }

        o.WriteLine(result.MasterKeyCreated
            ? $"Master key:       created {result.MasterKeyFile}{(result.MasterKeyOwnerOnly ? " (readable by you only)" : " (WARNING: could not restrict the file permissions, do it yourself)")}"
            : $"Master key:       already exists, kept: {result.MasterKeyFile}");
        if (!result.MasterKeyCreated && result.CreatedFolders.Count == 0)
        {
            o.WriteLine("Nothing to do: the data folder and the master key are already in place.");
        }

        if (print && result.MasterKey is not null)
        {
            env.Error.WriteLine("warning: --print puts the master key on stdout. Anyone who sees it can decrypt the key store.");
            o.WriteLine(result.MasterKey);
        }

        var inData = result.MasterKeyFile.StartsWith(result.DataPath, StringComparison.OrdinalIgnoreCase);
        if (inData)
        {
            o.WriteLine();
            o.WriteLine("Note: the master key is inside the data folder, next to the key store it protects. That is fine for local testing;");
            o.WriteLine("      for anything shared keep it elsewhere (a secret store, a Docker secret) and use --master-key-file.");
        }

        o.WriteLine();
        o.WriteLine("Give the key to the server (the file path, never the key itself):");
        o.WriteLine($"  PowerShell:  $env:EKMMOCK_MASTER_KEY_FILE = '{result.MasterKeyFile}'; $env:Data__Path = '{result.DataPath}'");
        o.WriteLine($"  bash:        export EKMMOCK_MASTER_KEY_FILE='{result.MasterKeyFile}' Data__Path='{result.DataPath}'");
        o.WriteLine("  Docker:      -e EKMMOCK_MASTER_KEY_FILE=/run/secrets/ekmmock_master_key -v <file>:/run/secrets/ekmmock_master_key:ro -v <data>:/data");
        o.WriteLine();
        o.WriteLine("Losing the master key makes every key in the key store unrecoverable. Back it up separately.");
    }
}
