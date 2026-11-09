using System.Xml.Linq;
using EkmMock.Server.WebConsole;
using EkmMock.TestSupport;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.DataProtection.KeyManagement;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace EkmMock.Server.Tests;

/// <summary>
/// M9: the console's Data Protection keys on the data volume. The framework's file repository writes through <c>/tmp</c>, which a read-only container does not have; <see cref="DataFolderXmlRepository"/>
/// writes only inside the data folder, so a key created before a restart still protects the tokens after it.
/// </summary>
public sealed class DataProtectionKeyFolderTests
{
    [Fact]
    public void AStoredKey_IsReadBackByANewInstance_AndLeavesNoTemporaryFile()
    {
        using var folder = new TempFolder();
        var directory = new DirectoryInfo(folder.Path);
        var element = new XElement("key", new XAttribute("id", "1"), "material");

        new DataFolderXmlRepository(directory).StoreElement(element, "key-0001");

        var read = new DataFolderXmlRepository(directory).GetAllElements();
        read.Count.ShouldBe(1);
        read.Single().Attribute("id")!.Value.ShouldBe("1");
        Directory.GetFiles(folder.Path).Select(Path.GetFileName).ShouldBe(["key-0001.xml"]);
    }

    [Fact]
    public void AFriendlyNameCannotEscapeTheFolder()
    {
        using var folder = new TempFolder();

        new DataFolderXmlRepository(new DirectoryInfo(folder.Path)).StoreElement(new XElement("key"), "../../evil/name");

        Directory.GetFiles(folder.Path, "*.xml", SearchOption.AllDirectories).Single().ShouldStartWith(folder.Path);
        Directory.GetDirectories(folder.Path).ShouldBeEmpty();
    }

    [Fact]
    public void AForeignOrHalfWrittenFile_IsIgnored_AndTheValidKeysAreStillRead()
    {
        using var folder = new TempFolder();
        var directory = new DirectoryInfo(folder.Path);
        new DataFolderXmlRepository(directory).StoreElement(new XElement("key", "good"), "key-good");
        File.WriteAllText(Path.Combine(folder.Path, "broken.xml"), "<key><unclosed>");

        new DataFolderXmlRepository(directory).GetAllElements().Select(static e => e.Value).ShouldBe(["good"]);
    }

    [Fact]
    public void ProtectedData_SurvivesARestart_WhenTheKeysAreOnTheDataFolder()
    {
        using var folder = new TempFolder();

        IDataProtector NewProcess(ServiceProvider[] holder)
        {
            var services = new ServiceCollection();
            services.AddDataProtection().SetApplicationName("EkmMock.Console");
            services.Configure<KeyManagementOptions>(options => options.XmlRepository = new DataFolderXmlRepository(new DirectoryInfo(folder.Path)));
            holder[0] = services.BuildServiceProvider();
            return holder[0].GetRequiredService<IDataProtectionProvider>().CreateProtector("test");
        }

        var first = new ServiceProvider[1];
        var token = NewProcess(first).Protect("antiforgery-token");
        first[0].Dispose();
        Directory.GetFiles(folder.Path, "*.xml").ShouldNotBeEmpty("the key ring was persisted");

        var second = new ServiceProvider[1];
        NewProcess(second).Unprotect(token).ShouldBe("antiforgery-token");
        second[0].Dispose();
    }

    [Fact]
    public void AWritableFolderIsDetected_AFileInPlaceOfTheFolderIsNot()
    {
        using var folder = new TempFolder();
        DataFolderXmlRepository.IsWritable(new DirectoryInfo(folder.Path)).ShouldBeTrue();
        Directory.GetFiles(folder.Path).ShouldBeEmpty("the probe cleans up after itself");

        var file = Path.Combine(folder.Path, "not-a-folder");
        File.WriteAllText(file, "x");
        DataFolderXmlRepository.IsWritable(new DirectoryInfo(file)).ShouldBeFalse();
    }

    [Fact]
    public void TheInMemoryFallback_KeepsKeys_ForTheLifeOfTheProcess()
    {
        var repository = new InMemoryXmlRepository();

        repository.StoreElement(new XElement("key", "a"), "key-a");

        repository.GetAllElements().Select(static e => e.Value).ShouldBe(["a"]);
    }
}
