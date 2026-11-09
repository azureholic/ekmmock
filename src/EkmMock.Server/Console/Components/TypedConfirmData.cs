namespace EkmMock.Server.WebConsole;

/// <summary>What a <see cref="TypedConfirmDialog"/> asks: the text the user must type, what will happen and an optional extra checkbox (for example "also destroy all keys").</summary>
public sealed record TypedConfirmData(
    string Message,
    string ExpectedText,
    string ConfirmText,
    IReadOnlyList<string> Consequences,
    string? OptionLabel = null);

/// <summary>The outcome of a confirmed <see cref="TypedConfirmDialog"/>: the text that was typed and the state of the optional checkbox.</summary>
public sealed record TypedConfirmResult(string Typed, bool Option);
