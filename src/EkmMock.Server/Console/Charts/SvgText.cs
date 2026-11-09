using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;

namespace EkmMock.Server.WebConsole.Charts;

/// <summary>
/// An SVG <c>&lt;text&gt;</c> element. Razor reserves <c>&lt;text&gt;</c> (it cannot carry attributes in a .razor file), so the charts render their labels through this
/// component, which builds the element by hand. Extra attributes (<c>data-role</c>, <c>aria-*</c>) are passed through.
/// </summary>
public sealed class SvgText : ComponentBase
{
    [Parameter]
    public string? X { get; set; }

    [Parameter]
    public string? Y { get; set; }

    /// <summary>The SVG <c>text-anchor</c>: start, middle or end.</summary>
    [Parameter]
    public string? Anchor { get; set; }

    [Parameter]
    public string? Class { get; set; }

    [Parameter]
    public RenderFragment? ChildContent { get; set; }

    [Parameter(CaptureUnmatchedValues = true)]
    public Dictionary<string, object>? Attributes { get; set; }

    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        builder.OpenElement(0, "text");
        builder.AddAttribute(1, "class", Class);
        builder.AddAttribute(2, "x", X);
        builder.AddAttribute(3, "y", Y);
        builder.AddAttribute(4, "text-anchor", Anchor);
        builder.AddMultipleAttributes(5, Attributes);
        builder.AddContent(6, ChildContent);
        builder.CloseElement();
    }
}
