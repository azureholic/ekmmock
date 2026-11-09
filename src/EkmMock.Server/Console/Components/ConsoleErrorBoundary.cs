using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using Microsoft.AspNetCore.Components.Web;

namespace EkmMock.Server.WebConsole.Components;

/// <summary>
/// The error boundary of every console page: a failed page shows a short, generic message and a way to try again; it never shows the exception, its message or a stack
/// trace (spec 5.4 and the repository rules). The exception <em>type</em> is logged; the message can quote request data and is not.
/// </summary>
public sealed class ConsoleErrorBoundary : ErrorBoundaryBase
{
    [Inject]
    private ILogger<ConsoleErrorBoundary> Logger { get; set; } = default!;

    protected override Task OnErrorAsync(Exception exception)
    {
        Logger.LogError("A console page failed: {ExceptionType}", exception.GetType().Name);
        return Task.CompletedTask;
    }

    protected override void BuildRenderTree(RenderTreeBuilder builder)
    {
        if (CurrentException is null)
        {
            builder.AddContent(0, ChildContent);
            return;
        }

        builder.OpenElement(1, "div");
        builder.AddAttribute(2, "class", "console-error");
        builder.AddAttribute(3, "role", "alert");
        builder.AddAttribute(4, "data-role", "page-error");
        builder.OpenElement(5, "strong");
        builder.AddContent(6, "This page ran into a problem.");
        builder.CloseElement();
        builder.OpenElement(7, "p");
        builder.AddContent(8, "The rest of the console keeps working. Details are in the server log.");
        builder.CloseElement();
        builder.OpenElement(9, "button");
        builder.AddAttribute(10, "type", "button");
        builder.AddAttribute(11, "class", "console-error-retry");
        builder.AddAttribute(12, "onclick", EventCallback.Factory.Create<MouseEventArgs>(this, Recover));
        builder.AddContent(13, "Try again");
        builder.CloseElement();
        builder.CloseElement();
    }
}
