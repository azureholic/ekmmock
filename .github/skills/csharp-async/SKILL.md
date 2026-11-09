---
name: csharp-async
description: 'Get best practices for C# async programming'
---

# C# Async Programming Best Practices

## EkmMock scope (local adaptation)

Follow [repository rules](../../copilot-instructions.md). Crypto operations remain
synchronous and are not cancelled once started (spec 10.1). Do not use Task.Run to
pretend the engine is cancellable. The bounded inspector producer never awaits its
consumer; preserve drop-oldest behavior and metrics. Dispose request deadline sources.
Use Blazor's synchronization context for UI updates; do not apply ConfigureAwait(false)
indiscriminately to component code.

Your goal is to help me follow best practices for asynchronous programming in C#.

## Naming Conventions

- Use the 'Async' suffix for all async methods
- Match method names with their synchronous counterparts when applicable (e.g., `GetDataAsync()` for `GetData()`)

## Return Types

- Return `Task<T>` when the method returns a value
- Return `Task` when the method doesn't return a value
- Consider `ValueTask<T>` for high-performance scenarios to reduce allocations
- Avoid returning `void` for async methods except for event handlers

## Exception Handling

- Catch only exceptions that can be handled meaningfully; otherwise propagate them.
- Avoid swallowing exceptions in async methods
- Use `ConfigureAwait(false)` when appropriate to prevent deadlocks in library code
- Let async methods propagate exceptions naturally; use Task.FromException only when
  deliberately returning a faulted task from a non-async method.

## Performance

- Use `Task.WhenAll()` for parallel execution of multiple tasks
- Use `Task.WhenAny()` for implementing timeouts or taking the first completed task
- Avoid unnecessary async/await when simply passing through task results
- Consider cancellation tokens for long-running operations

## Common Pitfalls

- Never use `.Wait()`, `.Result`, or `.GetAwaiter().GetResult()` in async code
- Avoid mixing blocking and async code
- Don't create async void methods (except for event handlers)
- Always await Task-returning methods

## Implementation Patterns

- Implement the async command pattern for long-running operations
- Use async streams (IAsyncEnumerable<T>) for processing sequences asynchronously
- Consider the task-based asynchronous pattern (TAP) for public APIs

When reviewing my C# code, identify these issues and suggest improvements that follow these best practices.
