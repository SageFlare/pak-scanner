using CUE4Parse.FileProvider;
using CUE4Parse.UE4.Assets;

namespace PakScanner.Rules;

/// <summary>
/// A parsed pak ready for inspection by security rules. Holds the virtual entry paths and a way
/// to load each asset package lazily. Built by <see cref="SecurityScanner"/> from a CUE4Parse
/// provider; rules see only this, never the raw file system.
/// </summary>
public sealed class ScanTarget
{
    private readonly IFileProvider? _provider;

    public ScanTarget(IFileProvider provider, IReadOnlyList<string> entryPaths)
    {
        _provider = provider;
        EntryPaths = entryPaths;
    }

    private ScanTarget(IReadOnlyList<string> entryPaths)
    {
        _provider = null;
        EntryPaths = entryPaths;
    }

    /// <summary>
    /// A target carrying only entry paths and no provider. For rules (and tests) that inspect
    /// paths without loading package contents. <see cref="TryLoadPackage"/> returns null.
    /// </summary>
    public static ScanTarget ForPathsOnly(IReadOnlyList<string> entryPaths) => new(entryPaths);

    /// <summary>Virtual paths of every file in the pak (e.g. "TBL/Content/Mods/.../X.uasset").</summary>
    public IReadOnlyList<string> EntryPaths { get; }

    /// <summary>Try to load an asset package by its virtual path. Returns null on failure or when no provider.</summary>
    public IPackage? TryLoadPackage(string path)
    {
        if (_provider is null) return null;
        try
        {
            return _provider.TryLoadPackage(path, out var pkg) ? pkg : null;
        }
        catch
        {
            return null;
        }
    }
}
