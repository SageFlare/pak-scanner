using PakScanner.Findings;
using PakScanner.Rules;
using Xunit;

namespace PakScanner.Tests;

public class WebWidgetRuleTests
{
    [Theory]
    [InlineData("TBLWebWidget")]
    [InlineData("BrowseToUrl")]
    [InlineData("CallFunc_BrowseToUrl_0")] // mangled/suffixed cooked form
    public void Names_referencing_the_web_widget_are_detected(string token)
    {
        var names = new[] { "BeginPlay", token };
        Assert.True(WebWidgetRule.NamesIndicateWebWidget(names, out var evidence));
        Assert.False(string.IsNullOrEmpty(evidence));
    }

    [Fact]
    public void Benign_names_are_not_detected()
    {
        var names = new[] { "BeginPlay", "PlaySound", "SetMaterial" };
        Assert.False(WebWidgetRule.NamesIndicateWebWidget(names, out _));
    }

    [Fact]
    public void Finding_is_high_and_delivery_controls_reachability()
    {
        var delivered = WebWidgetRule.MakeFinding("p", "e", delivered: true);
        Assert.Equal("web_widget", delivered.Rule);
        Assert.Equal(Severity.High, delivered.Severity);
        Assert.True(delivered.Reachable);

        var latent = WebWidgetRule.MakeFinding("p", "e", delivered: false);
        Assert.False(latent.Reachable);
    }
}
