using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Nocturne.API.Controllers.V4.Connectors;
using Nocturne.Core.Contracts.Connectors;
using Nocturne.Core.Models.Authorization;
using Xunit;

namespace Nocturne.API.Tests.Controllers.V4.Connectors;

/// <summary>
/// Saving a Nightscout API secret adopts it as a working credential, so only the account holder's
/// own sign-in may; every other connector credential stays savable by any credential holding
/// <c>tenant.settings</c>, platform access and the instance key included.
/// </summary>
public class ConfigurationControllerSaveSecretsTests
{
    private readonly Mock<IConnectorConfigurationService> _configService = new();

    private ConfigurationController Controller(AuthType authType)
    {
        var httpContext = new DefaultHttpContext();
        httpContext.Items["AuthContext"] = new AuthContext
        {
            IsAuthenticated = true,
            AuthType = authType,
            SubjectId = Guid.CreateVersion7(),
        };

        return new ConfigurationController(_configService.Object, NullLogger<ConfigurationController>.Instance)
        {
            ControllerContext = new ControllerContext { HttpContext = httpContext },
        };
    }

    [Theory]
    [InlineData(AuthType.ApiKey)]
    [InlineData(AuthType.DirectGrant)]
    [InlineData(AuthType.InstanceKey)]
    [InlineData(AuthType.PlatformAccess)]
    public async Task NightscoutApiSecret_FromADelegatedCredential_IsForbiddenAndNotSaved(AuthType authType)
    {
        var result = await Controller(authType).SaveSecrets(
            "nightscout", new Dictionary<string, string> { ["apiSecret"] = "s" }, CancellationToken.None);

        Assert.IsType<ForbidResult>(result);
        _configService.Verify(s => s.SaveSecretsAsync(
            It.IsAny<string>(), It.IsAny<Dictionary<string, string>>(), It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Never);
    }

    [Fact]
    public async Task NightscoutApiSecret_FromASession_IsSaved()
    {
        var result = await Controller(AuthType.SessionCookie).SaveSecrets(
            "Nightscout", new Dictionary<string, string> { ["ApiSecret"] = "s" }, CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }

    [Theory]
    [InlineData(AuthType.InstanceKey)]
    [InlineData(AuthType.PlatformAccess)]
    [InlineData(AuthType.ApiKey)]
    public async Task OtherConnectorCredentials_FromAnyCredential_AreSaved(AuthType authType)
    {
        var result = await Controller(authType).SaveSecrets(
            "dexcom", new Dictionary<string, string> { ["password"] = "s" }, CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
    }

    /// <summary>
    /// The CareLink settings form sends only the password. The refresh token and the values it is
    /// redeemed with belong to the connector, and losing them leaves only a CAPTCHA-blocked login.
    /// </summary>
    [Fact]
    public async Task CareLinkSettingsSave_KeepsTheConnectorsStoredSession()
    {
        _configService
            .Setup(s => s.GetSecretsAsync("carelink", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, string>
            {
                ["password"] = "old",
                ["refresh_token"] = "stored-refresh",
                ["client_id"] = "client",
                ["token_url"] = "https://login.example/oauth/token",
                ["audience"] = "",
            });

        var result = await Controller(AuthType.SessionCookie).SaveSecrets(
            "carelink", new Dictionary<string, string> { ["password"] = "new" }, CancellationToken.None);

        Assert.IsType<NoContentResult>(result);
        _configService.Verify(s => s.SaveSecretsAsync(
            "carelink",
            It.Is<Dictionary<string, string>>(saved =>
                saved.Count == 4
                && saved["password"] == "new"
                && saved["refresh_token"] == "stored-refresh"
                && saved["client_id"] == "client"
                && saved["token_url"] == "https://login.example/oauth/token"),
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    /// <summary>A refresh token pasted into the settings starts a new session, so the stored one must go.</summary>
    [Fact]
    public async Task CareLinkSettingsSave_WithAPastedRefreshToken_ReplacesTheStoredSession()
    {
        _configService
            .Setup(s => s.GetSecretsAsync("carelink", It.IsAny<CancellationToken>()))
            .ReturnsAsync(new Dictionary<string, string> { ["refresh_token"] = "stored-refresh" });

        await Controller(AuthType.SessionCookie).SaveSecrets(
            "carelink", new Dictionary<string, string> { ["refreshToken"] = "pasted" }, CancellationToken.None);

        _configService.Verify(s => s.SaveSecretsAsync(
            "carelink",
            It.Is<Dictionary<string, string>>(saved => saved.Count == 1 && saved["refreshToken"] == "pasted"),
            It.IsAny<string?>(),
            It.IsAny<CancellationToken>()), Times.Once);
    }

    [Fact]
    public async Task OtherConnectorSave_DoesNotReadTheStoredSecrets()
    {
        await Controller(AuthType.SessionCookie).SaveSecrets(
            "dexcom", new Dictionary<string, string> { ["password"] = "s" }, CancellationToken.None);

        _configService.Verify(s => s.GetSecretsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
    }
}
