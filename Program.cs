

using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme =
        CookieAuthenticationDefaults.AuthenticationScheme;

    options.DefaultChallengeScheme =
        OpenIdConnectDefaults.AuthenticationScheme;
})
.AddCookie(options =>
{
    options.Events.OnRedirectToAccessDenied = context =>
    {
        context.Response.StatusCode = 403;
        return Task.CompletedTask;
    };
})
.AddOpenIdConnect(options =>
{
    options.Authority =
        "http://localhost:8080/realms/college-realm";

    options.ClientId = "college-app";

    // Keep your actual regenerated Client Secret here.
    options.ClientSecret = builder.Configuration["Keycloak:ClientSecret"]
    ?? throw new InvalidOperationException("Keycloak Client Secret is missing.");
    options.ResponseType = "code";
    options.RequireHttpsMetadata = false;

    options.SaveTokens = true;
    options.GetClaimsFromUserInfoEndpoint = true;

    options.Scope.Add("profile");
    options.Scope.Add("email");

    options.ClaimActions.MapJsonKey("groups", "groups");
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("StudentOnly", policy =>
        policy.RequireClaim("groups", "/Students"));

    options.AddPolicy("TeacherOnly", policy =>
        policy.RequireClaim("groups", "/Teachers"));

    options.AddPolicy("AdminOnly", policy =>
        policy.RequireClaim("groups", "/Admins"));
});

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

// Home page
app.MapGet("/", (ClaimsPrincipal user) =>
{
    if (user.Identity?.IsAuthenticated == true)
        return Results.Redirect("/profile");

    return Results.Content(
        "<h2>Centralized Identity Provider</h2>" +
        "<a href='/login'>Login with Keycloak</a>",
        "text/html"
    );
});

// Login
app.MapGet("/login", () =>
    Results.Challenge(
        new AuthenticationProperties
        {
            RedirectUri = "/profile"
        },
        new[] { OpenIdConnectDefaults.AuthenticationScheme }
    )
);

// Automatically redirect users to their own dashboard
app.MapGet("/profile", (ClaimsPrincipal user) =>
{
    var groups = user.FindAll("groups")
        .Select(c => c.Value)
        .ToList();

    if (groups.Contains("/Students"))
        return Results.Redirect("/student-dashboard");

    if (groups.Contains("/Teachers"))
        return Results.Redirect("/teacher-dashboard");

    if (groups.Contains("/Admins"))
        return Results.Redirect("/admin-dashboard");

    return Results.Forbid();
}).RequireAuthorization();

// Student dashboard
app.MapGet("/student-dashboard", () =>
{
    return "Welcome to Student Dashboard!";
})
.RequireAuthorization("StudentOnly");

// Teacher dashboard
app.MapGet("/teacher-dashboard", () =>
{
    return "Welcome to Teacher Dashboard!";
})
.RequireAuthorization("TeacherOnly");

// Admin dashboard
app.MapGet("/admin-dashboard", () =>
{
    return "Welcome to Admin Dashboard!";
})
.RequireAuthorization("AdminOnly");

// View user claims
app.MapGet("/claims", (ClaimsPrincipal user) =>
{
    var claims = string.Join("",
        user.Claims.Select(c =>
            $"<li>{WebUtility.HtmlEncode(c.Type)}: " +
            $"{WebUtility.HtmlEncode(c.Value)}</li>"
        )
    );

    return Results.Content(
        $"<h2>Login Successful</h2><ul>{claims}</ul>" +
        "<a href='/logout'>Logout</a>",
        "text/html"
    );
}).RequireAuthorization();

// Logout
app.MapGet("/logout", () =>
    Results.SignOut(
        new AuthenticationProperties { RedirectUri = "/" },
        new[]
        {
            CookieAuthenticationDefaults.AuthenticationScheme,
            OpenIdConnectDefaults.AuthenticationScheme
        }
    )
);

app.Run();
