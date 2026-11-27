
from reconai.config import Settings
from reconai.tools import BUILTIN_TOOLS
from reconai.tools.arjun import Arjun
from reconai.tools.base import ToolArgError


def make_tool():
    return Arjun(Settings())


def test_arjun_is_registered():
    assert "arjun" in BUILTIN_TOOLS
    assert BUILTIN_TOOLS["arjun"] is Arjun


def test_arjun_default_command():
    tool = make_tool()

    argv = tool.build_argv({
        "target": "https://example.com/api/products"
    })

    assert argv == [
        "arjun",
        "-u", "https://example.com/api/products",
        "-m", "GET",
        "-t", "1",
        "-T", "10",
        "--ratelimit", "2",
        "--disable-redirects",
    ]


def test_arjun_custom_rate_and_timeout():
    tool = make_tool()

    argv = tool.build_argv({
        "target": "https://example.com/api",
        "rate_limit": 3,
        "request_timeout": 20,
    })

    assert "--ratelimit" in argv
    assert argv[argv.index("--ratelimit") + 1] == "3"

    assert "-T" in argv
    assert argv[argv.index("-T") + 1] == "20"


def test_arjun_only_accepts_declared_arguments():
    tool = make_tool()

    try:
        tool.validate({
            "target": "https://example.com",
            "method": "POST",
        })
        assert False, "Unexpected argument should be rejected"
    except ToolArgError:
        pass


def test_arjun_rejects_excessive_rate_limit():
    tool = make_tool()

    try:
        tool.validate({
            "target": "https://example.com",
            "rate_limit": 100,
        })
        assert False, "Excessive rate limit should be rejected"
    except ToolArgError:
        pass


def test_arjun_rejects_invalid_timeout():
    tool = make_tool()

    try:
        tool.validate({
            "target": "https://example.com",
            "request_timeout": 120,
        })
        assert False, "Invalid timeout should be rejected"
    except ToolArgError:
        pass


def test_arjun_never_follows_redirects():
    tool = make_tool()

    argv = tool.build_argv({
        "target": "https://example.com"
    })

    assert "--disable-redirects" in argv
    assert "-L" not in argv
    assert "--follow-redirects" not in argv


def test_arjun_uses_single_worker():
    tool = make_tool()

    argv = tool.build_argv({
        "target": "https://example.com"
    })

    assert argv[argv.index("-t") + 1] == "1"

def test_arjun_uses_correct_rate_limit_flag():
    tool = make_tool()

    argv = tool.build_argv({
        "target": "https://example.com",
        "rate_limit": 3,
    })

    assert "--rate-limit" in argv
    assert "--ratelimit" not in argv
    assert argv[argv.index("--rate-limit") + 1] == "3"
