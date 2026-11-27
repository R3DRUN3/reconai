
from reconai.config import Settings
from reconai.tools.katana import Katana


def test_katana_command_uses_target():
    tool = Katana(Settings())

    argv = tool.build_argv({"target": "https://example.com/"})

    assert argv[0] == "katana"
    assert argv[argv.index("-u") + 1] == "https://example.com/"


def test_katana_has_bounded_crawl_settings():
    tool = Katana(Settings())

    argv = tool.build_argv({"target": "https://example.com/"})

    expected_pairs = {
        "-d": "2",
        "-ct": "60s",
        "-mdp": "50",
        "-c": "2",
        "-p": "1",
        "-rl": "2",
        "-timeout": "10",
        "-retry": "1",
    }

    for flag, value in expected_pairs.items():
        assert argv[argv.index(flag) + 1] == value


def test_katana_enforces_exact_host_scope_and_disables_redirects():
    tool = Katana(Settings())

    argv = tool.build_argv({"target": "https://example.com/"})

    assert argv[argv.index("-fs") + 1] == "fqdn"
    assert "-dr" in argv
    assert "-ns" not in argv


def test_katana_uses_jsonl_without_raw_responses():
    tool = Katana(Settings())

    argv = tool.build_argv({"target": "https://example.com/"})

    assert "-j" in argv
    assert "-or" in argv
    assert "-ob" in argv
    assert "-silent" in argv
    assert "-nc" in argv


def test_katana_does_not_enable_headless_or_form_filling():
    tool = Katana(Settings())

    argv = tool.build_argv({"target": "https://example.com/"})

    assert "-headless" not in argv
    assert "-hl" not in argv
    assert "-aff" not in argv
