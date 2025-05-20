import subprocess
import time
import os
import signal
import pytest


APP_PATH = os.getenv('APP_PATH')
APP_DURATION = os.getenv('APP_DURATION')

CALM_SEC = 10
ONE_TEST_DURATION_SEC = CALM_SEC + int(APP_DURATION)/1000
FLOOD_TIMEOUT_SEC = str(15 * ONE_TEST_DURATION_SEC)  # seconds; flood timeout just in case; must be longer than all tests

FLOOD_ARG = os.getenv("POC_HPING_TRAFFIC", "--flood")
FLOOD_CMD = ["timeout", FLOOD_TIMEOUT_SEC, "hping3", "--udp", "-p", "12345", "--data", "123"] + FLOOD_ARG.split() + ["127.0.0.1"]
FLOOD_NUM = 5


def should_flood():
    return "--flood" in FLOOD_ARG

@pytest.fixture(scope="session", autouse=True)
def udp_flooder():
    print()

    hping3_instances = FLOOD_NUM if should_flood() else 1

    print(f"Starting UDP traffic {hping3_instances} x `hping3 {FLOOD_ARG}` (timeout {FLOOD_TIMEOUT_SEC})...")

    flood_procs = []
    for _ in range(hping3_instances):
        proc = subprocess.Popen(
            FLOOD_CMD,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            preexec_fn=os.setsid,
        )
        flood_procs.append(proc)

    print("Running tests...")
    yield

    print()
    print("Stopping hping3 flood...")
    for proc in flood_procs:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
    print("FINISHED")

@pytest.mark.parametrize("index, app_extra_args", list(enumerate([
    [],
    ["--perf"],
    ["--ring"],
    ["--ring", "--ring-delay", "0"],
    ["--ring", "--ring-delay", "10"],
    ["--ring", "--ring-delay", "20"],
    ["--ring", "--ring-delay", "50"],
    ["--ring", "--ring-delay", "100"],
    ["--ring", "--ring-delay", "200"],
    ["--ring", "--ring-delay", "500"],
], start=1)))
def test_axray_throughput(index, app_extra_args):
    app_cmd = [APP_PATH, "--iface", "lo", "--timeout", APP_DURATION] + app_extra_args

    time.sleep(CALM_SEC)  # Calm down
    print()
    print(f"[{index}] Run: {' '.join(app_cmd)}")
    subprocess.run(app_cmd)
