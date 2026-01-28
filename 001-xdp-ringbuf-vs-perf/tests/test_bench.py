import os
import pytest
import shutil
import signal
import subprocess
import time


APP = os.getenv('APP') or "./target/release/poc"
HPING = os.getenv('HPING')
TIMEOUT = os.getenv('TIMEOUT') or "1000"

CALM_SEC = 10
ONE_TEST_DURATION_SEC = CALM_SEC + int(TIMEOUT)/1000
FLOOD_TIMEOUT_SEC = str(15 * ONE_TEST_DURATION_SEC)  # seconds; flood timeout just in case; must be longer than all tests

FLOOD_ARG = os.getenv("POC_HPING_TRAFFIC", "--flood")
FLOOD_NUM = 5


def should_flood():
    return "--flood" in FLOOD_ARG

@pytest.fixture(scope="session", autouse=True)
def udp_flooder():
    print()

    # hping3 = shutil.which("hping3")
    hping3 = HPING
    print(f"hping3: {hping3}")

    if hping3 is None:
        pytest.exit("hping3 is not installed or not in PATH", returncode=1)

    FLOOD_CMD = ["timeout", FLOOD_TIMEOUT_SEC, hping3, "--udp", "-p", "12345", "--data", "123"] + FLOOD_ARG.split() + ["127.0.0.1"]
    human_cmd = ' '.join(FLOOD_CMD)
    print(f"hping3: {human_cmd}")

    hping3_instances = FLOOD_NUM if should_flood() else 1

    print(f"Starting UDP traffic {hping3_instances} x `hping3 {FLOOD_ARG}` (timeout {FLOOD_TIMEOUT_SEC})...")

    flood_procs = []
    for _ in range(hping3_instances):
        proc = subprocess.Popen(
            FLOOD_CMD,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            preexec_fn=os.setsid,
        )

        time.sleep(0.2)
        ret = proc.poll()
        if ret is not None:
            stdout, stderr = proc.communicate()
            if stderr is not None:
                print(f">> stdout: {stdout.strip()}")
                print(f">> stderr: {stderr.strip()}")
                cmd = ' '.join(FLOOD_CMD)
                pytest.exit(f"Process failed: '{human_cmd}'", returncode=1)

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
    app_cmd = [APP, "--iface", "lo", "--timeout", TIMEOUT] + app_extra_args

    if os.geteuid() != 0:
        pytest.exit("hping3 requires root privileges. Please run pytest with `sudo -E`.", returncode=1)

    time.sleep(CALM_SEC)  # Calm down
    print()
    print(f"[{index}] Run: {' '.join(app_cmd)}")
    subprocess.run(app_cmd)
