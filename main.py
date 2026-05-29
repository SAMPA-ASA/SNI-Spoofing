import asyncio
import ctypes
import datetime
import logging
import os
import socket
import subprocess
import sys
import threading
import json

# from utils.proxy_protocols import parse_vless_protocol
from utils.network_tools import get_default_interface_ipv4
from utils.packet_templates import ClientHelloMaker
from fake_tcp import FakeInjectiveConnection, FakeTcpInjector


def get_exe_dir():
    """Returns the directory where the .exe (or script) is located."""
    if getattr(sys, 'frozen', False):
        # Running as a PyInstaller EXE
        return os.path.dirname(sys.executable)
    else:
        # Running as a normal Python script
        return os.path.dirname(os.path.abspath(__file__))


class DailyDateFileHandler(logging.FileHandler):
    def __init__(self, logs_dir: str, base_name: str, encoding: str = "utf-8"):
        self.logs_dir = logs_dir
        self.base_name = base_name
        self.current_date = self._today()
        os.makedirs(self.logs_dir, exist_ok=True)
        super().__init__(self._build_path(self.current_date), mode="a", encoding=encoding, delay=False)

    @staticmethod
    def _today() -> str:
        return datetime.date.today().strftime("%Y-%m-%d")

    def _build_path(self, date_text: str) -> str:
        return os.path.join(self.logs_dir, f"{self.base_name}-{date_text}.log")

    def _roll_if_needed(self):
        new_date = self._today()
        if new_date == self.current_date:
            return

        self.acquire()
        try:
            if new_date != self.current_date:
                if self.stream:
                    self.stream.close()
                    self.stream = None
                self.current_date = new_date
                self.baseFilename = os.path.abspath(self._build_path(new_date))
                self.stream = self._open()
        finally:
            self.release()

    def emit(self, record: logging.LogRecord):
        self._roll_if_needed()
        super().emit(record)


def setup_logging():
    logs_dir = os.path.join(get_exe_dir(), "logs")
    os.makedirs(logs_dir, exist_ok=True)

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")

    file_handler = DailyDateFileHandler(logs_dir=logs_dir, base_name="sni-spoofing", encoding="utf-8")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    logging.basicConfig(
        level=logging.INFO,
        handlers=[file_handler, console_handler],
        force=True,
    )


def setup_global_exception_logging():
    def sys_excepthook(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            logging.info("KeyboardInterrupt received.")
            return
        logging.critical("Unhandled exception in main thread.", exc_info=(exc_type, exc_value, exc_traceback))

    def thread_excepthook(args: threading.ExceptHookArgs):
        if issubclass(args.exc_type, KeyboardInterrupt):
            logging.info("KeyboardInterrupt received in thread: %s", args.thread.name)
            return
        logging.critical(
            "Unhandled exception in thread: %s",
            args.thread.name,
            exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
        )

    def unraisablehook(unraisable: sys.UnraisableHookArgs):
        logging.critical(
            "Unraisable exception: %s",
            getattr(unraisable, "err_msg", "no message"),
            exc_info=(
                type(unraisable.exc_value),
                unraisable.exc_value,
                unraisable.exc_traceback,
            ),
        )

    sys.excepthook = sys_excepthook
    threading.excepthook = thread_excepthook
    sys.unraisablehook = unraisablehook


def setup_asyncio_exception_logging(loop: asyncio.AbstractEventLoop):
    def loop_exception_handler(_: asyncio.AbstractEventLoop, context: dict):
        exc = context.get("exception")
        msg = context.get("message", "Unhandled asyncio exception.")
        if isinstance(exc, asyncio.CancelledError):
            return
        if exc is not None:
            logging.error("Asyncio error: %s", msg, exc_info=(type(exc), exc, exc.__traceback__))
        else:
            logging.error("Asyncio error: %s | context=%s", msg, context)

    loop.set_exception_handler(loop_exception_handler)


def is_running_as_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    if os.name != "nt":
        return False

    if getattr(sys, "frozen", False):
        executable = sys.executable
        parameters = subprocess.list2cmdline(sys.argv[1:])
    else:
        executable = sys.executable
        script_path = os.path.abspath(__file__)
        parameters = subprocess.list2cmdline([script_path, *sys.argv[1:]])

    result = ctypes.windll.shell32.ShellExecuteW(
        None,
        "runas",
        executable,
        parameters,
        None,
        1,
    )
    return result > 32


# Build the path to config.json
config_path = os.path.join(get_exe_dir(), 'config.json')

# Load the config
with open(config_path, 'r') as f:
    config = json.load(f)

LISTEN_HOST = config["LISTEN_HOST"]
LISTEN_PORT = config["LISTEN_PORT"]
FAKE_SNI = config["FAKE_SNI"].encode()
CONNECT_IP = config["CONNECT_IP"]
CONNECT_PORT = config["CONNECT_PORT"]
DATA_MODE = "tls"
BYPASS_METHOD = "wrong_seq"

##################

fake_injective_connections: dict[tuple, FakeInjectiveConnection] = {}


def is_expected_disconnect(exc: Exception) -> bool:
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
        return True
    if isinstance(exc, OSError):
        return getattr(exc, "winerror", None) in {6, 64, 995, 10038, 10053, 10054, 10058}
    return False


def safe_close_socket(sock: socket.socket | None):
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


async def relay_main_loop(sock_1: socket.socket, sock_2: socket.socket, first_prefix_data: bytes):
    loop = asyncio.get_running_loop()
    try:
        while True:
            data = await loop.sock_recv(sock_1, 65575)
            if not data:
                break
            if first_prefix_data:
                data = first_prefix_data + data
                first_prefix_data = b""
            await loop.sock_sendall(sock_2, data)
    except asyncio.CancelledError:
        raise
    except Exception as exc:
        if not is_expected_disconnect(exc):
            logging.exception("Unexpected relay error: %r", exc)


async def handle(incoming_sock: socket.socket, incoming_remote_addr):
    outgoing_sock: socket.socket | None = None
    try:
        loop = asyncio.get_running_loop()
        interface_ipv4 = get_default_interface_ipv4(CONNECT_IP)
        if not interface_ipv4:
            logging.warning("No active IPv4 interface found for %s. Closing connection from %s.", CONNECT_IP, incoming_remote_addr)
            return
        # try:
        #     data = await loop.sock_recv(incoming_sock, 65575)
        #     if not data:
        #         raise ValueError("eof")
        # except Exception:
        #     incoming_sock.close()
        #     return
        # try:
        #     version, uuid_bytes, transport_protocol, remote_address_type, remote_address, remote_port, payload_index = parse_vless_protocol(
        #         data)
        # except Exception as e:
        #     print("No Vless Request!, Connection Closed", repr(e), data)
        #     incoming_sock.close()
        #     return
        # if transport_protocol != "tcp":
        #     print("Transport Protocol Error!, Connection Closed", transport_protocol, data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "hostname":
        #     print("hostname address not implemented yet!", data)
        #     incoming_sock.close()
        #     return
        # if remote_address_type == "ipv4":
        #     if not INTERFACE_IPV4:
        #         print("no interface ipv4!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET
        #     src_ip = INTERFACE_IPV4
        #
        # elif remote_address_type == "ipv6":
        #     if not INTERFACE_IPV6:
        #         print("no interface ipv6!", data)
        #         incoming_sock.close()
        #         return
        #     family = socket.AF_INET6
        #     src_ip = INTERFACE_IPV6
        #
        # else:
        #     print(data)
        #     sys.exit("impossible address type!")

        # try:
        #     fake_sni_host, data_mode, bypass_method = UUID_FAKE_MAP[uuid_bytes]
        # except KeyError:
        #     print("unmatched uuid", uuid_bytes)
        #     incoming_sock.close()
        #     return

        # if data_mode == "http":
        #     ...
        if DATA_MODE == "tls":
            fake_data = ClientHelloMaker.get_client_hello_with(os.urandom(32), os.urandom(32), FAKE_SNI,
                                                               os.urandom(32))
        else:
            logging.error("Invalid DATA_MODE: %s", DATA_MODE)
            return
        outgoing_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        outgoing_sock.setblocking(False)
        outgoing_sock.bind((interface_ipv4, 0))
        outgoing_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
        outgoing_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
        src_port = outgoing_sock.getsockname()[1]
        fake_injective_conn = FakeInjectiveConnection(outgoing_sock, interface_ipv4, CONNECT_IP, src_port, CONNECT_PORT,
                                                      fake_data,
                                                      BYPASS_METHOD, incoming_sock)
        fake_injective_connections[fake_injective_conn.id] = fake_injective_conn
        try:
            await loop.sock_connect(outgoing_sock, (CONNECT_IP, CONNECT_PORT))
        except Exception:
            fake_injective_conn.monitor = False
            del fake_injective_connections[fake_injective_conn.id]
            outgoing_sock.close()
            incoming_sock.close()
            return

        # if bypass_method == "wrong_checksum":
        #     ...

        if BYPASS_METHOD == "wrong_seq":
            try:
                await asyncio.wait_for(fake_injective_conn.t2a_event.wait(), 2)
                if fake_injective_conn.t2a_msg == "unexpected_close":
                    raise ValueError("unexpected close")
                if fake_injective_conn.t2a_msg == "fake_data_ack_recv":
                    pass
                else:
                    logging.error("Unexpected t2a message: %s", fake_injective_conn.t2a_msg)
                    return
            except Exception:
                fake_injective_conn.monitor = False
                del fake_injective_connections[fake_injective_conn.id]
                outgoing_sock.close()
                incoming_sock.close()
                return
        else:
            logging.error("Unknown BYPASS_METHOD: %s", BYPASS_METHOD)
            return

        fake_injective_conn.monitor = False
        del fake_injective_connections[fake_injective_conn.id]

        # early_data = data[payload_index:]
        # if early_data:
        #     try:
        #         sent_len = await loop.sock_sendall(outgoing_sock, early_data)
        #         if sent_len != len(early_data):
        #             raise ValueError("incomplete send")
        #     except Exception:
        #         outgoing_sock.close()
        #         incoming_sock.close()
        #         return

        ito_task = asyncio.create_task(relay_main_loop(incoming_sock, outgoing_sock, b""))
        oti_task = asyncio.create_task(relay_main_loop(outgoing_sock, incoming_sock, b""))  # bytes([version, 0])
        _, pending = await asyncio.wait({ito_task, oti_task}, return_when=asyncio.FIRST_COMPLETED)
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)



    except Exception:
        logging.exception("Unexpected error in connection handler from %s", incoming_remote_addr)
    finally:
        safe_close_socket(outgoing_sock)
        safe_close_socket(incoming_sock)


async def main():
    mother_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    mother_sock.setblocking(False)
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    mother_sock.bind((LISTEN_HOST, LISTEN_PORT))
    mother_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
    mother_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    mother_sock.listen()
    loop = asyncio.get_running_loop()
    setup_asyncio_exception_logging(loop)
    try:
        while True:
            incoming_sock, addr = await loop.sock_accept(mother_sock)
            incoming_sock.setblocking(False)
            incoming_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 11)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 2)
            incoming_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            asyncio.create_task(handle(incoming_sock, addr))
    finally:
        safe_close_socket(mother_sock)


if __name__ == "__main__":
    setup_logging()
    setup_global_exception_logging()

    if not is_running_as_admin():
        logging.warning("Program is not running as administrator. Trying to relaunch with admin rights.")
        if relaunch_as_admin():
            logging.info("Admin relaunch requested successfully. Exiting current process.")
            sys.exit(0)
        logging.error("Failed to relaunch as administrator.")
        sys.exit(1)

    w_filter = "tcp and (ip.DstAddr == " + CONNECT_IP + " or ip.SrcAddr == " + CONNECT_IP + ")"
    fake_tcp_injector = FakeTcpInjector(w_filter, fake_injective_connections)
    threading.Thread(target=fake_tcp_injector.run, args=(), daemon=True).start()
    logging.info("Program started.")
    print("هشن شومافر تیامح دینکیم هدافتسا دازآ تنرتنیا هب یسرتسد یارب همانرب نیا زا رگا")
    print(
        "دراد امش تیامح هب زاین هک مراد رظن رد دازآ تنرتنیا هب ناریا مدرم مامت یسرتسد یارب یدایز یاه همانرب و اه هژورپ")
    print("\n")
    print("USDT (BEP20): 0x76a768B53Ca77B43086946315f0BDF21156bF424\n")
    print("@patterniha")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("Shutdown requested by user (Ctrl+C).")
